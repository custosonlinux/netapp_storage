"""
Auto-Discovery: matches PVE storages to ONTAP volumes/LUNs.

NFS:  PVE NFS server IP ∈ ONTAP LIF IPs → SVM → volume via junction_path.
SAN:  PVE LVM VG → PV device serial ∈ ONTAP LUN serials → volume.
      Supports iSCSI (direct + multipath) and NVMe-oF.
"""

import logging
import shlex
import socket
import time
import uuid as _uuid
from datetime import datetime, timezone

import requests as _req

from pegaprox.core.db import get_db
from ._helpers import build_ontap_client, ssh_run

log = logging.getLogger(__name__)


def _db_execute_retry(db, sql, params, retries=8, delay=0.4):
    """db.execute() mit Retry bei SQLite-Lock (SQLITE_LOCKED tritt auch bei timeout=30 auf)."""
    for attempt in range(retries):
        try:
            db.execute(sql, params)
            return
        except Exception as exc:
            if "locked" in str(exc).lower() and attempt < retries - 1:
                time.sleep(delay)
            else:
                raise


# ── PVE-API-Session ───────────────────────────────────────────────────────────

def _pve_session(pve_host):
    """Build a requests.Session with PVE ticket auth.

    pve_host: {host, port, username, password, ssl_verify}
    Returns (session, base_url) or raises on error.
    """
    base = f"https://{pve_host['host']}:{pve_host['port']}/api2/json"
    ssl_verify = bool(pve_host.get("ssl_verify", 0))
    try:
        r = _req.post(
            f"{base}/access/ticket",
            data={"username": pve_host["username"], "password": pve_host["password"]},
            verify=ssl_verify,
            timeout=15,
        )
    except Exception as exc:
        raise RuntimeError(f"PVE-Login fehlgeschlagen ({pve_host['host']}): {exc}")

    if r.status_code != 200:
        raise RuntimeError(
            f"PVE-Login {pve_host['host']} → HTTP {r.status_code}: {r.text[:200]}"
        )
    data   = r.json().get("data", {})
    ticket = data.get("ticket", "")
    csrf   = data.get("CSRFPreventionToken", "")

    sess = _req.Session()
    sess.verify = ssl_verify
    sess.cookies.set("PVEAuthCookie", ticket)
    sess.headers.update({"CSRFPreventionToken": csrf})
    return sess, base


def _get_pve_nfs_storages(pve_host):
    """All NFS storages of a PVE host.

    Returns (storages, error_msg).
    storages = [{storage_id, server, export, nfs_mount_path, pve_host_id}]
    """
    try:
        sess, base = _pve_session(pve_host)
        r = sess.get(f"{base}/storage", timeout=15)
        if r.status_code != 200:
            return [], f"PVE /storage → HTTP {r.status_code}"

        all_storages = r.json().get("data", [])
        nfs = []
        for s in all_storages:
            if s.get("type") != "nfs":
                continue
            nfs.append({
                "storage_id":     s.get("storage", ""),
                "server":         s.get("server", ""),
                "export":         s.get("export", "").rstrip("/"),
                "nfs_mount_path": s.get("path", ""),
                "pve_host_id":    pve_host["id"],
                "pve_host_name":  pve_host["name"],
            })
        return nfs, None

    except Exception as exc:
        return [], str(exc)


def _resolve_ips(host):
    ips = {host}
    try:
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips


# ── Main discovery ────────────────────────────────────────────────────────────

def run_discovery(endpoint_id=None):
    """Run the full discovery pass.

    Returns (found_mappings, debug_info).
    """
    db  = get_db()
    now = datetime.now(timezone.utc).isoformat()

    ep_rows = db.query(
        "SELECT * FROM netapp_endpoints WHERE id=?" if endpoint_id else "SELECT * FROM netapp_endpoints",
        (endpoint_id,) if endpoint_id else ()
    )
    pve_rows = db.query("SELECT * FROM netapp_pve_hosts")

    found_mappings = []
    debug_info = {
        "pve_hosts_count":   len(pve_rows or []),
        "endpoints":         [],
        "pve_storages":      [],
        "no_match_reasons":  [],
    }

    if not pve_rows:
        debug_info["no_match_reasons"].append(
            "No PVE hosts configured. Please add a PVE host in the 'Endpoints' tab."
        )
        return found_mappings, debug_info

    # ── PVE-NFS-Storages sammeln ──────────────────────────────────────────────
    all_pve_storages = []
    for row in pve_rows:
        pve = dict(row)
        pve["password"] = db._decrypt(pve.pop("password_encrypted", ""))
        storages, err = _get_pve_nfs_storages(pve)
        if err:
            debug_info["no_match_reasons"].append(
                f"PVE '{pve['name']}' ({pve['host']}): {err}"
            )
        elif not storages:
            # NFS-Storages auflisten zur Diagnose
            try:
                sess, base = _pve_session(pve)
                r2 = sess.get(f"{base}/storage", timeout=15)
                all_types = []
                if r2.status_code == 200:
                    all_types = [
                        f"{s.get('storage')} (type={s.get('type')})"
                        for s in r2.json().get("data", [])
                    ]
                debug_info["no_match_reasons"].append(
                    f"PVE '{pve['name']}': no NFS datastores found. "
                    f"Available storages: {all_types or '(none)'}"
                )
            except Exception as exc2:
                debug_info["no_match_reasons"].append(
                    f"PVE '{pve['name']}': no NFS datastores found (diagnostic: {exc2})"
                )
        else:
            all_pve_storages.extend(storages)

    debug_info["pve_storages"] = [
        {
            "pve":        s["pve_host_name"],
            "storage_id": s["storage_id"],
            "server":     s["server"],
            "export":     s["export"],
        }
        for s in all_pve_storages
    ]

    # ── ONTAP-Endpoints ───────────────────────────────────────────────────────
    for ep_row in (ep_rows or []):
        ep = dict(ep_row)
        ep["password"] = db._decrypt(ep.pop("password_encrypted", ""))

        # SAN-only systems (e.g. NetApp ASA) skip NFS scan
        if ep.get("skip_nfs"):
            log.info(f"[netapp_storage] NFS scan skipped for '{ep['name']}' (skip_nfs=1)")
            continue

        try:
            client = build_ontap_client(ep)
        except Exception as exc:
            msg = f"ONTAP '{ep['name']}' ({ep['host']}): Verbindung fehlgeschlagen: {exc}"
            log.warning(f"[netapp_storage] {msg}")
            debug_info["no_match_reasons"].append(msg)
            continue

        try:
            ip_to_svm = client.get_lif_svm_map()
        except Exception as exc:
            msg = f"ONTAP '{ep['name']}': LIF-Abfrage fehlgeschlagen: {exc}"
            log.warning(f"[netapp_storage] {msg}")
            debug_info["no_match_reasons"].append(msg)
            ip_to_svm = {}

        try:
            ontap_volumes = client.get_volumes()
        except Exception as exc:
            msg = f"ONTAP '{ep['name']}': Volume-Abfrage fehlgeschlagen: {exc}"
            log.warning(f"[netapp_storage] {msg}")
            debug_info["no_match_reasons"].append(msg)
            continue

        vol_by_svm_and_path = {}
        for vol in ontap_volumes:
            jp  = (vol.get("nas") or {}).get("path", "").rstrip("/")
            svm = (vol.get("svm") or {}).get("name", "")
            if jp and svm:
                vol_by_svm_and_path.setdefault(svm, {})[jp] = vol

        debug_info["endpoints"].append({
            "endpoint":  ep["name"],
            "host":      ep["host"],
            "lif_count": len(ip_to_svm),
            "lif_map":   ip_to_svm,
            "volumes":   [
                {
                    "svm":      (v.get("svm") or {}).get("name", ""),
                    "name":     v.get("name", ""),
                    "junction": (v.get("nas") or {}).get("path", ""),
                }
                for v in ontap_volumes
                if (v.get("nas") or {}).get("path")
            ],
        })

        # ── Abgleich ─────────────────────────────────────────────────
        for stor in all_pve_storages:
            server     = stor["server"]
            export     = stor["export"]
            pve_host_id = stor["pve_host_id"]
            server_ips  = _resolve_ips(server)

            matched_svm = None
            matched_ip  = None
            for ip in server_ips:
                if ip in ip_to_svm:
                    matched_svm = ip_to_svm[ip]
                    matched_ip  = ip
                    break

            if not matched_svm:
                debug_info["no_match_reasons"].append(
                    f"'{stor['storage_id']}': NFS server {server} ({sorted(server_ips)}) "
                    f"not found in ONTAP LIFs ({sorted(ip_to_svm.keys())})"
                )
                continue

            svm_vols = vol_by_svm_and_path.get(matched_svm, {})
            if export not in svm_vols:
                debug_info["no_match_reasons"].append(
                    f"'{stor['storage_id']}': SVM '{matched_svm}' via LIF {matched_ip}, "
                    f"no volume with junction '{export}'. "
                    f"Available: {sorted(svm_vols.keys())}"
                )
                continue

            vol      = svm_vols[export]
            vol_uuid = vol.get("uuid", "")
            vol_name = vol.get("name", "")
            mid      = str(_uuid.uuid4())

            try:
                _db_execute_retry(
                    db,
                    "INSERT INTO netapp_volume_mapping "
                    "(id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name, "
                    "volume_uuid, volume_name, junction_path, nfs_export_ip, "
                    "nfs_mount_path, discovered_at, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET "
                    "endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name, "
                    "volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name, "
                    "junction_path=excluded.junction_path, nfs_export_ip=excluded.nfs_export_ip, "
                    "nfs_mount_path=excluded.nfs_mount_path, discovered_at=excluded.discovered_at",
                    (mid, ep["id"], pve_host_id, stor["storage_id"],
                     matched_svm, vol_uuid, vol_name, export, server,
                     stor["nfs_mount_path"], now, now),
                )
                row = db.query_one(
                    "SELECT * FROM netapp_volume_mapping "
                    "WHERE pve_cluster_id=? AND pve_storage_id=?",
                    (pve_host_id, stor["storage_id"]),
                )
                if row:
                    found_mappings.append(dict(row))
                log.info(
                    f"[netapp_storage] Mapping: {pve_host_id}/{stor['storage_id']} "
                    f"→ SVM {matched_svm}/{vol_name} (LIF {matched_ip})"
                )
            except Exception as exc:
                msg = (f"DB insert failed for '{stor['storage_id']}': {exc} "
                       f"| endpoint_id={ep['id']} vol_uuid={vol_uuid!r} vol_name={vol_name!r}")
                log.warning(f"[netapp_storage] {msg}")
                debug_info["no_match_reasons"].append(msg)

    # ── SAN-Discovery (iSCSI / NVMe-oF) ─────────────────────────────────────
    _run_san_discovery(db, ep_rows, pve_rows, found_mappings, debug_info, now)

    return found_mappings, debug_info


# ═══════════════════════════════════════════════════════════════════════════════
# SAN-Discovery (iSCSI / NVMe-oF)
# ═══════════════════════════════════════════════════════════════════════════════

def _ssh_creds(pve_host):
    """Returns (host, user, password, key_material) for ssh_run."""
    uname = pve_host.get("username", "root@pam")
    return pve_host["host"], uname.split("@")[0], pve_host["password"], ""


def _get_pve_lvm_storages(pve_host):
    """All lvm/lvmthin storages of a PVE host with PV device and serial number.

    Uses PVE REST API for VG/pool name and SSH for pvs + lsblk.
    Returns (storages, error_msg).
    storages = [{storage_id, vg_name, lvm_type, pool_name,
                 pv_device, pv_serial, protocol, pve_host_id, pve_host_name}]
    """
    try:
        sess, base = _pve_session(pve_host)
        r = sess.get(f"{base}/storage", timeout=15)
        if not r.ok:
            return [], f"PVE /storage → HTTP {r.status_code}"

        all_storages = r.json().get("data", [])
        lvm_storages = []
        for s in all_storages:
            stype = s.get("type", "")
            if stype not in ("lvm", "lvmthin"):
                continue
            vg = s.get("vgname", "")
            if not vg:
                continue
            lvm_storages.append({
                "storage_id":    s.get("storage", ""),
                "vg_name":       vg,
                "lvm_type":      "thin" if stype == "lvmthin" else "linear",
                "pool_name":     s.get("thinpool", "") if stype == "lvmthin" else "",
                "pv_device":     "",
                "pv_serial":     "",
                "nvme_ns_uuid":  "",
                "protocol":      "iscsi",
                "pve_host_id":   pve_host["id"],
                "pve_host_name": pve_host["name"],
            })

        if not lvm_storages:
            return [], None

        # SSH: PV → VG-Zuordnung
        h, u, p, k = _ssh_creds(pve_host)
        try:
            pvs_out = ssh_run(
                h, u, p,
                "pvs --noheadings -o pv_name,vg_name 2>/dev/null",
                capture=True, key_material=k,
            )
            pv_map = {}  # {vg_name: [pv_device, ...]}
            for line in pvs_out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    pv_map.setdefault(parts[1].strip(), []).append(parts[0].strip())
        except Exception as exc:
            log.warning(f"[netapp_storage] pvs auf {pve_host['host']} fehlgeschlagen: {exc}")
            return lvm_storages, f"pvs fehlgeschlagen: {exc}"

        # SSH: which VGs already have a netapp_snapmanifest LV?
        try:
            snap_out = ssh_run(
                h, u, p,
                "lvs --noheadings -o lv_name,vg_name 2>/dev/null "
                "| awk '$1==\"netapp_snapmanifest\"{print $2}'",
                capture=True, key_material=k,
            )
            snap_vgs = {line.strip() for line in snap_out.splitlines() if line.strip()}
        except Exception:
            snap_vgs = set()

        # SSH: Device-Basename → SCSI-Seriennummer
        # Multipath (/dev/mapper/mpathX) und direkte Devices (/dev/sdX, /dev/nvmeXnY)
        # erscheinen beide in lsblk OUTPUT mit ihrem Basename.
        try:
            lsblk_out = ssh_run(
                h, u, p,
                "lsblk -o NAME,SERIAL --noheadings 2>/dev/null",
                capture=True, key_material=k,
            )
            serial_map = {}  # {basename: serial}
            for line in lsblk_out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].strip():
                    serial_map[parts[0].lstrip()] = parts[1].strip()
        except Exception as exc:
            log.warning(f"[netapp_storage] lsblk failed on {pve_host['host']}: {exc}")
            serial_map = {}

        # Merge PV serials into storage entries
        for stor in lvm_storages:
            pvs_for_vg = pv_map.get(stor["vg_name"], [])
            if not pvs_for_vg:
                log.debug(
                    f"[netapp_storage] VG {stor['vg_name']}: kein PV-Device in pvs-Output "
                    f"(bekannte VGs: {sorted(pv_map.keys())})"
                )
                continue

            pv_dev   = pvs_for_vg[0]
            dev_base = pv_dev.split("/")[-1]
            stor["pv_device"] = pv_dev

            if "nvme" in pv_dev:
                # NVMe-oF: Namespace-UUID aus sysfs lesen.
                # If the PV is on a partition (e.g. nvme1n1p1), the parent
                # namespace (nvme1n1) must be used for UUID lookup — partitions
                # have no uuid attribute.
                stor["protocol"] = "nvme"
                import re as _re
                ns_base = _re.sub(r'p\d+$', '', dev_base)  # nvme1n1p1 → nvme1n1
                ns_dev  = f"/dev/{ns_base}"
                try:
                    uuid_out = ssh_run(
                        h, u, p,
                        f"cat /sys/class/block/{shlex.quote(ns_base)}/uuid 2>/dev/null",
                        capture=True, key_material=k,
                    )
                    ns_uuid = uuid_out.strip().lower()
                    if not ns_uuid:
                        # Fallback: nvme-cli (older kernels without sysfs uuid)
                        uuid_out2 = ssh_run(
                            h, u, p,
                            f"nvme id-ns {shlex.quote(ns_dev)} 2>/dev/null "
                            f"| awk '/^uuid/{{print $NF; exit}}'",
                            capture=True, key_material=k,
                        )
                        ns_uuid = uuid_out2.strip().lower()
                    stor["nvme_ns_uuid"] = ns_uuid
                    log.info(
                        f"[netapp_storage] NVMe UUID {pv_dev} (NS={ns_dev}): {ns_uuid or '—'}"
                    )
                except Exception as exc:
                    log.debug(f"[netapp_storage] NVMe UUID-Lookup {pv_dev}: {exc}")
            else:
                # iSCSI: Extract serial from device.
                # Case 1: multipath device — /dev/mapper/<WWID> where WWID is the
                #   DM WWID string like "3600a098038323449383f5a38746e4837".
                #   The ONTAP serial is encoded in chars 9-32 of the WWID
                #   (strip "3" DM prefix + "600a0980" NetApp NAA+OUI prefix = 9 chars).
                #   Fallback: try lsblk serial on the mapper name.
                # Case 2: direct device — /dev/sdX — use lsblk SERIAL directly.
                stor["protocol"] = "iscsi"
                serial = ""
                if pv_dev.startswith("/dev/mapper/"):
                    wwid = dev_base  # e.g. 3600a098038323449383f5a38746e4837
                    if len(wwid) == 33 and wwid.upper().startswith("3600A098"):
                        # NetApp ONTAP NAA-6 WWID: strip 1 DM prefix + 8 NAA/OUI chars
                        serial = wwid[9:].upper()
                        log.info(f"[netapp_storage] iSCSI multipath {pv_dev}: "
                                 f"extracted serial {serial} from WWID")
                    if not serial:
                        # Fallback: try lsblk on mapper device
                        serial = serial_map.get(dev_base, "").upper()
                        if not serial:
                            # Last resort: lsblk on first underlying physical path
                            try:
                                slaves_out = ssh_run(
                                    h, u, p,
                                    f"ls /sys/block/{shlex.quote(dev_base)}/slaves/ "
                                    f"2>/dev/null | head -1",
                                    capture=True, key_material=k,
                                )
                                slave = slaves_out.strip()
                                if slave:
                                    serial = serial_map.get(slave, "").upper()
                            except Exception:
                                pass
                else:
                    serial = serial_map.get(dev_base, "").upper()
                stor["pv_serial"] = serial

            # Flag whether snapmanifest LV already exists on this VG
            stor["snapmanifest_exists"] = stor["vg_name"] in snap_vgs

        return lvm_storages, None

    except Exception as exc:
        return [], str(exc)


def _run_san_discovery(db, ep_rows, pve_rows, found_mappings, debug_info, now):
    """SAN-Discovery: matched ONTAP-LUNs mit PVE-LVM-Storages via Seriennummer.

    Erweitert found_mappings und debug_info in-place.
    Seriennummern-Vergleich ist case-insensitive.
    """
    # PVE LVM-Storages mit PV-Serials sammeln
    all_lvm_storages = []
    for row in (pve_rows or []):
        pve = dict(row)
        pve["password"] = db._decrypt(pve.pop("password_encrypted", ""))
        storages, err = _get_pve_lvm_storages(pve)
        if err:
            debug_info["no_match_reasons"].append(
                f"PVE '{pve['name']}' SAN-Storages: {err}"
            )
        for s in storages:
            if s.get("pv_serial") or s.get("nvme_ns_uuid"):
                all_lvm_storages.append(s)
            elif s.get("pv_device"):
                debug_info["no_match_reasons"].append(
                    f"PVE '{pve['name']}' Storage '{s['storage_id']}': "
                    f"kein Identifier ermittelbar (VG={s['vg_name']}, "
                    f"PV={s['pv_device']}, Protokoll={s.get('protocol','?')})"
                )

    if not all_lvm_storages:
        return

    debug_info.setdefault("san_storages", []).extend([
        {"pve": s["pve_host_name"], "storage_id": s["storage_id"],
         "vg": s["vg_name"], "serial": s.get("pv_serial", ""),
         "nvme_uuid": s.get("nvme_ns_uuid", ""), "protocol": s["protocol"]}
        for s in all_lvm_storages
    ])

    def _serial_to_hex(s):
        """Normalize a LUN serial to uppercase hex for WWID matching.

        ONTAP REST API returns serial_number as ASCII text (SCSI VPD Page 80).
        The multipath WWID encodes the same bytes as raw hex.
        E.g. ONTAP '824I8?Z8tnH7' == WWID-embedded '38323449383F5A38746E4837'.
        """
        if not s:
            return ""
        try:
            return s.encode("latin-1").hex().upper()
        except Exception:
            return s.upper()

    # iSCSI: Serial → Storage — keys stored as uppercase hex from WWID
    serial_to_stor  = {
        s["pv_serial"].upper(): s
        for s in all_lvm_storages if s.get("pv_serial")
    }
    # NVMe: Namespace-UUID → Storage (normalisiert mit Bindestrichen, lowercase)
    def _norm_uuid(u):
        try:
            import uuid as _u
            return str(_u.UUID(str(u))).lower()
        except Exception:
            return (u or "").lower()

    nvme_uuid_to_stor = {
        _norm_uuid(s["nvme_ns_uuid"]): s
        for s in all_lvm_storages if s.get("nvme_ns_uuid")
    }

    # ── ONTAP-Endpoints ────────────────────────────────────────────────────
    for ep_row in (ep_rows or []):
        ep = dict(ep_row)
        ep["password"] = db._decrypt(ep.pop("password_encrypted", ""))

        try:
            client = build_ontap_client(ep)
        except Exception as exc:
            debug_info["no_match_reasons"].append(
                f"ONTAP '{ep['name']}': Verbindung fehlgeschlagen: {exc}"
            )
            continue

        # iSCSI: LUN-Serial-Matching
        if serial_to_stor:
            try:
                luns = client.list_luns()
            except Exception as exc:
                debug_info["no_match_reasons"].append(
                    f"ONTAP '{ep['name']}': LUN-Abfrage fehlgeschlagen: {exc}"
                )
                luns = []

            for lun in luns:
                serial_hex = _serial_to_hex(lun.get("serial_number") or "")
                if not serial_hex or serial_hex not in serial_to_stor:
                    continue
                stor = serial_to_stor[serial_hex]
                _san_upsert(db, ep, lun.get("location") or {}, lun.get("svm") or {},
                            lun.get("uuid", ""), lun.get("name", ""),
                            stor, found_mappings, debug_info, now)

        # NVMe-oF: Namespace-UUID-Matching
        if nvme_uuid_to_stor:
            try:
                namespaces = client.list_nvme_namespaces()
            except Exception as exc:
                debug_info["no_match_reasons"].append(
                    f"ONTAP '{ep['name']}': NVMe-Namespace-Abfrage fehlgeschlagen: {exc}"
                )
                namespaces = []

            if not namespaces:
                debug_info["no_match_reasons"].append(
                    f"ONTAP '{ep['name']}': NVMe-Namespace-Liste leer "
                    f"(suche UUIDs: {sorted(nvme_uuid_to_stor.keys())})"
                )
            else:
                ns_debug = [
                    {
                        "endpoint": ep["name"],
                        "ns_uuid":  ns.get("uuid", ""),
                        "ns_name":  ns.get("name", ""),
                        "svm":      (ns.get("svm") or {}).get("name", ""),
                        "vol_name": (((ns.get("location") or {}).get("volume")) or {}).get("name", ""),
                        "vol_uuid": (((ns.get("location") or {}).get("volume")) or {}).get("uuid", ""),
                    }
                    for ns in namespaces
                ]
                debug_info.setdefault("san_debug", []).extend(ns_debug)

                # Wenn Namespaces ohne Vol-UUID vorhanden: SVM-Volumes im UI anzeigen
                missing_vol_svms = {
                    e["svm"] for e in ns_debug if not e["vol_uuid"] and e["svm"]
                }
                for svm_n in missing_vol_svms:
                    try:
                        vols = client.get_volumes_san(svm_name=svm_n)
                        vol_names = sorted(v.get("name", "") for v in vols if v.get("name"))
                        debug_info["no_match_reasons"].append(
                            f"ONTAP '{ep['name']}' SVM '{svm_n}': Volumes auf dem System: "
                            + (", ".join(vol_names) if vol_names else "(keine)")
                        )
                    except Exception as exc:
                        debug_info["no_match_reasons"].append(
                            f"ONTAP '{ep['name']}' SVM '{svm_n}': Volume-Abfrage fehlgeschlagen: {exc}"
                        )

            for ns in namespaces:
                ns_uuid = _norm_uuid(ns.get("uuid") or "")
                if not ns_uuid or ns_uuid not in nvme_uuid_to_stor:
                    continue
                stor = nvme_uuid_to_stor[ns_uuid]
                _san_upsert(db, ep, ns.get("location") or {}, ns.get("svm") or {},
                            ns.get("uuid", ""), ns.get("name", ""),
                            stor, found_mappings, debug_info, now)


def _san_upsert(db, ep, location, svm_obj, lun_uuid, lun_path,
                stor, found_mappings, debug_info, now):
    """Insert or update a SAN mapping (ON CONFLICT)."""
    vol_uuid = (location.get("volume") or {}).get("uuid", "")
    vol_name = (location.get("volume") or {}).get("name", "")
    svm_name = svm_obj.get("name", "")

    if not vol_uuid:
        debug_info["no_match_reasons"].append(
            f"LUN/Namespace {lun_path}: kein Volume-UUID in ONTAP-Antwort"
        )
        return

    snap_initialized = 1 if stor.get("snapmanifest_exists") else 0
    mid = str(_uuid.uuid4())
    try:
        _db_execute_retry(
            db,
            "INSERT INTO netapp_volume_mapping "
            "(id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name, "
            "volume_uuid, volume_name, junction_path, nfs_export_ip, "
            "nfs_mount_path, discovered_at, created_at, "
            "storage_protocol, lun_uuid, lun_path, "
            "lvm_vg_name, lvm_type, lvm_pool_name, snapinfo_initialized) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET "
            "endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name, "
            "volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name, "
            "lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path, "
            "lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type, "
            "lvm_pool_name=excluded.lvm_pool_name, "
            "storage_protocol=excluded.storage_protocol, "
            "snapinfo_initialized=max(snapinfo_initialized, excluded.snapinfo_initialized), "
            "discovered_at=excluded.discovered_at",
            (mid, ep["id"], stor["pve_host_id"], stor["storage_id"],
             svm_name, vol_uuid, vol_name, "", "", "",
             now, now,
             stor["protocol"], lun_uuid, lun_path,
             stor["vg_name"], stor["lvm_type"], stor.get("pool_name", ""),
             snap_initialized),
        )
        row = db.query_one(
            "SELECT * FROM netapp_volume_mapping "
            "WHERE pve_cluster_id=? AND pve_storage_id=?",
            (stor["pve_host_id"], stor["storage_id"]),
        )
        if row:
            found_mappings.append(dict(row))
        log.info(
            f"[netapp_storage] SAN-Mapping: {stor['pve_host_id']}/{stor['storage_id']} "
            f"→ {svm_name}/{vol_name} ({stor['protocol'].upper()}, "
            f"VG={stor['vg_name']}, LUN={lun_path})"
        )
    except Exception as exc:
        msg = (
            f"SAN DB-Insert fehlgeschlagen '{stor['storage_id']}': {exc} | "
            f"lun_uuid={lun_uuid!r} vol_uuid={vol_uuid!r}"
        )
        log.warning(f"[netapp_storage] {msg}")
        debug_info["no_match_reasons"].append(msg)
