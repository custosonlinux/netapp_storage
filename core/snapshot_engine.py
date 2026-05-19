"""
NetApp ONTAP Snapshot Engine

Runs the complete snapshot workflow for QEMU VMs and LXC containers:
  1. Fetch VM/CT config via Proxmox API
  2. Write manifest + config file to NFS datastore (via SSH on PVE node)
     Fallback: store manifest in DB if NFS write via SSH fails.
  3. Apply consistency (crash / app / suspend)
  4. Create volume snapshot (ONTAP REST)
  5. Poll job
  6. Release consistency
  7. Index snapshot in DB
"""

import json
import uuid
import logging
import threading
import shlex
from datetime import datetime, timezone

from pegaprox.core.db import get_db
from pegaprox.constants import PEGAPROX_VERSION

from .ontap_client import OntapError
from ._helpers import (
    load_plugin_config, get_endpoint, get_mapping,
    build_ontap_client, build_pve_client,
    get_ssh_creds, ssh_run, JobLogger, JobCancelledError, check_cancel,
)
from ._job_registry import register as _reg_register, unregister as _reg_unregister

log = logging.getLogger(__name__)


def start_snapshot_job(job_id, params, username):
    """Starts the snapshot workflow in a background thread."""
    t = threading.Thread(target=_run_snapshot, args=(job_id, params, username), daemon=True)
    t.start()
    _reg_register(job_id, t)


def _find_pve_for_vms(db, volume_uuid, vmids, fallback_cluster_id):
    """Selects the PVE host that actually hosts the given VMs.

    Tries all hosts that know this volume first, then all
    configured PVE hosts as fallback.
    """
    tried = set()

    def _try(cid):
        if cid in tried:
            return None
        tried.add(cid)
        try:
            candidate = build_pve_client(db, cid)
            if candidate.find_vm_node(vmids[0]):
                return candidate
        except Exception:
            pass
        return None

    # First: hosts with known mapping for this volume
    rows = db.query(
        "SELECT DISTINCT pve_cluster_id FROM netapp_volume_mapping WHERE volume_uuid=?",
        (volume_uuid,)
    )
    for row in rows:
        result = _try(row["pve_cluster_id"])
        if result:
            return result

    # Fallback: all configured PVE hosts
    all_hosts = db.query("SELECT id FROM netapp_pve_hosts")
    for row in all_hosts:
        result = _try(row["id"])
        if result:
            return result

    return build_pve_client(db, fallback_cluster_id)


def _run_snapshot(job_id, params, username):
    db = get_db()
    jlog = JobLogger(job_id, db)

    cluster_id = params["cluster_id"]
    node = params["node"]
    vmids = params["vmids"]           # list of int
    mapping_id = params["mapping_id"]
    consistency = params.get("consistency", "crash")
    snap_name_input  = params.get("snap_name", "")       # manually provided by user
    snap_name_suffix = params.get("snap_name_suffix", "") # schedule name
    snap_label   = params.get("label", "")
    schedule_id  = params.get("schedule_id", "")

    cfg = load_plugin_config()
    snap_prefix = cfg.get("snapshot_prefix", "NPP_")

    if snap_name_input:
        # Manual snapshot: NPP_{user_name}
        snap_name = f"{snap_prefix}{snap_name_input}"
    else:
        # Schedule: NPP_{YYYYMMDD}_{HHMMSS}_{schedule_name}
        ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')
        snap_name = f"{snap_prefix}{ts}"
        if snap_name_suffix:
            snap_name += f"_{snap_name_suffix}"

    snapshot_id = str(uuid.uuid4())

    try:
        mapping = get_mapping(db, mapping_id)
        mgr = _find_pve_for_vms(db, mapping["volume_uuid"], vmids, cluster_id)
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client = build_ontap_client(endpoint)
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)

        # ── 1. Fetch VM/CT configurations ─────────────────────────────
        jlog.log("Fetching VM/CT configurations …")
        vm_entries = []
        vm_types = {}

        # resolve vmid → node once via cluster/resources (one API call)
        try:
            _r = mgr._api_get(f"{mgr._base}/cluster/resources?type=vm")
            _vm_node_map = {
                int(res["vmid"]): res["node"]
                for res in (_r.json().get("data", []) if _r.ok else [])
                if res.get("vmid") and res.get("node")
            }
        except Exception:
            _vm_node_map = {}

        for vmid in vmids:
            vm_node = _vm_node_map.get(int(vmid), node)
            vm_type = _detect_vm_type(mgr, vm_node, vmid)
            vm_types[str(vmid)] = vm_type
            result = mgr.get_vm_config(vm_node, vmid, vm_type)
            if not result.get("success"):
                raise RuntimeError(f"Proxmox config for {vm_type.upper()} {vmid} not available: {result.get('error')}")
            cfg_raw = result["config"].get("raw", {})
            disks = _extract_disk_files(cfg_raw, mapping["pve_storage_id"], vm_type)
            vm_entries.append({
                "vmid": vmid,
                "vm_type": vm_type,
                "name": cfg_raw.get("name", cfg_raw.get("hostname", f"vm-{vmid}")),
                "config_file": f"{vmid}.conf",
                "disks": disks,
                "_raw_conf": cfg_raw,
                "_node": vm_node,
            })

        # ── 2. Build manifest ──────────────────────────────────────────
        manifest = {
            "schema": "pegaprox-netapp-v1",
            "snapshot_name": snap_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "consistency": consistency,
            "cluster_id": cluster_id,
            "node": node,
            "pegaprox_version": PEGAPROX_VERSION,
            "ontap_cluster": endpoint["host"],
            "mapping_id": mapping_id,
            "volume_uuid": mapping["volume_uuid"],
            "vms": [
                {**{k: v for k, v in e.items() if k != "_raw_conf"},
                 "raw_config": e.get("_raw_conf", {})}
                for e in vm_entries
            ],
        }
        manifest_json_str = json.dumps(manifest, indent=2)

        # ── 3. Write manifest (NFS or SAN/snapmanifest) ──────────────────
        storage_protocol = mapping.get("storage_protocol", "nfs")
        is_san = storage_protocol in ("iscsi", "nvme")
        pve_host = _resolve_node_host(mgr, node)

        if is_san:
            # SAN: write manifest to snapmanifest LV — rides inside every ONTAP snapshot.
            if not mapping.get("snapinfo_initialized"):
                raise RuntimeError(
                    f"snapmanifest LV for '{mapping['pve_storage_id']}' not initialized. "
                    "Please run 'Setup snapmanifest' in settings."
                )
            vg_name = mapping["lvm_vg_name"]
            lv_name = "netapp_snapmanifest"  # always canonical; DB snapinfo_lv_name may be stale
            san_manifest = dict(manifest)
            san_manifest["vms"] = [
                {**{k: v for k, v in e.items() if k not in ("_raw_conf", "_node")},
                 "config": _config_to_conf_string(e.get("_raw_conf", {}))}
                for e in vm_entries
            ]
            try:
                jlog.log("Writing manifest to snapmanifest LV …")
                from .san_helpers import snapmanifest_write_manifest
                snapmanifest_write_manifest(
                    pve_host, pve_user, pve_pass, pve_key,
                    vg_name, lv_name, san_manifest, jlog=jlog,
                )
                manifest_path = f"snapmanifest:{vg_name}/{lv_name}/{snap_name}"
            except Exception as si_err:
                jlog.log(f"snapmanifest write failed ({si_err}); falling back to DB storage.")
                manifest_path = f"db:{snapshot_id}"
        else:
            # NFS: store manifest on the NFS datastore.
            manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
            snap_dir = f"{mapping['nfs_mount_path']}/{manifest_subdir}/{snap_name}"
            manifest_path = f"{snap_dir}/manifest.json"
            try:
                jlog.log("Writing manifest to NFS datastore …")
                ssh_run(pve_host, pve_user, pve_pass,
                        f"mkdir -p {shlex.quote(snap_dir)}",
                        key_material=pve_key)
                ssh_run(pve_host, pve_user, pve_pass,
                        f"cat > {shlex.quote(manifest_path)}",
                        stdin_data=manifest_json_str.encode(),
                        key_material=pve_key)
                for entry in vm_entries:
                    conf_content = _config_to_conf_string(entry["_raw_conf"])
                    conf_path = f"{snap_dir}/{entry['vmid']}.conf"
                    ssh_run(pve_host, pve_user, pve_pass,
                            f"cat > {shlex.quote(conf_path)}",
                            stdin_data=conf_content.encode(),
                            key_material=pve_key)
            except Exception as nfs_err:
                jlog.log(f"Manifest write to NFS failed ({nfs_err}); falling back to DB storage.")
                manifest_path = f"db:{snapshot_id}"

        # ── 4. Create snapshot record ──────────────────────────────────
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO netapp_snapshots "
            "(id, mapping_id, snap_name, consistency, pve_cluster_id, node, "
            "vmids_json, vm_types_json, manifest_path, manifest_json, label, schedule_id, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (snapshot_id, mapping_id, snap_name, consistency,
             cluster_id, node, json.dumps(vmids), json.dumps(vm_types),
             manifest_path, manifest_json_str, snap_label, schedule_id, "running", now),
        )
        db.execute("UPDATE netapp_jobs SET snapshot_id=? WHERE id=?", (snapshot_id, job_id))

        pre_script  = params.get("pre_script",  "").strip()
        post_script = params.get("post_script", "").strip()

        # ── 5. Pre-Script ─────────────────────────────────────────────
        if pre_script:
            jlog.log("Running pre-script …")
            _run_hook(pve_host, pve_user, pve_pass, pve_key,
                      pre_script, vmids, snap_name, node, jlog, "Pre-Script")

        # ── 6. Apply consistency ──────────────────────────────────────
        jlog.log(f"Applying consistency level '{consistency}' …")
        suspended, frozen = [], []
        try:
            if consistency == "app":
                for entry in vm_entries:
                    vmid   = entry["vmid"]
                    v_node = entry["_node"]
                    v_type = entry["vm_type"]
                    if v_type == "qemu":
                        ok = _qemu_fsfreeze(mgr, v_node, vmid)
                        if ok:
                            frozen.append(vmid)
                            jlog.log(f"VM {vmid}: filesystem frozen (app-consistent).")
                        else:
                            jlog.log(f"VM {vmid}: fsfreeze failed (guest agent available?) – trying suspend …")
                            if _vm_suspend(mgr, v_node, vmid, "qemu"):
                                suspended.append(vmid)
                                jlog.log(f"VM {vmid}: suspended (suspend fallback).")
                            else:
                                jlog.log(f"WARNING: VM {vmid}: suspend also failed – crash-consistent.")
                    else:  # LXC: no guest agent → suspend
                        if _vm_suspend(mgr, v_node, vmid, "lxc"):
                            suspended.append(vmid)
                            jlog.log(f"CT {vmid}: suspended (LXC app-consistent).")
                        else:
                            jlog.log(f"WARNING: CT {vmid}: suspend failed – crash-consistent.")

            elif consistency == "suspend":
                for entry in vm_entries:
                    vmid   = entry["vmid"]
                    v_node = entry["_node"]
                    v_type = entry["vm_type"]
                    label  = "VM" if v_type == "qemu" else "CT"
                    if _vm_suspend(mgr, v_node, vmid, v_type):
                        suspended.append(vmid)
                        jlog.log(f"{label} {vmid}: suspended.")
                    else:
                        jlog.log(f"WARNING: {label} {vmid}: suspend failed – crash-consistent.")

            # ── 7. Create ONTAP snapshot ───────────────────────────────
            jlog.log(f"Creating ONTAP snapshot '{snap_name}' …")
            job_uuid = client.create_snapshot(
                mapping["volume_uuid"], snap_name,
                comment=f"pegaprox cluster={cluster_id} vms={','.join(str(v) for v in vmids)}",
                snapmirror_label=snap_label,
            )

            # ── 8. Poll job ───────────────────────────────────────────
            poll_cfg = load_plugin_config()
            client.poll_job(
                job_uuid,
                interval_s=poll_cfg.get("job_poll_interval_s", 3),
                timeout_s=poll_cfg.get("job_poll_timeout_s", 300),
            )
            jlog.log("ONTAP job completed.")

            snaps = client.list_snapshots(mapping["volume_uuid"])
            ontap_snap_uuid = next((s["uuid"] for s in snaps if s["name"] == snap_name), "")

        finally:
            # ── 9. Release consistency ─────────────────────────────────
            for entry in vm_entries:
                vmid   = entry["vmid"]
                v_node = entry["_node"]
                v_type = entry["vm_type"]
                label  = "VM" if v_type == "qemu" else "CT"
                if vmid in frozen:
                    _qemu_fsthaw(mgr, v_node, vmid)
                    jlog.log(f"VM {vmid}: filesystem thawed.")
                if vmid in suspended:
                    if _vm_resume(mgr, v_node, vmid, v_type):
                        jlog.log(f"{label} {vmid}: resumed.")
                    else:
                        jlog.log(f"WARNING: {label} {vmid}: resume failed.")
            # Post-script runs even if snapshot failed
            if post_script:
                jlog.log("Running post-script …")
                _run_hook(pve_host, pve_user, pve_pass, pve_key,
                          post_script, vmids, snap_name, node, jlog, "Post-Script")

        # ── 9. Update DB ──────────────────────────────────────────────
        completed = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE netapp_snapshots SET status='done', ontap_snap_uuid=?, completed_at=? WHERE id=?",
            (ontap_snap_uuid, completed, snapshot_id),
        )
        db.execute(
            "UPDATE netapp_jobs SET status='done', progress_pct=100, completed_at=? WHERE id=?",
            (completed, job_id),
        )
        jlog.log(f"Snapshot '{snap_name}' created successfully.")

        # Optional SnapMirror® update after snapshot
        if params.get("snapmirror_update"):
            try:
                from .snapmirror import trigger_update_for_volume
                jlog.log("Triggering SnapMirror® update …")
                n = trigger_update_for_volume(db, mapping["volume_uuid"], mapping["endpoint_id"], jlog)
                if n == 0:
                    jlog.log("SnapMirror®: no relationships found (run scan first).")
            except Exception as sm_exc:
                jlog.log(f"SnapMirror® update: {sm_exc} (non-critical)")

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        now = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE netapp_jobs SET status='cancelled', completed_at=? WHERE id=?", (now, job_id))
        if snapshot_id:
            db.execute(
                "UPDATE netapp_snapshots SET status='failed', error='Cancelled', completed_at=? WHERE id=?",
                (now, snapshot_id),
            )
    except Exception as exc:
        log.error(f"[netapp_storage] snapshot job {job_id} failed: {exc}")
        now = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE netapp_jobs SET status='failed', completed_at=? WHERE id=?", (now, job_id))
        if snapshot_id:
            db.execute(
                "UPDATE netapp_snapshots SET status='failed', error=?, completed_at=? WHERE id=?",
                (str(exc), now, snapshot_id),
            )
        jlog.log(f"ERROR: {exc}")
    finally:
        _reg_unregister(job_id)
        # Send email notification for scheduled jobs if configured
        if params.get("notify_enabled") and params.get("notify_recipients"):
            try:
                job_row  = db.query_one("SELECT status, log_json FROM netapp_jobs WHERE id=?", (job_id,))
                fin_status  = job_row["status"] if job_row else "unknown"
                log_entries = json.loads(job_row["log_json"] or "[]") if job_row else []
                from ..api.settings import send_job_notification
                send_job_notification(
                    schedule_name=params.get("schedule_name", snap_name),
                    job_status=fin_status,
                    snap_name=snap_name or "",
                    recipients_csv=params["notify_recipients"],
                    notify_on=params.get("notify_on", "all"),
                    log_lines=log_entries,
                )
            except Exception as ne:
                log.warning(f"[netapp_storage] Notification failed for job {job_id}: {ne}")


# ── VM type detection ───────────────────────────────────────────────────────

def _detect_vm_type(mgr, node, vmid):
    """Checks whether vmid is a QEMU VM or an LXC container."""
    try:
        host = mgr.host
        r = mgr._api_get(
            f"https://{host}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/current"
        )
        if r.status_code == 200:
            return "qemu"
    except Exception:
        pass
    return "lxc"


# ── Extract disk file paths ──────────────────────────────────────────────────

def _extract_disk_files(config_raw, storage_id, vm_type="qemu"):
    """Extracts disk file paths from a Proxmox VM/CT config."""
    disks = []
    if vm_type == "qemu":
        disk_keys = ("scsi", "virtio", "ide", "sata", "efidisk", "tpmstate")
    else:
        # LXC: rootfs + mp0…mp9
        disk_keys = ("rootfs", "mp")

    for key, val in config_raw.items():
        if not isinstance(val, str):
            continue
        if not any(key.startswith(p) for p in disk_keys):
            continue
        if f"{storage_id}:" not in val:
            continue
        part = val.split(",")[0]
        file_part = part.split(":")[1] if ":" in part else ""
        if file_part:
            disks.append({"key": key, "storage": storage_id, "file": file_part})
    return disks


def _config_to_conf_string(raw_config):
    """Converts a Proxmox config dict back to .conf format."""
    lines = []
    for k, v in sorted(raw_config.items()):
        if isinstance(v, (dict, list)) or k == "digest":
            continue
        lines.append(f"{k}: {v}")
    return "\n".join(lines) + "\n"


def _resolve_node_host(mgr, node_name):
    # /cluster/status provides IPs; /nodes does not
    try:
        r = mgr._api_get(f"{mgr._base}/cluster/status")
        if r.ok:
            for item in r.json().get("data", []):
                if item.get("type") == "node" and item.get("name") == node_name:
                    ip = item.get("ip", "")
                    if ip:
                        log.debug(f"[netapp_storage] SSH target for {node_name}: {ip} (cluster/status)")
                        return ip
    except Exception:
        pass
    # Fallback: configured host address (works for single-node setups)
    host = getattr(mgr, "host", None)
    if host:
        log.debug(f"[netapp_storage] SSH target for {node_name}: {host} (mgr.host fallback)")
        return host
    return node_name


# ── Consistency operations ───────────────────────────────────────────────────

def _qemu_fsfreeze(mgr, node, vmid):
    try:
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/fsfreeze-freeze"
        r = mgr._api_post(url)
        return r.status_code == 200
    except Exception as e:
        log.warning(f"[netapp_storage] fsfreeze VM {vmid}: {e}")
        return False


def _qemu_fsthaw(mgr, node, vmid):
    try:
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/fsfreeze-thaw"
        mgr._api_post(url)
    except Exception as e:
        log.warning(f"[netapp_storage] fsthaw VM {vmid}: {e}")


def _vm_suspend(mgr, node, vmid, vm_type="qemu"):
    try:
        vt = "qemu" if vm_type == "qemu" else "lxc"
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{vt}/{vmid}/status/suspend"
        r = mgr._api_post(url)
        return r is not None and r.status_code in (200, 202)
    except Exception as e:
        log.warning(f"[netapp_storage] suspend {vm_type} {vmid}: {e}")
        return False


def _vm_resume(mgr, node, vmid, vm_type="qemu"):
    try:
        vt = "qemu" if vm_type == "qemu" else "lxc"
        url = f"https://{mgr.host}:8006/api2/json/nodes/{node}/{vt}/{vmid}/status/resume"
        r = mgr._api_post(url)
        return r is not None and r.status_code in (200, 202)
    except Exception as e:
        log.warning(f"[netapp_storage] resume {vm_type} {vmid}: {e}")
        return False


def _run_hook(pve_host, pve_user, pve_pass, pve_key,
              script, vmids, snap_name, node, jlog, label):
    """Runs a pre- or post-script via SSH on the PVE node.

    Environment variables for the script:
      PEGAPROX_VMIDS  – space-separated VMID list
      PEGAPROX_SNAP   – name of the ONTAP snapshot
      PEGAPROX_NODE   – PVE node name
    """
    env = (
        f"export PEGAPROX_VMIDS={shlex.quote(' '.join(str(v) for v in vmids))}; "
        f"export PEGAPROX_SNAP={shlex.quote(snap_name)}; "
        f"export PEGAPROX_NODE={shlex.quote(node)}; "
    )
    try:
        ssh_run(pve_host, pve_user, pve_pass,
                env + script,
                key_material=pve_key)
        jlog.log(f"{label}: OK.")
    except Exception as e:
        jlog.log(f"WARNING – {label}: {e}")
