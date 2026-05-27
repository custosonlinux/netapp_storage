"""
NetApp ONTAP Plugin — DR Recovery Engine  (v1.1)

Volume bind (adopt existing ONTAP volumes into a fresh PVE cluster):
  - NFS    — export policy check → pvesm add nfs → volume_mapping
  - iSCSI  — adopt iGroup → login → activate VG → pvesm → volume_mapping
  - NVMe   — adopt subsystem → connect → activate VG → pvesm → volume_mapping

SnapMirror secondary supported for all protocols:
  - Detects DP volumes automatically
  - Optional SM break before mount

VM config restore (protocol-independent):
  - NFS : reads manifest from .netapp-snapmanifest/<snap_name>/manifest.json
          on the already-mounted NFS volume (any available snapshot manifest)
  - SAN : reads manifest from live snapmanifest LV (= last-written manifest)
          VG must already be active (= after bind)
  - Writes /etc/pve/qemu-server/<vmid>.conf and /etc/pve/lxc/<vmid>.conf via SSH
  - Applies optional VMID offset and storage-ID rewrite
"""

import json
import logging
import shlex
import uuid as _uuid
from datetime import datetime, timezone

from ._helpers import (
    get_endpoint, build_ontap_client, build_pve_client,
    get_ssh_creds, JobLogger, ssh_run, load_plugin_config,
)
from .san_helpers import (
    get_iscsi_initiator_iqn,
    find_device_by_serial,
    _iscsi_serial_to_mapper,
    get_nvme_host_nqn,
    nvme_connect_to_subsystem,
    nvme_connect_all,
    nvme_list_devices,
    find_nvme_device_for_subsystem_nqn,
    find_new_nvme_device,
    snapmanifest_read_manifest,
    snapmanifest_initialize,
)

log = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Volume scan ────────────────────────────────────────────────────────────────

def scan_volumes_for_recovery(client, svm_name):
    """Scans an SVM for volumes suitable for recovery binding.

    Returns a list of dicts:
      uuid, name, type (rw/dp), size_bytes, junction, svm,
      snapmirror: {relationship_uuid, state, healthy, source_path} or None
    """
    try:
        vols = client.get_volumes_recovery(svm_name=svm_name)
    except Exception as exc:
        raise RuntimeError(f"Could not list volumes for SVM '{svm_name}': {exc}")

    result = []
    for v in vols:
        name = v.get("name", "")
        # Skip system volumes
        if not name or name.startswith("vol0") or name.endswith("_root"):
            continue

        vol_type   = v.get("type", "rw").lower()
        size_bytes = (v.get("space") or {}).get("size", 0)
        junction   = (v.get("nas") or {}).get("path", "")
        svm        = (v.get("svm") or {}).get("name", svm_name)

        sm_info = None
        if vol_type == "dp":
            try:
                rel = client.get_snapmirror_dest_relationship(svm, name)
                if rel:
                    sm_info = {
                        "relationship_uuid": rel.get("uuid", ""),
                        "state":             rel.get("state", ""),
                        "healthy":           rel.get("healthy", True),
                        "lag_time":          rel.get("lag_time", ""),
                        "source_path":       (rel.get("source") or {}).get("path", ""),
                    }
            except Exception:
                pass

        result.append({
            "uuid":       v.get("uuid", ""),
            "name":       name,
            "type":       vol_type,
            "size_bytes": size_bytes,
            "junction":   junction,
            "svm":        svm,
            "snapmirror": sm_info,
        })

    return result


# ── Manifest helpers ───────────────────────────────────────────────────────────

def list_nfs_manifests(ssh_host, ssh_user, ssh_pass, ssh_key, mount_point):
    """Lists available snapshot manifests on a mounted NFS volume.

    Reads the .netapp-snapmanifest directory and returns entries sorted newest-first
    (by directory mtime as reported by ls -1t).
    Returns [{snap_name, manifest_path}].
    """
    cfg            = load_plugin_config()
    manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
    base_path      = f"{mount_point}/{manifest_subdir}"
    try:
        out = ssh_run(
            ssh_host, ssh_user, ssh_pass,
            f"ls -1t {shlex.quote(base_path)} 2>/dev/null || true",
            capture=True, key_material=ssh_key, timeout=15,
        )
        names = [n.strip() for n in out.splitlines() if n.strip()]
        return [
            {"snap_name": n, "manifest_path": f"{base_path}/{n}/manifest.json"}
            for n in names
        ]
    except Exception as exc:
        log.warning(f"[netapp_storage] list_nfs_manifests {mount_point}: {exc}")
        return []


def read_nfs_manifest(ssh_host, ssh_user, ssh_pass, ssh_key, mount_point, snap_name):
    """Reads a manifest from a mounted NFS volume for a specific snapshot.

    Path: {mount_point}/.netapp-snapmanifest/{snap_name}/manifest.json
    Raises RuntimeError if not found or malformed.
    """
    cfg            = load_plugin_config()
    manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
    path = f"{mount_point}/{manifest_subdir}/{snap_name}/manifest.json"
    try:
        raw = ssh_run(
            ssh_host, ssh_user, ssh_pass,
            f"cat {shlex.quote(path)} 2>/dev/null",
            capture=True, key_material=ssh_key, timeout=15,
        )
        if not raw.strip():
            raise RuntimeError(f"Manifest not found: {path}")
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Manifest JSON malformed: {exc}")


def read_san_manifest_from_live_vg(ssh_host, ssh_user, ssh_pass, ssh_key, vg_name):
    """Reads manifest from the live snapmanifest LV (= last-written snapshot manifest).

    The VG must already be active (call after bind).
    """
    return snapmanifest_read_manifest(ssh_host, ssh_user, ssh_pass, ssh_key, vg_name)


# ── VM config restore ──────────────────────────────────────────────────────────

def _conf_string(vm_entry):
    """Extracts a PVE .conf string from a manifest VM entry.

    Prefers pre-serialised 'config' string; falls back to 'raw_config' dict.
    """
    if vm_entry.get("config"):
        return vm_entry["config"]
    raw = vm_entry.get("raw_config", {})
    if isinstance(raw, dict) and raw:
        return "\n".join(f"{k}: {v}" for k, v in raw.items() if v is not None) + "\n"
    return ""


def get_used_vmids(pve_host_ids, db):
    """Returns a sorted list of VMIDs currently in use on any of the given PVE hosts."""
    for hid in pve_host_ids:
        try:
            pve        = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            out = ssh_run(
                pve.host, su, sp,
                "{ ls /etc/pve/qemu-server/*.conf 2>/dev/null; "
                "  ls /etc/pve/lxc/*.conf 2>/dev/null; } "
                "| xargs -I{} basename {} .conf 2>/dev/null || true",
                capture=True, key_material=sk, timeout=10,
            )
            vmids = []
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    vmids.append(int(line))
            return sorted(set(vmids))
        except Exception:
            continue
    return []


def restore_vm_configs(manifest, pve_host_ids, vmid_offset,
                       vmids_to_restore, storage_id_old, storage_id_new, db, jlog,
                       vmid_map=None):
    """Writes VM .conf files from a manifest dict to PVE hosts.

    manifest           : dict with 'vms' list (from manifest.json)
    pve_host_ids       : list of netapp_pve_hosts.id to write to
    vmid_offset        : int — added to every VMID (0 = keep original)
    vmids_to_restore   : set of original VMIDs to restore, or None = all
    storage_id_old     : original pvesm storage ID in the conf (may be '')
    storage_id_new     : new pvesm storage ID after bind (may be '')
    vmid_map           : dict {orig_vmid(int): new_vmid(int)} — overrides offset
    Returns number of VM configs successfully written.
    """
    vms = manifest.get("vms", [])
    if not vms:
        jlog.log("WARNING: manifest contains no VMs — nothing to restore.")
        return 0

    vmid_map = vmid_map or {}
    restored = 0
    for vm in vms:
        try:
            vmid_orig = int(vm.get("vmid", 0))
        except (TypeError, ValueError):
            continue
        if not vmid_orig:
            continue
        if vmids_to_restore is not None and vmid_orig not in vmids_to_restore:
            continue

        vm_type  = (vm.get("vmtype") or "qemu").lower()
        conf_dir = "/etc/pve/lxc" if vm_type == "lxc" else "/etc/pve/qemu-server"
        vmid_new = vmid_map.get(vmid_orig, vmid_orig + vmid_offset)
        content  = _conf_string(vm)
        if not content:
            jlog.log(f"  VM {vmid_orig}: no config data in manifest — skipping.")
            continue

        # Rewrite storage ID references if the pvesm name changed
        if storage_id_old and storage_id_new and storage_id_old != storage_id_new:
            content = content.replace(
                f"{storage_id_old}:", f"{storage_id_new}:")

        conf_path = f"{conf_dir}/{vmid_new}.conf"
        written   = False

        for hid in pve_host_ids:
            try:
                pve             = build_pve_client(db, hid)
                su, sp, sk      = get_ssh_creds(pve)
                sh              = pve.host

                # Skip if config already exists (idempotent)
                check = ssh_run(
                    sh, su, sp,
                    f"test -f {shlex.quote(conf_path)} && echo EXISTS || echo MISSING",
                    capture=True, key_material=sk, timeout=10,
                )
                if "EXISTS" in check:
                    jlog.log(f"  VM {vmid_new} ({vm_type}): config already exists — skipping.")
                    written = True
                    break  # In a PVE cluster pmxcfs syncs automatically

                ssh_run(
                    sh, su, sp,
                    f"mkdir -p {shlex.quote(conf_dir)} && "
                    f"cat > {shlex.quote(conf_path)}",
                    stdin_data=content.encode("utf-8"),
                    key_material=sk, timeout=15,
                )
                jlog.log(f"  [{sh}] VM {vmid_new} ({vm_type}): config written → {conf_path}")
                written = True
                break  # Write to one node; PVE cluster syncs via pmxcfs

            except Exception as exc:
                jlog.log(f"  WARNING: VM {vmid_new} on host {hid}: {exc}")

        if written:
            restored += 1
        else:
            jlog.log(f"  VM {vmid_orig} → {vmid_new}: could not write to any host.")

    return restored


# ── Bind job dispatcher ────────────────────────────────────────────────────────

def run_bind(job_id, ds_id, params, username, db):
    """Background bind job. Dispatches by protocol, then optionally restores VM configs."""
    from ..api.provisioning import _set_ds_status, _finish_job, _fail_job

    jlog = JobLogger(job_id, db)
    try:
        protocol = params.get("protocol", "")
        jlog.log(f"Recovery bind: {protocol} volume '{params.get('volume_name', '')}' "
                 f"on SVM '{params.get('svm_name', '')}' …")

        if protocol == "nfs":
            _bind_nfs(ds_id, params, db, jlog)
        elif protocol == "iscsi":
            _bind_iscsi(ds_id, params, db, jlog)
        elif protocol == "nvme":
            _bind_nvme(ds_id, params, db, jlog)
        else:
            raise RuntimeError(f"Protocol '{protocol}' not supported for recovery bind")

        _finish_job(db, job_id)
        jlog.log("Bind complete.")

    except Exception as exc:
        log.error(f"[netapp_storage] recovery bind job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _set_ds_status(db, ds_id, "error", str(exc))
        _fail_job(db, job_id)


# ── NFS bind ──────────────────────────────────────────────────────────────────

def _bind_nfs(ds_id, params, db, jlog):
    """Binds an NFS volume to a fresh PVE cluster.

    1. Optional SnapMirror break
    2. Ensure junction path exists (set if missing)
    3. Ensure NFS export policy allows PVE hosts
    4. pvesm add nfs on every host
    5. DB: netapp_provisioned_datastores + netapp_volume_mapping
    """
    from ..api.provisioning import _set_ds_status

    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    volume_uuid    = params["volume_uuid"]
    volume_name    = params.get("volume_name", "")
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── Optional SnapMirror break ──────────────────────────────────────────────
    _maybe_break_snapmirror(client, params, svm_name, volume_name, jlog)

    # ── Resolve junction path ──────────────────────────────────────────────────
    vol_export    = client.get_volume_export_info(volume_uuid)
    current_path  = vol_export.get("junction_path") or ""
    override_path = params.get("junction_path_override") or ""

    junction_path = override_path or current_path

    if not junction_path:
        # No path at all — derive from volume name and mount
        junction_path = f"/{volume_name}"
        jlog.log(f"Volume has no junction path — mounting at {junction_path} …")
        client.mount_volume(volume_uuid, junction_path)
        jlog.log("Volume mounted.")
    elif override_path and override_path != current_path:
        # User-specified override differs from current ONTAP path — (re)mount
        if current_path:
            jlog.log(f"Volume currently mounted at '{current_path}' — "
                     f"remounting at '{override_path}' …")
            client.unmount_volume(volume_uuid)
        else:
            jlog.log(f"Volume not mounted — mounting at '{override_path}' …")
        client.mount_volume(volume_uuid, override_path)
        jlog.log("Volume mounted at junction path.")
    else:
        jlog.log(f"Junction path: {junction_path}")

    # ── Build PVE host map ─────────────────────────────────────────────────────
    host_meta = _build_host_meta(db, pve_host_ids, jlog)
    if not host_meta:
        raise RuntimeError("No PVE hosts accessible")

    # ── Ensure export policy allows PVE hosts ──────────────────────────────────
    export_policy_id = vol_export.get("export_policy_id", "")
    if export_policy_id:
        _ensure_nfs_export_rules(client, export_policy_id, pve_host_ids, db, jlog)

    # ── Get NFS LIF IP ─────────────────────────────────────────────────────────
    nfs_ip = params.get("nfs_ip") or client.get_nfs_lif_for_svm(svm_name)
    if not nfs_ip:
        raise RuntimeError(f"No NFS LIF found for SVM '{svm_name}'")
    jlog.log(f"NFS LIF: {nfs_ip}")

    # ── pvesm add nfs — first reachable host only (cluster propagates via pmxcfs) ──
    sid_q = shlex.quote(pve_storage_id)
    pvesm_cmd = (
        f"pvesm add nfs {sid_q} "
        f"--server {shlex.quote(nfs_ip)} "
        f"--export {shlex.quote(junction_path)} "
        f"--content images,rootdir "
        f"--options vers=3"
    )
    nfs_mount_path = f"/mnt/pve/{pve_storage_id}"

    pvesm_done = False
    for hid in pve_host_ids:
        m = host_meta.get(hid)
        if not m:
            continue
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        if pvesm_done:
            # Already registered on one cluster node — just resolve mount path
            jlog.log(f"[{sh}] PVE storage already propagated by cluster.")
        else:
            jlog.log(f"[{sh}] Registering PVE NFS storage '{pve_storage_id}' …")
            try:
                check = ssh_run(sh, su, sp,
                                f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null "
                                f"&& echo EXISTS || echo MISSING",
                                capture=True, key_material=sk)
                if "EXISTS" not in check:
                    ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=120)
                    jlog.log(f"[{sh}] PVE NFS storage registered.")
                else:
                    jlog.log(f"[{sh}] PVE NFS storage already exists.")
                pvesm_done = True
            except Exception as exc:
                jlog.log(f"[{sh}] WARNING: pvesm add nfs: {exc}")
                continue
        # Resolve actual mount path (on every host for the mapping)
        try:
            out = ssh_run(sh, su, sp,
                          f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null | awk 'NR>1{{print $1}}' || true",
                          capture=True, key_material=sk, timeout=10)
        except Exception:
            pass

    _set_ds_status(db, ds_id, "active")
    db.execute(
        "UPDATE netapp_provisioned_datastores "
        "SET volume_name=?, nfs_junction_path=?, updated_at=? WHERE id=?",
        (volume_name, junction_path, _now(), ds_id),
    )

    # ── Register volume_mapping for each host ──────────────────────────────────
    now = _now()
    for hid in pve_host_ids:
        if hid not in host_meta:
            continue
        pve_row   = db.query_one("SELECT nfs_ip, host FROM netapp_pve_hosts WHERE id=?", (hid,))
        host_nfs  = dict(pve_row or {}).get("nfs_ip") or dict(pve_row or {}).get("host", nfs_ip)
        _upsert_volume_mapping(
            db, endpoint_id, hid, pve_storage_id, svm_name,
            volume_uuid, volume_name,
            protocol="nfs",
            junction_path=junction_path,
            nfs_export_ip=host_nfs,
            nfs_mount_path=nfs_mount_path,
            now=now,
        )
        jlog.log(f"Volume mapping registered for host {hid}.")

    jlog.log(f"NFS bind complete. '{pve_storage_id}' active at {nfs_ip}:{junction_path}")


# ── iSCSI bind ────────────────────────────────────────────────────────────────

def _bind_iscsi(ds_id, params, db, jlog):
    """Binds an iSCSI LUN to a fresh PVE cluster (adopts existing LUN/VG).

    1. Optional SnapMirror break
    2. Discover LUN UUID + serial from the volume
    3. Adopt or create iGroup; add host IQNs
    4. Map LUN to iGroup (idempotent)
    5. iSCSI login + activate VG on every host
    6. pvesm add lvm / lvmthin
    7. DB registration
    """
    from ..api.provisioning import _set_ds_status

    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    volume_uuid    = params["volume_uuid"]
    volume_name    = params.get("volume_name", "")
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]
    vg_name        = params.get("vg_name", "")
    lvm_type       = params.get("lvm_type", "linear")
    lvm_pool_name  = params.get("lvm_pool_name", "") or "data"

    if not vg_name:
        raise RuntimeError("vg_name is required for iSCSI bind")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── Optional SnapMirror break ──────────────────────────────────────────────
    _maybe_break_snapmirror(client, params, svm_name, volume_name, jlog)

    # ── Find LUN in volume ─────────────────────────────────────────────────────
    lun_uuid, lun_path, serial = _find_lun_in_volume(client, svm_name, volume_uuid, volume_name, jlog)

    # ── Collect host IQNs ──────────────────────────────────────────────────────
    host_meta = _build_host_meta(db, pve_host_ids, jlog, collect_iqn=True)
    if not host_meta:
        raise RuntimeError("No iSCSI IQNs collected from any host")

    # ── Adopt or create iGroup ─────────────────────────────────────────────────
    igroup_uuid, igroup_name = _adopt_or_create_igroup(
        client, svm_name, lun_uuid, volume_name, host_meta, params, jlog)

    # ── Map LUN to iGroup (idempotent) ─────────────────────────────────────────
    jlog.log("Ensuring LUN is mapped to iGroup …")
    try:
        client.map_lun(lun_uuid, igroup_uuid, svm_name=svm_name)
        jlog.log("LUN mapped.")
    except Exception as exc:
        if "already" in str(exc).lower() or "409" in str(exc):
            jlog.log("LUN already mapped — OK.")
        else:
            raise

    # Persist ONTAP IDs before touching hosts
    db.execute(
        "UPDATE netapp_provisioned_datastores "
        "SET volume_name=?, lun_uuid=?, lun_path=?, "
        "igroup_uuid=?, igroup_name=?, updated_at=? WHERE id=?",
        (volume_name, lun_uuid, lun_path, igroup_uuid, igroup_name, _now(), ds_id),
    )

    # ── iSCSI target info ──────────────────────────────────────────────────────
    portal_ip  = client.get_iscsi_lif_for_svm(svm_name)
    target_iqn = client.get_iscsi_target_iqn(svm_name)
    if not portal_ip or not target_iqn:
        raise RuntimeError(f"No iSCSI target found for SVM '{svm_name}'")
    jlog.log(f"iSCSI target: {target_iqn} @ {portal_ip}")

    mapper_dev    = _iscsi_serial_to_mapper(serial)
    ordered_hosts = [hid for hid in pve_host_ids if hid in host_meta]

    # ── Per-host: login → activate / create VG ────────────────────────────────
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]

        jlog.log(f"[{sh}] iSCSI discover + login …")
        ssh_run(sh, su, sp,
                f"iscsiadm -m discovery -t sendtargets -p {shlex.quote(portal_ip)} 2>&1 || true",
                key_material=sk, timeout=30)
        ssh_run(sh, su, sp,
                f"iscsiadm -m node -T {shlex.quote(target_iqn)} -p {shlex.quote(portal_ip)}"
                f" --login 2>&1 || true",
                key_material=sk, timeout=30)

        jlog.log(f"[{sh}] Waiting for multipath device (serial={serial}) …")
        ssh_run(sh, su, sp,
                "sleep 3; udevadm settle --timeout=15 2>/dev/null; "
                "multipath 2>/dev/null; sleep 2; true",
                key_material=sk, timeout=40)
        device = find_device_by_serial(sh, su, sp, sk, serial, timeout_s=60)
        jlog.log(f"[{sh}] Device ready: {device}")

        # Activate existing VG (data is intact) or create fresh if not present
        vg_q  = shlex.quote(vg_name)
        dev_q = shlex.quote(device)
        out   = ssh_run(sh, su, sp,
                        f"vgs {vg_q} 2>/dev/null && echo EXISTS || echo MISSING",
                        capture=True, key_material=sk)
        if "EXISTS" in out:
            jlog.log(f"[{sh}] VG '{vg_name}' found — activating …")
            ssh_run(sh, su, sp,
                    f"pvscan --cache -aay {shlex.quote(mapper_dev)} 2>/dev/null; "
                    f"vgchange -ay {vg_q} 2>/dev/null; true",
                    key_material=sk, timeout=30)
            jlog.log(f"[{sh}] VG active.")
        else:
            jlog.log(f"[{sh}] VG '{vg_name}' not found — creating …")
            ssh_run(sh, su, sp, f"pvcreate {dev_q}", key_material=sk)
            ssh_run(sh, su, sp, f"vgcreate {vg_q} {dev_q}", key_material=sk)
            if lvm_type == "thin":
                ssh_run(sh, su, sp,
                        f"lvcreate -l 95%VG --thin {vg_q}/{shlex.quote(lvm_pool_name)}",
                        key_material=sk, timeout=30)
                jlog.log(f"[{sh}] Thin pool '{lvm_pool_name}' created.")
            try:
                snapmanifest_initialize(sh, su, sp, sk, vg_name)
                jlog.log(f"[{sh}] snapmanifest LV initialized.")
            except Exception as exc:
                jlog.log(f"[{sh}] WARNING: snapmanifest init: {exc}")
            jlog.log(f"[{sh}] VG '{vg_name}' created.")

    # ── pvscan on ALL hosts ────────────────────────────────────────────────────
    jlog.log("Activating VG on all hosts via pvscan …")
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        try:
            ssh_run(sh, su, sp,
                    f"pvscan --cache -aay {shlex.quote(mapper_dev)} 2>/dev/null; true",
                    key_material=sk, timeout=30)
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvscan: {exc}")

    # ── pvesm add lvm / lvmthin ───────────────────────────────────────────────
    vg_q  = shlex.quote(vg_name)
    sid_q = shlex.quote(pve_storage_id)
    if lvm_type == "thin":
        pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                     f" --thinpool {shlex.quote(lvm_pool_name)}"
                     f" --shared 1 --content images,rootdir")
    else:
        pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                     f" --shared 1 --content images,rootdir")

    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        jlog.log(f"[{sh}] Registering PVE storage '{pve_storage_id}' …")
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                try:
                    ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] PVE storage registered.")
                except Exception as exc:
                    if "already defined" in str(exc).lower():
                        jlog.log(f"[{sh}] PVE storage already in cluster config.")
                    else:
                        jlog.log(f"[{sh}] WARNING: pvesm add: {exc}")
            else:
                jlog.log(f"[{sh}] PVE storage already exists.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm: {exc}")

    _set_ds_status(db, ds_id, "active")

    # ── Register volume_mapping for each host ──────────────────────────────────
    now = _now()
    for hid in ordered_hosts:
        _upsert_volume_mapping(
            db, endpoint_id, hid, pve_storage_id, svm_name,
            volume_uuid, volume_name,
            protocol="iscsi",
            lun_uuid=lun_uuid, lun_path=lun_path,
            lvm_vg_name=vg_name, lvm_type=lvm_type, lvm_pool_name=lvm_pool_name,
            now=now,
        )
        jlog.log(f"Volume mapping registered for host {hid}.")

    jlog.log(f"iSCSI bind complete. Datastore '{params.get('name', '')}' is active.")


# ── NVMe bind ─────────────────────────────────────────────────────────────────

def _bind_nvme(ds_id, params, db, jlog):
    """Binds an NVMe namespace to a fresh PVE cluster (adopts existing namespace/VG).

    1. Optional SnapMirror break
    2. Discover namespace UUID from the volume
    3. Adopt or create subsystem; add host NQNs
    4. Map namespace to subsystem (idempotent)
    5. NVMe connect + activate VG on every host
    6. pvesm add lvm / lvmthin
    7. DB registration
    """
    from ..api.provisioning import _set_ds_status

    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    volume_uuid    = params["volume_uuid"]
    volume_name    = params.get("volume_name", "")
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]
    vg_name        = params.get("vg_name", "")
    lvm_type       = params.get("lvm_type", "linear")
    lvm_pool_name  = params.get("lvm_pool_name", "") or "data"

    if not vg_name:
        raise RuntimeError("vg_name is required for NVMe bind")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── Optional SnapMirror break ──────────────────────────────────────────────
    _maybe_break_snapmirror(client, params, svm_name, volume_name, jlog)

    # ── Find namespace in volume ───────────────────────────────────────────────
    ns_uuid, ns_path = _find_namespace_in_volume(client, svm_name, volume_uuid, volume_name, jlog)

    # ── Collect host NQNs ──────────────────────────────────────────────────────
    host_meta = _build_host_meta(db, pve_host_ids, jlog, collect_nqn=True)
    if not host_meta:
        raise RuntimeError("No NVMe NQNs collected from any host")

    # ── Adopt or create subsystem ──────────────────────────────────────────────
    subsystem_uuid, subsystem_name = _adopt_or_create_subsystem(
        client, svm_name, ns_uuid, volume_name, host_meta, params, jlog)

    # ── Map namespace to subsystem (idempotent) ────────────────────────────────
    jlog.log("Ensuring namespace is mapped to subsystem …")
    try:
        client.add_nvme_namespace_to_subsystem(subsystem_uuid, ns_uuid, svm_name=svm_name)
        jlog.log("Namespace mapped.")
    except Exception as exc:
        if "already" in str(exc).lower() or "409" in str(exc):
            jlog.log("Namespace already mapped — OK.")
        else:
            raise

    # Persist ONTAP IDs
    db.execute(
        "UPDATE netapp_provisioned_datastores "
        "SET volume_name=?, ns_uuid=?, subsystem_uuid=?, subsystem_name=?, updated_at=? "
        "WHERE id=?",
        (volume_name, ns_uuid, subsystem_uuid, subsystem_name, _now(), ds_id),
    )

    # ── Get NVMe LIF IPs and subsystem NQN ───────────────────────────────────
    lif_ips      = client.get_nvme_lifs_for_svm(svm_name)
    subsystem_nqn = ""
    try:
        sub_info      = client.get_nvme_subsystem(subsystem_uuid)
        subsystem_nqn = sub_info.get("target_nqn", "")
    except Exception:
        pass
    jlog.log(f"NVMe/TCP LIFs: {lif_ips}")
    if subsystem_nqn:
        jlog.log(f"Subsystem NQN: {subsystem_nqn}")

    ordered_hosts = [hid for hid in pve_host_ids if hid in host_meta]

    # ── Per-host: connect → activate VG ───────────────────────────────────────
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]

        jlog.log(f"[{sh}] Capturing NVMe device baseline …")
        devices_before = nvme_list_devices(sh, su, sp, sk)

        if subsystem_nqn and lif_ips:
            jlog.log(f"[{sh}] Connecting NVMe (direct per-LIF) …")
            nvme_connect_to_subsystem(sh, su, sp, sk, lif_ips, subsystem_nqn)
        else:
            jlog.log(f"[{sh}] Connecting NVMe (connect-all fallback) …")
            nvme_connect_all(sh, su, sp, sk)

        jlog.log(f"[{sh}] Waiting for NVMe namespace device …")
        if subsystem_nqn:
            device = find_nvme_device_for_subsystem_nqn(sh, su, sp, sk, subsystem_nqn, timeout_s=90)
        else:
            device = find_new_nvme_device(sh, su, sp, sk, devices_before, timeout_s=90)
        jlog.log(f"[{sh}] Device ready: {device}")
        host_meta[hid]["device"] = device

        vg_q  = shlex.quote(vg_name)
        dev_q = shlex.quote(device)
        out   = ssh_run(sh, su, sp,
                        f"vgs {vg_q} 2>/dev/null && echo EXISTS || echo MISSING",
                        capture=True, key_material=sk)
        if "EXISTS" in out:
            jlog.log(f"[{sh}] VG '{vg_name}' found — activating …")
            ssh_run(sh, su, sp,
                    f"pvscan --cache -aay {dev_q} 2>/dev/null; "
                    f"vgchange -ay {vg_q} 2>/dev/null; true",
                    key_material=sk, timeout=30)
            jlog.log(f"[{sh}] VG active.")
        else:
            jlog.log(f"[{sh}] VG '{vg_name}' not found — creating …")
            ssh_run(sh, su, sp, f"pvcreate {dev_q}", key_material=sk)
            ssh_run(sh, su, sp, f"vgcreate {vg_q} {dev_q}", key_material=sk)
            if lvm_type == "thin":
                ssh_run(sh, su, sp,
                        f"lvcreate -l 95%VG --thin {vg_q}/{shlex.quote(lvm_pool_name)}",
                        key_material=sk, timeout=30)
                jlog.log(f"[{sh}] Thin pool '{lvm_pool_name}' created.")
            try:
                snapmanifest_initialize(sh, su, sp, sk, vg_name)
                jlog.log(f"[{sh}] snapmanifest LV initialized.")
            except Exception as exc:
                jlog.log(f"[{sh}] WARNING: snapmanifest init: {exc}")
            jlog.log(f"[{sh}] VG '{vg_name}' created.")

    # ── pvscan on ALL hosts ────────────────────────────────────────────────────
    jlog.log("Activating VG on all hosts via pvscan …")
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        dev = m.get("device", "")
        try:
            if dev:
                ssh_run(sh, su, sp,
                        f"pvscan --cache -aay {shlex.quote(dev)} 2>/dev/null; true",
                        key_material=sk, timeout=30)
            else:
                ssh_run(sh, su, sp,
                        f"vgchange -ay {shlex.quote(vg_name)} 2>/dev/null; true",
                        key_material=sk, timeout=30)
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvscan: {exc}")

    # ── pvesm add lvm / lvmthin ───────────────────────────────────────────────
    vg_q  = shlex.quote(vg_name)
    sid_q = shlex.quote(pve_storage_id)
    if lvm_type == "thin":
        pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                     f" --thinpool {shlex.quote(lvm_pool_name)}"
                     f" --shared 1 --content images,rootdir")
    else:
        pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                     f" --shared 1 --content images,rootdir")

    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        jlog.log(f"[{sh}] Registering PVE storage '{pve_storage_id}' …")
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                try:
                    ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] PVE storage registered.")
                except Exception as exc:
                    if "already defined" in str(exc).lower():
                        jlog.log(f"[{sh}] Already propagated from cluster.")
                    else:
                        jlog.log(f"[{sh}] WARNING: pvesm add: {exc}")
            else:
                jlog.log(f"[{sh}] PVE storage already exists.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm: {exc}")

    _set_ds_status(db, ds_id, "active")

    # ── Register volume_mapping for each host ──────────────────────────────────
    now = _now()
    for hid in ordered_hosts:
        _upsert_volume_mapping(
            db, endpoint_id, hid, pve_storage_id, svm_name,
            volume_uuid, volume_name,
            protocol="nvme",
            lun_uuid=ns_uuid, lun_path=ns_path,
            lvm_vg_name=vg_name, lvm_type=lvm_type, lvm_pool_name=lvm_pool_name,
            now=now,
        )
        jlog.log(f"Volume mapping registered for host {hid}.")

    jlog.log(f"NVMe bind complete. Datastore '{params.get('name', '')}' is active.")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _maybe_break_snapmirror(client, params, svm_name, volume_name, jlog):
    """Breaks SnapMirror relationship if params['snapmirror_break'] is true."""
    if not params.get("snapmirror_break"):
        return
    rel_uuid = params.get("snapmirror_relationship_uuid", "")
    if not rel_uuid:
        rel = client.get_snapmirror_dest_relationship(svm_name, volume_name)
        if rel:
            rel_uuid = rel.get("uuid", "")
    if rel_uuid:
        jlog.log("Breaking SnapMirror relationship …")
        client.snapmirror_break(rel_uuid)
        jlog.log("SnapMirror broken — volume is now RW.")
    else:
        jlog.log("WARNING: SnapMirror relationship not found — proceeding without break.")


def _build_host_meta(db, pve_host_ids, jlog,
                     collect_iqn=False, collect_nqn=False):
    """Builds a dict {host_id: {host, user, pass, key, [iqn], [nqn]}} for accessible hosts."""
    result = {}
    for hid in pve_host_ids:
        try:
            pve            = build_pve_client(db, hid)
            su, sp, sk     = get_ssh_creds(pve)
            entry          = {"host": pve.host, "user": su, "pass": sp, "key": sk}
            if collect_iqn:
                iqn = get_iscsi_initiator_iqn(pve.host, su, sp, sk)
                if iqn:
                    entry["iqn"] = iqn
                    jlog.log(f"  {pve.host}: IQN={iqn}")
                else:
                    jlog.log(f"  WARNING: no IQN from {pve.host} — host skipped")
                    continue
            if collect_nqn:
                nqn = get_nvme_host_nqn(pve.host, su, sp, sk)
                if nqn:
                    entry["nqn"] = nqn
                    jlog.log(f"  {pve.host}: NQN={nqn}")
                else:
                    jlog.log(f"  WARNING: no NQN from {pve.host} — host skipped")
                    continue
            result[hid] = entry
        except Exception as exc:
            jlog.log(f"  WARNING: cannot connect to host {hid}: {exc}")
    return result


def _find_lun_in_volume(client, svm_name, volume_uuid, volume_name, jlog):
    """Returns (lun_uuid, lun_path, serial) for the first LUN found in the volume."""
    jlog.log(f"Scanning for LUN in volume '{volume_name}' …")
    all_luns = client.list_luns(svm_name=svm_name)
    for lun in all_luns:
        loc_vol = (lun.get("location") or {}).get("volume") or {}
        if loc_vol.get("uuid") == volume_uuid or loc_vol.get("name") == volume_name:
            lun_uuid = lun.get("uuid", "")
            lun_path = lun.get("name", "")
            serial   = lun.get("serial_number", "")
            if not serial and lun_uuid:
                serial = client.get_lun_serial(lun_uuid)
            jlog.log(f"Found LUN: {lun_path} (UUID={lun_uuid}, serial={serial})")
            return lun_uuid, lun_path, serial
    raise RuntimeError(f"No LUN found in volume '{volume_name}' ({volume_uuid})")


def _find_namespace_in_volume(client, svm_name, volume_uuid, volume_name, jlog):
    """Returns (ns_uuid, ns_path) for the first NVMe namespace found in the volume."""
    jlog.log(f"Scanning for NVMe namespace in volume '{volume_name}' …")
    all_ns = client.list_nvme_namespaces(svm_name=svm_name)
    for ns in all_ns:
        loc = ns.get("location") or {}
        loc_vol = loc.get("volume") or {}
        if loc_vol.get("uuid") == volume_uuid or loc_vol.get("name") == volume_name:
            ns_uuid = ns.get("uuid", "")
            ns_path = ns.get("name", "")
            jlog.log(f"Found namespace: {ns_path} (UUID={ns_uuid})")
            return ns_uuid, ns_path
    raise RuntimeError(f"No NVMe namespace found in volume '{volume_name}' ({volume_uuid})")


def _adopt_or_create_igroup(client, svm_name, lun_uuid, volume_name, host_meta, params, jlog):
    """Finds the existing iGroup the LUN is mapped to (and adds our IQNs),
    or creates a new iGroup.  Returns (igroup_uuid, igroup_name).
    """
    igroup_uuid = params.get("igroup_uuid", "")
    igroup_name = params.get("igroup_name", "")

    if not igroup_uuid:
        # Try to adopt from existing LUN mapping
        try:
            maps = client.list_lun_maps(lun_uuid=lun_uuid)
            if maps:
                ig          = maps[0].get("igroup") or {}
                igroup_uuid = ig.get("uuid", "")
                igroup_name = ig.get("name", "")
                jlog.log(f"Adopting existing iGroup '{igroup_name}' ({igroup_uuid}).")
        except Exception as exc:
            jlog.log(f"WARNING: LUN map lookup: {exc}")

    if not igroup_uuid:
        igroup_name = f"igr-rcv-{volume_name[:20]}"
        jlog.log(f"Creating new iGroup '{igroup_name}' …")
        igroup_uuid = client.create_igroup(svm_name, igroup_name, protocol="iscsi", os_type="linux")
        jlog.log(f"iGroup created: {igroup_uuid}")

    # Add our host IQNs (idempotent)
    try:
        existing_ig    = next(
            (g for g in client.list_igroups(svm_name=svm_name)
             if g.get("uuid") == igroup_uuid), None)
        existing_inits = {i.get("name", "")
                          for i in ((existing_ig or {}).get("initiators") or [])}
        for m in host_meta.values():
            iqn = m.get("iqn", "")
            if iqn and iqn not in existing_inits:
                client.add_igroup_initiator(igroup_uuid, iqn)
                jlog.log(f"  Added IQN to iGroup: {iqn}")
    except Exception as exc:
        jlog.log(f"WARNING: iGroup IQN update: {exc}")

    return igroup_uuid, igroup_name


def _adopt_or_create_subsystem(client, svm_name, ns_uuid, volume_name, host_meta, params, jlog):
    """Finds the existing NVMe subsystem the namespace is mapped to (and adds our NQNs),
    or creates a new subsystem.  Returns (subsystem_uuid, subsystem_name).
    """
    subsystem_uuid = params.get("subsystem_uuid", "")
    subsystem_name = params.get("subsystem_name", "")

    if not subsystem_uuid:
        try:
            sub = client.get_nvme_subsystem_for_namespace(ns_uuid, svm_name)
            subsystem_uuid = sub.get("uuid", "")
            subsystem_name = sub.get("name", "")
            if subsystem_uuid:
                jlog.log(f"Adopting existing subsystem '{subsystem_name}' ({subsystem_uuid}).")
        except Exception as exc:
            jlog.log(f"WARNING: subsystem lookup: {exc}")

    if not subsystem_uuid:
        subsystem_name = f"sub-rcv-{volume_name[:20]}"
        jlog.log(f"Creating new subsystem '{subsystem_name}' …")
        subsystem_uuid = client.create_nvme_subsystem(svm_name, subsystem_name)
        jlog.log(f"Subsystem created: {subsystem_uuid}")

    # Add our host NQNs (idempotent)
    try:
        existing_sub  = client.get_nvme_subsystem(subsystem_uuid)
        existing_nqns = {h.get("nqn", "")
                         for h in (existing_sub.get("hosts") or [])}
        for m in host_meta.values():
            nqn = m.get("nqn", "")
            if nqn and nqn not in existing_nqns:
                client.add_nvme_host_to_subsystem(subsystem_uuid, nqn)
                jlog.log(f"  Added NQN to subsystem: {nqn}")
    except Exception as exc:
        jlog.log(f"WARNING: subsystem NQN update: {exc}")

    return subsystem_uuid, subsystem_name


def _ensure_nfs_export_rules(client, export_policy_id, pve_host_ids, db, jlog):
    """Adds any missing NFS export rules for the PVE host IPs."""
    try:
        existing_rules   = client.list_nfs_export_rules(export_policy_id)
        existing_clients = {c.get("match", "")
                            for r in existing_rules
                            for c in (r.get("clients") or [])}
        if "0.0.0.0/0" in existing_clients:
            return  # already open
        for hid in pve_host_ids:
            row = db.query_one("SELECT nfs_ip, host FROM netapp_pve_hosts WHERE id=?", (hid,))
            ip  = dict(row or {}).get("nfs_ip") or dict(row or {}).get("host", "")
            if ip and ip not in existing_clients:
                client.add_nfs_export_rule_rw(export_policy_id, ip)
                jlog.log(f"NFS export rule added for {ip}.")
    except Exception as exc:
        jlog.log(f"WARNING: NFS export rule update: {exc}")


def _upsert_volume_mapping(db, endpoint_id, host_id, pve_storage_id, svm_name,
                            volume_uuid, volume_name, *, protocol,
                            junction_path="", nfs_export_ip="", nfs_mount_path="",
                            lun_uuid="", lun_path="",
                            lvm_vg_name="", lvm_type="linear", lvm_pool_name="",
                            now=None):
    """Inserts or updates a netapp_volume_mapping row."""
    if now is None:
        now = _now()
    mid = str(_uuid.uuid4())
    db.execute(
        """INSERT INTO netapp_volume_mapping
           (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
            volume_uuid, volume_name, junction_path, nfs_export_ip,
            nfs_mount_path, discovered_at, storage_protocol,
            lun_uuid, lun_path, lvm_vg_name, lvm_type, lvm_pool_name,
            snapinfo_initialized, snapinfo_lv_name, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
           endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
           volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
           junction_path=excluded.junction_path, nfs_export_ip=excluded.nfs_export_ip,
           nfs_mount_path=excluded.nfs_mount_path,
           lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path,
           lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type,
           lvm_pool_name=excluded.lvm_pool_name,
           storage_protocol=excluded.storage_protocol,
           snapinfo_initialized=excluded.snapinfo_initialized,
           discovered_at=excluded.discovered_at""",
        (mid, endpoint_id, host_id, pve_storage_id, svm_name,
         volume_uuid, volume_name, junction_path, nfs_export_ip, nfs_mount_path,
         now, protocol, lun_uuid, lun_path,
         lvm_vg_name, lvm_type, lvm_pool_name,
         1, "netapp_snapmanifest", now),
    )
