"""
NetApp ONTAP Plugin — Recovery API  (v1.1)

Endpoints for the "Bind Volume + Restore VMs" wizard:

  GET  /provisioning/recovery/scan-volumes
       Scans an SVM for volumes available for recovery binding.
       Query params: endpoint_id, svm_name
       Returns: {volumes: [{uuid, name, type, size_bytes, junction, svm, snapmirror}]}

  GET  /provisioning/recovery/manifests
       Lists or reads snapshot manifests from a bound datastore.
       Query params: ds_id, [snap_name]
         - Without snap_name: returns available manifest snapshot names
         - With snap_name   : returns full manifest with VM list
       Returns: {snapshots: [...]} or {manifest: {...}, vms: [...]}

  POST /provisioning/recovery/bind
       Starts a background job to bind a volume to a fresh PVE cluster.
       Body: { endpoint_id, svm_name, volume_uuid, volume_name, protocol,
               pve_storage_id, pve_host_ids, vg_name, lvm_type, lvm_pool_name,
               [snapmirror_break], [snapmirror_relationship_uuid],
               [junction_path_override], [nfs_ip], name }
       Returns: {id: ds_id, job_id: job_id}, 202

  POST /provisioning/recovery/restore-vms
       Writes VM .conf files from a manifest to PVE hosts.
       Body: { ds_id, snap_name, vmids, vmid_offset,
               storage_id_old, storage_id_new }
       Returns: {restored: N} (N = number of configs written)
"""

import json
import logging
import re
import uuid as _uuid
from datetime import datetime, timezone

from pegaprox.core.db import get_db

from ..core._helpers import (
    get_endpoint, build_ontap_client, build_pve_client,
    get_ssh_creds, JobLogger, ssh_run,
)
from ..core._helpers import PLUGIN_ID  # noqa: F401

log = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _require_admin():
    from flask import request
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users    = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


# ── GET /provisioning/recovery/scan-volumes ────────────────────────────────────

def _recovery_scan_volumes():
    err = _require_admin()
    if err:
        return err
    from flask import request
    endpoint_id = request.args.get("endpoint_id")
    svm_name    = request.args.get("svm_name", "")
    if not endpoint_id:
        return {"error": "endpoint_id required"}, 400

    db       = get_db()
    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    from ..core.recovery_engine import scan_volumes_for_recovery
    try:
        volumes = scan_volumes_for_recovery(client, svm_name)
        return {"volumes": volumes}
    except Exception as exc:
        log.error(f"[netapp_storage] recovery scan-volumes: {exc}")
        return {"error": str(exc)}, 500


# ── GET /provisioning/recovery/manifests ──────────────────────────────────────

def _recovery_manifests():
    """Lists available manifest snapshots, or returns a specific manifest's VM list.

    Operates on a BOUND datastore (ds_id).
    For NFS: reads .netapp-snapmanifest/ on the mounted volume.
    For SAN: reads live snapmanifest LV (= last-written manifest; no snap selection).
    """
    err = _require_admin()
    if err:
        return err
    from flask import request
    ds_id     = request.args.get("ds_id")
    snap_name = request.args.get("snap_name", "")
    if not ds_id:
        return {"error": "ds_id required"}, 400

    db  = get_db()
    row = db.query_one("SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404
    ds = dict(row)

    protocol       = ds.get("protocol", "nfs")
    pve_storage_id = ds.get("pve_storage_id", "")
    vg_name        = ds.get("vg_name", "")
    pve_host_ids   = json.loads(ds.get("pve_host_ids") or "[]")

    if not pve_host_ids:
        return {"error": "No PVE hosts associated with this datastore"}, 400

    # Use first available host
    first_host = None
    for hid in pve_host_ids:
        try:
            pve            = build_pve_client(db, hid)
            su, sp, sk     = get_ssh_creds(pve)
            first_host     = {"host": pve.host, "user": su, "pass": sp, "key": sk, "id": hid}
            break
        except Exception:
            continue
    if not first_host:
        return {"error": "No accessible PVE host found"}, 503

    sh, su, sp, sk = first_host["host"], first_host["user"], first_host["pass"], first_host["key"]

    # ── NFS ───────────────────────────────────────────────────────────────────
    if protocol == "nfs":
        # Resolve mount point from volume_mapping or fallback
        mapping = db.query_one(
            "SELECT nfs_mount_path FROM netapp_volume_mapping "
            "WHERE pve_storage_id=? AND pve_cluster_id=? LIMIT 1",
            (pve_storage_id, first_host["id"]),
        )
        mount_point = (dict(mapping or {}).get("nfs_mount_path") or
                       f"/mnt/pve/{pve_storage_id}")

        from ..core.recovery_engine import list_nfs_manifests, read_nfs_manifest

        if not snap_name:
            # List available manifests
            try:
                snapshots = list_nfs_manifests(sh, su, sp, sk, mount_point)
                return {"snapshots": snapshots, "protocol": "nfs"}
            except Exception as exc:
                return {"error": str(exc)}, 500
        else:
            # Read specific manifest
            try:
                manifest = read_nfs_manifest(sh, su, sp, sk, mount_point, snap_name)
                vms      = _summarize_vms(manifest)
                return {
                    "manifest":             manifest,
                    "vms":                  vms,
                    "snap_name":            snap_name,
                    "detected_storage_ids": _detect_storage_ids(manifest),
                }
            except Exception as exc:
                return {"error": str(exc)}, 500

    # ── SAN (iSCSI / NVMe) ────────────────────────────────────────────────────
    elif protocol in ("iscsi", "nvme"):
        if not vg_name:
            return {"error": "vg_name not set on this datastore"}, 400

        from ..core.recovery_engine import read_san_manifest_from_live_vg
        try:
            manifest = read_san_manifest_from_live_vg(sh, su, sp, sk, vg_name)
            vms      = _summarize_vms(manifest)
            # SAN: only the live (= last) manifest is available without a temp clone
            return {
                "manifest":             manifest,
                "vms":                  vms,
                "snap_name":            manifest.get("snap_name", "latest"),
                "snapshots":            [{"snap_name": manifest.get("snap_name", "latest"),
                                         "manifest_path": f"snapmanifest:{vg_name}"}],
                "protocol":             protocol,
                "detected_storage_ids": _detect_storage_ids(manifest),
            }
        except Exception as exc:
            return {"error": str(exc)}, 500

    return {"error": f"Unsupported protocol: {protocol}"}, 400


def _summarize_vms(manifest):
    """Returns a condensed VM list [{vmid, name, vmtype}] from a manifest dict."""
    return [
        {
            "vmid":   vm.get("vmid"),
            "name":   vm.get("name", f"VM {vm.get('vmid')}"),
            "vmtype": vm.get("vmtype", "qemu"),
        }
        for vm in manifest.get("vms", [])
        if vm.get("vmid")
    ]


_DISK_KEY_RE = re.compile(
    r"^(?:scsi|virtio|ide|sata|efidisk|tpmstate|unused)\d*:\s*([^:,\s]+):",
    re.MULTILINE,
)
_DEFAULT_STORAGE = {"local", "local-lvm", "local-zfs", "local-btrfs"}


def _detect_storage_ids(manifest):
    """Scans VM configs in the manifest and returns storage IDs sorted by frequency.

    Returns a list of non-default pvesm storage IDs found in disk lines,
    most common first.  Example: ['aff-nfs-ds06', 'local-lvm']
    """
    counts: dict = {}
    for vm in manifest.get("vms", []):
        conf = vm.get("config", "")
        if not conf:
            raw = vm.get("raw_config", {})
            if isinstance(raw, dict):
                conf = "\n".join(f"{k}: {v}" for k, v in raw.items() if v)
        for sid in _DISK_KEY_RE.findall(conf):
            if sid not in _DEFAULT_STORAGE:
                counts[sid] = counts.get(sid, 0) + 1
    return sorted(counts, key=lambda s: -counts[s])


# ── POST /provisioning/recovery/bind ──────────────────────────────────────────

def _recovery_bind():
    err = _require_admin()
    if err:
        return err
    from flask import request
    body = request.get_json(force=True) or {}

    required = ["endpoint_id", "svm_name", "volume_uuid", "protocol",
                "pve_storage_id", "pve_host_ids", "name"]
    for f in required:
        if not body.get(f):
            return {"error": f"Required field missing: {f}"}, 400

    protocol = body["protocol"]
    if protocol not in ("nfs", "iscsi", "nvme"):
        return {"error": f"Unknown protocol: {protocol}"}, 400
    if protocol in ("iscsi", "nvme") and not body.get("vg_name"):
        return {"error": "vg_name required for iSCSI/NVMe bind"}, 400

    db       = get_db()
    username = request.session.get("user", "unknown")
    now      = _now()
    ds_id    = str(_uuid.uuid4())

    # Insert provisioned_datastores row (status=provisioning)
    db.execute(
        """INSERT INTO netapp_provisioned_datastores
           (id, name, endpoint_id, svm_name, volume_uuid, volume_name,
            protocol, lun_uuid, lun_path, igroup_uuid, igroup_name,
            ns_uuid, subsystem_uuid, subsystem_name,
            vg_name, lvm_type, lvm_pool_name, nfs_junction_path,
            pve_storage_id, pve_host_ids, size_bytes, status, error_message,
            imported_from, created_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ds_id, body["name"], body["endpoint_id"],
            body.get("svm_name", ""), body.get("volume_uuid", ""),
            body.get("volume_name", ""), protocol,
            "", "", "", "",
            "", "", "",
            body.get("vg_name", ""), body.get("lvm_type", "linear"),
            body.get("lvm_pool_name", ""), body.get("junction_path_override", ""),
            body["pve_storage_id"],
            json.dumps(body["pve_host_ids"]),
            int(body.get("size_bytes", 0)),
            "provisioning", "",
            "recovery_bind",
            username, now, now,
        ),
    )

    job_id = _start_job(db, "recovery_bind", ds_id, username)
    _run_bind_async(job_id, ds_id, body, username)
    return {"id": ds_id, "job_id": job_id}, 202


# ── POST /provisioning/recovery/restore-vms ───────────────────────────────────

def _recovery_restore_vms():
    """Writes VM .conf files from a manifest to PVE hosts.

    Body:
      ds_id          — bound provisioned datastore
      snap_name      — snapshot manifest name (NFS); ignored for SAN (uses live)
      vmids          — list of VMIDs to restore (empty/absent = all)
      vmid_offset    — int offset added to every VMID (default 0)
      storage_id_old — original pvesm ID in conf lines (for rewrite; may be empty)
    """
    err = _require_admin()
    if err:
        return err
    from flask import request
    body  = request.get_json(force=True) or {}
    ds_id = body.get("ds_id")
    if not ds_id:
        return {"error": "ds_id required"}, 400

    db  = get_db()
    row = db.query_one("SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404
    ds = dict(row)

    if ds.get("status") not in ("active", "error"):
        return {"error": "Datastore must be active before restoring VMs"}, 409

    protocol       = ds.get("protocol", "nfs")
    pve_storage_id = ds.get("pve_storage_id", "")
    vg_name        = ds.get("vg_name", "")
    pve_host_ids   = json.loads(ds.get("pve_host_ids") or "[]")
    snap_name      = body.get("snap_name", "")
    vmids_raw      = body.get("vmids")
    vmids_to_restore = set(int(v) for v in vmids_raw) if vmids_raw else None
    vmid_offset    = int(body.get("vmid_offset", 0))
    storage_id_old = body.get("storage_id_old", "")
    # vmid_map: {orig_vmid_str: new_vmid} — takes precedence over offset
    vmid_map_raw   = body.get("vmid_map", {})
    vmid_map       = {int(k): int(v) for k, v in vmid_map_raw.items()} if vmid_map_raw else {}
    # target_host_id: restrict writing to a single specific host (optional)
    target_host_id = body.get("target_host_id") or None
    if target_host_id and target_host_id in pve_host_ids:
        pve_host_ids = [target_host_id]
    elif target_host_id:
        log.warning(f"[netapp_storage] target_host_id {target_host_id} not in ds.pve_host_ids — ignoring")

    # Resolve manifest
    manifest = None
    if protocol == "nfs":
        if not snap_name:
            return {"error": "snap_name required for NFS VM restore"}, 400
        # Find first accessible host
        for hid in pve_host_ids:
            try:
                pve = build_pve_client(db, hid)
                su, sp, sk = get_ssh_creds(pve)
                mapping = db.query_one(
                    "SELECT nfs_mount_path FROM netapp_volume_mapping "
                    "WHERE pve_storage_id=? AND pve_cluster_id=? LIMIT 1",
                    (pve_storage_id, hid),
                )
                mount_point = (dict(mapping or {}).get("nfs_mount_path") or
                               f"/mnt/pve/{pve_storage_id}")
                from ..core.recovery_engine import read_nfs_manifest
                manifest = read_nfs_manifest(pve.host, su, sp, sk, mount_point, snap_name)
                break
            except Exception as exc:
                log.warning(f"[netapp_storage] restore-vms manifest read: {exc}")
        if manifest is None:
            return {"error": "Could not read manifest from any PVE host"}, 500

    elif protocol in ("iscsi", "nvme"):
        if not vg_name:
            return {"error": "vg_name not set"}, 400
        for hid in pve_host_ids:
            try:
                pve = build_pve_client(db, hid)
                su, sp, sk = get_ssh_creds(pve)
                from ..core.recovery_engine import read_san_manifest_from_live_vg
                manifest = read_san_manifest_from_live_vg(pve.host, su, sp, sk, vg_name)
                break
            except Exception as exc:
                log.warning(f"[netapp_storage] restore-vms SAN manifest read: {exc}")
        if manifest is None:
            return {"error": "Could not read snapmanifest from VG"}, 500
    else:
        return {"error": f"Unsupported protocol: {protocol}"}, 400

    # Write configs
    from ..core.recovery_engine import restore_vm_configs
    try:
        restored = restore_vm_configs(
            manifest, pve_host_ids,
            vmid_offset, vmids_to_restore,
            storage_id_old, pve_storage_id,
            db,
            _FakeJlog(),
            vmid_map=vmid_map,
        )
        return {"restored": restored, "message": f"{restored} VM config(s) written."}
    except Exception as exc:
        log.error(f"[netapp_storage] restore-vms: {exc}")
        return {"error": str(exc)}, 500


def _recovery_used_vmids():
    """Returns sorted list of VMIDs currently in use on the PVE hosts of a datastore.

    Query params: ds_id
    Returns: {vmids: [100, 101, ...]}
    """
    err = _require_admin()
    if err:
        return err
    from flask import request
    ds_id = request.args.get("ds_id")
    if not ds_id:
        return {"error": "ds_id required"}, 400

    db  = get_db()
    row = db.query_one("SELECT pve_host_ids FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404

    pve_host_ids = json.loads(dict(row).get("pve_host_ids") or "[]")
    from ..core.recovery_engine import get_used_vmids
    try:
        vmids = get_used_vmids(pve_host_ids, db)
        return {"vmids": vmids}
    except Exception as exc:
        return {"error": str(exc)}, 500


class _FakeJlog:
    """Minimal JobLogger substitute for synchronous restore-vms endpoint."""
    def log(self, msg):
        log.info(f"[netapp_storage] restore-vms: {msg}")


# ── Job helpers ───────────────────────────────────────────────────────────────

def _start_job(db, job_type, ds_id, username):
    job_id = str(_uuid.uuid4())
    db.execute(
        """INSERT INTO netapp_jobs
           (id, job_type, status, progress_pct, log_json, created_by, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (job_id, job_type, "running", 0, "[]", username, _now()),
    )
    return job_id


def _run_bind_async(job_id, ds_id, params, username):
    import threading
    from pegaprox.core.db import get_db as _get_db
    from ..core.recovery_engine import run_bind

    def _target():
        db = _get_db()
        run_bind(job_id, ds_id, params, username, db)

    t = threading.Thread(target=_target, daemon=True)
    t.start()


# ── Route registration ────────────────────────────────────────────────────────

def register_routes():
    from pegaprox.api.plugins import register_plugin_route
    register_plugin_route(PLUGIN_ID, "provisioning/recovery/scan-volumes", _recovery_scan_volumes)
    register_plugin_route(PLUGIN_ID, "provisioning/recovery/manifests",    _recovery_manifests)
    register_plugin_route(PLUGIN_ID, "provisioning/recovery/bind",         _recovery_bind)
    register_plugin_route(PLUGIN_ID, "provisioning/recovery/restore-vms",  _recovery_restore_vms)
    register_plugin_route(PLUGIN_ID, "provisioning/recovery/used-vmids",   _recovery_used_vmids)
