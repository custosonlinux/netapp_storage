"""
Clone API

  clone/start    POST  – start clone job
  clone/nextid   GET   – next free VMID from PVE
  clone/nodes    GET   – available PVE nodes for a mapping
"""

import uuid
import json
import logging
from datetime import datetime, timezone

from flask import request
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

from ..core.clone_engine import start_clone_job, start_clone_san_job, start_dr_clone_job

log = logging.getLogger(__name__)
from ..core._helpers import PLUGIN_ID  # noqa: F401


def _require_admin():
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


def _start_clone():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}

    for field in ("src_vmid", "new_vmid"):
        if not str(data.get(field, "")).strip():
            return {"error": f"Required field missing: {field}"}, 400

    db = get_db()
    now      = datetime.now(timezone.utc).isoformat()
    username = request.session.get("user", "system")

    # ── ONTAP-native snapshot (not in plugin DB) ───────────────────────
    if data.get("native"):
        mapping_id = data.get("mapping_id")
        snap_name  = data.get("snap_name")
        if not all([mapping_id, snap_name]):
            return {"error": "mapping_id and snap_name required"}, 400

        from ..core._helpers import get_mapping, load_plugin_config
        mapping = get_mapping(db, mapping_id)
        is_san  = mapping.get("storage_protocol", "nfs") in ("iscsi", "nvme")

        if is_san:
            # SAN: manifest is in the snapmanifest LV inside the snapshot;
            # not directly readable here. Pass empty path so the clone engine
            # falls back to PVE config + VG LV discovery.
            manifest_path = ""
        else:
            cfg = load_plugin_config()
            manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
            manifest_path = (
                f"{mapping['nfs_mount_path']}/.snapshot/{snap_name}"
                f"/{manifest_subdir}/{snap_name}/manifest.json"
            )

        snapshot_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO netapp_snapshots "
            "(id, mapping_id, snap_name, consistency, pve_cluster_id, node, "
            "vmids_json, vm_types_json, manifest_path, manifest_json, label, status, created_at, completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (snapshot_id, mapping_id, snap_name, "–",
             mapping["pve_cluster_id"], "",
             "[]", "{}", manifest_path, "", "", "done", now, now),
        )

    # ── Plugin-managed snapshot (in DB) ──────────────────────────────
    else:
        if not str(data.get("snapshot_id", "")).strip():
            return {"error": "Required field missing: snapshot_id"}, 400

        snapshot_id = data["snapshot_id"]
        snap = db.query_one("SELECT id, status FROM netapp_snapshots WHERE id=?",
                            (snapshot_id,))
        if not snap:
            return {"error": "Snapshot not found"}, 404
        if snap["status"] != "done":
            return {"error": f"Snapshot not ready (status: {snap['status']})"}, 409

    job_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO netapp_jobs "
        "(id, job_type, snapshot_id, vmid, status, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, "clone", snapshot_id, int(data["new_vmid"]),
         "running", username, now),
    )

    params = {
        "snapshot_id":     snapshot_id,
        "src_vmid":        data["src_vmid"],
        "new_vmid":        data["new_vmid"],
        "target_node":     data.get("target_node", ""),
        "new_name":        data.get("new_name", ""),
        "start_after":     bool(data.get("start_after", False)),
        "network_isolated": bool(data.get("network_isolated", False)),
    }

    # Route SAN snapshots to the SAN clone engine
    from ..core._helpers import get_mapping, get_snapshot_record
    snap    = get_snapshot_record(db, snapshot_id)
    mapping = get_mapping(db, snap["mapping_id"])
    if mapping.get("storage_protocol") in ("iscsi", "nvme"):
        start_clone_san_job(job_id, params, username)
    else:
        start_clone_job(job_id, params, username)
    return {"success": True, "job_id": job_id}


def _get_nextid():
    """Returns the next free VMID from the PVE cluster."""
    pve_cluster_id = request.args.get("pve_cluster_id")
    if not pve_cluster_id:
        return {"error": "pve_cluster_id required"}, 400
    db = get_db()
    try:
        from ..core._helpers import build_pve_client
        mgr = build_pve_client(db, pve_cluster_id)
        r = mgr._api_get(f"{mgr._base}/cluster/nextid")
        if r.ok:
            return {"vmid": r.json().get("data")}
        return {"error": f"PVE error: {r.status_code}"}, 500
    except Exception as exc:
        return {"error": str(exc)}, 500


def _get_nodes():
    """Returns available PVE nodes for a PVE host."""
    pve_cluster_id = request.args.get("pve_cluster_id")
    if not pve_cluster_id:
        return {"error": "pve_cluster_id required"}, 400
    db = get_db()
    try:
        from ..core._helpers import build_pve_client
        mgr = build_pve_client(db, pve_cluster_id)
        nodes = sorted(mgr.get_node_status().keys())
        if nodes:
            return {"nodes": nodes}
        log.warning("[netapp_storage] clone/nodes: get_node_status returned empty for %s", pve_cluster_id)
    except Exception as exc:
        log.warning("[netapp_storage] clone/nodes: PVE API failed for %s: %s", pve_cluster_id, exc)
    # Fallback: collect nodes seen in recent snapshots for this cluster
    rows = db.query(
        "SELECT DISTINCT node FROM netapp_snapshots "
        "WHERE pve_cluster_id=? AND node != '' "
        "ORDER BY created_at DESC LIMIT 20",
        (pve_cluster_id,),
    )
    nodes = list(dict.fromkeys(r["node"] for r in rows))
    log.info("[netapp_storage] clone/nodes: fallback returned %d nodes for %s", len(nodes), pve_cluster_id)
    return {"nodes": nodes}


def _start_dr_clone():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    for field in ("relationship_id", "snap_name", "src_vmid", "new_vmid", "mapping_id"):
        if not str(data.get(field, "")).strip():
            return {"error": f"Required field missing: {field}"}, 400

    db = get_db()
    username = request.session.get("user", "system")
    now = datetime.now(timezone.utc).isoformat()
    job_id = str(uuid.uuid4())

    db.execute(
        "INSERT INTO netapp_jobs "
        "(id, job_type, vmid, node, status, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, "clone_dr", int(data["new_vmid"]), "", "running", username, now),
    )

    params = {
        "relationship_id": data["relationship_id"],
        "snap_name":       data["snap_name"],
        "src_vmid":        int(data["src_vmid"]),
        "new_vmid":        int(data["new_vmid"]),
        "new_name":        data.get("new_name", ""),
        "mapping_id":      data["mapping_id"],
        "start_after":     bool(data.get("start_after", False)),
    }
    start_dr_clone_job(job_id, params, username)
    return {"success": True, "job_id": job_id}


def register_routes():
    register_plugin_route(PLUGIN_ID, "clone/start",    _start_clone)
    register_plugin_route(PLUGIN_ID, "clone/dr-start", _start_dr_clone)
    register_plugin_route(PLUGIN_ID, "clone/nextid",   _get_nextid)
    register_plugin_route(PLUGIN_ID, "clone/nodes",    _get_nodes)
