"""
SnapMirror® API

  snapmirror/scan               POST  – scan relationships
  snapmirror/relationships      GET   – cached relationships
  snapmirror/update             POST  – trigger manual update
  snapmirror/secondary-snapshots GET  – snapshots on secondary volume
  snapmirror/ensure-export      POST  – ensure NFS export on secondary
"""

import logging
from flask import request
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

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


def _scan_relationships():
    err = _require_admin()
    if err:
        return err
    from ..core.snapmirror import scan_relationships
    db = get_db()
    found, errors = scan_relationships(db)
    return {"success": True, "found": found, "errors": errors}


def _list_relationships():
    db = get_db()
    rows = db.query(
        "SELECT r.*, ep_src.name AS source_endpoint_name, ep_dst.name AS dest_endpoint_name "
        "FROM netapp_snapmirror_relationships r "
        "LEFT JOIN netapp_endpoints ep_src ON ep_src.id = r.source_endpoint_id "
        "LEFT JOIN netapp_endpoints ep_dst ON ep_dst.id = r.dest_endpoint_id "
        "ORDER BY r.source_volume, r.dest_volume"
    )
    return [dict(r) for r in (rows or [])]


def _update_relationship():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    relationship_id = data.get("relationship_id")
    if not relationship_id:
        return {"error": "relationship_id required"}, 400

    db = get_db()
    rel = db.query_one(
        "SELECT * FROM netapp_snapmirror_relationships WHERE id=?", (relationship_id,)
    )
    if not rel:
        return {"error": "Relationship not found"}, 404
    rel = dict(rel)

    from ..core._helpers import get_endpoint, build_ontap_client
    try:
        # Start transfer from destination cluster (UUID is known there)
        ep_id = rel.get("dest_endpoint_id") or rel["source_endpoint_id"]
        ep = get_endpoint(db, ep_id)
        client = build_ontap_client(ep)
        job_uuid = client.trigger_snapmirror_transfer(rel["relationship_uuid"])
        return {"success": True, "job_uuid": job_uuid}
    except Exception as exc:
        return {"error": str(exc)}, 500


def _secondary_snapshots():
    relationship_id = request.args.get("relationship_id")
    if not relationship_id:
        return {"error": "relationship_id required"}, 400

    db = get_db()
    from ..core.snapmirror import get_secondary_snapshots
    try:
        snaps, rel = get_secondary_snapshots(db, relationship_id)
        return {
            "snapshots": snaps,
            "relationship": {
                "id": rel["id"],
                "dest_volume": rel["dest_volume"],
                "dest_svm": rel["dest_svm"],
                "dest_cluster_name": rel["dest_cluster_name"],
                "dest_nfs_ip": rel["dest_nfs_ip"],
                "dest_junction_path": rel["dest_junction_path"],
            },
        }
    except Exception as exc:
        return {"error": str(exc)}, 500


def _ensure_export():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    relationship_id = data.get("relationship_id")
    if not relationship_id:
        return {"error": "relationship_id required"}, 400

    db = get_db()
    from ..core.snapmirror import ensure_secondary_nfs_export
    try:
        nfs_ip, junction, created = ensure_secondary_nfs_export(db, relationship_id)
        return {
            "success": True,
            "nfs_ip": nfs_ip,
            "junction_path": junction,
            "rule_created": created,
        }
    except Exception as exc:
        return {"error": str(exc)}, 500


def _check_secondary():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    relationship_id = data.get("relationship_id")
    if not relationship_id:
        return {"error": "relationship_id required"}, 400

    db = get_db()
    from ..core.snapmirror import check_secondary_connectivity
    try:
        result = check_secondary_connectivity(db, relationship_id)
        return result
    except Exception as exc:
        return {"error": str(exc)}, 500


def _dr_snap_vms():
    """
    Returns VMs contained in a specific DR snapshot.

    Looks up the manifest stored in the DB snapshot record for the given
    relationship + snap_name. Falls back to listing all VMs on the primary
    mapping's PVE cluster.
    """
    data = request.get_json() or {}
    relationship_id = data.get("relationship_id")
    snap_name = data.get("snap_name")
    if not relationship_id or not snap_name:
        return {"error": "relationship_id and snap_name required"}, 400

    db = get_db()
    import json

    try:
        rel = db.query_one(
            "SELECT * FROM netapp_snapmirror_relationships WHERE id=?",
            (relationship_id,)
        )
        if not rel:
            return {"error": "Relationship not found"}, 404
        rel = dict(rel)

        # Find the primary mapping via source_volume_uuid
        mapping = db.query_one(
            "SELECT * FROM netapp_volume_mapping WHERE volume_uuid=?",
            (rel["source_volume_uuid"],)
        )
        if not mapping:
            return {"vms": [], "source": "none", "hint": "No mapping found for source volume"}
        mapping = dict(mapping)

        # Try to find the snapshot record in the DB (plugin-created snapshots
        # replicated via SnapMirror carry the same snap_name)
        snap_row = db.query_one(
            "SELECT * FROM netapp_snapshots WHERE mapping_id=? AND snap_name=? "
            "ORDER BY created_at DESC LIMIT 1",
            (mapping["id"], snap_name),
        )

        if snap_row:
            snap = dict(snap_row)
            manifest_json = snap.get("manifest_json", "")
            if manifest_json:
                try:
                    manifest = json.loads(manifest_json)
                    vm_types = json.loads(snap.get("vm_types_json") or "{}")
                    vms_raw = manifest.get("vms", [])
                    vms = []
                    for entry in vms_raw:
                        vmid = entry.get("vmid")
                        if vmid:
                            vms.append({
                                "vmid": int(vmid),
                                "name": entry.get("name", f"vm-{vmid}"),
                                "vm_type": vm_types.get(str(vmid), entry.get("vm_type", "qemu")),
                            })
                    if vms:
                        return {"vms": sorted(vms, key=lambda v: v["vmid"]), "source": "manifest"}
                except Exception:
                    pass

        # Fallback: list VMs from the primary PVE cluster that are known
        # from any snapshot of this mapping (vm_types_json column)
        vmid_set = {}
        rows = db.query(
            "SELECT vm_types_json FROM netapp_snapshots WHERE mapping_id=? "
            "AND vm_types_json IS NOT NULL AND vm_types_json != '' LIMIT 20",
            (mapping["id"],)
        ) or []
        for row in rows:
            try:
                for vid, vtype in json.loads(row["vm_types_json"]).items():
                    vmid_set[int(vid)] = vtype
            except Exception:
                pass

        if vmid_set:
            vms = [{"vmid": vid, "name": f"vm-{vid}", "vm_type": vt}
                   for vid, vt in sorted(vmid_set.items())]
            return {"vms": vms, "source": "history",
                    "hint": "Snapshot not in DB — showing VMs from snapshot history"}

        return {"vms": [], "source": "none",
                "hint": "No VM information available — enter VMID manually"}

    except Exception as exc:
        return {"error": str(exc)}, 500


def _snapmirror_policy_labels():
    """Returns SM relationship status and policy retention labels for a mapping."""
    mapping_id = request.args.get("mapping_id")
    if not mapping_id:
        return {"error": "mapping_id required"}, 400

    db = get_db()
    mapping = db.query_one("SELECT * FROM netapp_volume_mapping WHERE id=?", (mapping_id,))
    if not mapping:
        return {"error": "Mapping not found"}, 404
    mapping = dict(mapping)

    rel = db.query_one(
        "SELECT * FROM netapp_snapmirror_relationships WHERE source_volume_uuid=?",
        (mapping["volume_uuid"],)
    )
    if not rel:
        return {"has_relationship": False, "labels": []}
    rel = dict(rel)

    from ..core._helpers import get_endpoint, build_ontap_client
    try:
        # Relationship UUID is valid on the destination cluster (where the scan ran).
        ep_id = rel.get("dest_endpoint_id") or rel["source_endpoint_id"]
        ep = get_endpoint(db, ep_id)
        client = build_ontap_client(ep)
        labels = client.get_snapmirror_policy_labels(rel["relationship_uuid"])
        return {
            "has_relationship": True,
            "labels": labels,
            "source_svm": rel.get("source_svm", ""),
            "source_volume": rel.get("source_volume", ""),
            "dest_cluster": rel.get("dest_cluster_name", ""),
            "dest_svm": rel.get("dest_svm", ""),
            "dest_volume": rel.get("dest_volume", ""),
            "policy_type": rel.get("policy_type", ""),
            "state": rel.get("state", ""),
            "healthy": bool(rel.get("healthy", 1)),
        }
    except Exception as exc:
        log.warning(f"[netapp_storage] policy-labels for {mapping_id}: {exc}")
        return {
            "has_relationship": True,
            "labels": [],
            "source_svm": rel.get("source_svm", ""),
            "source_volume": rel.get("source_volume", ""),
            "dest_cluster": rel.get("dest_cluster_name", ""),
            "dest_svm": rel.get("dest_svm", ""),
            "dest_volume": rel.get("dest_volume", ""),
            "policy_type": rel.get("policy_type", ""),
            "state": rel.get("state", ""),
            "healthy": bool(rel.get("healthy", 1)),
            "warning": str(exc),
        }


def register_routes():
    register_plugin_route(PLUGIN_ID, "snapmirror/scan", _scan_relationships)
    register_plugin_route(PLUGIN_ID, "snapmirror/relationships", _list_relationships)
    register_plugin_route(PLUGIN_ID, "snapmirror/update", _update_relationship)
    register_plugin_route(PLUGIN_ID, "snapmirror/secondary-snapshots", _secondary_snapshots)
    register_plugin_route(PLUGIN_ID, "snapmirror/ensure-export", _ensure_export)
    register_plugin_route(PLUGIN_ID, "snapmirror/check-secondary", _check_secondary)
    register_plugin_route(PLUGIN_ID, "snapmirror/dr-snap-vms", _dr_snap_vms)
    register_plugin_route(PLUGIN_ID, "snapmirror/policy-labels", _snapmirror_policy_labels)
