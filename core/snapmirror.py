"""
SnapMirror® business logic

Detects SnapMirror® relationships, triggers updates, and prepares
restore from the secondary system.

SnapMirror® is a registered trademark of NetApp, Inc.
"""

import uuid
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def scan_relationships(db):
    """
    Scans ALL configured endpoints for SnapMirror® relationships.
    Intercluster relationships are only visible from the destination cluster —
    so the destination cluster must be configured as an endpoint.
    Returns (found, errors).
    """
    from ._helpers import get_endpoint, build_ontap_client

    # Lookup: "svm:volume" → mapping (endpoint-independent)
    mappings = db.query("SELECT * FROM netapp_volume_mapping")
    mapping_by_src_path = {}
    for m in (mappings or []):
        m = dict(m)
        key = f"{m['svm_name']}:{m['volume_name']}"
        mapping_by_src_path[key] = m

    known_paths = list(mapping_by_src_path.keys())
    log.warning(f"[netapp_storage] SnapMirror scan: known source paths: {known_paths}")

    # Scan all endpoints (including destination cluster)
    all_ep_rows = db.query("SELECT id FROM netapp_endpoints") or []
    found = 0
    errors = []

    for ep_row in all_ep_rows:
        ep_id = ep_row["id"]
        try:
            ep = get_endpoint(db, ep_id)
            client = build_ontap_client(ep)
            rels = client.list_snapmirror_relationships()
            log.warning(
                f"[netapp_storage] SnapMirror scan '{ep.get('name','?')}': "
                f"{len(rels)} relationships — paths: "
                f"{[((r.get('source') or {}).get('path','?')) for r in rels]}"
            )
            for rel in rels:
                src_path = (rel.get("source") or {}).get("path", "")
                mapping = mapping_by_src_path.get(src_path)
                if mapping:
                    _upsert_relationship(db, rel, mapping)
                    found += 1
                    log.warning(f"[netapp_storage] SnapMirror matched: {src_path}")
        except Exception as exc:
            log.warning(f"[netapp_storage] SnapMirror scan endpoint '{ep_id}': {exc}")
            errors.append(str(exc))

    match_endpoints(db)
    return found, errors


def match_endpoints(db):
    """
    Tries to find a matching endpoint by cluster name
    for relationships without a dest_endpoint_id.
    """
    from ._helpers import get_endpoint, build_ontap_client

    unmatched = db.query(
        "SELECT * FROM netapp_snapmirror_relationships WHERE dest_endpoint_id='' OR dest_volume_uuid=''"
    )
    if not unmatched:
        return

    endpoints = db.query("SELECT * FROM netapp_endpoints")
    ep_cluster = {}
    for ep_row in (endpoints or []):
        ep = dict(ep_row)
        ep["password"] = db._decrypt(ep.pop("password_encrypted", ""))
        try:
            client = build_ontap_client(ep)
            cluster_name, cluster_uuid = client.get_cluster_info()
            ep_cluster[cluster_name.lower()] = ep
        except Exception:
            pass

    for rel in (unmatched or []):
        rel = dict(rel)
        dest_cluster = rel["dest_cluster_name"].lower()
        matched_ep = ep_cluster.get(dest_cluster)
        if not matched_ep:
            continue
        try:
            client = build_ontap_client(matched_ep)
            vol = client.get_volume_by_name(rel["dest_svm"], rel["dest_volume"])
            vol_uuid = vol.get("uuid", "")
            junction = vol.get("nas", {}).get("path", "") or (vol.get("nas") or {}).get("path", "")
            nfs_ip = client.get_nfs_lif_for_svm(rel["dest_svm"])
            # get junction_path from get_volume_by_name
            export_info = client.get_volume_export_info(vol_uuid)
            junction = export_info.get("junction_path", "")
            db.execute(
                "UPDATE netapp_snapmirror_relationships "
                "SET dest_endpoint_id=?, dest_volume_uuid=?, dest_nfs_ip=?, dest_junction_path=? "
                "WHERE id=?",
                (matched_ep["id"], vol_uuid, nfs_ip, junction, rel["id"]),
            )
            log.info(f"[netapp_storage] SnapMirror endpoint matched: {rel['dest_cluster_name']} → {matched_ep['name']}")
        except Exception as exc:
            log.warning(f"[netapp_storage] SnapMirror endpoint match failed {rel['dest_cluster_name']}: {exc}")


def _upsert_relationship(db, rel, mapping):
    """Creates or updates a relationship."""
    rel_uuid = rel.get("uuid", "")
    if not rel_uuid:
        return

    dest = rel.get("destination") or {}
    src = rel.get("source") or {}
    policy = rel.get("policy") or {}
    transfer = rel.get("transfer") or {}

    existing = db.query_one(
        "SELECT id FROM netapp_snapmirror_relationships WHERE relationship_uuid=?", (rel_uuid,)
    )

    now = datetime.now(timezone.utc).isoformat()
    state = rel.get("state", "")
    healthy = 1 if rel.get("healthy", True) else 0
    lag = rel.get("lag_time", "")
    last_transfer = transfer.get("end_time", "")
    policy_type = policy.get("type", "")

    # ONTAP returns source/destination as {path: "svm:volume", cluster: {...}}
    # path format: "svm_name:volume_name"
    src_path = src.get("path", "")
    dest_path = dest.get("path", "")
    src_svm, src_vol = src_path.split(":", 1) if ":" in src_path else (src_path, "")
    dest_svm_vol = dest_path.split(":", 1) if ":" in dest_path else [dest_path, ""]
    dest_svm = dest_svm_vol[0]
    dest_vol = dest_svm_vol[1] if len(dest_svm_vol) > 1 else ""
    dest_cluster = (dest.get("cluster") or {}).get("name", "")

    if existing:
        db.execute(
            "UPDATE netapp_snapmirror_relationships "
            "SET state=?, healthy=?, lag_time=?, last_transfer_time=?, last_scanned_at=? "
            "WHERE relationship_uuid=?",
            (state, healthy, lag, last_transfer, now, rel_uuid),
        )
    else:
        rid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO netapp_snapmirror_relationships "
            "(id, source_endpoint_id, source_volume_uuid, source_svm, source_volume, "
            "dest_cluster_name, dest_svm, dest_volume, "
            "relationship_uuid, policy_type, state, healthy, lag_time, last_transfer_time, last_scanned_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, mapping["endpoint_id"], mapping["volume_uuid"],
             src_svm, src_vol,
             dest_cluster, dest_svm, dest_vol,
             rel_uuid, policy_type, state, healthy, lag, last_transfer, now),
        )


def trigger_update_for_volume(db, volume_uuid, source_endpoint_id, jlog=None):
    """
    Triggers SnapMirror® updates for all relationships of a volume.
    Errors are logged but not re-raised.
    Returns the number of started transfers.
    """
    from ._helpers import get_endpoint, build_ontap_client

    rels = db.query(
        "SELECT * FROM netapp_snapmirror_relationships "
        "WHERE source_volume_uuid=? AND source_endpoint_id=?",
        (volume_uuid, source_endpoint_id),
    )
    if not rels:
        return 0

    started = 0

    for rel in rels:
        rel = dict(rel)
        # Start transfer from destination cluster (UUID is known there)
        ep_id = rel.get("dest_endpoint_id") or source_endpoint_id
        try:
            ep = get_endpoint(db, ep_id)
            client = build_ontap_client(ep)
            job_uuid = client.trigger_snapmirror_transfer(rel["relationship_uuid"])
            msg = (f"SnapMirror® update started: {rel['source_volume']} → "
                   f"{rel['dest_cluster_name']}:{rel['dest_volume']}")
            if job_uuid:
                msg += f" (Job {job_uuid[:8]})"
            if jlog:
                jlog.log(msg)
            else:
                log.info(f"[netapp_storage] {msg}")
            started += 1
        except Exception as exc:
            msg = f"SnapMirror® update failed for {rel['dest_volume']}: {exc}"
            if jlog:
                jlog.log(msg)
            else:
                log.warning(f"[netapp_storage] {msg}")

    return started


def get_secondary_snapshots(db, relationship_id):
    """
    Returns snapshots on the secondary volume.
    Requires dest_endpoint_id and dest_volume_uuid to be set.
    """
    from ._helpers import get_endpoint, build_ontap_client

    rel = db.query_one(
        "SELECT * FROM netapp_snapmirror_relationships WHERE id=?", (relationship_id,)
    )
    if not rel:
        raise RuntimeError(f"Relationship '{relationship_id}' not found")
    rel = dict(rel)

    if not rel["dest_endpoint_id"]:
        raise RuntimeError("No secondary endpoint configured. Run scan first.")
    if not rel["dest_volume_uuid"]:
        raise RuntimeError("Secondary volume UUID unknown. Run scan first.")

    ep = get_endpoint(db, rel["dest_endpoint_id"])
    client = build_ontap_client(ep)
    snaps = client.list_snapshots(rel["dest_volume_uuid"])
    return snaps, rel


def ensure_secondary_nfs_export(db, relationship_id):
    """
    Checks if the secondary volume is exported via NFS.
    Creates a read-only export rule if none exists.
    Returns (nfs_ip, junction_path, created).
    """
    from ._helpers import get_endpoint, build_ontap_client

    rel = db.query_one(
        "SELECT * FROM netapp_snapmirror_relationships WHERE id=?", (relationship_id,)
    )
    if not rel:
        raise RuntimeError(f"Relationship '{relationship_id}' not found")
    rel = dict(rel)

    if not rel["dest_endpoint_id"] or not rel["dest_volume_uuid"]:
        raise RuntimeError("Secondary endpoint or volume UUID missing. Run scan first.")

    ep = get_endpoint(db, rel["dest_endpoint_id"])
    client = build_ontap_client(ep)

    export_info = client.get_volume_export_info(rel["dest_volume_uuid"])
    junction = export_info.get("junction_path", "")
    policy_id = export_info.get("export_policy_id", "")
    nfs_ip = rel["dest_nfs_ip"]

    if not nfs_ip:
        nfs_ip = client.get_nfs_lif_for_svm(rel["dest_svm"])
        if nfs_ip:
            db.execute(
                "UPDATE netapp_snapmirror_relationships SET dest_nfs_ip=? WHERE id=?",
                (nfs_ip, rel["id"]),
            )

    if not junction:
        junction = f"/{rel['dest_volume']}"
        log.info(
            f"[netapp_storage] DP volume '{rel['dest_volume']}' has no junction path "
            f"— mounting at {junction}"
        )
        client.mount_volume(rel["dest_volume_uuid"], junction)
        db.execute(
            "UPDATE netapp_snapmirror_relationships SET dest_junction_path=? WHERE id=?",
            (junction, rel["id"]),
        )

    created = False
    if policy_id:
        rules = client.list_nfs_export_rules(policy_id)
        has_open_rule = any(
            any(c.get("match") in ("0.0.0.0/0", "all", "::0/0")
                for c in (r.get("clients") or []))
            for r in rules
        )
        if not has_open_rule:
            client.add_nfs_export_rule(policy_id)
            created = True
            log.info(f"[netapp_storage] NFS export rule 0.0.0.0/0 created for {rel['dest_volume']}")

    if not rel["dest_junction_path"] and junction:
        db.execute(
            "UPDATE netapp_snapmirror_relationships SET dest_junction_path=? WHERE id=?",
            (junction, rel["id"]),
        )

    return nfs_ip, junction, created


def check_secondary_connectivity(db, relationship_id):
    """
    Protocol-aware connectivity check for the SnapMirror® secondary.

    NFS  — verifies junction path exists, creates export rule if missing.
    iSCSI — verifies iSCSI service + LIF reachable on destination SVM.
    NVMe  — verifies NVMe/TCP service + LIF reachable on destination SVM.

    Returns a dict with success=True and human-readable details.
    Raises RuntimeError when a required prerequisite is missing.
    """
    from ._helpers import get_endpoint, build_ontap_client

    rel = db.query_one(
        "SELECT * FROM netapp_snapmirror_relationships WHERE id=?", (relationship_id,)
    )
    if not rel:
        raise RuntimeError(f"Relationship '{relationship_id}' not found")
    rel = dict(rel)

    if not rel.get("dest_endpoint_id") or not rel.get("dest_volume_uuid"):
        raise RuntimeError(
            "Secondary endpoint or volume UUID missing — run SnapMirror scan first.")

    # Determine protocol from the source volume mapping
    mapping = db.query_one(
        "SELECT * FROM netapp_volume_mapping WHERE volume_uuid=?",
        (rel["source_volume_uuid"],),
    )
    protocol = (dict(mapping).get("storage_protocol", "nfs") if mapping else "nfs")

    dest_svm      = rel["dest_svm"]
    dest_vol_uuid = rel["dest_volume_uuid"]

    secondary_ep     = get_endpoint(db, rel["dest_endpoint_id"])
    secondary_client = build_ontap_client(secondary_ep)

    # Verify the DP volume is still known
    try:
        vol_info = secondary_client.get_volume(dest_vol_uuid)
        vol_name = vol_info.get("name", dest_vol_uuid)
    except Exception as exc:
        raise RuntimeError(f"Cannot reach secondary volume: {exc}")

    if protocol == "nfs":
        nfs_ip, junction, created = ensure_secondary_nfs_export(db, relationship_id)
        msg = (
            f"NFS OK — {nfs_ip}:{junction}"
            + (" (export rule created)" if created else "")
        )
        return {
            "success": True,
            "protocol": "nfs",
            "details": msg,
            "nfs_ip": nfs_ip,
            "junction_path": junction,
            "rule_created": created,
        }

    elif protocol == "iscsi":
        portal = secondary_client.get_iscsi_lif_for_svm(dest_svm)
        target_iqn = secondary_client.get_iscsi_target_iqn(dest_svm)
        if not portal:
            raise RuntimeError(
                f"No iSCSI data LIF found on secondary SVM '{dest_svm}' — "
                "verify iSCSI service is running and a LIF with data_iscsi role exists.")
        if not target_iqn:
            raise RuntimeError(
                f"iSCSI service has no target IQN on secondary SVM '{dest_svm}'.")
        msg = (
            f"iSCSI OK — portal: {portal}, "
            f"target: {target_iqn}, "
            f"volume: {vol_name}"
        )
        return {
            "success": True,
            "protocol": "iscsi",
            "details": msg,
            "portal": portal,
            "target_iqn": target_iqn,
            "volume": vol_name,
        }

    elif protocol == "nvme":
        # NVMe/TCP: look for a LIF with data_nvme_tcp service
        try:
            lifs = secondary_client._get_all_records(
                "network/ip/interfaces",
                params={"services": "data_nvme_tcp", "svm.name": dest_svm,
                        "fields": "ip.address,state", "max_records": 50},
            )
        except Exception:
            lifs = []
        active_lifs = [
            (r.get("ip") or {}).get("address", "")
            for r in lifs
            if r.get("state", "up") == "up"
        ]
        active_lifs = [a for a in active_lifs if a]
        if not active_lifs:
            raise RuntimeError(
                f"No NVMe/TCP data LIF found on secondary SVM '{dest_svm}' — "
                "verify NVMe/TCP service is running and a LIF with data_nvme_tcp role exists.")
        msg = (
            f"NVMe/TCP OK — portal(s): {', '.join(active_lifs)}, "
            f"volume: {vol_name}"
        )
        return {
            "success": True,
            "protocol": "nvme",
            "details": msg,
            "portals": active_lifs,
            "volume": vol_name,
        }

    else:
        raise RuntimeError(f"Unknown storage protocol '{protocol}' for this mapping.")
