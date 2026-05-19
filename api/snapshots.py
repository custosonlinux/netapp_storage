"""
Snapshot API

Routes under /api/plugins/netapp_storage/api/...

  endpoints               GET/POST – manage endpoints
  endpoints/add           POST
  endpoints/delete        POST
  endpoints/test          POST

  volume-mappings         GET  – list auto-discovery cache
  discover                POST – trigger discovery

  snapshots               GET   – snapshot list
  snapshots/create        POST  – start snapshot
  snapshots/delete        POST  – delete snapshot
  snapshots/volumes       GET   – ONTAP volumes for an endpoint

  jobs/status             GET   – job status (?job_id=) or all jobs
  ui                      GET   – plugin UI (HTML)
"""

import uuid
import json
import logging
from datetime import datetime, timezone

from flask import request
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

from ..core._helpers import get_endpoint, build_ontap_client, load_plugin_config
from ..core.snapshot_engine import start_snapshot_job

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


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _list_endpoints():
    db = get_db()
    rows = db.query("SELECT id, name, host, username, ssl_verify, san_optimized, created_at, updated_at "
                    "FROM netapp_endpoints ORDER BY name")
    return [dict(r) for r in rows]


def _add_endpoint():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    for field in ("name", "host", "username", "password"):
        if not data.get(field):
            return {"error": f"Required field missing: {field}"}, 400

    db = get_db()
    eid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Detect platform on add so san_optimized is available immediately
    san_opt = 0
    try:
        from ..core.ontap_client import OntapClient
        tmp = OntapClient(data["host"], data["username"], data["password"],
                          ssl_verify=bool(data.get("ssl_verify", True)))
        _, _, san_opt_bool = tmp.test_connection()
        san_opt = 1 if san_opt_bool else 0
    except Exception:
        pass

    db.execute(
        "INSERT INTO netapp_endpoints (id, name, host, username, password_encrypted, "
        "ssl_verify, skip_nfs, san_optimized, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (eid, data["name"], data["host"], data["username"],
         db._encrypt(data["password"]),
         1 if data.get("ssl_verify", True) else 0,
         1 if data.get("skip_nfs") else 0,
         san_opt, now, now),
    )
    return {"success": True, "id": eid}


def _delete_endpoint():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    eid = data.get("id")
    if not eid:
        return {"error": "id required"}, 400
    db = get_db()
    db.execute("DELETE FROM netapp_endpoints WHERE id=?", (eid,))
    return {"success": True}


def _test_endpoint():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    eid = data.get("id")
    if not eid:
        return {"error": "id required"}, 400
    db = get_db()
    try:
        endpoint = get_endpoint(db, eid)
        client = build_ontap_client(endpoint)
        cluster_name, version, san_optimized = client.test_connection()
        db.execute("UPDATE netapp_endpoints SET san_optimized=?, updated_at=? WHERE id=?",
                   (1 if san_optimized else 0,
                    datetime.now(timezone.utc).isoformat(), eid))
        return {"success": True, "cluster_name": cluster_name,
                "ontap_version": version, "san_optimized": san_optimized}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ── PVE-Hosts ─────────────────────────────────────────────────────────────────

def _list_pve_hosts():
    db = get_db()
    rows = db.query("SELECT id, name, host, port, username, ssl_verify, nfs_ip, created_at "
                    "FROM netapp_pve_hosts ORDER BY name")
    return [dict(r) for r in rows]


def _add_pve_host():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    for field in ("name", "host", "username", "password"):
        if not data.get(field):
            return {"error": f"Required field missing: {field}"}, 400
    db = get_db()
    hid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO netapp_pve_hosts (id, name, host, port, username, password_encrypted, "
        "ssl_verify, nfs_ip, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (hid, data["name"], data["host"],
         int(data.get("port", 8006)),
         data["username"],
         db._encrypt(data["password"]),
         1 if data.get("ssl_verify", False) else 0,
         data.get("nfs_ip", "").strip(),
         now),
    )
    return {"success": True, "id": hid}


def _delete_pve_host():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    hid = data.get("id")
    if not hid:
        return {"error": "id required"}, 400
    db = get_db()
    db.execute("DELETE FROM netapp_pve_hosts WHERE id=?", (hid,))
    return {"success": True}


def _test_pve_host():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    hid = data.get("id")
    if not hid:
        return {"error": "id required"}, 400
    db = get_db()
    try:
        from ..core._helpers import build_pve_client
        pve = build_pve_client(db, hid)
        # query PVE version
        rv = pve._api_get(f"{pve._base}/version")
        version = rv.json().get("data", {}).get("version", "?") if rv.ok else "?"
        # determine nodes
        nodes = list(pve.get_node_status().keys())
        return {"success": True, "pve_version": version, "nodes": nodes}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ── Discovery ─────────────────────────────────────────────────────────────────

def _list_mappings():
    """Returns all known volume mappings from auto-discovery."""
    db = get_db()
    rows = db.query(
        "SELECT vm.*, ep.name AS endpoint_name, ep.host AS endpoint_host, "
        "ep.san_optimized, ph.name AS pve_host_name "
        "FROM netapp_volume_mapping vm "
        "JOIN netapp_endpoints ep ON ep.id = vm.endpoint_id "
        "LEFT JOIN netapp_pve_hosts ph ON ph.id = vm.pve_cluster_id "
        "ORDER BY vm.pve_storage_id"
    )
    return [dict(r) for r in rows]


def _run_discovery():
    """Triggers auto-discovery and returns found mappings and debug info."""
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    endpoint_id = data.get("endpoint_id")
    try:
        from ..core.discovery import run_discovery
        mappings, debug_info = run_discovery(endpoint_id=endpoint_id)
        return {"success": True, "mappings": mappings, "count": len(mappings),
                "debug": debug_info}
    except Exception as exc:
        return {"error": str(exc)}, 500


def _delete_mapping():
    """POST {mapping_id} — Deletes a volume mapping from DB."""
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    mapping_id = data.get("mapping_id")
    if not mapping_id:
        return {"error": "mapping_id required"}, 400
    db = get_db()
    row = db.query_one("SELECT id, pve_storage_id FROM netapp_volume_mapping WHERE id=?",
                       (mapping_id,))
    if not row:
        return {"error": "Mapping not found"}, 404
    db.execute("DELETE FROM netapp_volume_mapping WHERE id=?", (mapping_id,))
    return {"success": True, "deleted": row["pve_storage_id"]}


# ── Snapshots ─────────────────────────────────────────────────────────────────

def _list_snapshots():
    from ..core._helpers import get_endpoint, build_ontap_client

    db = get_db()

    # ── 1. Plugin-managed snapshots from DB ─────────────────────────────
    rows = db.query(
        "SELECT s.*, vm.pve_storage_id, vm.volume_name, vm.volume_uuid, vm.endpoint_id, "
        "vm.storage_protocol, vm.lvm_vg_name, ep.san_optimized "
        "FROM netapp_snapshots s "
        "JOIN netapp_volume_mapping vm ON vm.id = s.mapping_id "
        "JOIN netapp_endpoints ep ON ep.id = vm.endpoint_id "
        "ORDER BY s.created_at DESC LIMIT 200"
    )
    result = []
    db_keys = set()   # (volume_uuid, snap_name) — for deduplication
    for r in rows:
        d = dict(r)
        d["vmids"] = json.loads(d.get("vmids_json") or "[]")
        try:
            manifest = json.loads(d.get("manifest_json") or "{}")
            d["vm_names"] = {str(v["vmid"]): v.get("name", "") for v in manifest.get("vms", [])}
        except Exception:
            d["vm_names"] = {}
        d["source"] = "plugin"
        d["san_optimized"] = bool(d.get("san_optimized", 0))
        db_keys.add((d["volume_uuid"], d["snap_name"]))
        result.append(d)

    # ── 2. ONTAP-native snapshots (not in DB) ──────────────────────────
    mappings = db.query(
        "SELECT vm.*, ep.id AS ep_id, ep.san_optimized "
        "FROM netapp_volume_mapping vm "
        "JOIN netapp_endpoints ep ON ep.id = vm.endpoint_id"
    )
    for m in (mappings or []):
        m = dict(m)
        try:
            ep = get_endpoint(db, m["endpoint_id"])
            client = build_ontap_client(ep)
            ontap_snaps = client.list_snapshots(m["volume_uuid"])
            for s in ontap_snaps:
                if (m["volume_uuid"], s["name"]) in db_keys:
                    continue
                result.append({
                    "id": s["uuid"],
                    "mapping_id": m["id"],
                    "snap_name": s["name"],
                    "ontap_snap_uuid": s["uuid"],
                    "consistency": "–",
                    "pve_cluster_id": m["pve_cluster_id"],
                    "node": "",
                    "vmids": [],
                    "vm_names": {},
                    "label": s.get("snapmirror_label", ""),
                    "status": "done",
                    "error": "",
                    "schedule_id": "",
                    "pve_storage_id": m["pve_storage_id"],
                    "volume_name": m["volume_name"],
                    "volume_uuid": m["volume_uuid"],
                    "storage_protocol": m.get("storage_protocol", "nfs"),
                    "lvm_vg_name": m.get("lvm_vg_name", ""),
                    "manifest_path": "",
                    "created_at": s.get("create_time", ""),
                    "completed_at": "",
                    "source": "ontap_native",
                    "san_optimized": bool(m.get("san_optimized", 0)),
                })
        except Exception as exc:
            log.warning(f"[netapp_storage] ONTAP snapshot scan {m.get('volume_name')}: {exc}")

    result.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return result[:300]


def _create_snapshot():
    import re as _re
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    for field in ("vmids", "mapping_id"):
        if not data.get(field):
            return {"error": f"Required field missing: {field}"}, 400

    # User-provided name — only ONTAP-valid characters, max 80
    raw_name = data.get("name", "").strip()
    if not raw_name:
        return {"error": "Required field missing: name"}, 400
    safe_name = _re.sub(r'[^a-zA-Z0-9_.\-]', '_', raw_name)[:80].strip('_')
    if not safe_name:
        return {"error": "Invalid name (only letters, digits, -, _, . allowed)"}, 400
    data["snap_name"] = safe_name

    vmids = data["vmids"]
    if not isinstance(vmids, list) or not vmids:
        return {"error": "vmids must be a non-empty list"}, 400

    db = get_db()

    # Derive cluster_id from mapping if not provided
    if not data.get("cluster_id"):
        row = db.query_one("SELECT pve_cluster_id FROM netapp_volume_mapping WHERE id=?",
                           (data["mapping_id"],))
        if not row:
            return {"error": "Mapping not found"}, 404
        data["cluster_id"] = row["pve_cluster_id"]

    # Derive node from PVE if not provided
    if not data.get("node"):
        try:
            from ..core._helpers import build_pve_client
            pve = build_pve_client(db, data["cluster_id"])
            # find VM node
            node = pve.find_vm_node(data["vmids"][0])
            if not node:
                nodes = list(pve.get_node_status().keys())
                node = nodes[0] if nodes else ""
            data["node"] = node
        except Exception:
            data.setdefault("node", "")

    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    username = request.session.get("user", "system")
    db.execute(
        "INSERT INTO netapp_jobs (id, job_type, vmid, node, status, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, "snapshot", None, data.get("node", ""), "running", username, now),
    )

    start_snapshot_job(job_id, data, username)
    return {"success": True, "job_id": job_id}


def _delete_snapshot():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    db = get_db()

    # ── ONTAP-native snapshot (not in plugin DB) ───────────────────────
    if data.get("native"):
        ontap_snap_uuid = data.get("ontap_snap_uuid")
        mapping_id = data.get("mapping_id")
        if not ontap_snap_uuid or not mapping_id:
            return {"error": "ontap_snap_uuid and mapping_id required"}, 400
        try:
            from ..core._helpers import get_mapping, get_endpoint
            mapping = get_mapping(db, mapping_id)
            endpoint = get_endpoint(db, mapping["endpoint_id"])
            client = build_ontap_client(endpoint)
            del_job = client.delete_snapshot(mapping["volume_uuid"], ontap_snap_uuid)
            if del_job:
                client.poll_job(del_job, timeout_s=120)
        except Exception as exc:
            return {"error": str(exc)}, 500
        return {"success": True}

    # ── Plugin-managed snapshot (in DB) ──────────────────────────────
    snapshot_id = data.get("id")
    if not snapshot_id:
        return {"error": "id required"}, 400

    snap = db.query_one("SELECT * FROM netapp_snapshots WHERE id=?", (snapshot_id,))
    if not snap:
        return {"error": "Snapshot not found"}, 404
    snap = dict(snap)

    try:
        from ..core._helpers import get_mapping, get_endpoint
        mapping = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client = build_ontap_client(endpoint)

        ontap_snap_uuid = snap.get("ontap_snap_uuid", "")
        if ontap_snap_uuid:
            del_job = client.delete_snapshot(mapping["volume_uuid"], ontap_snap_uuid)
            if del_job:
                client.poll_job(del_job, timeout_s=120)
    except Exception as exc:
        log.warning(f"[netapp_storage] ONTAP snapshot deletion failed: {exc}")

    db.execute("DELETE FROM netapp_snapshots WHERE id=?", (snapshot_id,))
    return {"success": True}


def _vms_for_mapping():
    """Returns VMs that have disks on the given storage."""
    mapping_id = request.args.get("mapping_id") or (request.get_json() or {}).get("mapping_id")
    if not mapping_id:
        return {"error": "mapping_id required"}, 400
    db = get_db()
    try:
        from ..core._helpers import get_mapping, build_pve_client
        mapping = get_mapping(db, mapping_id)
        storage_id = mapping["pve_storage_id"]
        volume_uuid = mapping["volume_uuid"]

        # All PVE hosts that know this volume (for multi-host setups without cluster)
        host_rows = db.query(
            "SELECT DISTINCT pve_cluster_id FROM netapp_volume_mapping WHERE volume_uuid=?",
            (volume_uuid,)
        )
        host_ids = [r["pve_cluster_id"] for r in host_rows]
        if mapping["pve_cluster_id"] not in host_ids:
            host_ids.insert(0, mapping["pve_cluster_id"])

        storage_vmids = set()
        vm_info_map = {}
        is_san = mapping.get("storage_protocol", "nfs") in ("iscsi", "nvme")

        for hid in host_ids:
            try:
                pve = build_pve_client(db, hid)

                nodes = list(pve.get_node_status().keys())
                log.warning(f"[netapp_storage] vms-for-mapping {storage_id}: host={pve.host} nodes={nodes}")
                for node_name in nodes:
                    rc = pve._api_get(
                        f"{pve._base}/nodes/{node_name}/storage/{storage_id}/content"
                    )
                    log.warning(f"[netapp_storage] vms-for-mapping content {node_name}/{storage_id}: HTTP {rc.status_code} data={rc.json().get('data') if rc.ok else rc.text[:200]}")
                    if rc.ok:
                        for item in rc.json().get("data", []):
                            vmid = item.get("vmid")
                            if vmid:
                                storage_vmids.add(int(vmid))
                        if not is_san:
                            break  # NFS is shared — first OK is sufficient

                r = pve._api_get(f"{pve._base}/cluster/resources?type=vm")
                if r.ok:
                    for res in r.json().get("data", []):
                        vmid = res.get("vmid")
                        if vmid and int(vmid) not in vm_info_map:
                            vm_info_map[int(vmid)] = {
                                "vmid": int(vmid),
                                "name": res.get("name", f"vm-{vmid}"),
                                "node": res.get("node"),
                                "type": res.get("type", "qemu"),
                                "status": res.get("status"),
                            }
            except Exception as _exc:
                log.warning(f"[netapp_storage] vms-for-mapping {storage_id} host {hid}: {_exc}")
                continue

        log.warning(f"[netapp_storage] vms-for-mapping {storage_id}: found vmids={storage_vmids}")
        vms = [
            vm_info_map.get(vid, {"vmid": vid, "name": f"vm-{vid}",
                                  "node": "", "type": "qemu", "status": "unknown"})
            for vid in sorted(storage_vmids)
        ]
        return {"vms": vms}
    except Exception as exc:
        return {"error": str(exc)}, 500


def _snapshot_manifest():
    """Reads the manifest of an ONTAP snapshot on-demand from the .snapshot directory."""
    params = request.args if request.method == "GET" else (request.get_json() or {})
    snap_name  = params.get("snap_name")
    mapping_id = params.get("mapping_id")
    if not snap_name or not mapping_id:
        return {"error": "snap_name and mapping_id required"}, 400

    db = get_db()
    try:
        from ..core._helpers import get_mapping, load_plugin_config, get_ssh_creds, ssh_run, build_pve_client
        import shlex

        mapping = get_mapping(db, mapping_id)
        cfg = load_plugin_config()
        manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")

        mgr = build_pve_client(db, mapping["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)

        # SSH target (IP of the PVE host)
        try:
            r = mgr._api_get(f"{mgr._base}/cluster/status")
            pve_host = mgr.host
            if r.ok:
                for item in r.json().get("data", []):
                    if item.get("type") == "node" and item.get("ip"):
                        pve_host = item["ip"]
                        break
        except Exception:
            pve_host = mgr.host

        # 1. Exact path: snap_name as subdirectory (PegaProx snapshot)
        exact = (f"{mapping['nfs_mount_path']}/.snapshot/{snap_name}"
                 f"/{manifest_subdir}/{snap_name}/manifest.json")
        manifest = None
        used_path = None
        try:
            out = ssh_run(pve_host, pve_user, pve_pass,
                          f"cat {shlex.quote(exact)}", capture=True, key_material=pve_key)
            manifest = json.loads(out)
            used_path = exact
        except Exception:
            pass

        # 2. Fallback: find most recent manifest in .snapshot directory
        if manifest is None:
            search_dir = (f"{mapping['nfs_mount_path']}/.snapshot/{snap_name}"
                          f"/{manifest_subdir}")
            try:
                out = ssh_run(pve_host, pve_user, pve_pass,
                              f"find {shlex.quote(search_dir)} -name manifest.json 2>/dev/null "
                              f"| sort | tail -1",
                              capture=True, key_material=pve_key)
                found = out.strip()
                if found:
                    out2 = ssh_run(pve_host, pve_user, pve_pass,
                                   f"cat {shlex.quote(found)}", capture=True, key_material=pve_key)
                    manifest = json.loads(out2)
                    used_path = found
            except Exception:
                pass

        if manifest is None:
            return {"error": "No manifest found in this snapshot"}, 404

        vms = manifest.get("vms", [])
        return {
            "snap_name": snap_name,
            "manifest_snap_name": manifest.get("snapshot_name", ""),
            "used_path": used_path,
            "vmids": [v["vmid"] for v in vms],
            "vm_names": {str(v["vmid"]): v.get("name", "") for v in vms},
            "vm_types": {str(v["vmid"]): v.get("vm_type", "qemu") for v in vms},
            "consistency": manifest.get("consistency", "–"),
            "created_at": manifest.get("created_at", ""),
        }
    except Exception as exc:
        return {"error": str(exc)}, 500


def _list_ontap_volumes():
    """Returns ONTAP volumes for an endpoint (for the mapping wizard)."""
    err = _require_admin()
    if err:
        return err
    endpoint_id = request.args.get("endpoint_id") or (request.get_json() or {}).get("endpoint_id")
    if not endpoint_id:
        return {"error": "endpoint_id required"}, 400
    db = get_db()
    try:
        endpoint = get_endpoint(db, endpoint_id)
        client = build_ontap_client(endpoint)
        volumes = client.get_volumes()
        return {"volumes": volumes}
    except Exception as exc:
        return {"error": str(exc)}, 500


# ── job status ────────────────────────────────────────────────────────────────

def _job_status():
    """Returns a single job (?job_id=...) or all jobs (no parameter)."""
    job_id = request.args.get("job_id")
    db = get_db()
    if job_id and job_id != "list":
        row = db.query_one("SELECT * FROM netapp_jobs WHERE id=?", (job_id,))
        if not row:
            return {"error": "Job not found"}, 404
        d = dict(row)
        d["log"] = json.loads(d.get("log_json") or "[]")
        return d
    # All jobs
    rows = db.query("SELECT * FROM netapp_jobs ORDER BY created_at DESC LIMIT 500")
    result = []
    for r in rows:
        d = dict(r)
        d["log"] = json.loads(d.get("log_json") or "[]")
        result.append(d)
    return result


def _delete_job():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    jid = data.get("id")
    if not jid:
        return {"error": "id required"}, 400
    db = get_db()
    row = db.query_one("SELECT status FROM netapp_jobs WHERE id=?", (jid,))
    if not row:
        return {"error": "Job not found"}, 404
    if row["status"] in ("running", "cancelling"):
        return {"error": "Cannot delete running jobs — cancel first"}, 409
    db.execute("DELETE FROM netapp_jobs WHERE id=?", (jid,))
    return {"success": True}


def _cancel_job():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    job_id = data.get("id") or request.args.get("job_id")
    if not job_id:
        return {"error": "id required"}, 400

    db = get_db()
    row = db.query_one("SELECT status FROM netapp_jobs WHERE id=?", (job_id,))
    if not row:
        return {"error": "Job not found"}, 404
    if row["status"] not in ("running", "cancelling"):
        return {"error": f"Job is not running (status: {row['status']})"}, 409

    from ..core._job_registry import request_cancel, thread_alive

    if thread_alive(job_id):
        request_cancel(job_id)
        db.execute("UPDATE netapp_jobs SET status='cancelling' WHERE id=?", (job_id,))
        return {"success": True, "message": "Cancellation requested — job will stop at next checkpoint"}
    else:
        # Thread is dead but status stuck at running (e.g. after server restart)
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        db.execute(
            "UPDATE netapp_jobs SET status='cancelled', completed_at=? WHERE id=?",
            (now, job_id),
        )
        return {"success": True, "message": "Stale job marked as cancelled"}


def _cleanup_jobs():
    err = _require_admin()
    if err:
        return err
    db = get_db()
    result = db.query_one(
        "SELECT COUNT(*) AS cnt FROM netapp_jobs WHERE status IN ('done','failed')"
    )
    count = result["cnt"] if result else 0
    db.execute("DELETE FROM netapp_jobs WHERE status IN ('done','failed')")
    return {"success": True, "deleted": count}


# ── SAN: snapmanifest LV ─────────────────────────────────────────────────────────

def _snapmanifest_init():
    """POST {mapping_id} – creates the snapinfo LV and sets snapinfo_initialized=1."""
    err = _require_admin()
    if err:
        return err

    data = request.get_json(force=True, silent=True) or {}
    mapping_id = data.get("mapping_id", "").strip()
    if not mapping_id:
        return {"success": False, "error": "mapping_id missing"}

    db = get_db()
    from ..core._helpers import get_mapping, build_pve_client, get_ssh_creds

    try:
        mapping = get_mapping(db, mapping_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    storage_protocol = mapping.get("storage_protocol", "nfs")
    if storage_protocol == "nfs":
        return {"success": False, "error": "snapmanifest is only required for SAN storages"}

    vg_name = mapping.get("lvm_vg_name", "")
    lv_name = "netapp_snapmanifest"  # always use canonical name; migrate stale DB entries on write
    if not vg_name:
        return {"success": False, "error": "lvm_vg_name not set in mapping (re-run discovery)"}

    pve_cluster_id = mapping.get("pve_cluster_id", "")
    try:
        mgr = build_pve_client(db, pve_cluster_id)
        ssh_user, ssh_pass, ssh_key = get_ssh_creds(mgr)
        ssh_host = mgr.host
    except Exception as exc:
        return {"success": False, "error": f"PVE connection failed: {exc}"}

    from ..core.san_helpers import snapmanifest_initialize
    try:
        snapmanifest_initialize(ssh_host, ssh_user, ssh_pass, ssh_key, vg_name, lv_name)
    except Exception as exc:
        return {"success": False, "error": f"snapmanifest init failed: {exc}"}

    db.execute(
        "UPDATE netapp_volume_mapping SET snapinfo_initialized=1, snapinfo_lv_name=? WHERE id=?",
        (lv_name, mapping_id),
    )
    return {"success": True, "message": f"snapmanifest LV {vg_name}/{lv_name} initialized"}


def _snapmanifest_check():
    """POST {mapping_id} — SSH-checks if snapmanifest LV exists; corrects snapinfo_initialized in DB."""
    import shlex as _shlex
    data = request.get_json(force=True, silent=True) or {}
    mapping_id = data.get("mapping_id", "").strip()
    if not mapping_id:
        return {"success": False, "error": "mapping_id required"}

    db = get_db()
    from ..core._helpers import get_mapping, build_pve_client, get_ssh_creds, ssh_run

    try:
        mapping = get_mapping(db, mapping_id)
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    vg_name = mapping.get("lvm_vg_name", "")
    lv_name = "netapp_snapmanifest"  # always canonical; DB may still have old snapinfo name
    if not vg_name:
        return {"success": False, "error": "lvm_vg_name not set"}

    pve_cluster_id = mapping.get("pve_cluster_id", "")
    try:
        mgr = build_pve_client(db, pve_cluster_id)
        ssh_user, ssh_pass, ssh_key = get_ssh_creds(mgr)
        ssh_host = mgr.host
    except Exception as exc:
        return {"success": False, "error": f"PVE connection failed: {exc}"}

    try:
        out = ssh_run(
            ssh_host, ssh_user, ssh_pass,
            f"lvs {_shlex.quote(vg_name)}/{_shlex.quote(lv_name)} 2>/dev/null"
            f" && echo EXISTS || echo MISSING",
            capture=True, key_material=ssh_key,
        )
        exists = "EXISTS" in out
    except Exception as exc:
        return {"success": False, "error": f"SSH check failed: {exc}"}

    db.execute(
        "UPDATE netapp_volume_mapping SET snapinfo_initialized=? WHERE id=?",
        (1 if exists else 0, mapping_id),
    )
    return {"success": True, "exists": exists, "lv": f"{vg_name}/{lv_name}"}


# ── Admin UI ──────────────────────────────────────────────────────────────────

def _serve_ui():
    from flask import send_file
    import os
    ui_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui.html")
    return send_file(ui_file, mimetype="text/html")


# ── Route registration ──────────────────────────────────────────────────────────

def register_routes():
    register_plugin_route(PLUGIN_ID, "endpoints", _list_endpoints)
    register_plugin_route(PLUGIN_ID, "endpoints/add", _add_endpoint)
    register_plugin_route(PLUGIN_ID, "endpoints/delete", _delete_endpoint)
    register_plugin_route(PLUGIN_ID, "endpoints/test", _test_endpoint)

    register_plugin_route(PLUGIN_ID, "pve-hosts", _list_pve_hosts)
    register_plugin_route(PLUGIN_ID, "pve-hosts/add", _add_pve_host)
    register_plugin_route(PLUGIN_ID, "pve-hosts/delete", _delete_pve_host)
    register_plugin_route(PLUGIN_ID, "pve-hosts/test", _test_pve_host)

    register_plugin_route(PLUGIN_ID, "volume-mappings", _list_mappings)
    register_plugin_route(PLUGIN_ID, "volume-mappings/delete", _delete_mapping)
    register_plugin_route(PLUGIN_ID, "discover", _run_discovery)
    register_plugin_route(PLUGIN_ID, "san/snapmanifest-init",  _snapmanifest_init)
    register_plugin_route(PLUGIN_ID, "san/snapmanifest-check", _snapmanifest_check)

    register_plugin_route(PLUGIN_ID, "snapshots", _list_snapshots)
    register_plugin_route(PLUGIN_ID, "snapshots/create", _create_snapshot)
    register_plugin_route(PLUGIN_ID, "snapshots/delete", _delete_snapshot)
    register_plugin_route(PLUGIN_ID, "snapshots/volumes", _list_ontap_volumes)
    register_plugin_route(PLUGIN_ID, "snapshots/vms-for-mapping", _vms_for_mapping)
    register_plugin_route(PLUGIN_ID, "snapshots/manifest", _snapshot_manifest)

    register_plugin_route(PLUGIN_ID, "jobs/status", _job_status)
    register_plugin_route(PLUGIN_ID, "jobs/delete", _delete_job)
    register_plugin_route(PLUGIN_ID, "jobs/cancel", _cancel_job)
    register_plugin_route(PLUGIN_ID, "jobs/cleanup", _cleanup_jobs)
    register_plugin_route(PLUGIN_ID, "ui", _serve_ui)
