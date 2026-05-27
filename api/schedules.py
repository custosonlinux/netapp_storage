"""
Schedule API for automatic snapshots

  schedules           GET   – list all schedules
  schedules/add       POST  – add schedule
  schedules/update    POST  – update schedule
  schedules/delete    POST  – delete schedule
  schedules/run-now   POST  – run schedule immediately
"""

import re
import uuid
import json
import logging
import threading
import time
from datetime import datetime, timezone

from flask import request
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

log = logging.getLogger(__name__)
from ..core._helpers import PLUGIN_ID  # noqa: F401

_scheduler_thread = None
_scheduler_stop = threading.Event()


def _require_admin():
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


# ── Cron parser (minimal implementation, no external deps) ─────────────────────

def _cron_is_due(cron_expr, last_run_at):
    """Returns True if the schedule is due now.

    Supports: @hourly, @daily, @weekly, @monthly and classic
    5-field cron (minute hour day month weekday).
    Checks only whether the current minute matches the cron expression.
    """
    now = datetime.now()

    aliases = {
        "@hourly":  "0 * * * *",
        "@daily":   "0 0 * * *",
        "@midnight":"0 0 * * *",
        "@weekly":  "0 0 * * 0",
        "@monthly": "0 0 1 * *",
    }
    expr = aliases.get(cron_expr.strip(), cron_expr.strip())

    try:
        parts = expr.split()
        if len(parts) != 5:
            return False
        m_expr, h_expr, dom_expr, mon_expr, dow_expr = parts

        def _match(val, expr):
            if expr == "*":
                return True
            for part in expr.split(","):
                if "/" in part:
                    base, step = part.split("/", 1)
                    start = 0 if base == "*" else int(base)
                    if val >= start and (val - start) % int(step) == 0:
                        return True
                elif "-" in part:
                    lo, hi = part.split("-", 1)
                    if int(lo) <= val <= int(hi):
                        return True
                else:
                    if val == int(part):
                        return True
            return False

        if not (_match(now.minute, m_expr) and _match(now.hour, h_expr) and
                _match(now.day, dom_expr) and _match(now.month, mon_expr) and
                _match(now.weekday(), dow_expr)):
            return False

        # Prevent a schedule from firing twice within the same minute
        if last_run_at:
            try:
                last = datetime.fromisoformat(last_run_at.replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - last).total_seconds() < 60:
                    return False
            except Exception:
                pass

        return True
    except Exception:
        return False


# ── VM sync helper ─────────────────────────────────────────────────────────────

def _sync_vmids_for_schedule(db, mapping_row):
    """Query PVE storage content API and return current vmid list for this datastore."""
    from ..core._helpers import build_pve_client
    storage_id = mapping_row["pve_storage_id"]
    volume_uuid = mapping_row["volume_uuid"]
    is_san = mapping_row.get("storage_protocol", "nfs") in ("iscsi", "nvme")

    host_rows = db.query(
        "SELECT DISTINCT pve_cluster_id FROM netapp_volume_mapping WHERE volume_uuid=?",
        (volume_uuid,),
    )
    host_ids = [r["pve_cluster_id"] for r in host_rows]
    if mapping_row["pve_cluster_id"] not in host_ids:
        host_ids.insert(0, mapping_row["pve_cluster_id"])

    storage_vmids = set()
    for hid in host_ids:
        try:
            pve = build_pve_client(db, hid)
            for node_name in list(pve.get_node_status().keys()):
                rc = pve._api_get(
                    f"{pve._base}/nodes/{node_name}/storage/{storage_id}/content"
                )
                if rc.ok:
                    for item in rc.json().get("data", []):
                        vmid = item.get("vmid")
                        if vmid:
                            storage_vmids.add(int(vmid))
                    if not is_san:
                        break  # NFS is cluster-shared — one node is enough
        except Exception as exc:
            log.warning(f"[netapp_storage] sync_vmids {storage_id} host {hid}: {exc}")
    return sorted(storage_vmids)


# ── Schedule execution ──────────────────────────────────────────────────────────

def _execute_schedule(schedule):
    """Executes a scheduled snapshot (runs in its own thread)."""
    from ..core.snapshot_engine import start_snapshot_job

    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    job_id = str(uuid.uuid4())

    db.execute(
        "INSERT INTO netapp_jobs (id, job_type, vmid, node, status, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, "snapshot", None, "", "running", f"schedule:{schedule['name']}", now),
    )

    vmids = json.loads(schedule.get("vmids_json") or "[]")

    # Auto-sync: replace vmids with current datastore content before running
    mapping_row_early = db.query_one(
        "SELECT * FROM netapp_volume_mapping WHERE id=?", (schedule["mapping_id"],)
    )
    if schedule.get("sync_vmids") and mapping_row_early:
        try:
            synced = _sync_vmids_for_schedule(db, dict(mapping_row_early))
            if synced is not None:
                vmids = synced
                db.execute(
                    "UPDATE netapp_snapshot_schedules SET vmids_json=? WHERE id=?",
                    (json.dumps(vmids), schedule["id"]),
                )
                log.info(f"[netapp_storage] Schedule '{schedule['name']}' synced vmids: {vmids}")
        except Exception as exc:
            log.warning(f"[netapp_storage] Schedule '{schedule['name']}' vmid sync failed: {exc}")

    # Derive node from mapping (via plugin-managed PVE client)
    mapping_row = db.query_one(
        "SELECT * FROM netapp_volume_mapping WHERE id=?", (schedule["mapping_id"],)
    )
    node = ""
    cluster_id = ""
    if mapping_row:
        cluster_id = mapping_row["pve_cluster_id"]
        try:
            from ..core._helpers import build_pve_client
            pve = build_pve_client(db, cluster_id)
            vmids_for_node = json.loads(schedule.get("vmids_json") or "[]")
            if vmids_for_node:
                found = pve.find_vm_node(vmids_for_node[0])
                if found:
                    node = found
            if not node:
                nodes = list(pve.get_node_status().keys())
                if nodes:
                    node = nodes[0]
        except Exception as exc:
            log.warning(f"[netapp_storage] Schedule node lookup failed: {exc}")

    sched_name_safe = re.sub(r'[^a-zA-Z0-9_-]', '-', schedule.get("name", ""))[:30].strip('-')
    data = {
        "cluster_id": cluster_id,
        "node": node,
        "vmids": vmids,
        "mapping_id": schedule["mapping_id"],
        "pve_storage_id":    mapping_row["pve_storage_id"] if mapping_row else "",
        "consistency":       schedule.get("consistency", "crash"),
        "label":             schedule.get("label", ""),
        "pre_script":        schedule.get("pre_script",  "") or "",
        "post_script":       schedule.get("post_script", "") or "",
        "schedule_id":       schedule["id"],
        "schedule_name":     schedule.get("name", ""),
        "snap_name_suffix":  sched_name_safe,
        "retention_count":   int(schedule.get("retention_count") or 7),
        "snapmirror_update": bool(schedule.get("snapmirror_update", 0)),
        "notify_enabled":    bool(schedule.get("notify_enabled", 0)),
        "notify_on":         schedule.get("notify_on", "all") or "all",
        "notify_recipients": schedule.get("notify_recipients", "") or "",
    }
    status = "done"
    try:
        start_snapshot_job(job_id, data, f"schedule:{schedule['name']}")
    except Exception as exc:
        log.error(f"[netapp_storage] Schedule '{schedule['name']}' failed: {exc}")
        status = "failed"

    db.execute(
        "UPDATE netapp_snapshot_schedules SET last_run_at=?, last_run_status=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), status, schedule["id"]),
    )
    # Retention is now handled inside snapshot_engine._run_snapshot, directly after
    # the snapshot status is set to 'done'.  This avoids the race condition where the
    # retention count ran while the new snapshot was still status='running' and therefore
    # not included in the count, causing a permanent off-by-one (retention+1 snapshots).


def _scheduler_loop():
    """Runs as daemon thread; checks for due schedules every minute."""
    log.info("[netapp_storage] Schedule thread started")
    while not _scheduler_stop.wait(60):
        try:
            db = get_db()
            schedules = db.query(
                "SELECT * FROM netapp_snapshot_schedules WHERE enabled=1"
            )
            for sched in (schedules or []):
                s = dict(sched)
                if _cron_is_due(s.get("cron_expr", ""), s.get("last_run_at", "")):
                    threading.Thread(
                        target=_execute_schedule, args=(s,), daemon=True
                    ).start()
        except Exception as exc:
            log.error(f"[netapp_storage] Schedule loop error: {exc}")
    log.info("[netapp_storage] Schedule thread stopped")


def start_scheduler():
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()


def stop_scheduler():
    _scheduler_stop.set()


# ── API handlers ───────────────────────────────────────────────────────────────

def _list_schedules():
    db = get_db()
    rows = db.query(
        "SELECT s.*, vm.pve_storage_id, vm.volume_name, vm.volume_uuid, ep.name AS endpoint_name "
        "FROM netapp_snapshot_schedules s "
        "JOIN netapp_volume_mapping vm ON vm.id = s.mapping_id "
        "JOIN netapp_endpoints ep ON ep.id = vm.endpoint_id "
        "ORDER BY s.name"
    )
    result = []
    for r in rows:
        d = dict(r)
        d["vmids"] = json.loads(d.get("vmids_json") or "[]")

        # Attach SnapMirror relationship for this volume (prefer healthy/most-recent)
        sm_rows = db.query(
            "SELECT dest_cluster_name, dest_svm, dest_volume, state, healthy, "
            "lag_time, last_transfer_time "
            "FROM netapp_snapmirror_relationships "
            "WHERE source_volume_uuid=? "
            "ORDER BY healthy DESC, last_transfer_time DESC LIMIT 1",
            (d.get("volume_uuid", ""),),
        )
        if sm_rows:
            rel = dict(sm_rows[0])
            d["snapmirror"] = {
                "exists":             True,
                "dest_cluster":       rel.get("dest_cluster_name", ""),
                "dest_svm":           rel.get("dest_svm", ""),
                "dest_volume":        rel.get("dest_volume", ""),
                "state":              rel.get("state", ""),
                "healthy":            bool(rel.get("healthy", 0)),
                "lag_time":           rel.get("lag_time", ""),
                "last_transfer_time": rel.get("last_transfer_time", ""),
            }
        else:
            d["snapmirror"] = {"exists": False}

        result.append(d)
    return result


def _add_schedule():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    for field in ("name", "mapping_id", "cron_expr"):
        if not data.get(field):
            return {"error": f"Required field missing: {field}"}, 400

    vmids = data.get("vmids", [])
    if not isinstance(vmids, list):
        vmids = []

    db = get_db()
    sid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    username = request.session.get("user", "system")

    db.execute(
        "INSERT INTO netapp_snapshot_schedules "
        "(id, name, mapping_id, vmids_json, cron_expr, retention_count, "
        "consistency, label, pre_script, post_script, snapmirror_update, "
        "notify_enabled, notify_on, notify_recipients, sync_vmids, enabled, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, data["name"], data["mapping_id"], json.dumps(vmids),
         data["cron_expr"], int(data.get("retention_count", 7)),
         data.get("consistency", "crash"), data.get("label", ""),
         data.get("pre_script", ""), data.get("post_script", ""),
         1 if data.get("snapmirror_update") else 0,
         1 if data.get("notify_enabled") else 0,
         data.get("notify_on", "all"),
         data.get("notify_recipients", ""),
         1 if data.get("sync_vmids") else 0,
         1, username, now),
    )
    return {"success": True, "id": sid}


def _update_schedule():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    sid = data.get("id")
    if not sid:
        return {"error": "id required"}, 400

    db = get_db()
    fields = []
    values = []
    for col, val in [
        ("name", data.get("name")),
        ("cron_expr", data.get("cron_expr")),
        ("retention_count", data.get("retention_count")),
        ("consistency", data.get("consistency")),
        ("label", data.get("label")),
        ("pre_script",  data.get("pre_script")),
        ("post_script", data.get("post_script")),
        ("snapmirror_update", 1 if data.get("snapmirror_update") else (0 if "snapmirror_update" in data else None)),
        ("notify_enabled",    1 if data.get("notify_enabled") else (0 if "notify_enabled" in data else None)),
        ("notify_on",         data.get("notify_on")),
        ("notify_recipients", data.get("notify_recipients")),
        ("sync_vmids",        1 if data.get("sync_vmids") else (0 if "sync_vmids" in data else None)),
        ("enabled", data.get("enabled")),
        ("vmids_json", json.dumps(data["vmids"]) if "vmids" in data else None),
        ("mapping_id", data.get("mapping_id")),
    ]:
        if val is not None:
            fields.append(f"{col}=?")
            values.append(int(val) if col in ("retention_count", "enabled") else val)

    if not fields:
        return {"error": "No changes"}, 400

    values.append(sid)
    db.execute(f"UPDATE netapp_snapshot_schedules SET {','.join(fields)} WHERE id=?", values)
    return {"success": True}


def _delete_schedule():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    sid = data.get("id")
    if not sid:
        return {"error": "id required"}, 400
    db = get_db()
    db.execute("DELETE FROM netapp_snapshot_schedules WHERE id=?", (sid,))
    return {"success": True}


def _run_schedule_now():
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    sid = data.get("id")
    if not sid:
        return {"error": "id required"}, 400

    db = get_db()
    row = db.query_one("SELECT * FROM netapp_snapshot_schedules WHERE id=?", (sid,))
    if not row:
        return {"error": "Schedule not found"}, 404

    threading.Thread(target=_execute_schedule, args=(dict(row),), daemon=True).start()
    return {"success": True, "message": "Schedule is being executed"}


# ── Route registration ──────────────────────────────────────────────────────────

def register_routes():
    register_plugin_route(PLUGIN_ID, "schedules", _list_schedules)
    register_plugin_route(PLUGIN_ID, "schedules/add", _add_schedule)
    register_plugin_route(PLUGIN_ID, "schedules/update", _update_schedule)
    register_plugin_route(PLUGIN_ID, "schedules/delete", _delete_schedule)
    register_plugin_route(PLUGIN_ID, "schedules/run-now", _run_schedule_now)
