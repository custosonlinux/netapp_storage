"""
Disaster Recovery API  (v3.0 — direct peer-to-peer sync)

Architecture:
  PRIMARY    — manages DR plans, pushes config sync to SECONDARY every 60 s
  SECONDARY  — receives config from PRIMARY, executes failover on demand
  STANDALONE — no peer configured

Communication:
  Both sides talk directly via HTTPS REST calls.
  Auth: shared sync token (X-DR-Sync-Token header), generated on peer setup.
  Background heartbeat every 30 s → peer status in DB.
  Background sync every 60 s (PRIMARY only) → plan config pushed to SECONDARY.

Routes:
  dr/role                         GET  — current role + peer status summary
  dr/role/set                     POST {role} — set role, notify peer

  dr/peer/status                  GET  — peer config + live connectivity
  dr/peer/configure               POST — store peer URL / credentials / token
  dr/peer/remove                  POST — remove peer
  dr/peer/sync/push               POST — manual immediate sync to peer

  dr/peer/heartbeat               POST — RECEIVE heartbeat from peer (token auth)
  dr/peer/sync/receive            POST — RECEIVE sync payload from peer (token auth)
  dr/peer/role-notify             POST — RECEIVE role-change notice from peer (token auth)

  dr/plans                        GET
  dr/plans/create                 POST
  dr/plans/detail                 GET  ?plan_id=
  dr/plans/update                 POST
  dr/plans/delete                 POST

  dr/plans/entries/add            POST
  dr/plans/entries/update         POST
  dr/plans/entries/delete         POST
  dr/plans/auto-detect            POST {plan_id}

  dr/plans/groups/create          POST
  dr/plans/groups/update          POST
  dr/plans/groups/delete          POST
  dr/plans/groups/reorder         POST

  dr/plans/groups/vms/add         POST
  dr/plans/groups/vms/delete      POST
  dr/plans/groups/vms/update      POST

  dr/plans/status                 GET  ?plan_id=
  dr/plans/precheck               GET  ?plan_id=
  dr/plans/failover               POST
  dr/plans/failover-jobs          GET  ?plan_id=
  dr/plans/snapshots              GET  ?plan_id=&entry_id=
"""

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import request, jsonify
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

from ..core._helpers import PLUGIN_ID

log = logging.getLogger(__name__)

_SYNC_TOKEN_HEADER = "X-DR-Sync-Token"
_BG_STARTED = False
_BG_LOCK = threading.Lock()


# ── Basic helpers ─────────────────────────────────────────────────────────────

def _spawn(fn, *args, **kwargs):
    """Spawn fn in background, gevent-aware (avoids BlockingSwitchOutError)."""
    try:
        import gevent
        gevent.spawn(fn, *args, **kwargs)
    except ImportError:
        threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True).start()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _require_admin():
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


def _json_field(val):
    try:
        return json.loads(val or "[]")
    except Exception:
        return []


def _body():
    return request.get_json(silent=True) or {}


def _verify_sync_token():
    """Verify X-DR-Sync-Token header for peer-receive endpoints."""
    token = request.headers.get(_SYNC_TOKEN_HEADER, "").strip()
    if not token:
        return {"error": "Missing sync token"}, 401
    db = get_db()
    peer = db.query_one("SELECT sync_token FROM netapp_dr_peer WHERE id='default'")
    if not peer or not peer["sync_token"] or peer["sync_token"] != token:
        return {"error": "Invalid sync token"}, 403
    return None


# ── Plugin config (role) ──────────────────────────────────────────────────────

def _get_plugin_config():
    """Return plugin_config row, creating default if missing. Role: PRIMARY | SECONDARY | STANDALONE."""
    db = get_db()
    cfg = db.query_one("SELECT * FROM netapp_plugin_config WHERE id='default'")
    if not cfg:
        db.execute(
            "INSERT INTO netapp_plugin_config "
            "(id, role, role_forced, config_volume_id, config_storage_id, config_pve_host_ids, last_role_check, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("default", "PRIMARY", 0, "", "", "[]", "", _now())
        )
        cfg = db.query_one("SELECT * FROM netapp_plugin_config WHERE id='default'")
    # Migrate legacy role names on first read
    cfg = dict(cfg)
    legacy = {"MASTER": "PRIMARY", "DR_SLAVE": "SECONDARY", "DR_TEST": "SECONDARY"}
    if cfg.get("role") in legacy:
        new_role = legacy[cfg["role"]]
        get_db().execute("UPDATE netapp_plugin_config SET role=? WHERE id='default'", (new_role,))
        cfg["role"] = new_role
    return cfg


def _get_role():
    """GET dr/role"""
    cfg = _get_plugin_config()
    peer = _get_peer()
    peer_summary = None
    if peer:
        peer_summary = {
            "name":        peer.get("name", ""),
            "url":         peer.get("url", ""),
            "peer_role":   peer.get("peer_role", ""),
            "sync_status": peer.get("sync_status", "unconfigured"),
            "last_seen":   peer.get("last_seen", ""),
            "last_sync_sent": peer.get("last_sync_sent", ""),
        }
    return jsonify({
        "role":        cfg.get("role", "PRIMARY"),
        "role_forced": bool(cfg.get("role_forced", 0)),
        "peer":        peer_summary,
    })


def _set_role():
    """POST dr/role/set — set this instance's role and notify peer."""
    err = _require_admin()
    if err: return err
    data = _body()
    role = (data.get("role") or "").upper()
    if role not in ("PRIMARY", "SECONDARY", "STANDALONE"):
        return {"error": "role must be PRIMARY, SECONDARY, or STANDALONE"}, 400
    _get_plugin_config()
    db = get_db()
    forced = 1 if data.get("forced", True) else 0
    db.execute(
        "UPDATE netapp_plugin_config SET role=?, role_forced=?, updated_at=? WHERE id='default'",
        (role, forced, _now())
    )
    # Notify peer — fire-and-forget in background
    threading.Thread(
        target=_peer_push_role_notify,
        args=(role,),
        daemon=True
    ).start()
    return jsonify({"role": role, "role_forced": bool(forced), "message": f"Role set to {role}"})


# ── Peer configuration ────────────────────────────────────────────────────────

def _get_peer():
    """Return peer row as dict, or None if not configured."""
    db = get_db()
    # Ensure table exists (first boot before schema migration runs)
    try:
        row = db.query_one("SELECT * FROM netapp_dr_peer WHERE id='default'")
    except Exception:
        return None
    return dict(row) if row else None


def _peer_status():
    """GET dr/peer/status — peer config + live ping."""
    peer = _get_peer()
    if not peer or not peer.get("url"):
        return jsonify({"configured": False})

    result = {
        "configured":       True,
        "name":             peer.get("name", ""),
        "url":              peer.get("url", ""),
        "ssl_verify":       bool(peer.get("ssl_verify", 0)),
        "peer_role":        peer.get("peer_role", ""),
        "sync_status":      peer.get("sync_status", "unknown"),
        "sync_error":       peer.get("sync_error", ""),
        "last_seen":        peer.get("last_seen", ""),
        "last_sync_sent":   peer.get("last_sync_sent", ""),
        "last_sync_received": peer.get("last_sync_received", ""),
        "paired_at":        peer.get("paired_at", ""),
        "has_token":        bool(peer.get("sync_token", "")),
    }
    # Live ping
    resp, err = _peer_call("POST", "dr/peer/heartbeat", {}, peer=peer, timeout=5)
    result["online"] = err is None
    if err:
        result["ping_error"] = err
    return jsonify(result)


def _configure_peer():
    """POST dr/peer/configure — store or update peer config."""
    err = _require_admin()
    if err: return err
    data = _body()
    url  = (data.get("url") or "").strip().rstrip("/")
    if not url:
        return {"error": "url is required"}, 400
    name        = (data.get("name") or "DR Site").strip()
    ssl_verify  = int(bool(data.get("ssl_verify", False)))
    sync_token  = (data.get("sync_token") or "").strip()
    if not sync_token:
        sync_token = str(uuid.uuid4())

    db = get_db()
    existing = db.query_one("SELECT id FROM netapp_dr_peer WHERE id='default'")
    now = _now()

    if existing:
        db.execute(
            "UPDATE netapp_dr_peer SET name=?, url=?, ssl_verify=?, sync_token=?, updated_at=? WHERE id='default'",
            (name, url, ssl_verify, sync_token, now)
        )
    else:
        db.execute(
            "INSERT INTO netapp_dr_peer "
            "(id, name, url, ssl_verify, sync_token, "
            "peer_role, last_seen, last_sync_sent, last_sync_received, sync_status, sync_error, paired_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("default", name, url, ssl_verify, sync_token,
             "", "", "", "", "unconfigured", "", now, now)
        )

    return jsonify({
        "message": "Peer configured",
        "sync_token": sync_token,
        "note": "Copy this sync_token to the other side's peer configuration."
    })


def _remove_peer():
    """POST dr/peer/remove — delete peer config."""
    err = _require_admin()
    if err: return err
    db = get_db()
    db.execute("DELETE FROM netapp_dr_peer WHERE id='default'")
    return jsonify({"message": "Peer removed"})


# ── Outbound peer calls ───────────────────────────────────────────────────────

def _peer_call(method, path, payload=None, peer=None, timeout=15):
    """
    Call peer's plugin API. Returns (response_dict, error_string).
    Uses sync token for authentication — no session needed.
    """
    try:
        import requests as _req
    except ImportError:
        return None, "requests library not available"

    if peer is None:
        peer = _get_peer()
    if not peer or not peer.get("url"):
        return None, "Peer not configured"
    token = peer.get("sync_token", "")
    if not token:
        return None, "Peer sync token not set"

    _PEER_RECV_PATHS = {"dr/peer/heartbeat", "dr/peer/sync/receive", "dr/peer/role-notify"}
    base = peer["url"].rstrip("/")
    ns = "peer" if path in _PEER_RECV_PATHS else "api"
    url  = f"{base}/api/plugins/netapp_storage/{ns}/{path}"
    ssl  = bool(peer.get("ssl_verify", 0))
    headers = {_SYNC_TOKEN_HEADER: token, "Content-Type": "application/json"}
    try:
        if method == "GET":
            r = _req.get(url, headers=headers, verify=ssl, timeout=timeout)
        else:
            r = _req.post(url, json=payload or {}, headers=headers, verify=ssl, timeout=timeout)
        r.raise_for_status()
        return r.json(), None
    except Exception as exc:
        return None, str(exc)


def _peer_push_heartbeat():
    """Send heartbeat to peer, update peer row with result."""
    peer = _get_peer()
    if not peer or not peer.get("url"):
        return
    cfg = _get_plugin_config()
    resp, err = _peer_call("POST", "dr/peer/heartbeat",
                            {"role": cfg.get("role", "PRIMARY"), "timestamp": _now()},
                            peer=peer, timeout=10)
    try:
        db = get_db()
        if err:
            db.execute(
                "UPDATE netapp_dr_peer SET sync_status='offline', sync_error=? WHERE id='default'",
                (err[:500],)
            )
        else:
            db.execute(
                "UPDATE netapp_dr_peer SET sync_status='online', sync_error='', "
                "peer_role=?, last_seen=? WHERE id='default'",
                (resp.get("role", "") if resp else "", _now())
            )
    except Exception as exc:
        log.warning(f"[netapp_dr] heartbeat DB update failed: {exc}")


def _peer_push_sync(peer=None):
    """Push full plan sync payload to peer. Returns (ok, error)."""
    if peer is None:
        peer = _get_peer()
    if not peer or not peer.get("url"):
        return False, "Peer not configured"
    payload = _build_sync_payload()
    resp, err = _peer_call("POST", "dr/peer/sync/receive", payload, peer=peer, timeout=60)
    try:
        db = get_db()
        if err:
            db.execute(
                "UPDATE netapp_dr_peer SET sync_status='error', sync_error=? WHERE id='default'",
                (err[:500],)
            )
            return False, err
        else:
            db.execute(
                "UPDATE netapp_dr_peer SET last_sync_sent=?, sync_status='online', sync_error='' WHERE id='default'",
                (_now(),)
            )
            return True, None
    except Exception as exc:
        log.warning(f"[netapp_dr] sync push DB update failed: {exc}")
        return False, str(exc)


def _peer_push_role_notify(new_role):
    """Notify peer that our role changed — they should switch to the complementary role."""
    peer = _get_peer()
    if not peer or not peer.get("url"):
        return
    peer_new_role = "SECONDARY" if new_role == "PRIMARY" else "PRIMARY"
    _peer_call("POST", "dr/peer/role-notify",
               {"sender_role": new_role, "suggested_peer_role": peer_new_role},
               peer=peer, timeout=10)


def _sync_push_manual():
    """POST dr/peer/sync/push — manually trigger sync to peer."""
    err = _require_admin()
    if err: return err
    ok, error = _peer_push_sync()
    if not ok:
        return jsonify({"ok": False, "error": error}), 502
    return jsonify({"ok": True, "message": "Sync pushed to peer"})


# ── Peer receive endpoints ────────────────────────────────────────────────────

def _peer_heartbeat_recv():
    """POST dr/peer/heartbeat — receive heartbeat from remote peer."""
    err = _verify_sync_token()
    if err: return err
    data = _body()
    peer_role = data.get("role", "")
    try:
        db = get_db()
        db.execute(
            "UPDATE netapp_dr_peer SET peer_role=?, last_seen=?, sync_status='online', sync_error='' WHERE id='default'",
            (peer_role, _now())
        )
    except Exception:
        pass
    cfg = _get_plugin_config()
    return jsonify({"role": cfg.get("role", "PRIMARY"), "timestamp": _now()})


def _peer_sync_recv():
    """POST dr/peer/sync/receive — receive full plan sync from PRIMARY."""
    err = _verify_sync_token()
    if err: return err
    data = _body()
    try:
        db = get_db()
        _apply_sync_payload(data, db)
        db.execute(
            "UPDATE netapp_dr_peer SET last_sync_received=?, sync_status='online', sync_error='' WHERE id='default'",
            (_now(),)
        )
        return jsonify({"ok": True, "message": "Sync applied"})
    except Exception as exc:
        log.error(f"[netapp_dr] sync receive failed: {exc}")
        return {"error": str(exc)}, 500


def _peer_role_notify_recv():
    """POST dr/peer/role-notify — receive role-change notification from peer."""
    err = _verify_sync_token()
    if err: return err
    data = _body()
    suggested = (data.get("suggested_peer_role") or "").upper()
    sender_role = (data.get("sender_role") or "").upper()
    try:
        db = get_db()
        # Update what we know about the peer
        if sender_role:
            db.execute("UPDATE netapp_dr_peer SET peer_role=?, last_seen=? WHERE id='default'",
                       (sender_role, _now()))
        # Only auto-apply role change if this instance is not in an active failover
        cfg = _get_plugin_config()
        current_role = cfg.get("role", "PRIMARY")
        active_states = ("failover_running", "failback_running")
        has_active = db.query_one(
            "SELECT id FROM netapp_dr_plans WHERE state IN (?,?) LIMIT 1", active_states
        )
        if not has_active and suggested in ("PRIMARY", "SECONDARY", "STANDALONE"):
            if not cfg.get("role_forced"):
                db.execute(
                    "UPDATE netapp_plugin_config SET role=?, updated_at=? WHERE id='default'",
                    (suggested, _now())
                )
                log.info(f"[netapp_dr] Role auto-changed to {suggested} (peer sent role-notify, was {current_role})")
    except Exception as exc:
        log.warning(f"[netapp_dr] role-notify handling failed: {exc}")
    return jsonify({"ok": True})


# ── Sync payload builder / applier ────────────────────────────────────────────

def _build_sync_payload():
    """Collect all DR plan data + SM relationships for sync to peer."""
    db = get_db()
    plans   = [dict(r) for r in (db.query("SELECT * FROM netapp_dr_plans") or [])]
    entries = []
    for e in (db.query("SELECT * FROM netapp_dr_plan_entries") or []):
        entry = dict(e)
        # Enrich with endpoint host so receiving side can do local resolution
        ep = db.query_one("SELECT host FROM netapp_endpoints WHERE id=?",
                          (entry.get("source_endpoint_id", ""),))
        entry["source_endpoint_host"] = ep["host"] if ep else ""
        ep2 = db.query_one("SELECT host FROM netapp_endpoints WHERE id=?",
                           (entry.get("dr_endpoint_id", ""),))
        entry["dr_endpoint_host"] = ep2["host"] if ep2 else ""
        entries.append(entry)
    groups  = [dict(r) for r in (db.query("SELECT * FROM netapp_dr_vm_groups") or [])]
    vms     = [dict(r) for r in (db.query("SELECT * FROM netapp_dr_vm_assignments") or [])]
    sm_rels = [dict(r) for r in (db.query("SELECT * FROM netapp_snapmirror_relationships") or [])]

    cfg = _get_plugin_config()
    return {
        "schema_version": 1,
        "source_role":    cfg.get("role", "PRIMARY"),
        "timestamp":      _now(),
        "plans":          plans,
        "entries":        entries,
        "vm_groups":      groups,
        "vm_assignments": vms,
        "snapmirror_rels": sm_rels,
    }


def _apply_sync_payload(data, db):
    """Apply received sync payload — upsert all DR tables."""
    now = _now()

    # Plans
    for p in (data.get("plans") or []):
        existing = db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (p["id"],))
        if existing:
            db.execute(
                "UPDATE netapp_dr_plans SET name=?, notes=?, updated_at=? WHERE id=?",
                (p.get("name",""), p.get("notes",""), now, p["id"])
            )
        else:
            db.execute(
                "INSERT INTO netapp_dr_plans "
                "(id, name, dr_site_id, state, notes, last_failover_at, last_test_at, created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (p["id"], p.get("name",""), p.get("dr_site_id",""),
                 "standby", p.get("notes",""),
                 p.get("last_failover_at",""), p.get("last_test_at",""),
                 p.get("created_by","sync"), p.get("created_at", now), now)
            )

    # Plan entries
    existing_entry_ids = set(
        r["id"] for r in (db.query("SELECT id FROM netapp_dr_plan_entries") or [])
    )
    received_entry_ids = set()
    for e in (data.get("entries") or []):
        received_entry_ids.add(e["id"])
        # Resolve local endpoint IDs by host if originals not found locally
        src_ep_id = _resolve_endpoint_id(db, e.get("source_endpoint_id",""), e.get("source_endpoint_host",""))
        dr_ep_id  = _resolve_endpoint_id(db, e.get("dr_endpoint_id",""),     e.get("dr_endpoint_host",""))
        if e["id"] in existing_entry_ids:
            db.execute(
                "UPDATE netapp_dr_plan_entries SET "
                "source_endpoint_id=?, source_svm=?, source_volume=?, "
                "snapmirror_rel_uuid=?, dr_endpoint_id=?, dr_svm=?, dr_volume=?, "
                "dr_pve_storage_id=?, dr_pve_host_ids=?, sort_order=? WHERE id=?",
                (src_ep_id, e.get("source_svm",""), e.get("source_volume",""),
                 e.get("snapmirror_rel_uuid",""), dr_ep_id, e.get("dr_svm",""), e.get("dr_volume",""),
                 e.get("dr_pve_storage_id",""), e.get("dr_pve_host_ids","[]"),
                 e.get("sort_order", 0), e["id"])
            )
        else:
            db.execute(
                "INSERT INTO netapp_dr_plan_entries "
                "(id, plan_id, source_endpoint_id, source_svm, source_volume, "
                "snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume, "
                "dr_pve_storage_id, dr_pve_host_ids, sort_order, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e["id"], e.get("plan_id",""), src_ep_id, e.get("source_svm",""), e.get("source_volume",""),
                 e.get("snapmirror_rel_uuid",""), dr_ep_id, e.get("dr_svm",""), e.get("dr_volume",""),
                 e.get("dr_pve_storage_id",""), e.get("dr_pve_host_ids","[]"),
                 e.get("sort_order",0), e.get("created_at", now))
            )
    # Remove entries deleted on primary
    for stale_id in (existing_entry_ids - received_entry_ids):
        db.execute("DELETE FROM netapp_dr_plan_entries WHERE id=?", (stale_id,))

    # VM groups
    existing_group_ids = set(r["id"] for r in (db.query("SELECT id FROM netapp_dr_vm_groups") or []))
    received_group_ids = set()
    for g in (data.get("vm_groups") or []):
        received_group_ids.add(g["id"])
        if g["id"] in existing_group_ids:
            db.execute(
                "UPDATE netapp_dr_vm_groups SET name=?, group_type=?, sort_order=?, "
                "start_mode=?, startup_delay_sec=?, max_parallel=? WHERE id=?",
                (g.get("name",""), g.get("group_type","standard"), g.get("sort_order",0),
                 g.get("start_mode","auto"), g.get("startup_delay_sec",30),
                 g.get("max_parallel",1), g["id"])
            )
        else:
            db.execute(
                "INSERT INTO netapp_dr_vm_groups "
                "(id, plan_id, name, group_type, sort_order, start_mode, startup_delay_sec, max_parallel, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (g["id"], g.get("plan_id",""), g.get("name",""), g.get("group_type","standard"),
                 g.get("sort_order",0), g.get("start_mode","auto"),
                 g.get("startup_delay_sec",30), g.get("max_parallel",1), g.get("created_at",now))
            )
    for stale_id in (existing_group_ids - received_group_ids):
        db.execute("DELETE FROM netapp_dr_vm_groups WHERE id=?", (stale_id,))

    # VM assignments
    existing_vm_ids = set(r["id"] for r in (db.query("SELECT id FROM netapp_dr_vm_assignments") or []))
    received_vm_ids = set()
    for v in (data.get("vm_assignments") or []):
        received_vm_ids.add(v["id"])
        if v["id"] in existing_vm_ids:
            db.execute(
                "UPDATE netapp_dr_vm_assignments SET vmid=?, vm_name=?, target_node=?, start_order=? WHERE id=?",
                (v.get("vmid",0), v.get("vm_name",""), v.get("target_node",""), v.get("start_order",0), v["id"])
            )
        else:
            db.execute(
                "INSERT INTO netapp_dr_vm_assignments (id, group_id, vmid, vm_name, target_node, start_order, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (v["id"], v.get("group_id",""), v.get("vmid",0), v.get("vm_name",""),
                 v.get("target_node",""), v.get("start_order",0), v.get("created_at",now))
            )
    for stale_id in (existing_vm_ids - received_vm_ids):
        db.execute("DELETE FROM netapp_dr_vm_assignments WHERE id=?", (stale_id,))

    # SnapMirror relationships (best-effort)
    for r in (data.get("snapmirror_rels") or []):
        try:
            rel_uuid = r.get("relationship_uuid","")
            if not rel_uuid:
                continue
            existing_rel = db.query_one(
                "SELECT id FROM netapp_snapmirror_relationships WHERE relationship_uuid=?", (rel_uuid,)
            )
            if existing_rel:
                db.execute(
                    "UPDATE netapp_snapmirror_relationships SET state=?, healthy=?, lag_time=?, "
                    "last_transfer_time=?, last_scanned_at=? WHERE relationship_uuid=?",
                    (r.get("state",""), r.get("healthy",1), r.get("lag_time",""),
                     r.get("last_transfer_time",""), r.get("last_scanned_at",now), rel_uuid)
                )
            else:
                rid = str(uuid.uuid4())[:8]
                db.execute(
                    "INSERT INTO netapp_snapmirror_relationships "
                    "(id, source_endpoint_id, source_volume_uuid, source_svm, source_volume, "
                    "dest_endpoint_id, dest_cluster_name, dest_svm, dest_volume, dest_volume_uuid, "
                    "dest_nfs_ip, dest_junction_path, relationship_uuid, policy_type, state, healthy, "
                    "lag_time, last_transfer_time, last_scanned_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, r.get("source_endpoint_id",""), r.get("source_volume_uuid",""),
                     r.get("source_svm",""), r.get("source_volume",""),
                     r.get("dest_endpoint_id",""), r.get("dest_cluster_name",""),
                     r.get("dest_svm",""), r.get("dest_volume",""), r.get("dest_volume_uuid",""),
                     r.get("dest_nfs_ip",""), r.get("dest_junction_path",""), rel_uuid,
                     r.get("policy_type",""), r.get("state",""), r.get("healthy",1),
                     r.get("lag_time",""), r.get("last_transfer_time",""), now)
                )
        except Exception as exc:
            log.debug(f"[netapp_dr] SM rel upsert skipped ({rel_uuid}): {exc}")


def _resolve_endpoint_id(db, ep_id, ep_host):
    """Return ep_id if it exists locally, else find matching endpoint by host."""
    if ep_id:
        row = db.query_one("SELECT id FROM netapp_endpoints WHERE id=?", (ep_id,))
        if row:
            return ep_id
    if ep_host:
        row = db.query_one("SELECT id FROM netapp_endpoints WHERE host=?", (ep_host,))
        if row:
            return row["id"]
    return ep_id  # keep original even if not locally found


# ── Background threads ────────────────────────────────────────────────────────

def _heartbeat_loop():
    """Background: ping peer every 30 s."""
    while True:
        try:
            _peer_push_heartbeat()
        except Exception as exc:
            log.debug(f"[netapp_dr] heartbeat loop error: {exc}")
        time.sleep(30)


def _sync_loop():
    """Background: push plan sync to peer every 60 s (PRIMARY only)."""
    time.sleep(15)  # stagger start relative to heartbeat
    while True:
        try:
            cfg = _get_plugin_config()
            peer = _get_peer()
            if cfg.get("role") == "PRIMARY" and peer and peer.get("url"):
                _peer_push_sync(peer=peer)
        except Exception as exc:
            log.debug(f"[netapp_dr] sync loop error: {exc}")
        time.sleep(60)


def _start_background_threads():
    global _BG_STARTED
    with _BG_LOCK:
        if _BG_STARTED:
            return
        _BG_STARTED = True
    _spawn(_heartbeat_loop)
    _spawn(_sync_loop)
    log.info("[netapp_dr] Background threads started (heartbeat + sync)")


# ── Job helpers ────────────────────────────────────────────────────────────────

def _dr_start_job(job_type, username, plan_id=""):
    db = get_db()
    job_id = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_jobs (id, job_type, snapshot_id, status, log_json, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, job_type, plan_id, "running", "[]", username, _now())
    )
    return job_id


def _dr_job_log(job_id, lines):
    db = get_db()
    db.execute("UPDATE netapp_jobs SET log_json=? WHERE id=?", (json.dumps(lines), job_id))


def _dr_job_finish(job_id, status, lines):
    db = get_db()
    db.execute(
        "UPDATE netapp_jobs SET status=?, log_json=?, completed_at=? WHERE id=?",
        (status, json.dumps(lines), _now(), job_id)
    )


# ── DR Plans ──────────────────────────────────────────────────────────────────

def _plan_summary(row, db):
    p = dict(row)
    entry_cnt = db.query_one("SELECT COUNT(*) as c FROM netapp_dr_plan_entries WHERE plan_id=?", (p["id"],))
    group_cnt = db.query_one("SELECT COUNT(*) as c FROM netapp_dr_vm_groups WHERE plan_id=?", (p["id"],))
    p["entry_count"] = entry_cnt["c"] if entry_cnt else 0
    p["group_count"] = group_cnt["c"] if group_cnt else 0
    return p


def _list_dr_plans():
    db = get_db()
    rows = db.query("SELECT * FROM netapp_dr_plans ORDER BY name") or []
    return jsonify([_plan_summary(r, db) for r in rows])


def _create_dr_plan():
    err = _require_admin()
    if err: return err
    data = _body()
    name = (data.get("name") or "").strip()
    if not name:
        return {"error": "name is required"}, 400
    db = get_db()
    pid = str(uuid.uuid4())[:8]
    now = _now()
    username = request.session.get("user", "system")
    db.execute(
        "INSERT INTO netapp_dr_plans (id, name, dr_site_id, state, notes, created_by, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (pid, name, "", "standby", data.get("notes", ""), username, now, now)
    )
    core_id = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_groups "
        "(id, plan_id, name, group_type, sort_order, start_mode, startup_delay_sec, max_parallel, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (core_id, pid, "Core Infrastructure", "core", 0, "auto", 0, 2, now)
    )
    _spawn(_peer_push_sync)
    return jsonify({"id": pid, "message": "DR plan created"}), 201


def _get_dr_plan_detail():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    row = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not row:
        return {"error": "DR plan not found"}, 404
    p = _plan_summary(row, db)
    entries = db.query(
        "SELECT * FROM netapp_dr_plan_entries WHERE plan_id=? ORDER BY sort_order", (plan_id,)
    ) or []
    p["entries"] = [_enrich_entry(dict(e), db) for e in entries]
    groups = db.query(
        "SELECT * FROM netapp_dr_vm_groups WHERE plan_id=? ORDER BY sort_order", (plan_id,)
    ) or []
    p["vm_groups"] = []
    for g in groups:
        grp = dict(g)
        vms = db.query(
            "SELECT * FROM netapp_dr_vm_assignments WHERE group_id=? ORDER BY start_order", (grp["id"],)
        ) or []
        grp["vms"] = [dict(v) for v in vms]
        p["vm_groups"].append(grp)
    return jsonify(p)


def _update_dr_plan():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    updates, params = [], []
    for k in ("name", "notes"):
        if k in data:
            updates.append(f"{k}=?"); params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    updates.append("updated_at=?"); params.extend([_now(), plan_id])
    db.execute(f"UPDATE netapp_dr_plans SET {', '.join(updates)} WHERE id=?", params)
    _spawn(_peer_push_sync)
    return jsonify({"message": "DR plan updated"})


def _delete_dr_plan():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("id") or "").strip()
    db = get_db()
    row = db.query_one("SELECT state FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not row:
        return {"error": "DR plan not found"}, 404
    if row["state"] not in ("standby",):
        return {"error": f"Cannot delete plan in state '{row['state']}'"}, 409
    db.execute("DELETE FROM netapp_dr_plans WHERE id=?", (plan_id,))
    _spawn(_peer_push_sync)
    return jsonify({"message": "DR plan deleted"})


# ── Plan Entries ──────────────────────────────────────────────────────────────

def _lookup_primary_storage_id(db, source_endpoint_id, source_svm, source_volume):
    row = db.query_one(
        "SELECT pve_storage_id FROM netapp_volume_mapping "
        "WHERE endpoint_id=? AND svm_name=? AND volume_name=? LIMIT 1",
        (source_endpoint_id, source_svm, source_volume)
    )
    if row and row["pve_storage_id"]:
        return row["pve_storage_id"]
    row = db.query_one(
        "SELECT pve_storage_id FROM netapp_provisioned_datastores "
        "WHERE endpoint_id=? AND svm_name=? AND volume_name=? LIMIT 1",
        (source_endpoint_id, source_svm, source_volume)
    )
    return row["pve_storage_id"] if row and row["pve_storage_id"] else ""


def _enrich_entry(entry, db):
    ep = db.query_one("SELECT name FROM netapp_endpoints WHERE id=?", (entry.get("source_endpoint_id", ""),))
    entry["source_endpoint_name"] = ep["name"] if ep else ""
    dr_ep = db.query_one("SELECT name FROM netapp_endpoints WHERE id=?", (entry.get("dr_endpoint_id", ""),))
    entry["dr_endpoint_name"] = dr_ep["name"] if dr_ep else ""
    entry["dr_pve_host_ids"] = _json_field(entry.get("dr_pve_host_ids"))

    primary_storage_id = _lookup_primary_storage_id(
        db, entry.get("source_endpoint_id", ""),
        entry.get("source_svm", ""), entry.get("source_volume", "")
    )
    entry["source_pve_storage_id"] = primary_storage_id
    if not entry.get("dr_pve_storage_id") and primary_storage_id:
        entry["dr_pve_storage_id"] = primary_storage_id
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                db.execute("UPDATE netapp_dr_plan_entries SET dr_pve_storage_id=? WHERE id=?",
                           (primary_storage_id, entry["id"]))
            except Exception:
                pass

    if entry.get("snapmirror_rel_uuid"):
        rel = db.query_one(
            "SELECT state, healthy, lag_time, last_transfer_time "
            "FROM netapp_snapmirror_relationships WHERE relationship_uuid=?",
            (entry["snapmirror_rel_uuid"],)
        )
        if rel:
            entry.update({
                "sm_state": rel["state"], "sm_healthy": bool(rel["healthy"]),
                "sm_lag_time": rel["lag_time"], "sm_last_transfer": rel["last_transfer_time"],
            })
        else:
            entry.update({"sm_state": "unknown", "sm_healthy": None, "sm_lag_time": "", "sm_last_transfer": ""})
    return entry


def _add_plan_entry():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id            = (data.get("plan_id") or "").strip()
    source_endpoint_id = (data.get("source_endpoint_id") or "").strip()
    source_svm         = (data.get("source_svm") or "").strip()
    source_volume      = (data.get("source_volume") or "").strip()
    if not plan_id or not source_endpoint_id or not source_svm or not source_volume:
        return {"error": "plan_id, source_endpoint_id, source_svm, source_volume required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404

    snapmirror_rel_uuid = (data.get("snapmirror_rel_uuid") or "").strip()
    dr_endpoint_id      = (data.get("dr_endpoint_id") or "").strip()
    dr_svm              = (data.get("dr_svm") or "").strip()
    dr_volume           = (data.get("dr_volume") or "").strip()

    if not snapmirror_rel_uuid:
        rel = db.query_one(
            "SELECT relationship_uuid, dest_endpoint_id, dest_svm, dest_volume "
            "FROM netapp_snapmirror_relationships "
            "WHERE source_endpoint_id=? AND source_svm=? AND source_volume=? LIMIT 1",
            (source_endpoint_id, source_svm, source_volume)
        )
        if rel:
            snapmirror_rel_uuid = rel["relationship_uuid"]
            if not dr_endpoint_id: dr_endpoint_id = rel["dest_endpoint_id"] or ""
            if not dr_svm:         dr_svm         = rel["dest_svm"]         or ""
            if not dr_volume:      dr_volume      = rel["dest_volume"]      or ""

    max_ord = db.query_one("SELECT MAX(sort_order) as m FROM netapp_dr_plan_entries WHERE plan_id=?", (plan_id,))
    sort_order = (max_ord["m"] or 0) + 1
    eid = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_plan_entries "
        "(id, plan_id, source_endpoint_id, source_svm, source_volume, "
        "snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume, "
        "dr_pve_storage_id, dr_pve_host_ids, sort_order, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, plan_id, source_endpoint_id, source_svm, source_volume,
         snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume,
         data.get("dr_pve_storage_id", ""),
         json.dumps(data.get("dr_pve_host_ids") or []),
         sort_order, _now())
    )
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    entry = dict(db.query_one("SELECT * FROM netapp_dr_plan_entries WHERE id=?", (eid,)))
    _spawn(_peer_push_sync)
    return jsonify(_enrich_entry(entry, db)), 201


def _update_plan_entry():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    entry_id = (data.get("entry_id") or "").strip()
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plan_entries WHERE id=? AND plan_id=?", (entry_id, plan_id)):
        return {"error": "Entry not found"}, 404
    allowed = {"dr_endpoint_id", "dr_svm", "dr_volume", "dr_pve_storage_id", "dr_pve_host_ids", "snapmirror_rel_uuid"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            val = json.dumps(data[k]) if k == "dr_pve_host_ids" else data[k]
            updates.append(f"{k}=?"); params.append(val)
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(entry_id)
    db.execute(f"UPDATE netapp_dr_plan_entries SET {', '.join(updates)} WHERE id=?", params)
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    entry = dict(db.query_one("SELECT * FROM netapp_dr_plan_entries WHERE id=?", (entry_id,)))
    _spawn(_peer_push_sync)
    return jsonify(_enrich_entry(entry, db))


def _delete_plan_entry():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    entry_id = (data.get("entry_id") or "").strip()
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plan_entries WHERE id=? AND plan_id=?", (entry_id, plan_id)):
        return {"error": "Entry not found"}, 404
    db.execute("DELETE FROM netapp_dr_plan_entries WHERE id=?", (entry_id,))
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _spawn(_peer_push_sync)
    return jsonify({"message": "Entry removed"})


def _auto_detect_entries():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    rels = db.query("SELECT * FROM netapp_snapmirror_relationships") or []
    added = 0
    skipped = 0
    for rel in [dict(r) for r in rels]:
        existing = db.query_one(
            "SELECT id FROM netapp_dr_plan_entries WHERE plan_id=? AND source_svm=? AND source_volume=?",
            (plan_id, rel["source_svm"], rel["source_volume"])
        )
        if existing:
            skipped += 1; continue
        max_ord = db.query_one("SELECT MAX(sort_order) as m FROM netapp_dr_plan_entries WHERE plan_id=?", (plan_id,))
        sort_order = (max_ord["m"] or 0) + 1
        eid = str(uuid.uuid4())[:8]
        primary_storage_id = _lookup_primary_storage_id(
            db, rel["source_endpoint_id"], rel["source_svm"], rel["source_volume"]
        )
        db.execute(
            "INSERT INTO netapp_dr_plan_entries "
            "(id, plan_id, source_endpoint_id, source_svm, source_volume, "
            "snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume, "
            "dr_pve_storage_id, dr_pve_host_ids, sort_order, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, plan_id,
             rel["source_endpoint_id"], rel["source_svm"], rel["source_volume"],
             rel["relationship_uuid"],
             rel.get("dest_endpoint_id", ""), rel["dest_svm"], rel["dest_volume"],
             primary_storage_id, "[]", sort_order, _now())
        )
        added += 1
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _spawn(_peer_push_sync)
    return jsonify({"added": added, "skipped": skipped})


# ── VM Groups ─────────────────────────────────────────────────────────────────

def _create_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id    = (data.get("plan_id") or "").strip()
    name       = (data.get("name") or "").strip()
    if not plan_id or not name:
        return {"error": "plan_id and name are required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    max_ord = db.query_one("SELECT MAX(sort_order) as m FROM netapp_dr_vm_groups WHERE plan_id=?", (plan_id,))
    sort_order = (max_ord["m"] or 0) + 1
    gid = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_groups "
        "(id, plan_id, name, group_type, sort_order, start_mode, startup_delay_sec, max_parallel, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (gid, plan_id, name, "standard", sort_order,
         data.get("start_mode", "auto"),
         int(data.get("startup_delay_sec", 30)),
         int(data.get("max_parallel", 1)),
         _now())
    )
    _spawn(_peer_push_sync)
    return jsonify({"id": gid, "message": "VM group created"}), 201


def _update_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    group_id = (data.get("id") or "").strip()
    db = get_db()
    grp = db.query_one("SELECT * FROM netapp_dr_vm_groups WHERE id=?", (group_id,))
    if not grp:
        return {"error": "VM group not found"}, 404
    updates, params = [], []
    for k in ("name", "start_mode", "startup_delay_sec", "max_parallel"):
        if k in data:
            updates.append(f"{k}=?"); params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(group_id)
    db.execute(f"UPDATE netapp_dr_vm_groups SET {', '.join(updates)} WHERE id=?", params)
    _spawn(_peer_push_sync)
    return jsonify({"message": "VM group updated"})


def _delete_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    group_id = (data.get("id") or "").strip()
    db = get_db()
    grp = db.query_one("SELECT * FROM netapp_dr_vm_groups WHERE id=?", (group_id,))
    if not grp:
        return {"error": "VM group not found"}, 404
    if grp["group_type"] == "core":
        return {"error": "Cannot delete Core group"}, 409
    db.execute("DELETE FROM netapp_dr_vm_groups WHERE id=?", (group_id,))
    _spawn(_peer_push_sync)
    return jsonify({"message": "VM group deleted"})


def _reorder_vm_groups():
    err = _require_admin()
    if err: return err
    data = _body()
    order = data.get("order") or []
    db = get_db()
    for i, gid in enumerate(order):
        db.execute("UPDATE netapp_dr_vm_groups SET sort_order=? WHERE id=?", (i, gid))
    _spawn(_peer_push_sync)
    return jsonify({"message": "Groups reordered"})


# ── VM Assignments ────────────────────────────────────────────────────────────

def _add_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    group_id = (data.get("group_id") or "").strip()
    vmid     = data.get("vmid")
    if not group_id or vmid is None:
        return {"error": "group_id and vmid are required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=?", (group_id,)):
        return {"error": "VM group not found"}, 404
    max_ord = db.query_one("SELECT MAX(start_order) as m FROM netapp_dr_vm_assignments WHERE group_id=?", (group_id,))
    start_order = (max_ord["m"] or 0) + 1
    aid = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_assignments (id, group_id, vmid, vm_name, target_node, start_order, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (aid, group_id, int(vmid), data.get("vm_name", ""),
         data.get("target_node", ""), start_order, _now())
    )
    _spawn(_peer_push_sync)
    return jsonify({"id": aid, "message": "VM added to group"}), 201


def _remove_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    assignment_id = (data.get("id") or "").strip()
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_vm_assignments WHERE id=?", (assignment_id,)):
        return {"error": "VM assignment not found"}, 404
    db.execute("DELETE FROM netapp_dr_vm_assignments WHERE id=?", (assignment_id,))
    _spawn(_peer_push_sync)
    return jsonify({"message": "VM removed from group"})


def _update_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    assignment_id = (data.get("id") or "").strip()
    db = get_db()
    asn = db.query_one("SELECT * FROM netapp_dr_vm_assignments WHERE id=?", (assignment_id,))
    if not asn:
        return {"error": "VM assignment not found"}, 404
    updates, params = [], []
    for k in ("vm_name", "target_node", "start_order"):
        if k in data:
            updates.append(f"{k}=?"); params.append(data[k])
    # Move to different group
    if "group_id" in data:
        new_group = data["group_id"]
        if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=?", (new_group,)):
            return {"error": "Target VM group not found"}, 404
        updates.append("group_id=?"); params.append(new_group)
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(assignment_id)
    db.execute(f"UPDATE netapp_dr_vm_assignments SET {', '.join(updates)} WHERE id=?", params)
    _spawn(_peer_push_sync)
    return jsonify({"message": "VM assignment updated"})


# ── Plan Status + Precheck ────────────────────────────────────────────────────

def _plan_status():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    entries = db.query("SELECT * FROM netapp_dr_plan_entries WHERE plan_id=?", (plan_id,)) or []
    status_list = []
    overall_healthy = True
    for e in entries:
        item = {
            "entry_id": e["id"], "source_volume": e["source_volume"], "dr_volume": e["dr_volume"],
            "sm_state": "", "sm_healthy": None, "sm_lag_time": "", "sm_last_transfer": "",
        }
        if e["snapmirror_rel_uuid"]:
            rel = db.query_one(
                "SELECT state, healthy, lag_time, last_transfer_time, last_scanned_at "
                "FROM netapp_snapmirror_relationships WHERE relationship_uuid=?",
                (e["snapmirror_rel_uuid"],)
            )
            if rel:
                item.update({
                    "sm_state": rel["state"], "sm_healthy": bool(rel["healthy"]),
                    "sm_lag_time": rel["lag_time"], "sm_last_transfer": rel["last_transfer_time"],
                    "sm_last_scanned": rel["last_scanned_at"],
                })
                if not rel["healthy"]:
                    overall_healthy = False
            else:
                item["sm_state"] = "not_scanned"; overall_healthy = False
        else:
            item["sm_state"] = "no_relationship"; overall_healthy = False
        status_list.append(item)
    plan = db.query_one("SELECT state, last_test_at FROM netapp_dr_plans WHERE id=?", (plan_id,))
    return jsonify({
        "plan_id": plan_id,
        "plan_state": plan["state"] if plan else "",
        "overall_healthy": overall_healthy,
        "entries": status_list,
        "last_test_at": plan["last_test_at"] if plan else "",
    })


def _failover_precheck():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    plan = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not plan:
        return {"error": "DR plan not found"}, 404
    checks = []

    def _chk(name, status, msg):
        checks.append({"name": name, "status": status, "message": msg})

    entries = db.query("SELECT * FROM netapp_dr_plan_entries WHERE plan_id=?", (plan_id,)) or []
    _chk("Plan entries", "ok" if entries else "error", f"{len(entries)} datastore(s) in plan")

    missing_storage = [e["source_volume"] for e in entries if not e.get("dr_pve_storage_id")]
    _chk("Storage IDs", "error" if missing_storage else "ok",
         f"Missing: {', '.join(missing_storage)}" if missing_storage else "All entries have storage IDs")

    missing_hosts = [e["source_volume"] for e in entries if not _json_field(e.get("dr_pve_host_ids"))]
    _chk("DR PVE hosts", "error" if missing_hosts else "ok",
         f"No host: {', '.join(missing_hosts)}" if missing_hosts else "All entries have DR host(s)")

    missing_rel = [e["source_volume"] for e in entries if not e.get("snapmirror_rel_uuid")]
    _chk("SnapMirror links", "error" if missing_rel else "ok",
         f"No relationship: {', '.join(missing_rel)}" if missing_rel else "All entries linked")

    unhealthy = [e["source_volume"] for e in entries if e.get("snapmirror_rel_uuid") and
                 (lambda r: r and not r["healthy"])(db.query_one(
                     "SELECT healthy FROM netapp_snapmirror_relationships WHERE relationship_uuid=?",
                     (e["snapmirror_rel_uuid"],)))]
    _chk("SnapMirror health", "warn" if unhealthy else "ok",
         f"Unhealthy: {', '.join(unhealthy)}" if unhealthy else "All relationships healthy")

    vm_groups = db.query(
        "SELECT g.name, g.group_type, (SELECT COUNT(*) FROM netapp_dr_vm_assignments a WHERE a.group_id=g.id) as vm_count "
        "FROM netapp_dr_vm_groups g WHERE g.plan_id=? ORDER BY g.sort_order", (plan_id,)
    ) or []
    total_vms = sum(g["vm_count"] for g in vm_groups)
    core = next((g for g in vm_groups if g["group_type"] == "core"), None)
    core_vms = core["vm_count"] if core else 0
    _chk("VM groups", "warn" if not vm_groups or core_vms == 0 else "ok",
         f"{len(vm_groups)} group(s), {total_vms} VM(s)" if vm_groups
         else "No VM groups — storage will be mounted, VMs must be started manually")

    overall = all(c["status"] in ("ok", "warn") for c in checks)
    return jsonify({"ok": overall, "checks": checks})


# ── Failover ──────────────────────────────────────────────────────────────────

def _start_failover():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id      = (data.get("plan_id") or "").strip()
    failover_type = (data.get("failover_type") or "planned").strip()
    if failover_type not in ("planned", "emergency"):
        return {"error": "failover_type must be 'planned' or 'emergency'"}, 400
    db = get_db()
    plan = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not plan:
        return {"error": "DR plan not found"}, 404
    if plan["state"] in ("failover_running", "failback_running"):
        return {"error": f"Plan is already in state '{plan['state']}'"}, 409
    entry_ids = data.get("entry_ids") or []
    snap_map  = data.get("snap_map") or {}
    username = request.session.get("user", "admin")
    job_id = _dr_start_job("dr_" + failover_type + "_failover", username, plan_id)
    db.execute("UPDATE netapp_dr_plans SET state='failover_running', updated_at=? WHERE id=?", (_now(), plan_id))
    threading.Thread(
        target=_execute_failover,
        args=(job_id, plan_id, failover_type, entry_ids, snap_map),
        daemon=True
    ).start()
    return jsonify({"job_id": job_id, "message": "Failover started"}), 202


def _execute_failover(job_id, plan_id, failover_type, entry_ids=None, snap_map=None):
    import shlex, time
    from ..core._helpers import build_ontap_client, build_pve_client, get_ssh_creds, ssh_run, get_endpoint

    log_lines = []

    def _log(msg):
        log_lines.append({"ts": _now(), "msg": msg})
        db = get_db()
        db.execute("UPDATE netapp_jobs SET log_json=? WHERE id=?", (json.dumps(log_lines), job_id))

    def _finish(state):
        plan_state = "failed_over" if state == "success" else "standby"
        status = "done" if state == "success" else "failed"
        db = get_db()
        db.execute(
            "UPDATE netapp_jobs SET status=?, completed_at=?, log_json=? WHERE id=?",
            (status, _now(), json.dumps(log_lines), job_id)
        )
        db.execute("UPDATE netapp_dr_plans SET state=?, last_failover_at=?, updated_at=? WHERE id=?",
                   (plan_state, _now(), _now(), plan_id))
        if state == "success":
            db.execute(
                "UPDATE netapp_plugin_config SET role='PRIMARY', role_forced=0, updated_at=? WHERE id='default'",
                (_now(),)
            )
            # Notify peer to become SECONDARY
            _spawn(_peer_push_role_notify, "PRIMARY")

    try:
        db = get_db()
        all_entries = db.query(
            "SELECT * FROM netapp_dr_plan_entries WHERE plan_id=? ORDER BY sort_order", (plan_id,)
        ) or []
        if not all_entries:
            _log("[ERR] No plan entries found"); _finish("failed"); return

        entries = [dict(e) for e in all_entries if not entry_ids or dict(e)["id"] in entry_ids]
        skipped_count = len(all_entries) - len(entries)
        if skipped_count:
            _log(f"[INFO] {skipped_count} datastore(s) skipped (not selected)")

        _log(f"[INFO] Starting {failover_type.upper()} FAILOVER — {len(entries)} datastore(s)")

        for entry in entries:
            dr_ep_id   = entry.get("dr_endpoint_id", "")
            dr_svm     = entry.get("dr_svm", "")
            dr_volume  = entry.get("dr_volume", "")
            rel_uuid   = entry.get("snapmirror_rel_uuid", "")
            storage_id = entry.get("dr_pve_storage_id", "")
            pve_host_ids = _json_field(entry.get("dr_pve_host_ids")) or []

            _log(f"[INFO] ── {entry['source_volume']} → {dr_volume} ──")
            if not rel_uuid:
                _log(f"[WARN] No SnapMirror relationship — skipping"); continue
            if not storage_id:
                _log(f"[WARN] No DR storage ID — skipping"); continue
            if not pve_host_ids:
                _log(f"[WARN] No DR PVE host — skipping"); continue

            try:
                dr_ep = get_endpoint(db, dr_ep_id)
                dr_client = build_ontap_client(dr_ep)
            except Exception as exc:
                _log(f"[ERR] Cannot connect to DR ONTAP: {exc}"); _finish("failed"); return

            if failover_type == "planned":
                _log("[INFO] Triggering final SnapMirror update…")
                try:
                    dr_client.trigger_snapmirror_transfer(rel_uuid)
                    time.sleep(5)
                    _log("[INFO] Final update triggered")
                except Exception as exc:
                    _log(f"[WARN] Final update failed (continuing): {exc}")

            _log(f"[INFO] Breaking SnapMirror {rel_uuid}…")
            try:
                dr_client.snapmirror_break(rel_uuid)
                _log("[INFO] SnapMirror broken — volume is now read-write")
            except Exception as exc:
                _log(f"[ERR] SnapMirror break failed: {exc}"); _finish("failed"); return

            try:
                vol = dr_client.get_volume_by_name(dr_svm, dr_volume)
                vol_uuid = vol.get("uuid", "")
                junction = (vol.get("nas") or {}).get("path", "")
                if not junction:
                    junction = f"/{dr_volume}"
                    dr_client.mount_volume(vol_uuid, junction)
                    _log(f"[INFO] Volume mounted at {junction}")
                else:
                    _log(f"[INFO] Junction path: {junction}")
            except Exception as exc:
                _log(f"[ERR] Volume info/mount failed: {exc}"); _finish("failed"); return

            try:
                nfs_ip = dr_client.get_nfs_lif_for_svm(dr_svm)
                if not nfs_ip:
                    _log(f"[ERR] No NFS LIF on DR SVM '{dr_svm}'"); _finish("failed"); return
                _log(f"[INFO] NFS LIF: {nfs_ip}")
            except Exception as exc:
                _log(f"[ERR] NFS LIF lookup failed: {exc}"); _finish("failed"); return

            sid_q = shlex.quote(storage_id)
            pvesm_cmd = (f"pvesm add nfs {sid_q} --server {shlex.quote(nfs_ip)}"
                         f" --export {shlex.quote(junction)} --content images,rootdir --options vers=3")
            for pve_host_id in pve_host_ids:
                try:
                    pve = build_pve_client(db, pve_host_id)
                    su, sp, sk = get_ssh_creds(pve)
                    sh = pve.host
                    _log(f"[INFO] [{sh}] Registering storage '{storage_id}'…")
                    check = ssh_run(sh, su, sp, f"pvesm status {sid_q} 2>/dev/null && echo EXISTS || echo MISSING",
                                    capture=True, key_material=sk)
                    if "EXISTS" in check:
                        _log(f"[INFO] [{sh}] Storage already registered")
                    else:
                        ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=60)
                        _log(f"[INFO] [{sh}] Storage registered ✓")
                except Exception as exc:
                    _log(f"[ERR] [{pve_host_id}] Storage registration failed: {exc}")
                    _finish("failed"); return

            db.execute(
                "UPDATE netapp_snapmirror_relationships SET dest_nfs_ip=?, dest_junction_path=? WHERE relationship_uuid=?",
                (nfs_ip, junction, rel_uuid)
            )

            manifest_root = f"/mnt/pve/{storage_id}/.netapp-snapmanifest"
            for pve_host_id in pve_host_ids:
                try:
                    pve = build_pve_client(db, pve_host_id)
                    su, sp, sk = get_ssh_creds(pve)
                    sh = pve.host
                    chosen_snap = (snap_map or {}).get(entry["id"], "")
                    if chosen_snap:
                        latest_dir = f"{manifest_root}/{chosen_snap}"
                        _log(f"[INFO] [{sh}] Using snapshot: {chosen_snap}")
                    else:
                        find_latest = (
                            f"ls -dt {shlex.quote(manifest_root)}/*/manifest.json 2>/dev/null"
                            f" | head -1 | xargs -r dirname"
                        )
                        latest_dir = ssh_run(sh, su, sp, find_latest, capture=True, key_material=sk).strip()
                    if not latest_dir:
                        _log(f"[INFO] [{sh}] No snapmanifest — VM configs must be registered manually")
                        continue
                    vms_in_plan = db.query(
                        "SELECT a.vmid, a.vm_name FROM netapp_dr_vm_assignments a "
                        "JOIN netapp_dr_vm_groups g ON g.id=a.group_id WHERE g.plan_id=?", (plan_id,)
                    ) or []
                    restored = 0
                    for vm in vms_in_plan:
                        vmid = vm["vmid"]
                        conf_src = f"{latest_dir}/{vmid}.conf"
                        conf_dst = f"/etc/pve/qemu-server/{vmid}.conf"
                        check = ssh_run(sh, su, sp, f"test -f {shlex.quote(conf_src)} && echo EXISTS || echo MISSING",
                                        capture=True, key_material=sk)
                        if "MISSING" in check:
                            _log(f"[WARN] [{sh}] No config for VM {vmid} — skipping"); continue
                        existing = ssh_run(sh, su, sp, f"test -f {shlex.quote(conf_dst)} && echo EXISTS || echo MISSING",
                                           capture=True, key_material=sk)
                        if "EXISTS" in existing:
                            _log(f"[INFO] [{sh}] VM {vmid} already registered — keeping existing"); continue
                        ssh_run(sh, su, sp, f"cp {shlex.quote(conf_src)} {shlex.quote(conf_dst)}", key_material=sk)
                        _log(f"[INFO] [{sh}] VM {vmid} ({vm['vm_name'] or vmid}): config restored ✓")
                        restored += 1
                    if restored:
                        _log(f"[INFO] [{sh}] {restored} VM config(s) restored from snapmanifest")
                except Exception as exc:
                    _log(f"[WARN] VM config restore on {pve_host_id}: {exc}")

        vm_groups = db.query(
            "SELECT * FROM netapp_dr_vm_groups WHERE plan_id=? ORDER BY sort_order", (plan_id,)
        ) or []
        if not vm_groups:
            _log("[INFO] No VM groups — storage is mounted and ready")
        else:
            _log(f"[INFO] Starting {len(vm_groups)} VM group(s)…")
            for group in vm_groups:
                group = dict(group)
                assignments = db.query(
                    "SELECT * FROM netapp_dr_vm_assignments WHERE group_id=? ORDER BY start_order",
                    (group["id"],)
                ) or []
                mode_label = "AUTO" if group["start_mode"] == "auto" else "MANUAL"
                _log(f"[INFO] Group '{group['name']}' [{group['group_type'].upper()} / {mode_label}] — {len(assignments)} VM(s)")
                if group["start_mode"] == "manual":
                    _log(f"[INFO]   → Skipped (manual — start via UI after confirming primary is down)")
                    continue

                first_host = next(
                    (h for e in entries for h in _json_field(e.get("dr_pve_host_ids"))), None
                )
                if not first_host:
                    _log(f"[WARN]   → No DR PVE host found — skipping group"); continue

                max_par = max(1, int(group.get("max_parallel", 1)))
                for batch_start in range(0, len(assignments), max_par):
                    batch = assignments[batch_start:batch_start + max_par]
                    for assignment in batch:
                        assignment = dict(assignment)
                        vmid = assignment["vmid"]
                        vm_name = assignment.get("vm_name") or str(vmid)
                        try:
                            pve = build_pve_client(db, first_host)
                            su, sp, sk = get_ssh_creds(pve)
                            sh = pve.host
                            check = ssh_run(sh, su, sp, f"qm status {vmid} 2>/dev/null && echo EXISTS || echo MISSING",
                                            capture=True, key_material=sk)
                            if "MISSING" in check:
                                _log(f"[WARN]   VM {vmid} ({vm_name}): not registered — skipping"); continue
                            ssh_run(sh, su, sp, f"qm start {vmid}", key_material=sk, timeout=120)
                            _log(f"[INFO]   VM {vmid} ({vm_name}): started ✓")
                        except Exception as exc:
                            _log(f"[WARN]   VM {vmid} ({vm_name}): start failed: {exc}")

                delay = group.get("startup_delay_sec", 30)
                if delay > 0 and group != vm_groups[-1]:
                    _log(f"[INFO]   Waiting {delay}s before next group…")
                    time.sleep(delay)

        _log("[INFO] ✅ Failover complete — this instance is now PRIMARY")
        _finish("success")

    except Exception as exc:
        _log(f"[ERR] Unexpected error: {exc}")
        _finish("failed")


def _list_dr_snapshots():
    plan_id  = request.args.get("plan_id") or ""
    entry_id = request.args.get("entry_id") or ""
    db = get_db()
    entry = db.query_one(
        "SELECT * FROM netapp_dr_plan_entries WHERE id=? AND plan_id=?", (entry_id, plan_id)
    )
    if not entry:
        return {"error": "Entry not found"}, 404
    entry = dict(entry)
    try:
        from ..core._helpers import get_endpoint, build_ontap_client
        dr_ep = get_endpoint(db, entry["dr_endpoint_id"])
        client = build_ontap_client(dr_ep)
        vol = client.get_volume_by_name(entry["dr_svm"], entry["dr_volume"])
        vol_uuid = vol.get("uuid", "")
        snaps = client.list_snapshots(vol_uuid)
        result = [{"name": s.get("name", ""), "created": s.get("create_time", "")} for s in (snaps or [])]
        result.sort(key=lambda s: s["created"], reverse=True)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _get_failover_jobs():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    if not plan_id:
        return {"error": "plan_id required"}, 400
    jobs = db.query(
        "SELECT id, job_type, status, log_json, created_at, completed_at, created_by "
        "FROM netapp_jobs WHERE snapshot_id=? AND job_type LIKE 'dr_%failover%' "
        "ORDER BY created_at DESC LIMIT 5",
        (plan_id,)
    ) or []
    result = []
    for j in jobs:
        row = dict(j)
        row["state"] = "success" if row.get("status") == "done" else row.get("status", "")
        try:
            row["log"] = json.loads(row.pop("log_json") or "[]")
        except Exception:
            row["log"] = []
        result.append(row)
    return jsonify(result)


# ── Route Registration ────────────────────────────────────────────────────────

def register_routes():
    rpr = register_plugin_route

    # Role
    rpr(PLUGIN_ID, "dr/role",           _get_role)
    rpr(PLUGIN_ID, "dr/role/set",       _set_role)

    # Peer management
    rpr(PLUGIN_ID, "dr/peer/status",         _peer_status)
    rpr(PLUGIN_ID, "dr/peer/configure",      _configure_peer)
    rpr(PLUGIN_ID, "dr/peer/remove",         _remove_peer)
    rpr(PLUGIN_ID, "dr/peer/sync/push",      _sync_push_manual)

    # Peer receive (called by remote peer — token auth)
    rpr(PLUGIN_ID, "dr/peer/heartbeat",      _peer_heartbeat_recv)
    rpr(PLUGIN_ID, "dr/peer/sync/receive",   _peer_sync_recv)
    rpr(PLUGIN_ID, "dr/peer/role-notify",    _peer_role_notify_recv)

    # DR Plans
    rpr(PLUGIN_ID, "dr/plans",               _list_dr_plans)
    rpr(PLUGIN_ID, "dr/plans/create",        _create_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/detail",        _get_dr_plan_detail)
    rpr(PLUGIN_ID, "dr/plans/update",        _update_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/delete",        _delete_dr_plan)

    # Plan Entries
    rpr(PLUGIN_ID, "dr/plans/entries/add",    _add_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/update", _update_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/delete", _delete_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/auto-detect",    _auto_detect_entries)

    # VM Groups
    rpr(PLUGIN_ID, "dr/plans/groups/create",  _create_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/update",  _update_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/delete",  _delete_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/reorder", _reorder_vm_groups)

    # VM Assignments
    rpr(PLUGIN_ID, "dr/plans/groups/vms/add",    _add_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/delete", _remove_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/update", _update_vm_assignment)

    # Status + Failover
    rpr(PLUGIN_ID, "dr/plans/status",         _plan_status)
    rpr(PLUGIN_ID, "dr/plans/precheck",        _failover_precheck)
    rpr(PLUGIN_ID, "dr/plans/failover",        _start_failover)
    rpr(PLUGIN_ID, "dr/plans/failover-jobs",   _get_failover_jobs)
    rpr(PLUGIN_ID, "dr/plans/snapshots",       _list_dr_snapshots)

    _start_background_threads()
