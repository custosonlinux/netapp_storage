"""
Disaster Recovery API  (v2.0 — NFS config-volume sync, role model)

Architecture:
  MASTER   — writes plans/config to a dedicated NFS config volume (SnapMirror'd to DR)
  DR_SLAVE — reads config from the DP destination of that volume (read-only NFS mount)
  DR_TEST  — (future) FlexClone-based isolated test

Role is auto-detected: if the config volume type == 'dp' (SnapMirror destination) → DR_SLAVE,
otherwise MASTER.  Admin can always force-override via dr/role/set.

Config volume NFS path layout:
  <mount_path>/.netapp-dr/
    role.json
    config.json         (sites + endpoints)
    plans/<plan_id>.json

Routes under /api/plugins/netapp_storage/api/...

  dr/role                         GET  — current role + config volume info
  dr/role/set                     POST {role} — force role
  dr/role/detect                  POST — auto-detect from ONTAP volume type

  dr/config-volume                GET  — config volume setup status
  dr/config-volume/setup          POST {volume_id, mount_path} — designate config volume
  dr/config-volume/nfs-volumes    GET  — list NFS volume mappings for selection

  dr/sites                        GET  — list DR sites
  dr/sites/create                 POST — create DR site
  dr/sites/update                 POST — update DR site
  dr/sites/delete                 POST — delete DR site
  dr/clusters                     GET  — list PegaProx clusters (for PVE import)

  dr/plans                        GET  — list DR plans
  dr/plans/create                 POST — create DR plan (auto-creates Core group)
  dr/plans/detail                 GET  ?plan_id= — full plan detail
  dr/plans/update                 POST — update plan name/notes
  dr/plans/delete                 POST — delete plan

  dr/plans/entries/add            POST — add datastore entry
  dr/plans/entries/update         POST — update entry fields
  dr/plans/entries/delete         POST — remove entry
  dr/plans/auto-detect            POST {plan_id} — detect SnapMirror rels

  dr/plans/groups/create          POST — create VM group
  dr/plans/groups/update          POST — update VM group
  dr/plans/groups/delete          POST — delete VM group (core group protected)
  dr/plans/groups/reorder         POST — reorder groups

  dr/plans/groups/vms/add         POST — add VM to group
  dr/plans/groups/vms/delete      POST — remove VM
  dr/plans/groups/vms/update      POST — update VM (name, target_node, move group)

  dr/plans/status                 GET  ?plan_id= — live SnapMirror status
  dr/plans/precheck               GET  ?plan_id= — failover pre-check
  dr/plans/failover               POST — start failover
  dr/plans/failover-jobs          GET  ?plan_id= — last failover jobs
  dr/plans/snapshots              GET  ?plan_id=&entry_id= — ONTAP snapshots on DR volume
"""

import json
import logging
import threading
import uuid
from datetime import datetime, timezone

from flask import request, jsonify
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

from ..core._helpers import PLUGIN_ID

log = logging.getLogger(__name__)


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


# ── Plugin Config: Role + Config Volume ───────────────────────────────────────

def _get_plugin_config():
    """Return the plugin config row, creating default row if missing."""
    db = get_db()
    cfg = db.query_one("SELECT * FROM netapp_plugin_config WHERE id='default'")
    if not cfg:
        db.execute(
            "INSERT INTO netapp_plugin_config "
            "(id, role, role_forced, config_volume_id, config_mount_path, last_role_check, updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("default", "MASTER", 0, "", "", "", _now())
        )
        cfg = db.query_one("SELECT * FROM netapp_plugin_config WHERE id='default'")
    return dict(cfg)


def _get_role():
    """GET dr/role"""
    cfg = _get_plugin_config()
    db = get_db()
    vol_info = None
    if cfg.get("config_volume_id"):
        vol = db.query_one(
            "SELECT volume_name, pve_storage_id, nfs_export_ip FROM netapp_volume_mapping WHERE id=?",
            (cfg["config_volume_id"],)
        )
        if vol:
            vol_info = dict(vol)
    return jsonify({
        "role":             cfg.get("role", "MASTER"),
        "role_forced":      bool(cfg.get("role_forced", 0)),
        "config_volume_id": cfg.get("config_volume_id", ""),
        "config_mount_path": cfg.get("config_mount_path", ""),
        "config_volume":    vol_info,
        "last_role_check":  cfg.get("last_role_check", ""),
    })


def _set_role():
    """POST dr/role/set — force-set plugin role."""
    err = _require_admin()
    if err: return err
    data = _body()
    role = (data.get("role") or "").upper()
    if role not in ("MASTER", "DR_SLAVE", "DR_TEST"):
        return {"error": "role must be MASTER, DR_SLAVE, or DR_TEST"}, 400
    _get_plugin_config()
    db = get_db()
    forced = 1 if data.get("forced", True) else 0
    db.execute(
        "UPDATE netapp_plugin_config SET role=?, role_forced=?, updated_at=? WHERE id='default'",
        (role, forced, _now())
    )
    return jsonify({"role": role, "role_forced": bool(forced), "message": f"Role set to {role}"})


def _detect_role():
    """POST dr/role/detect — auto-detect role from ONTAP config volume type."""
    cfg = _get_plugin_config()
    if not cfg.get("config_volume_id"):
        return jsonify({
            "role": "MASTER", "detected": False,
            "reason": "No config volume configured — assuming MASTER"
        })
    db = get_db()
    vol = db.query_one("SELECT * FROM netapp_volume_mapping WHERE id=?", (cfg["config_volume_id"],))
    if not vol:
        return jsonify({
            "role": "MASTER", "detected": False,
            "reason": "Config volume not found in volume mappings"
        })
    try:
        from ..core._helpers import get_endpoint, build_ontap_client
        ep = get_endpoint(db, vol["endpoint_id"])
        client = build_ontap_client(ep)
        vol_info = client.get_volume_by_uuid(vol["volume_uuid"])
        vol_type = (vol_info or {}).get("type", "rw")
        detected_role = "DR_SLAVE" if vol_type == "dp" else "MASTER"
        now = _now()
        if not cfg.get("role_forced"):
            db.execute(
                "UPDATE netapp_plugin_config SET role=?, last_role_check=?, updated_at=? WHERE id='default'",
                (detected_role, now, now)
            )
        else:
            db.execute("UPDATE netapp_plugin_config SET last_role_check=? WHERE id='default'", (now,))
        effective_role = cfg["role"] if cfg.get("role_forced") else detected_role
        return jsonify({
            "role": effective_role,
            "detected_role": detected_role,
            "volume_type": vol_type,
            "forced": bool(cfg.get("role_forced")),
            "detected": True,
            "reason": f"Config volume type is '{vol_type}' → {'DR_SLAVE' if vol_type == 'dp' else 'MASTER'}",
        })
    except Exception as exc:
        return jsonify({
            "role": cfg.get("role", "MASTER"), "detected": False,
            "reason": f"ONTAP detection failed: {exc}"
        })


def _config_volume_status():
    """GET dr/config-volume"""
    import os
    cfg = _get_plugin_config()
    result = {
        "configured":       bool(cfg.get("config_volume_id")),
        "config_volume_id": cfg.get("config_volume_id", ""),
        "config_mount_path": cfg.get("config_mount_path", ""),
    }
    if cfg.get("config_volume_id"):
        db = get_db()
        vol = db.query_one(
            "SELECT volume_name, pve_storage_id, nfs_export_ip FROM netapp_volume_mapping WHERE id=?",
            (cfg["config_volume_id"],)
        )
        if vol:
            result.update({
                "volume_name": vol["volume_name"],
                "storage_id":  vol["pve_storage_id"],
                "nfs_ip":      vol["nfs_export_ip"],
            })
    mount_path = cfg.get("config_mount_path", "")
    if mount_path:
        result["mount_accessible"]  = os.path.isdir(mount_path)
        result["config_dir_exists"] = os.path.isdir(f"{mount_path}/.netapp-dr")
    return jsonify(result)


def _setup_config_volume():
    """POST dr/config-volume/setup — designate an NFS volume as the config volume."""
    import os
    err = _require_admin()
    if err: return err
    data = _body()
    volume_id  = (data.get("volume_id") or "").strip()
    mount_path = (data.get("mount_path") or "").strip().rstrip("/")
    if not volume_id or not mount_path:
        return {"error": "volume_id and mount_path are required"}, 400
    db = get_db()
    vol = db.query_one("SELECT * FROM netapp_volume_mapping WHERE id=?", (volume_id,))
    if not vol:
        return {"error": "Volume not found in volume mappings"}, 404

    # Save the config regardless of mount state — the volume may not be mounted yet
    _get_plugin_config()
    db.execute(
        "UPDATE netapp_plugin_config SET config_volume_id=?, config_mount_path=?, updated_at=? WHERE id='default'",
        (volume_id, mount_path, _now())
    )

    # Try to create config dir if mount is already accessible
    warning = None
    if os.path.isdir(mount_path):
        config_dir = f"{mount_path}/.netapp-dr"
        try:
            os.makedirs(f"{config_dir}/plans", exist_ok=True)
            _write_config_to_volume()
        except Exception as exc:
            warning = f"Config saved but could not create directory: {exc}"
    else:
        warning = (f"Config saved. Mount path '{mount_path}' is not yet accessible on this server. "
                   f"Mount the NFS volume first: mount -t nfs {vol['nfs_export_ip']}:{vol['junction_path']} {mount_path}")

    result = {"message": "Config volume saved", "volume_name": vol["volume_name"]}
    if warning:
        result["warning"] = warning
    return jsonify(result)


def _list_nfs_volumes():
    """GET dr/config-volume/nfs-volumes — list NFS volume mappings for config volume selection."""
    db = get_db()
    rows = db.query(
        "SELECT DISTINCT vm.id, vm.volume_name, vm.pve_storage_id, vm.nfs_export_ip, "
        "vm.nfs_mount_path, ep.name as endpoint_name "
        "FROM netapp_volume_mapping vm "
        "LEFT JOIN netapp_endpoints ep ON ep.id=vm.endpoint_id "
        "WHERE vm.storage_protocol='nfs' "
        "ORDER BY ep.name, vm.volume_name"
    ) or []
    return jsonify([dict(r) for r in rows])


def _write_config_to_volume():
    """Write plan configs + role/site info as JSON files to the config volume NFS mount."""
    import os
    db = get_db()
    cfg = db.query_one("SELECT * FROM netapp_plugin_config WHERE id='default'")
    if not cfg or not cfg.get("config_mount_path"):
        return False
    mount_path = cfg["config_mount_path"].rstrip("/")
    config_dir = f"{mount_path}/.netapp-dr"
    try:
        os.makedirs(f"{config_dir}/plans", exist_ok=True)
        with open(f"{config_dir}/role.json", "w") as f:
            json.dump({"role": cfg.get("role", "MASTER"), "last_updated": _now()}, f, indent=2)
        sites = db.query("SELECT * FROM netapp_dr_sites") or []
        eps   = db.query("SELECT id, name, host FROM netapp_endpoints") or []
        with open(f"{config_dir}/config.json", "w") as f:
            json.dump({
                "plugin": "netapp_storage", "exported_at": _now(),
                "sites": [dict(s) for s in sites],
                "endpoints": [dict(e) for e in eps],
            }, f, indent=2)
        plans = db.query("SELECT * FROM netapp_dr_plans") or []
        for plan_row in plans:
            plan_data = _build_plan_export_data(plan_row["id"], db)
            with open(f"{config_dir}/plans/{plan_row['id']}.json", "w") as f:
                json.dump(plan_data, f, indent=2)
        return True
    except Exception as exc:
        log.warning(f"[netapp_storage] Config volume write failed: {exc}")
        return False


def _build_plan_export_data(plan_id, db):
    """Build a full plan export dict for writing to the config volume."""
    plan = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not plan:
        return {}
    p = dict(plan)
    entries = db.query(
        "SELECT * FROM netapp_dr_plan_entries WHERE plan_id=? ORDER BY sort_order", (plan_id,)
    ) or []
    p["entries"] = [dict(e) for e in entries]
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
    return p


# ── DR Sites ──────────────────────────────────────────────────────────────────

def _list_dr_sites():
    db = get_db()
    rows = db.query("SELECT * FROM netapp_dr_sites ORDER BY name") or []
    result = []
    for r in rows:
        s = dict(r)
        s["pve_host_ids"] = _json_field(s.get("pve_host_ids"))
        ep = db.query_one("SELECT name FROM netapp_endpoints WHERE id=?", (s["endpoint_id"],))
        s["endpoint_name"] = ep["name"] if ep else ""
        cnt = db.query_one("SELECT COUNT(*) as c FROM netapp_dr_plans WHERE dr_site_id=?", (s["id"],))
        s["plan_count"] = cnt["c"] if cnt else 0
        pve_hosts = []
        for hid in s["pve_host_ids"]:
            h = db.query_one("SELECT name, host FROM netapp_pve_hosts WHERE id=?", (hid,))
            if h:
                pve_hosts.append({"id": hid, "name": h["name"], "host": h["host"]})
        s["pve_hosts"] = pve_hosts
        result.append(s)
    return jsonify(result)


def _resolve_dr_pve_hosts(data, db):
    """Resolve DR PVE host IDs from one of three input modes.

    Mode 1 — existing:  data["pve_host_ids"] = ["id1", "id2", ...]
    Mode 2 — inline:    data["pve_hosts_inline"] = [{"name","host","username","password"}, ...]
    Mode 3 — cluster:   data["pve_cluster_id"] = "<pegaprox_cluster_id>"
    """
    now = _now()
    if data.get("pve_host_ids"):
        return [h for h in data["pve_host_ids"] if h]
    if data.get("pve_hosts_inline"):
        host_ids = []
        for h in data["pve_hosts_inline"]:
            host_val = (h.get("host") or "").strip()
            name_val = (h.get("name") or host_val).strip()
            user_val = (h.get("username") or "root").strip()
            pass_val = h.get("password", "")
            if not host_val:
                continue
            existing = db.query_one("SELECT id FROM netapp_pve_hosts WHERE host=?", (host_val,))
            if existing:
                hid = existing["id"]
            else:
                hid = str(uuid.uuid4())[:8]
                pw_enc = db._encrypt(pass_val) if pass_val else ""
                db.execute(
                    "INSERT INTO netapp_pve_hosts (id, name, host, port, username, password_encrypted, ssl_verify, nfs_ip, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (hid, name_val, host_val, 8006, user_val, pw_enc, 0, "", now)
                )
            host_ids.append(hid)
        return host_ids
    if data.get("pve_cluster_id"):
        cluster_id = data["pve_cluster_id"]
        host_ids = []
        try:
            from pegaprox.globals import cluster_managers
            mgr = cluster_managers.get(cluster_id)
            if not mgr:
                return []
            cluster_host = getattr(mgr, "host", "") or getattr(mgr, "api_host", "")
            cluster_user = getattr(mgr, "user", "root")
            cluster_pass = getattr(mgr, "password", "") or getattr(mgr, "_password", "")
            for node_name in (getattr(mgr, "get_nodes", lambda: [])() or []):
                node_ip = node_name.get("ip") or node_name.get("host") or cluster_host
                existing = db.query_one("SELECT id FROM netapp_pve_hosts WHERE host=?", (node_ip,))
                if existing:
                    hid = existing["id"]
                else:
                    hid = str(uuid.uuid4())[:8]
                    pw_enc = db._encrypt(cluster_pass) if cluster_pass else ""
                    db.execute(
                        "INSERT INTO netapp_pve_hosts (id, name, host, port, username, password_encrypted, ssl_verify, nfs_ip, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (hid, node_name.get("node", node_ip), node_ip, 8006, cluster_user, pw_enc, 0, "", now)
                    )
                host_ids.append(hid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR site cluster import failed: {exc}")
        return host_ids
    return []


def _list_pegaprox_clusters():
    try:
        db = get_db()
        rows = db.query("SELECT id, name, host FROM clusters ORDER BY name") or []
        return jsonify([{"id": r["id"], "name": r["name"], "host": r["host"]} for r in rows])
    except Exception as exc:
        log.warning(f"[netapp_storage] list_pegaprox_clusters: {exc}")
        return jsonify([])


def _create_dr_site():
    err = _require_admin()
    if err: return err
    data = _body()
    name        = (data.get("name") or "").strip()
    endpoint_id = (data.get("endpoint_id") or "").strip()
    if not name or not endpoint_id:
        return {"error": "name and endpoint_id are required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_endpoints WHERE id=?", (endpoint_id,)):
        return {"error": "Endpoint not found"}, 404
    pve_host_ids = _resolve_dr_pve_hosts(data, db)
    sid = str(uuid.uuid4())[:8]
    now = _now()
    db.execute(
        "INSERT INTO netapp_dr_sites (id, name, endpoint_id, pve_host_ids, description, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (sid, name, endpoint_id, json.dumps(pve_host_ids), data.get("description", ""), now, now)
    )
    _write_config_to_volume()
    return jsonify({"id": sid, "message": "DR site created"}), 201


def _update_dr_site():
    err = _require_admin()
    if err: return err
    data = _body()
    site_id = (data.get("id") or "").strip()
    db = get_db()
    if not site_id or not db.query_one("SELECT id FROM netapp_dr_sites WHERE id=?", (site_id,)):
        return {"error": "DR site not found"}, 404
    allowed = {"name", "endpoint_id", "pve_host_ids", "description"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            val = json.dumps(data[k]) if k == "pve_host_ids" else data[k]
            updates.append(f"{k}=?")
            params.append(val)
    if not updates:
        return {"error": "No fields to update"}, 400
    updates.append("updated_at=?")
    params.extend([_now(), site_id])
    db.execute(f"UPDATE netapp_dr_sites SET {', '.join(updates)} WHERE id=?", params)
    _write_config_to_volume()
    return jsonify({"message": "DR site updated"})


def _delete_dr_site():
    err = _require_admin()
    if err: return err
    data = _body()
    site_id = (data.get("id") or "").strip()
    db = get_db()
    if not site_id or not db.query_one("SELECT id FROM netapp_dr_sites WHERE id=?", (site_id,)):
        return {"error": "DR site not found"}, 404
    plans = db.query("SELECT id FROM netapp_dr_plans WHERE dr_site_id=?", (site_id,)) or []
    if plans:
        return {"error": f"Cannot delete: {len(plans)} DR plan(s) use this site"}, 409
    db.execute("DELETE FROM netapp_dr_sites WHERE id=?", (site_id,))
    _write_config_to_volume()
    return jsonify({"message": "DR site deleted"})


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
    site = db.query_one("SELECT name FROM netapp_dr_sites WHERE id=?", (p["dr_site_id"],))
    p["site_name"] = site["name"] if site else ""
    return p


def _list_dr_plans():
    db = get_db()
    rows = db.query("SELECT * FROM netapp_dr_plans ORDER BY name") or []
    return jsonify([_plan_summary(r, db) for r in rows])


def _create_dr_plan():
    err = _require_admin()
    if err: return err
    data = _body()
    name       = (data.get("name") or "").strip()
    dr_site_id = (data.get("dr_site_id") or "").strip()
    if not name or not dr_site_id:
        return {"error": "name and dr_site_id are required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_sites WHERE id=?", (dr_site_id,)):
        return {"error": "DR site not found"}, 404
    pid = str(uuid.uuid4())[:8]
    now = _now()
    username = request.session.get("user", "system")
    db.execute(
        "INSERT INTO netapp_dr_plans (id, name, dr_site_id, state, notes, created_by, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (pid, name, dr_site_id, "standby", data.get("notes", ""), username, now, now)
    )
    # Auto-create Core group (always first, always auto, cannot be deleted)
    core_id = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_groups "
        "(id, plan_id, name, group_type, sort_order, start_mode, startup_delay_sec, max_parallel, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (core_id, pid, "Core Infrastructure", "core", 0, "auto", 0, 2, now)
    )
    _write_config_to_volume()
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
    _write_config_to_volume()
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
    _write_config_to_volume()
    return jsonify({"message": "DR plan deleted"})


# ── Plan Entries ──────────────────────────────────────────────────────────────

def _lookup_primary_storage_id(db, source_endpoint_id, source_svm, source_volume):
    """Return the primary PVE storage ID for a given source volume, or ''."""
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
    _write_config_to_volume()
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
    _write_config_to_volume()
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
    _write_config_to_volume()
    return jsonify({"message": "Entry removed"})


def _auto_detect_entries():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    plan = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not plan_id or not plan:
        return {"error": "DR plan not found"}, 404
    site = db.query_one("SELECT * FROM netapp_dr_sites WHERE id=?", (plan["dr_site_id"],))
    if not site:
        return {"error": "DR site not found"}, 404
    dr_endpoint_id = site["endpoint_id"]
    rels = db.query(
        "SELECT * FROM netapp_snapmirror_relationships WHERE dest_endpoint_id=?", (dr_endpoint_id,)
    ) or []
    added = 0
    skipped = 0
    for rel in rels:
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
             rel["dest_endpoint_id"] or dr_endpoint_id,
             rel["dest_svm"] or "", rel["dest_volume"] or "",
             primary_storage_id, "[]", sort_order, _now())
        )
        added += 1
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _write_config_to_volume()
    if added > 0:
        msg = f"Added {added} datastore(s)"
        if skipped: msg += f" ({skipped} already present)"
    elif len(rels) == 0:
        msg = "No SnapMirror relationships found for this DR site endpoint — run 'Scan Relationships' in the SnapMirror tab first"
    else:
        msg = f"No new entries added ({skipped} already present)"
    return jsonify({"added": added, "skipped": skipped, "total": len(rels), "message": msg})


# ── VM Groups ─────────────────────────────────────────────────────────────────

def _create_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id    = (data.get("plan_id") or "").strip()
    name       = (data.get("name") or "").strip()
    group_type = (data.get("group_type") or "standard").strip()
    if not plan_id or not name:
        return {"error": "plan_id and name are required"}, 400
    if group_type not in ("core", "standard"):
        group_type = "standard"
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    if group_type == "core":
        if db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE plan_id=? AND group_type='core'", (plan_id,)):
            return {"error": "A Core group already exists for this plan"}, 409
        sort_order = 0
    else:
        max_ord = db.query_one("SELECT MAX(sort_order) as m FROM netapp_dr_vm_groups WHERE plan_id=?", (plan_id,))
        sort_order = (max_ord["m"] or -1) + 1
    gid = str(uuid.uuid4())[:8]
    start_mode = "auto" if group_type == "core" else data.get("start_mode", "auto")
    db.execute(
        "INSERT INTO netapp_dr_vm_groups "
        "(id, plan_id, name, group_type, sort_order, start_mode, startup_delay_sec, max_parallel, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (gid, plan_id, name, group_type, sort_order, start_mode,
         int(data.get("startup_delay_sec", 30)),
         int(data.get("max_parallel", 1)), _now())
    )
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _write_config_to_volume()
    row = dict(db.query_one("SELECT * FROM netapp_dr_vm_groups WHERE id=?", (gid,)))
    row["vms"] = []
    return jsonify(row), 201


def _update_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    group_id = (data.get("group_id") or "").strip()
    db = get_db()
    grp = db.query_one("SELECT * FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (group_id, plan_id))
    if not grp:
        return {"error": "VM group not found"}, 404
    is_core = grp["group_type"] == "core"
    allowed = {"name", "startup_delay_sec", "max_parallel"}
    if not is_core:
        allowed.add("start_mode")
    updates, params = [], []
    for k in allowed:
        if k in data:
            updates.append(f"{k}=?"); params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(group_id)
    db.execute(f"UPDATE netapp_dr_vm_groups SET {', '.join(updates)} WHERE id=?", params)
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _write_config_to_volume()
    return jsonify({"message": "VM group updated"})


def _delete_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    group_id = (data.get("group_id") or "").strip()
    db = get_db()
    grp = db.query_one("SELECT * FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (group_id, plan_id))
    if not grp:
        return {"error": "VM group not found"}, 404
    if grp["group_type"] == "core":
        return {"error": "The Core group cannot be deleted"}, 409
    db.execute("DELETE FROM netapp_dr_vm_groups WHERE id=?", (group_id,))
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _write_config_to_volume()
    return jsonify({"message": "VM group deleted"})


def _reorder_vm_groups():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    # Core group always stays at sort_order=0 regardless of reorder
    core = db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE plan_id=? AND group_type='core'", (plan_id,))
    for i, gid in enumerate(data.get("order") or []):
        grp = db.query_one("SELECT group_type FROM netapp_dr_vm_groups WHERE id=?", (gid,))
        if grp and grp["group_type"] == "core":
            db.execute("UPDATE netapp_dr_vm_groups SET sort_order=0 WHERE id=? AND plan_id=?", (gid, plan_id))
        else:
            # Standard groups start at sort_order=1+
            non_core_index = i + 1 if core else i
            db.execute("UPDATE netapp_dr_vm_groups SET sort_order=? WHERE id=? AND plan_id=?", (non_core_index, gid, plan_id))
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    _write_config_to_volume()
    return jsonify({"message": "Groups reordered"})


# ── VM Assignments ─────────────────────────────────────────────────────────────

def _add_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    group_id = (data.get("group_id") or "").strip()
    vmid = data.get("vmid")
    if not plan_id or not group_id or vmid is None:
        return {"error": "plan_id, group_id, vmid are required"}, 400
    try:
        vmid = int(vmid)
    except (ValueError, TypeError):
        return {"error": "vmid must be a number"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (group_id, plan_id)):
        return {"error": "VM group not found"}, 404
    existing = db.query_one(
        "SELECT va.id FROM netapp_dr_vm_assignments va "
        "JOIN netapp_dr_vm_groups vg ON va.group_id=vg.id "
        "WHERE vg.plan_id=? AND va.vmid=?", (plan_id, vmid)
    )
    if existing:
        return {"error": f"VM {vmid} is already assigned to a group in this plan"}, 409
    max_ord = db.query_one("SELECT MAX(start_order) as m FROM netapp_dr_vm_assignments WHERE group_id=?", (group_id,))
    start_order = (max_ord["m"] or -1) + 1
    vid = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_assignments (id, group_id, vmid, vm_name, target_node, start_order, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (vid, group_id, vmid, data.get("vm_name", ""), data.get("target_node", ""), start_order, _now())
    )
    _write_config_to_volume()
    return jsonify({"id": vid, "message": "VM added to group"}), 201


def _remove_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id          = (data.get("plan_id") or "").strip()
    group_id         = (data.get("group_id") or "").strip()
    vm_assignment_id = (data.get("vm_id") or "").strip()
    db = get_db()
    row = db.query_one(
        "SELECT va.id FROM netapp_dr_vm_assignments va "
        "JOIN netapp_dr_vm_groups vg ON va.group_id=vg.id "
        "WHERE va.id=? AND vg.id=? AND vg.plan_id=?",
        (vm_assignment_id, group_id, plan_id)
    )
    if not row:
        return {"error": "VM assignment not found"}, 404
    db.execute("DELETE FROM netapp_dr_vm_assignments WHERE id=?", (vm_assignment_id,))
    _write_config_to_volume()
    return jsonify({"message": "VM removed from group"})


def _update_vm_assignment():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id          = (data.get("plan_id") or "").strip()
    group_id         = (data.get("group_id") or "").strip()
    vm_assignment_id = (data.get("vm_id") or "").strip()
    db = get_db()
    row = db.query_one(
        "SELECT va.id FROM netapp_dr_vm_assignments va "
        "JOIN netapp_dr_vm_groups vg ON va.group_id=vg.id "
        "WHERE va.id=? AND vg.id=? AND vg.plan_id=?",
        (vm_assignment_id, group_id, plan_id)
    )
    if not row:
        return {"error": "VM assignment not found"}, 404
    allowed = {"vm_name", "target_node", "start_order", "group_id"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            if k == "group_id":
                if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (data[k], plan_id)):
                    return {"error": "Target group not in same plan"}, 400
            updates.append(f"{k}=?"); params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(vm_assignment_id)
    db.execute(f"UPDATE netapp_dr_vm_assignments SET {', '.join(updates)} WHERE id=?", params)
    _write_config_to_volume()
    return jsonify({"message": "VM assignment updated"})


# ── Plan Status ───────────────────────────────────────────────────────────────

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


# ── Failover ─────────────────────────────────────────────────────────────────

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
            # Write new role (this instance is now MASTER)
            db2 = get_db()
            db2.execute("UPDATE netapp_plugin_config SET role='MASTER', role_forced=0, updated_at=? WHERE id='default'", (_now(),))
            _write_config_to_volume()

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

            # Restore VM configs from snapmanifest
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

        # Start VM groups (sequential, Core first, with max_parallel per group)
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
                    _log(f"[INFO]   → Skipped (manual group — start via UI after confirming primary is down)")
                    continue

                first_host = next(
                    (h for e in entries for h in _json_field(e.get("dr_pve_host_ids"))), None
                )
                if not first_host:
                    _log(f"[WARN]   → No DR PVE host found — skipping group"); continue

                max_par = max(1, int(group.get("max_parallel", 1)))
                for batch_start in range(0, len(assignments), max_par):
                    batch = assignments[batch_start:batch_start + max_par]
                    batch_threads = []
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

        _log("[INFO] ✅ Failover complete — this instance is now MASTER")
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

    # Role + config volume
    rpr(PLUGIN_ID, "dr/role",                    _get_role)
    rpr(PLUGIN_ID, "dr/role/set",                _set_role)
    rpr(PLUGIN_ID, "dr/role/detect",             _detect_role)
    rpr(PLUGIN_ID, "dr/config-volume",           _config_volume_status)
    rpr(PLUGIN_ID, "dr/config-volume/setup",     _setup_config_volume)
    rpr(PLUGIN_ID, "dr/config-volume/nfs-volumes", _list_nfs_volumes)

    # DR Sites
    rpr(PLUGIN_ID, "dr/sites",                   _list_dr_sites)
    rpr(PLUGIN_ID, "dr/sites/create",            _create_dr_site)
    rpr(PLUGIN_ID, "dr/sites/update",            _update_dr_site)
    rpr(PLUGIN_ID, "dr/sites/delete",            _delete_dr_site)
    rpr(PLUGIN_ID, "dr/clusters",                _list_pegaprox_clusters)

    # DR Plans
    rpr(PLUGIN_ID, "dr/plans",                   _list_dr_plans)
    rpr(PLUGIN_ID, "dr/plans/create",            _create_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/detail",            _get_dr_plan_detail)
    rpr(PLUGIN_ID, "dr/plans/update",            _update_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/delete",            _delete_dr_plan)

    # Plan Entries
    rpr(PLUGIN_ID, "dr/plans/entries/add",       _add_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/update",    _update_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/delete",    _delete_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/auto-detect",       _auto_detect_entries)

    # VM Groups
    rpr(PLUGIN_ID, "dr/plans/groups/create",     _create_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/update",     _update_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/delete",     _delete_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/reorder",    _reorder_vm_groups)

    # VM Assignments
    rpr(PLUGIN_ID, "dr/plans/groups/vms/add",    _add_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/delete", _remove_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/update", _update_vm_assignment)

    # Status + Failover
    rpr(PLUGIN_ID, "dr/plans/status",            _plan_status)
    rpr(PLUGIN_ID, "dr/plans/precheck",          _failover_precheck)
    rpr(PLUGIN_ID, "dr/plans/failover",          _start_failover)
    rpr(PLUGIN_ID, "dr/plans/failover-jobs",     _get_failover_jobs)
    rpr(PLUGIN_ID, "dr/plans/snapshots",         _list_dr_snapshots)
