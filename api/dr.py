"""
Disaster Recovery API  (v1.2.0 — configuration & plan management)

Routes follow the plugin framework pattern:
  - No URL path parameters (IDs passed in JSON body or query string)
  - No methods= kwarg (framework accepts all methods; handlers check request.method)
  - Verb-based paths for mutating operations (create/update/delete)

Routes under /api/plugins/netapp_storage/api/...

  dr/sites                        GET  — list DR sites
  dr/sites/create                 POST — create DR site
  dr/sites/update                 POST {id} — update DR site
  dr/sites/delete                 POST {id} — delete DR site
  dr/sites/test-ssh               POST {id} — test SSH connection to DR PegaProx

  dr/plans                        GET  — list DR plans
  dr/plans/create                 POST — create DR plan
  dr/plans/detail                 GET  ?plan_id= — plan detail (entries + groups)
  dr/plans/update                 POST {id} — update plan
  dr/plans/delete                 POST {id} — delete plan

  dr/plans/entries/add            POST {plan_id, ...} — add datastore entry
  dr/plans/entries/update         POST {plan_id, entry_id, ...} — update entry fields
  dr/plans/entries/delete         POST {plan_id, entry_id} — remove entry
  dr/plans/auto-detect            POST {plan_id} — detect SnapMirror rels

  dr/plans/groups/create          POST {plan_id, name, ...} — create VM group
  dr/plans/groups/update          POST {plan_id, group_id, ...} — update VM group
  dr/plans/groups/delete          POST {plan_id, group_id} — delete VM group
  dr/plans/groups/reorder         POST {plan_id, order:[gid,...]} — reorder groups

  dr/plans/groups/vms/add         POST {plan_id, group_id, vmid, ...} — add VM
  dr/plans/groups/vms/delete      POST {plan_id, group_id, vm_id} — remove VM
  dr/plans/groups/vms/update      POST {plan_id, group_id, vm_id, ...} — update VM

  dr/plans/status                 GET  ?plan_id= — live SnapMirror status
  dr/plans/sync                   POST {plan_id} — push DB export via SCP
  dr/plans/sync-status            GET  ?plan_id= — last sync jobs
"""

import json
import logging
import subprocess
import tempfile
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
        s.setdefault("last_test_at", "")
        s.setdefault("last_test_result", "")
        result.append(s)
    return jsonify(result)


def _resolve_dr_pve_hosts(data, db):
    """Resolve DR PVE host IDs from one of three input modes.

    Mode 1 — existing:   data["pve_host_ids"] = ["id1", "id2", ...]
    Mode 2 — inline:     data["pve_hosts_inline"] = [{"name","host","username","password"}, ...]
    Mode 3 — cluster:    data["pve_cluster_id"] = "<pegaprox_cluster_id>"

    Returns a list of netapp_pve_hosts.id values (creates new entries for modes 2+3).
    """
    now = _now()

    # Mode 1: already-registered host IDs
    if data.get("pve_host_ids"):
        return [h for h in data["pve_host_ids"] if h]

    # Mode 2: inline host definitions
    if data.get("pve_hosts_inline"):
        host_ids = []
        for h in data["pve_hosts_inline"]:
            host_val  = (h.get("host") or "").strip()
            name_val  = (h.get("name") or host_val).strip()
            user_val  = (h.get("username") or "root").strip()
            pass_val  = h.get("password", "")
            if not host_val:
                continue
            # idempotent: reuse existing entry with same host
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

    # Mode 3: import from PegaProx cluster
    if data.get("pve_cluster_id"):
        cluster_id = data["pve_cluster_id"]
        host_ids = []
        try:
            from pegaprox.globals import cluster_managers
            mgr = cluster_managers.get(cluster_id)
            if not mgr:
                return []
            node_status = mgr.get_node_status() or {}
            # cluster object has host + credentials
            cluster_host = getattr(mgr, "host", "") or getattr(mgr, "api_host", "")
            cluster_user = getattr(mgr, "user", "root")
            cluster_pass = getattr(mgr, "password", "") or getattr(mgr, "_password", "")
            for node_name, ninfo in node_status.items():
                node_ip = ninfo.get("ip") or ninfo.get("host") or node_name
                # try to resolve node IP from PVE API
                try:
                    nodes = mgr.get_nodes() or []
                    for n in nodes:
                        if n.get("node") == node_name:
                            node_ip = n.get("ip") or n.get("host") or cluster_host
                            break
                except Exception:
                    node_ip = cluster_host  # fallback: use cluster API host
                existing = db.query_one("SELECT id FROM netapp_pve_hosts WHERE host=?", (node_ip,))
                if existing:
                    hid = existing["id"]
                else:
                    hid = str(uuid.uuid4())[:8]
                    pw_enc = db._encrypt(cluster_pass) if cluster_pass else ""
                    db.execute(
                        "INSERT INTO netapp_pve_hosts (id, name, host, port, username, password_encrypted, ssl_verify, nfs_ip, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (hid, node_name, node_ip, 8006, cluster_user, pw_enc, 0, "", now)
                    )
                host_ids.append(hid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR site: cluster import failed: {exc}")
        return host_ids

    return []


def _list_pegaprox_clusters():
    """Return PegaProx-managed clusters from the clusters table."""
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
    pw_enc = ""
    if data.get("sync_password"):
        try:
            pw_enc = db._encrypt(data["sync_password"])
        except Exception:
            pass

    db.execute(
        "INSERT INTO netapp_dr_sites (id, name, endpoint_id, pve_host_ids, sync_host, sync_user, sync_path, sync_password_encrypted, description, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sid, name, endpoint_id,
         json.dumps(pve_host_ids),
         data.get("sync_host", ""),
         data.get("sync_user", "root"),
         data.get("sync_path", "/opt/PegaProx/plugins/netapp_storage/"),
         pw_enc,
         data.get("description", ""),
         now, now)
    )
    return jsonify({"id": sid, "message": "DR site created", "pve_host_ids": pve_host_ids}), 201


def _update_dr_site():
    err = _require_admin()
    if err: return err
    data = _body()
    site_id = (data.get("id") or "").strip()
    db = get_db()
    if not site_id or not db.query_one("SELECT id FROM netapp_dr_sites WHERE id=?", (site_id,)):
        return {"error": "DR site not found"}, 404
    allowed = {"name", "endpoint_id", "pve_host_ids", "sync_host", "sync_user", "sync_path", "description"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            val = json.dumps(data[k]) if k == "pve_host_ids" else data[k]
            updates.append(f"{k}=?")
            params.append(val)
    if "sync_password" in data:
        if data["sync_password"]:
            try:
                updates.append("sync_password_encrypted=?")
                params.append(db._encrypt(data["sync_password"]))
            except Exception:
                pass
        else:
            updates.append("sync_password_encrypted=?")
            params.append("")  # clear password
    if not updates:
        return {"error": "No fields to update"}, 400
    updates.append("updated_at=?")
    params.extend([_now(), site_id])
    db.execute(f"UPDATE netapp_dr_sites SET {', '.join(updates)} WHERE id=?", params)
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
        return {"error": f"Cannot delete: {len(plans)} DR plan(s) use this site. Delete plans first."}, 409
    db.execute("DELETE FROM netapp_dr_sites WHERE id=?", (site_id,))
    return jsonify({"message": "DR site deleted"})


def _dr_start_job(site_id, job_type, username):
    """Create a netapp_jobs entry for a DR site operation. Returns job_id."""
    db = get_db()
    job_id = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_jobs (id, job_type, status, log_json, created_by, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (job_id, job_type, "running", "[]", username, _now())
    )
    return job_id


def _dr_job_log(job_id, lines):
    db = get_db()
    db.execute("UPDATE netapp_jobs SET log_json=? WHERE id=?", (json.dumps(lines), job_id))


def _dr_job_finish(job_id, status, lines, site_id=None, test_result=None):
    db = get_db()
    db.execute(
        "UPDATE netapp_jobs SET status=?, log_json=?, completed_at=? WHERE id=?",
        (status, json.dumps(lines), _now(), job_id)
    )
    if site_id and test_result is not None:
        result_str = ("✅ " if status == "done" else "❌ ") + test_result
        db.execute(
            "UPDATE netapp_dr_sites SET last_test_at=?, last_test_result=?, updated_at=? WHERE id=?",
            (_now(), result_str[:500], _now(), site_id)
        )


def _build_ssh_cmd(host, user, password, key_path, extra_args, remote_cmd=None):
    """Build ssh or sshpass+ssh command list."""
    import shutil
    has_sshpass = shutil.which("sshpass") is not None
    if password and has_sshpass:
        cmd = ["sshpass", "-p", password, "ssh",
               "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    else:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
               "-o", "BatchMode=yes"]
        if key_path:
            cmd += ["-i", key_path]
    cmd += extra_args
    cmd.append(f"{user}@{host}")
    if remote_cmd:
        cmd.append(remote_cmd)
    return cmd


def _build_scp_cmd(host, user, password, key_path, src, dest):
    """Build scp or sshpass+scp command list."""
    import shutil
    has_sshpass = shutil.which("sshpass") is not None
    if password and has_sshpass:
        cmd = ["sshpass", "-p", password, "scp",
               "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
    else:
        cmd = ["scp", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]
        if key_path:
            cmd += ["-i", key_path]
    cmd += [src, dest]
    return cmd


def _get_site_credentials(site):
    """Return (host, user, password, key_path) for a DR site."""
    host = site.get("sync_host", "")
    user = site.get("sync_user", "root")
    pw_enc = site.get("sync_password_encrypted", "")
    password = ""
    if pw_enc:
        try:
            db = get_db()
            password = db._decrypt(pw_enc)
        except Exception:
            pass
    key_path = _get_ssh_key_path()
    return host, user, password, key_path


def _test_dr_site_ssh():
    err = _require_admin()
    if err: return err
    data = _body()
    site_id = (data.get("id") or "").strip()
    db = get_db()
    row = db.query_one("SELECT * FROM netapp_dr_sites WHERE id=?", (site_id,))
    if not row:
        return {"error": "DR site not found"}, 404
    site = dict(row)
    host, user, password, key_path = _get_site_credentials(site)
    if not host:
        return {"error": "No sync_host configured"}, 400

    username = request.session.get("user", "system")
    job_id = _dr_start_job(site_id, "dr_ssh_test", username)
    threading.Thread(target=_run_ssh_test, args=(job_id, site_id, host, user, password, key_path), daemon=True).start()
    return jsonify({"job_id": job_id, "message": "SSH test started"}), 202


def _run_ssh_test(job_id, site_id, host, user, password, key_path):
    lines = []
    def _log(msg):
        lines.append({"ts": _now(), "msg": msg})
        _dr_job_log(job_id, lines)

    _log(f"[INFO] Testing SSH connection to {user}@{host} …")
    if not password and not key_path:
        _log("[WARN] No SSH key found and no password configured")
    elif password:
        _log("[INFO] Using password authentication (sshpass)")
    else:
        _log(f"[INFO] Using SSH key: {key_path}")

    cmd = _build_ssh_cmd(host, user, password, key_path, [], "echo OK")
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=15)
        if result.returncode == 0 and b"OK" in result.stdout:
            _log(f"[INFO] ✅ SSH connection successful")
            _dr_job_finish(job_id, "done", lines, site_id, f"SSH to {user}@{host} successful")
        else:
            stderr = result.stderr.decode(errors="replace")[:300]
            msg = stderr or "SSH failed (no output)"
            _log(f"[ERR] {msg}")
            _dr_job_finish(job_id, "failed", lines, site_id, msg)
    except subprocess.TimeoutExpired:
        _log(f"[ERR] Connection to {host} timed out")
        _dr_job_finish(job_id, "failed", lines, site_id, f"Connection to {host} timed out")
    except Exception as exc:
        _log(f"[ERR] {exc}")
        _dr_job_finish(job_id, "failed", lines, site_id, str(exc)[:200])


def _push_ssh_key_to_dr():
    """Push the primary PegaProx SSH public key to the DR PegaProx via ssh-copy-id."""
    err = _require_admin()
    if err: return err
    data = _body()
    site_id = (data.get("id") or "").strip()
    db = get_db()
    row = db.query_one("SELECT * FROM netapp_dr_sites WHERE id=?", (site_id,))
    if not row:
        return {"error": "DR site not found"}, 404
    site = dict(row)
    host, user, password, key_path = _get_site_credentials(site)
    if not host:
        return {"error": "No sync_host configured"}, 400
    if not password:
        return {"error": "sync_password required to push SSH key. Set it in the DR site settings."}, 400

    username = request.session.get("user", "system")
    job_id = _dr_start_job(site_id, "dr_push_ssh_key", username)
    threading.Thread(target=_run_push_ssh_key, args=(job_id, site_id, host, user, password, key_path), daemon=True).start()
    return jsonify({"job_id": job_id, "message": "SSH key push started"}), 202


def _run_push_ssh_key(job_id, site_id, host, user, password, key_path):
    import shutil
    lines = []
    def _log(msg):
        lines.append({"ts": _now(), "msg": msg})
        _dr_job_log(job_id, lines)

    _log(f"[INFO] Pushing SSH public key to {user}@{host} …")
    has_sshpass = shutil.which("sshpass") is not None
    if not has_sshpass:
        _log("[ERR] sshpass not installed. Run: apt install sshpass")
        _dr_job_finish(job_id, "failed", lines)
        return
    if not key_path:
        _log("[ERR] No SSH public key found on this PegaProx instance")
        _dr_job_finish(job_id, "failed", lines)
        return

    pub_key_path = key_path + ".pub" if not key_path.endswith(".pub") else key_path
    if not __import__("os").path.exists(pub_key_path):
        _log(f"[ERR] Public key not found: {pub_key_path}")
        _dr_job_finish(job_id, "failed", lines)
        return

    cmd = ["sshpass", "-p", password, "ssh-copy-id",
           "-i", pub_key_path,
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10",
           f"{user}@{host}"]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode == 0:
            _log(f"[INFO] ✅ SSH key successfully pushed to {user}@{host}")
            _log("[INFO] You can now remove the sync_password — key-based auth will be used")
            _dr_job_finish(job_id, "done", lines, site_id, f"SSH key pushed to {user}@{host}")
        else:
            stderr = result.stderr.decode(errors="replace")[:300]
            _log(f"[ERR] ssh-copy-id failed: {stderr}")
            _dr_job_finish(job_id, "failed", lines)
    except subprocess.TimeoutExpired:
        _log(f"[ERR] Timed out pushing key to {host}")
        _dr_job_finish(job_id, "failed", lines)
    except Exception as exc:
        _log(f"[ERR] {exc}")
        _dr_job_finish(job_id, "failed", lines)


def _get_ssh_key_path():
    import os
    candidates = []
    try:
        import pwd
        home = pwd.getpwuid(os.getuid()).pw_dir
        candidates = [
            os.path.join(home, ".ssh", "id_ed25519"),
            os.path.join(home, ".ssh", "id_rsa"),
        ]
    except Exception:
        pass
    candidates += ["/opt/PegaProx/.ssh/id_ed25519", "/opt/PegaProx/.ssh/id_rsa"]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


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
    return jsonify({"id": pid, "message": "DR plan created"}), 201


def _get_dr_plan_detail():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    row = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not row:
        return {"error": "DR plan not found"}, 404
    p = _plan_summary(row, db)

    entries = db.query("SELECT * FROM netapp_dr_plan_entries WHERE plan_id=? ORDER BY sort_order", (plan_id,)) or []
    p["entries"] = [_enrich_entry(dict(e), db) for e in entries]

    groups = db.query("SELECT * FROM netapp_dr_vm_groups WHERE plan_id=? ORDER BY sort_order", (plan_id,)) or []
    p["vm_groups"] = []
    for g in groups:
        grp = dict(g)
        vms = db.query("SELECT * FROM netapp_dr_vm_assignments WHERE group_id=? ORDER BY start_order", (grp["id"],)) or []
        grp["vms"] = [dict(v) for v in vms]
        p["vm_groups"].append(grp)

    last_sync = db.query_one(
        "SELECT state, created_at, completed_at FROM netapp_dr_jobs "
        "WHERE plan_id=? AND job_type='sync' ORDER BY created_at DESC LIMIT 1",
        (plan_id,)
    )
    p["last_sync_job"] = dict(last_sync) if last_sync else None
    return jsonify(p)


def _update_dr_plan():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    allowed = {"name", "notes"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            updates.append(f"{k}=?")
            params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    updates.append("updated_at=?")
    params.extend([_now(), plan_id])
    db.execute(f"UPDATE netapp_dr_plans SET {', '.join(updates)} WHERE id=?", params)
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
        return {"error": f"Cannot delete plan in state '{row['state']}'. Reset to standby first."}, 409
    db.execute("DELETE FROM netapp_dr_plans WHERE id=?", (plan_id,))
    return jsonify({"message": "DR plan deleted"})


# ── Plan Entries ──────────────────────────────────────────────────────────────

def _enrich_entry(entry, db):
    ep = db.query_one("SELECT name FROM netapp_endpoints WHERE id=?", (entry.get("source_endpoint_id", ""),))
    entry["source_endpoint_name"] = ep["name"] if ep else ""
    dr_ep = db.query_one("SELECT name FROM netapp_endpoints WHERE id=?", (entry.get("dr_endpoint_id", ""),))
    entry["dr_endpoint_name"] = dr_ep["name"] if dr_ep else ""
    entry["dr_pve_host_ids"] = _json_field(entry.get("dr_pve_host_ids"))
    if entry.get("snapmirror_rel_uuid"):
        rel = db.query_one(
            "SELECT state, healthy, lag_time, last_transfer_time "
            "FROM netapp_snapmirror_relationships WHERE relationship_uuid=?",
            (entry["snapmirror_rel_uuid"],)
        )
        if rel:
            entry.update({
                "sm_state": rel["state"],
                "sm_healthy": bool(rel["healthy"]),
                "sm_lag_time": rel["lag_time"],
                "sm_last_transfer": rel["last_transfer_time"],
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
        return {"error": "plan_id, source_endpoint_id, source_svm, source_volume are required"}, 400
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
        "(id, plan_id, source_endpoint_id, source_svm, source_volume, mapping_id, ds_id, "
        "snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume, dr_pve_storage_id, dr_pve_host_ids, sort_order, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, plan_id, source_endpoint_id, source_svm, source_volume,
         data.get("mapping_id", ""), data.get("ds_id", ""),
         snapmirror_rel_uuid, dr_endpoint_id, dr_svm, dr_volume,
         data.get("dr_pve_storage_id", ""),
         json.dumps(data.get("dr_pve_host_ids") or []),
         sort_order, _now())
    )
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    entry = dict(db.query_one("SELECT * FROM netapp_dr_plan_entries WHERE id=?", (eid,)))
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
            updates.append(f"{k}=?")
            params.append(val)
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(entry_id)
    db.execute(f"UPDATE netapp_dr_plan_entries SET {', '.join(updates)} WHERE id=?", params)
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    entry = dict(db.query_one("SELECT * FROM netapp_dr_plan_entries WHERE id=?", (entry_id,)))
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
    return jsonify({"message": "Entry removed"})


def _auto_detect_entries():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    entries = db.query(
        "SELECT * FROM netapp_dr_plan_entries WHERE plan_id=? AND snapmirror_rel_uuid=''", (plan_id,)
    ) or []
    updated = 0
    for e in entries:
        rel = db.query_one(
            "SELECT relationship_uuid, dest_endpoint_id, dest_svm, dest_volume "
            "FROM netapp_snapmirror_relationships "
            "WHERE source_endpoint_id=? AND source_svm=? AND source_volume=? LIMIT 1",
            (e["source_endpoint_id"], e["source_svm"], e["source_volume"])
        )
        if rel:
            db.execute(
                "UPDATE netapp_dr_plan_entries SET snapmirror_rel_uuid=?, dr_endpoint_id=?, dr_svm=?, dr_volume=? WHERE id=?",
                (rel["relationship_uuid"],
                 rel["dest_endpoint_id"] or e["dr_endpoint_id"],
                 rel["dest_svm"]         or e["dr_svm"],
                 rel["dest_volume"]      or e["dr_volume"],
                 e["id"])
            )
            updated += 1
    return jsonify({"updated": updated, "total": len(entries)})


# ── VM Groups ─────────────────────────────────────────────────────────────────

def _create_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    name    = (data.get("name") or "").strip()
    if not plan_id or not name:
        return {"error": "plan_id and name are required"}, 400
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    max_ord = db.query_one("SELECT MAX(sort_order) as m FROM netapp_dr_vm_groups WHERE plan_id=?", (plan_id,))
    sort_order = (max_ord["m"] or -1) + 1
    gid = str(uuid.uuid4())[:8]
    db.execute(
        "INSERT INTO netapp_dr_vm_groups (id, plan_id, name, sort_order, start_mode, startup_delay_sec, health_check_timeout_sec, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (gid, plan_id, name, sort_order,
         data.get("start_mode", "auto"),
         int(data.get("startup_delay_sec", 30)),
         int(data.get("health_check_timeout_sec", 120)),
         _now())
    )
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
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
    if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (group_id, plan_id)):
        return {"error": "VM group not found"}, 404
    allowed = {"name", "start_mode", "startup_delay_sec", "health_check_timeout_sec"}
    updates, params = [], []
    for k in allowed:
        if k in data:
            updates.append(f"{k}=?")
            params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(group_id)
    db.execute(f"UPDATE netapp_dr_vm_groups SET {', '.join(updates)} WHERE id=?", params)
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    return jsonify({"message": "VM group updated"})


def _delete_vm_group():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id  = (data.get("plan_id") or "").strip()
    group_id = (data.get("group_id") or "").strip()
    db = get_db()
    if not db.query_one("SELECT id FROM netapp_dr_vm_groups WHERE id=? AND plan_id=?", (group_id, plan_id)):
        return {"error": "VM group not found"}, 404
    db.execute("DELETE FROM netapp_dr_vm_groups WHERE id=?", (group_id,))
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
    return jsonify({"message": "VM group deleted"})


def _reorder_vm_groups():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    for i, gid in enumerate(data.get("order") or []):
        db.execute(
            "UPDATE netapp_dr_vm_groups SET sort_order=? WHERE id=? AND plan_id=?",
            (i, gid, plan_id)
        )
    db.execute("UPDATE netapp_dr_plans SET updated_at=? WHERE id=?", (_now(), plan_id))
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
        "WHERE vg.plan_id=? AND va.vmid=?",
        (plan_id, vmid)
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
            updates.append(f"{k}=?")
            params.append(data[k])
    if not updates:
        return {"error": "No fields to update"}, 400
    params.append(vm_assignment_id)
    db.execute(f"UPDATE netapp_dr_vm_assignments SET {', '.join(updates)} WHERE id=?", params)
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
            "entry_id": e["id"],
            "source_volume": e["source_volume"],
            "dr_volume": e["dr_volume"],
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
                    "sm_state": rel["state"],
                    "sm_healthy": bool(rel["healthy"]),
                    "sm_lag_time": rel["lag_time"],
                    "sm_last_transfer": rel["last_transfer_time"],
                    "sm_last_scanned": rel["last_scanned_at"],
                })
                if not rel["healthy"]:
                    overall_healthy = False
            else:
                item["sm_state"] = "not_scanned"
                overall_healthy = False
        else:
            item["sm_state"] = "no_relationship"
            overall_healthy = False
        status_list.append(item)

    plan = db.query_one("SELECT state, last_tested_at, last_sync_at FROM netapp_dr_plans WHERE id=?", (plan_id,))
    return jsonify({
        "plan_id": plan_id,
        "plan_state": plan["state"] if plan else "",
        "overall_healthy": overall_healthy,
        "entries": status_list,
        "last_tested_at": plan["last_tested_at"] if plan else "",
        "last_sync_at": plan["last_sync_at"] if plan else "",
    })


# ── DB Sync ───────────────────────────────────────────────────────────────────

def _sync_to_dr_site():
    err = _require_admin()
    if err: return err
    data = _body()
    plan_id = (data.get("plan_id") or "").strip()
    db = get_db()
    row = db.query_one("SELECT * FROM netapp_dr_plans WHERE id=?", (plan_id,))
    if not row:
        return {"error": "DR plan not found"}, 404
    site = db.query_one("SELECT * FROM netapp_dr_sites WHERE id=?", (dict(row)["dr_site_id"],))
    if not site:
        return {"error": "DR site not found"}, 404
    site = dict(site)
    if not site.get("sync_host"):
        return {"error": "No sync_host configured on DR site"}, 400

    job_id = str(uuid.uuid4())[:8]
    now = _now()
    username = request.session.get("user", "system")
    db.execute(
        "INSERT INTO netapp_dr_jobs (id, plan_id, job_type, state, log_json, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, plan_id, "sync", "running", "[]", username, now)
    )
    threading.Thread(target=_execute_sync, args=(job_id, plan_id, site), daemon=True).start()
    return jsonify({"job_id": job_id, "message": "Sync started"}), 202


def _execute_sync(job_id, plan_id, site):
    log_lines = []

    def _log(msg):
        log_lines.append({"ts": _now(), "msg": msg})
        db = get_db()
        db.execute("UPDATE netapp_dr_jobs SET log_json=? WHERE id=?", (json.dumps(log_lines), job_id))

    def _finish(state):
        db = get_db()
        db.execute(
            "UPDATE netapp_dr_jobs SET state=?, completed_at=?, log_json=? WHERE id=?",
            (state, _now(), json.dumps(log_lines), job_id)
        )
        if state == "success":
            db.execute("UPDATE netapp_dr_plans SET last_sync_at=?, updated_at=? WHERE id=?",
                       (_now(), _now(), plan_id))

    try:
        _log("[INFO] Starting DB export…")
        from .settings import build_export_payload
        payload = build_export_payload()
        import os
        export_json = json.dumps(payload, indent=2)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False,
                                         prefix="netapp_dr_sync_") as f:
            f.write(export_json)
            tmp_path = f.name
        _log(f"[INFO] Export written ({len(export_json)} bytes)")

        host, user, password, key_path = _get_site_credentials(site)
        remote_path = site.get("sync_path", "/opt/PegaProx/plugins/netapp_storage/").rstrip("/")
        remote_dest = f"{user}@{host}:{remote_path}/netapp_storage_dr_sync.json"
        cmd = _build_scp_cmd(host, user, password, key_path, tmp_path, remote_dest)

        _log(f"[INFO] SCP → {remote_dest}")
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")[:300]
            _log(f"[ERR] SCP failed: {stderr}")
            _finish("failed")
            return

        _log("[INFO] SCP completed successfully")
        _finish("success")
    except Exception as exc:
        _log(f"[ERR] Sync failed: {exc}")
        _finish("failed")


def _get_sync_status():
    plan_id = request.args.get("plan_id") or (_body().get("plan_id") or "")
    db = get_db()
    if not plan_id or not db.query_one("SELECT id FROM netapp_dr_plans WHERE id=?", (plan_id,)):
        return {"error": "DR plan not found"}, 404
    jobs = db.query(
        "SELECT id, state, log_json, created_at, completed_at, created_by "
        "FROM netapp_dr_jobs WHERE plan_id=? AND job_type='sync' ORDER BY created_at DESC LIMIT 5",
        (plan_id,)
    ) or []
    result = []
    for j in jobs:
        row = dict(j)
        try:
            row["log"] = json.loads(row.pop("log_json") or "[]")
        except Exception:
            row["log"] = []
        result.append(row)
    return jsonify(result)


# ── Route Registration ────────────────────────────────────────────────────────

def register_routes():
    rpr = register_plugin_route

    rpr(PLUGIN_ID, "dr/sites",              _list_dr_sites)
    rpr(PLUGIN_ID, "dr/sites/create",       _create_dr_site)
    rpr(PLUGIN_ID, "dr/clusters",           _list_pegaprox_clusters)
    rpr(PLUGIN_ID, "dr/sites/update",       _update_dr_site)
    rpr(PLUGIN_ID, "dr/sites/delete",       _delete_dr_site)
    rpr(PLUGIN_ID, "dr/sites/test-ssh",     _test_dr_site_ssh)
    rpr(PLUGIN_ID, "dr/sites/push-ssh-key", _push_ssh_key_to_dr)

    rpr(PLUGIN_ID, "dr/plans",              _list_dr_plans)
    rpr(PLUGIN_ID, "dr/plans/create",       _create_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/detail",       _get_dr_plan_detail)
    rpr(PLUGIN_ID, "dr/plans/update",       _update_dr_plan)
    rpr(PLUGIN_ID, "dr/plans/delete",       _delete_dr_plan)

    rpr(PLUGIN_ID, "dr/plans/entries/add",    _add_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/update", _update_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/entries/delete", _delete_plan_entry)
    rpr(PLUGIN_ID, "dr/plans/auto-detect",    _auto_detect_entries)

    rpr(PLUGIN_ID, "dr/plans/groups/create",  _create_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/update",  _update_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/delete",  _delete_vm_group)
    rpr(PLUGIN_ID, "dr/plans/groups/reorder", _reorder_vm_groups)

    rpr(PLUGIN_ID, "dr/plans/groups/vms/add",    _add_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/delete", _remove_vm_assignment)
    rpr(PLUGIN_ID, "dr/plans/groups/vms/update", _update_vm_assignment)

    rpr(PLUGIN_ID, "dr/plans/status",       _plan_status)
    rpr(PLUGIN_ID, "dr/plans/sync",         _sync_to_dr_site)
    rpr(PLUGIN_ID, "dr/plans/sync-status",  _get_sync_status)
