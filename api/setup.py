"""
Deploy Wizard API

  setup/status            GET  — overall wizard state (deps, ssh key, endpoints, pve hosts)
  setup/test-endpoints    POST — test ONTAP API connectivity for all configured endpoints
  setup/test-ssh          POST — test SSH to all configured PVE hosts
  setup/ssh-pubkey        GET  — return (or generate) the SSH public key
  setup/push-ssh-key      POST — push SSH pub key to a PVE host using one-time password
  setup/check-packages    POST — check which packages are installed on a PVE host
  setup/install-packages  POST — install packages on a PVE host (background job)
  setup/create-ontap-user POST — create a dedicated plugin user on an ONTAP cluster
"""

import json
import logging
import os
import shutil
import subprocess
import threading
import uuid as _uuid
from datetime import datetime, timezone

from flask import request, jsonify
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

from ..core._helpers import PLUGIN_ID, JobLogger, ssh_run

log = logging.getLogger(__name__)

# Packages needed per protocol on PVE hosts
PROTOCOL_PACKAGES = {
    "nfs":    ["nfs-common"],
    "iscsi":  ["open-iscsi", "multipath-tools", "lvm2"],
    "nvme":   ["nvme-cli", "lvm2"],
}

# All packages we care about across all protocols
ALL_PACKAGES = ["nfs-common", "open-iscsi", "multipath-tools", "lvm2", "nvme-cli"]


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Step 1: PegaProx system status ───────────────────────────────────────────

def _setup_status():
    """Returns an overview of current wizard state — fast, no external connections."""
    db = get_db()

    # Python package checks (import-based)
    dep_results = {}
    for pkg in ("requests",):
        try:
            __import__(pkg)
            dep_results[pkg] = True
        except ImportError:
            dep_results[pkg] = False

    # System command checks
    dep_results["ssh"]     = shutil.which("ssh") is not None
    dep_results["sshpass"] = shutil.which("sshpass") is not None

    # SSH public key
    pubkey = _read_ssh_pubkey()

    # Endpoints (without passwords, without testing connectivity)
    ep_rows = db.query("SELECT id, name, host, username, ssl_verify FROM netapp_endpoints ORDER BY name")
    endpoints = [dict(r) for r in ep_rows]

    # PVE hosts (without testing SSH)
    pve_rows = db.query("SELECT id, name, host, username FROM netapp_pve_hosts ORDER BY name")
    pve_hosts = [dict(r) for r in pve_rows]

    return jsonify({
        "deps":      dep_results,
        "ssh_pubkey": pubkey,
        "endpoints": endpoints,
        "pve_hosts": pve_hosts,
    })


# ── Step 2: Test ONTAP endpoints ─────────────────────────────────────────────

def _test_endpoints():
    """Tests ONTAP REST API connectivity for all configured endpoints."""
    db = get_db()
    from ..core._helpers import get_endpoint, build_ontap_client

    rows = db.query("SELECT id FROM netapp_endpoints ORDER BY name")
    results = []
    for row in rows:
        ep = get_endpoint(db, row["id"])
        r = {"id": ep["id"], "name": ep["name"], "host": ep["host"]}
        try:
            client = build_ontap_client(ep)
            info = client._get("cluster", params={"fields": "name,version"})
            r["ok"]      = True
            r["cluster"] = info.get("name", "")
            r["version"] = info.get("version", {}).get("full", "")
        except Exception as exc:
            r["ok"]    = False
            r["error"] = str(exc)[:200]
        results.append(r)

    return jsonify({"results": results})


# ── Step 3: Create dedicated ONTAP user ──────────────────────────────────────

def _create_ontap_user():
    """Creates a dedicated plugin user on an ONTAP cluster.

    Body:
      host          — cluster management IP/FQDN
      admin_user    — existing admin username
      admin_password
      new_username  — username to create (default: pegaprox)
      new_password  — password for the new user
      ssl_verify    — bool (default false)
      role          — 'admin' (default) or 'readonly'
    """
    data = request.get_json() or {}

    host           = data.get("host", "").strip()
    admin_user     = data.get("admin_user", "admin").strip()
    admin_password = data.get("admin_password", "").strip()
    new_username   = data.get("new_username", "pegaprox").strip()
    new_password   = data.get("new_password", "").strip()
    ssl_verify     = bool(data.get("ssl_verify", False))
    role_name      = data.get("role", "admin")

    if not host or not admin_password or not new_password:
        return jsonify({"error": "host, admin_password and new_password are required"}), 400
    if not new_username:
        return jsonify({"error": "new_username must not be empty"}), 400

    from ..core.ontap_client import OntapClient, OntapError
    try:
        client = OntapClient(
            host=host,
            username=admin_user,
            password=admin_password,
            ssl_verify=ssl_verify,
            timeout=20,
        )

        # Verify admin credentials work
        client._get("cluster", params={"fields": "name"})

        # Check if user already exists
        try:
            existing = client._get(f"security/accounts/{new_username}")
            return jsonify({
                "ok":      True,
                "created": False,
                "message": f"User '{new_username}' already exists.",
            })
        except OntapError as e:
            if e.status_code != 404:
                raise

        # Create the user: HTTP application + password auth, restricted to REST API only
        body = {
            "name": new_username,
            "role": {"name": role_name},
            "password": new_password,
            "applications": [
                {
                    "application": "http",
                    "authentication_methods": ["password"],
                }
            ],
        }
        client._post("security/accounts", body=body)

        return jsonify({
            "ok":      True,
            "created": True,
            "message": (
                f"User '{new_username}' created with role '{role_name}'. "
                f"HTTP/REST access only — no CLI or SSH access."
            ),
        })

    except OntapError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        log.error(f"[setup] create_ontap_user failed: {exc}")
        return jsonify({"error": str(exc)}), 500


# ── Step 4: SSH key management ────────────────────────────────────────────────

def _ensure_home_and_ssh(home: str) -> str:
    """Ensure *home* and *home/.ssh* exist and are writable.

    Tries three approaches in order:
      1. Direct ``os.makedirs`` — succeeds when running as root or when the
         directories already exist with correct permissions.
      2. ``sudo -n`` commands — succeeds when the service account has
         NOPASSWD sudo rights (common in some installations).
      3. Raises ``PermissionError`` — caller shows manual instructions.

    Returns the ssh_dir path on success.
    """
    import pwd as _pwd
    import grp as _grp

    ssh_dir = os.path.join(home, ".ssh")

    # Fast path — ssh_dir already usable
    if os.path.isdir(ssh_dir) and os.access(ssh_dir, os.W_OK):
        return ssh_dir

    # ── Attempt 1: direct mkdir ───────────────────────────────────────────────
    try:
        os.makedirs(home,    mode=0o750, exist_ok=True)
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        log.info(f"[setup] Created {ssh_dir} directly")
        return ssh_dir
    except PermissionError:
        pass

    # ── Attempt 2: passwordless sudo ─────────────────────────────────────────
    try:
        pw       = _pwd.getpwuid(os.getuid())
        username = pw.pw_name
        try:
            grp_name = _grp.getgrgid(pw.pw_gid).gr_name
        except Exception:
            grp_name = username

        subprocess.run(
            ["sudo", "-n", "mkdir", "-p", home],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "-n", "chmod", "750", home],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["sudo", "-n", "chown", f"{username}:{grp_name}", home],
            check=True, capture_output=True, timeout=10,
        )
        # Fix /etc/passwd home entry when it differs from the actual path we just created
        if pw.pw_dir != home:
            subprocess.run(
                ["sudo", "-n", "usermod", "-d", home, username],
                check=True, capture_output=True, timeout=10,
            )
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        log.info(f"[setup] Created {ssh_dir} via sudo")
        return ssh_dir
    except Exception as exc:
        log.info(f"[setup] sudo home-dir approach failed: {exc}")

    raise PermissionError(f"Cannot create {home}/.ssh — no write access and sudo unavailable")


def _get_ssh_pubkey():
    """Returns the SSH public key, generating an ed25519 keypair if none exists.

    Automatically attempts to create the home directory and ~/.ssh when they
    are missing or not writable, so fresh installs where the service account
    has no proper home work out of the box.
    """
    pubkey = _read_ssh_pubkey()
    if pubkey:
        return jsonify({"pubkey": pubkey, "generated": False})

    home = os.path.expanduser("~")

    # ── Ensure home + ~/.ssh exist ────────────────────────────────────────────
    try:
        ssh_dir = _ensure_home_and_ssh(home)
    except PermissionError:
        # Auto-fix failed → produce actionable manual instructions
        import pwd as _pwd, grp as _grp
        try:
            pw       = _pwd.getpwuid(os.getuid())
            username = pw.pw_name
            grp_name = _grp.getgrgid(pw.pw_gid).gr_name
        except Exception:
            username = grp_name = "pegaprox"
        suggested_home = f"/home/{username}"
        hint = (
            f"Run as root on the PegaProx server:\n"
            f"  mkdir -p {suggested_home}\n"
            f"  chown {username}:{grp_name} {suggested_home}\n"
            f"  usermod -d {suggested_home} {username}\n"
            f"Then reload the wizard."
        )
        log.warning(f"[setup] Cannot prepare ~/.ssh for home={home}")
        return jsonify({
            "error": "SSH home directory not accessible — automatic setup failed.",
            "hint":  hint,
            "auto_fix_attempted": True,
        }), 500

    # ── Generate keypair ──────────────────────────────────────────────────────
    priv_path = os.path.join(ssh_dir, "id_ed25519")
    pub_path  = priv_path + ".pub"
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", priv_path],
            check=True, capture_output=True, timeout=15,
        )
        with open(pub_path) as f:
            pubkey = f.read().strip()
        return jsonify({"pubkey": pubkey, "generated": True})
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace")[:300]
        log.warning(f"[setup] ssh-keygen failed: {stderr}")
        return jsonify({
            "error": f"ssh-keygen failed: {stderr}",
            "hint":  "Make sure openssh-client is installed on the PegaProx host.",
        }), 500
    except Exception as exc:
        log.warning(f"[setup] ssh-pubkey generation failed: {exc}")
        return jsonify({"error": str(exc)}), 500


def _read_ssh_pubkey():
    """Returns the first available SSH public key string, or ''."""
    home = os.path.expanduser("~")
    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        pub_path = os.path.join(home, ".ssh", name + ".pub")
        if os.path.exists(pub_path):
            try:
                with open(pub_path) as f:
                    return f.read().strip()
            except Exception:
                pass
    return ""


def _push_ssh_key():
    """Pushes the local SSH public key to a PVE host using one-time password auth.

    Body: {"host_id": ..., "password": "..."}
    """
    data    = request.get_json() or {}
    host_id = data.get("host_id")
    password = data.get("password", "").strip()

    if not host_id:
        return jsonify({"error": "host_id required"}), 400

    db = get_db()
    row = db.query_one("SELECT * FROM netapp_pve_hosts WHERE id=?", (host_id,))
    if not row:
        return jsonify({"error": "PVE host not found"}), 404

    pve_host = dict(row)
    pve_host["password"] = db._decrypt(pve_host.pop("password_encrypted", ""))
    target_host  = pve_host["host"]
    target_user  = pve_host.get("username", "root@pam").split("@")[0]
    auth_password = password or pve_host.get("password", "")

    pubkey = _read_ssh_pubkey()
    if not pubkey:
        return jsonify({"error": "No SSH public key found. Generate one first."}), 400

    if not shutil.which("sshpass"):
        return jsonify({
            "error": "sshpass is not installed on PegaProx. Install it with: apt-get install sshpass",
        }), 400

    # Use ssh-copy-id via sshpass to push the key
    try:
        result = subprocess.run(
            [
                "sshpass", "-p", auth_password,
                "ssh-copy-id",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"{target_user}@{target_host}",
            ],
            capture_output=True,
            timeout=20,
        )
        if result.returncode == 0:
            return jsonify({"ok": True, "message": f"SSH key pushed to {target_host}"})
        else:
            stderr = result.stderr.decode()[:300]
            return jsonify({"error": f"ssh-copy-id failed: {stderr}"}), 400
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Connection timed out"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Step 4: Test SSH to all PVE hosts ────────────────────────────────────────

def _test_ssh():
    """Tests SSH connectivity to all configured PVE hosts.

    Body: {} — tests all hosts; or {"host_id": "..."} for one host only.
    """
    data    = request.get_json() or {}
    host_id = data.get("host_id")
    db = get_db()

    if host_id:
        rows = db.query("SELECT * FROM netapp_pve_hosts WHERE id=?", (host_id,))
    else:
        rows = db.query("SELECT * FROM netapp_pve_hosts ORDER BY name")

    results = []
    for row in rows:
        h = dict(row)
        h["password"] = db._decrypt(h.pop("password_encrypted", ""))
        user  = h.get("username", "root@pam").split("@")[0]
        host  = h["host"]
        passw = h.get("password", "")
        r = {"id": h["id"], "name": h["name"], "host": host}
        try:
            out = ssh_run(host, user, passw, "echo __pgssh_ok__",
                          capture=True, timeout=15)
            r["ok"] = "__pgssh_ok__" in (out or "")
            if not r["ok"]:
                r["error"] = f"Unexpected output: {(out or '')[:100]}"
        except Exception as exc:
            r["ok"]    = False
            r["error"] = str(exc)[:200]
        results.append(r)

    return jsonify({"results": results})


# ── Step 5: Package management ────────────────────────────────────────────────

def _check_packages():
    """Checks which packages are installed on a PVE host via SSH.

    Body: {"host_id": "..."}
    Returns: {"packages": {"nvme-cli": true, "lvm2": false, ...}}
    """
    data    = request.get_json() or {}
    host_id = data.get("host_id")
    if not host_id:
        return jsonify({"error": "host_id required"}), 400

    db  = get_db()
    row = db.query_one("SELECT * FROM netapp_pve_hosts WHERE id=?", (host_id,))
    if not row:
        return jsonify({"error": "PVE host not found"}), 404

    h = dict(row)
    h["password"] = db._decrypt(h.pop("password_encrypted", ""))
    user  = h.get("username", "root@pam").split("@")[0]
    host  = h["host"]
    passw = h.get("password", "")

    # Build a single SSH call that checks all packages at once
    pkg_list = " ".join(ALL_PACKAGES)
    cmd = (
        "for p in " + pkg_list + "; do "
        "dpkg-query -W -f='${Status}\\n' $p 2>/dev/null | "
        "grep -q 'install ok installed' && echo \"${p}:ok\" || echo \"${p}:missing\"; "
        "done"
    )
    try:
        out = ssh_run(host, user, passw, cmd, capture=True, timeout=30)
    except Exception as exc:
        return jsonify({"error": f"SSH failed: {exc}"}), 400

    packages = {}
    for line in (out or "").splitlines():
        line = line.strip()
        if ":" in line:
            pkg, status = line.split(":", 1)
            packages[pkg.strip()] = (status.strip() == "ok")

    return jsonify({"packages": packages})


def _install_packages():
    """Installs packages on a PVE host as a background job.

    Body: {"host_id": "...", "packages": ["nvme-cli", "lvm2", ...]}
    Returns: {"job_id": "..."}
    """
    data     = request.get_json() or {}
    host_id  = data.get("host_id")
    packages = data.get("packages", [])
    if not host_id:
        return jsonify({"error": "host_id required"}), 400
    if not packages:
        return jsonify({"error": "packages list is empty"}), 400

    db  = get_db()
    row = db.query_one("SELECT * FROM netapp_pve_hosts WHERE id=?", (host_id,))
    if not row:
        return jsonify({"error": "PVE host not found"}), 404

    username = request.session.get("user", "system") if hasattr(request, "session") else "system"
    job_id   = str(_uuid.uuid4())
    db.execute(
        """INSERT INTO netapp_jobs
           (id, job_type, status, progress_pct, log_json, created_by, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (job_id, "pkg_install", "running", 0, "[]", username, _now()),
    )

    h = dict(row)
    h["password"] = db._decrypt(h.pop("password_encrypted", ""))
    threading.Thread(
        target=_run_pkg_install,
        args=(job_id, h, packages),
        daemon=True,
    ).start()

    return jsonify({"job_id": job_id})


def _run_pkg_install(job_id, host_row, packages):
    """Background worker: installs apt packages on a PVE host and logs progress."""
    from pegaprox.core.db import get_db as _get_db
    db   = _get_db()
    jlog = JobLogger(job_id, db)

    user  = host_row.get("username", "root@pam").split("@")[0]
    host  = host_row["host"]
    passw = host_row.get("password", "")
    pkg_str = " ".join(packages)

    jlog.log(f"Installing packages on {host}: {pkg_str}")
    try:
        db.execute(
            "UPDATE netapp_jobs SET progress_pct=10 WHERE id=?", (job_id,)
        )
        cmd = f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg_str} 2>&1"
        out = ssh_run(host, user, passw, cmd, capture=True, timeout=300)
        for line in (out or "").splitlines():
            line = line.strip()
            if line:
                jlog.log(line)
        jlog.log(f"[OK] Package installation complete on {host}")
        db.execute(
            "UPDATE netapp_jobs SET status='done', progress_pct=100, completed_at=? WHERE id=?",
            (_now(), job_id),
        )
    except Exception as exc:
        jlog.log(f"[ERR] {exc}")
        db.execute(
            "UPDATE netapp_jobs SET status='failed', completed_at=? WHERE id=?",
            (_now(), job_id),
        )


# ── Route registration ────────────────────────────────────────────────────────

def register_routes():
    register_plugin_route(PLUGIN_ID, "setup/status",            _setup_status)
    register_plugin_route(PLUGIN_ID, "setup/test-endpoints",    _test_endpoints)
    register_plugin_route(PLUGIN_ID, "setup/test-ssh",          _test_ssh)
    register_plugin_route(PLUGIN_ID, "setup/ssh-pubkey",        _get_ssh_pubkey)
    register_plugin_route(PLUGIN_ID, "setup/push-ssh-key",      _push_ssh_key)
    register_plugin_route(PLUGIN_ID, "setup/check-packages",    _check_packages)
    register_plugin_route(PLUGIN_ID, "setup/install-packages",  _install_packages)
    register_plugin_route(PLUGIN_ID, "setup/create-ontap-user", _create_ontap_user)
