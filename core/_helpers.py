"""
Shared helpers for snapshot_engine, restore_engine, and clone_engine.
"""

import os
import json
import logging
import subprocess
import shlex
import tempfile
from datetime import datetime, timezone

import requests as _requests

log = logging.getLogger(__name__)

_PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Derived from the actual directory name so the plugin works regardless of how
# the repo was cloned (e.g. `git clone ... netapp_storage` vs the default name).
PLUGIN_ID = os.path.basename(_PLUGIN_DIR)


class JobCancelledError(RuntimeError):
    """Raised inside a job thread when a cancel request is detected."""


def check_cancel(job_id: str) -> None:
    """Raise JobCancelledError if a cancel has been requested for this job."""
    from ._job_registry import is_cancel_requested
    if is_cancel_requested(job_id):
        raise JobCancelledError("Cancelled by user")


def load_plugin_config():
    try:
        with open(os.path.join(_PLUGIN_DIR, "config.json")) as f:
            return json.load(f)
    except Exception:
        return {}


def get_endpoint(db, endpoint_id):
    row = db.query_one("SELECT * FROM netapp_endpoints WHERE id=?", (endpoint_id,))
    if not row:
        raise RuntimeError(f"ONTAP endpoint '{endpoint_id}' not found")
    d = dict(row)
    d["password"] = db._decrypt(d.pop("password_encrypted", ""))
    return d


def get_mapping(db, mapping_id):
    row = db.query_one("SELECT * FROM netapp_volume_mapping WHERE id=?", (mapping_id,))
    if not row:
        raise RuntimeError(f"Volume mapping '{mapping_id}' not found")
    return dict(row)


def get_snapshot_record(db, snapshot_id):
    row = db.query_one("SELECT * FROM netapp_snapshots WHERE id=?", (snapshot_id,))
    if not row:
        raise RuntimeError(f"Snapshot '{snapshot_id}' not found")
    return dict(row)


def build_ontap_client(endpoint):
    from .ontap_client import OntapClient
    return OntapClient(
        host=endpoint["host"],
        username=endpoint["username"],
        password=endpoint["password"],
        ssl_verify=bool(endpoint.get("ssl_verify", 1)),
    )


def build_pve_client(db, pve_host_id):
    """Returns a PluginPveSession for a plugin-managed PVE host."""
    row = db.query_one("SELECT * FROM netapp_pve_hosts WHERE id=?", (pve_host_id,))
    if not row:
        raise RuntimeError(f"PVE host '{pve_host_id}' not found in netapp_pve_hosts")
    d = dict(row)
    d["password"] = db._decrypt(d.pop("password_encrypted", ""))
    return PluginPveSession(d)


class PluginPveSession:
    """Lightweight PVE REST client using plugin-managed credentials.

    Implements the same interface as PegaProx ClusterManager so that
    snapshot_engine and restore_engine work without modification.
    """

    def __init__(self, pve_host):
        self.host   = pve_host["host"]
        self.nfs_ip = pve_host.get("nfs_ip", "").strip()
        self.port   = int(pve_host.get("port", 8006))
        self._base = f"https://{self.host}:{self.port}/api2/json"
        ssl_verify = bool(pve_host.get("ssl_verify", 0))

        self._session = _requests.Session()
        self._session.verify = ssl_verify
        if not ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        last_exc = None
        for attempt in range(3):
            try:
                r = self._session.post(
                    f"{self._base}/access/ticket",
                    data={"username": pve_host["username"], "password": pve_host["password"]},
                    timeout=(10, 60),
                )
                r.raise_for_status()
                break
            except Exception as exc:
                last_exc = exc
                import time as _time
                _time.sleep(5)
        else:
            raise last_exc
        data = r.json().get("data", {})
        self._session.cookies.set("PVEAuthCookie", data["ticket"])
        self._session.headers.update({"CSRFPreventionToken": data.get("CSRFPreventionToken", "")})
        self.is_connected = True

        # SSH credentials: root@pam → user=root, same password
        uname = pve_host.get("username", "root@pam")
        self.ssh_user = uname.split("@")[0]
        self.ssh_password = pve_host["password"]
        self.ssh_key = ""

    def _api_get(self, url):
        return self._session.get(url, timeout=(10, 60))

    def _api_post(self, url, data=None):
        return self._session.post(url, json=data or {}, timeout=(10, 120))

    def get_node_status(self):
        """{node_name: {ip, host}} für alle Nodes im Cluster."""
        r = self._api_get(f"{self._base}/nodes")
        if not r.ok:
            return {}
        result = {}
        for n in r.json().get("data", []):
            name = n.get("node", "")
            if name:
                result[name] = {"ip": n.get("ip", name), "host": name}
        return result

    def get_vm_config(self, node, vmid, vm_type="qemu"):
        """{'success': bool, 'config': {'raw': dict}}"""
        vt = "qemu" if vm_type == "qemu" else "lxc"
        r = self._api_get(f"{self._base}/nodes/{node}/{vt}/{vmid}/config")
        if not r.ok:
            return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"success": True, "config": {"raw": r.json().get("data", {})}}

    def find_vm_node(self, vmid):
        """Returns the node name where a VM/CT is running."""
        r = self._api_get(f"{self._base}/cluster/resources?type=vm")
        if not r.ok:
            return None
        for res in r.json().get("data", []):
            if res.get("vmid") == int(vmid):
                return res.get("node")
        return None


def get_ssh_creds(mgr):
    """Returns (user, password, key_material) from a ClusterManager or PluginPveSession."""
    if isinstance(mgr, PluginPveSession):
        return mgr.ssh_user, mgr.ssh_password, mgr.ssh_key
    # PegaProx ClusterManager
    user = getattr(mgr.config, "ssh_user", None) or "root"
    key_material = getattr(mgr.config, "ssh_key", None) or ""
    password = mgr.config.pass_ if not key_material else ""
    return user, password, key_material


def _find_system_ssh_key():
    """Returns the path to the first available system SSH key, or None."""
    home = os.path.expanduser("~")
    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        path = os.path.join(home, ".ssh", name)
        if os.path.exists(path):
            return path
    return None


def ssh_run(host, user, password, cmd, capture=False, stdin_data=None, timeout=60, key_material=""):
    """Runs an SSH command. Raises RuntimeError on failure.

    Authentication priority:
      1. key_material (SSH private key as string) → temp file → -i
      2. password → sshpass (if installed)
      3. No auth → only works with a pre-configured SSH agent key

    capture=True returns stdout as a string.
    stdin_data=bytes pipes data to stdin.
    """
    from pegaprox.utils.ssh_pool import controlmaster_args
    cm_args = controlmaster_args(host, user)

    base_ssh = [
        "ssh",
        *cm_args,
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={min(timeout, 15)}",
        "-o", "BatchMode=yes",
    ]

    key_tmp = None
    try:
        if key_material:
            # Write private key to a temp file for -i flag
            fd, key_tmp = tempfile.mkstemp(prefix="pegaprox-ssh-key-")
            try:
                os.write(fd, key_material.encode() if isinstance(key_material, str) else key_material)
            finally:
                os.close(fd)
            os.chmod(key_tmp, 0o600)
            ssh_cmd = base_ssh + ["-i", key_tmp, "-o", "PasswordAuthentication=no",
                                   f"{user}@{host}", cmd]
            final_cmd = ssh_cmd
        elif password:
            # Prefer system key (PVE often disables password login for root)
            _system_key = _find_system_ssh_key()
            if _system_key:
                ssh_cmd = base_ssh + ["-i", _system_key, "-o", "PasswordAuthentication=no",
                                      f"{user}@{host}", cmd]
                final_cmd = ssh_cmd
            else:
                # sshpass braucht BatchMode=no
                no_batch = [c if c != "BatchMode=yes" else "BatchMode=no" for c in base_ssh]
                ssh_cmd = no_batch + [f"{user}@{host}", cmd]
                try:
                    subprocess.run(["sshpass", "--version"], capture_output=True, check=True)
                    final_cmd = ["sshpass", "-p", password] + ssh_cmd
                except (FileNotFoundError, subprocess.CalledProcessError):
                    log.warning("[netapp_storage] sshpass not found")
                    final_cmd = ssh_cmd
        else:
            ssh_cmd = base_ssh + [f"{user}@{host}", cmd]
            final_cmd = ssh_cmd

        try:
            result = subprocess.run(
                final_cmd,
                input=stdin_data,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"SSH timeout after {timeout}s: {cmd[:80]}")
        except FileNotFoundError:
            raise RuntimeError("ssh binary not found")

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            raise RuntimeError(f"SSH command failed (rc={result.returncode}): {stderr[:300]}")

        if capture:
            return result.stdout.decode(errors="replace")
        return ""

    finally:
        if key_tmp and os.path.exists(key_tmp):
            try:
                os.unlink(key_tmp)
            except Exception:
                pass


class JobLogger:
    """Appends log lines to netapp_jobs.log_json."""

    def __init__(self, job_id, db):
        self.job_id = job_id
        self.db = db

    def log(self, msg):
        log.info(f"[netapp_storage job={self.job_id}] {msg}")
        try:
            row = self.db.query_one("SELECT log_json FROM netapp_jobs WHERE id=?", (self.job_id,))
            existing = json.loads(row["log_json"] or "[]") if row else []
            entry = {"ts": datetime.now(timezone.utc).isoformat(), "msg": msg}
            existing.append(entry)
            self.db.execute(
                "UPDATE netapp_jobs SET log_json=? WHERE id=?",
                (json.dumps(existing), self.job_id),
            )
        except Exception as e:
            log.warning(f"[netapp_storage] JobLogger write failed: {e}")
