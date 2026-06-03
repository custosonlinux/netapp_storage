"""
ONTAP REST API Client

Thin wrapper around the ONTAP REST API (port 443).
All methods return Python dicts on success; errors raise OntapError.
TLS verification is configurable per endpoint (ssl_verify=False for self-signed certs).
"""

import time
import logging
import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)


class OntapError(Exception):
    def __init__(self, msg, status_code=None):
        super().__init__(msg)
        self.status_code = status_code


class OntapClient:
    def __init__(self, host, username, password, ssl_verify=True, timeout=30):
        self.base_url = f"https://{host}/api"
        self.auth = HTTPBasicAuth(username, password)
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self._session = requests.Session()
        self._session.auth = self.auth
        self._session.verify = ssl_verify
        self._session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
        if not ssl_verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # Tracks FlexClone/CLI-bridge volumes created as namespace clone fallback.
        # Keyed by clone namespace UUID; value is {"uuid": vol_uuid, "name": vol_name, "svm": svm}.
        # delete_namespace() uses this to delete the whole volume instead of just the namespace.
        self._clone_vol_for_ns: dict = {}

    # ── Internal helpers ──────────────────────────────────────────────────

    def _get(self, path, params=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            r = self._session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise OntapError(f"GET {path} network error: {e}")
        if not r.ok:
            raise OntapError(f"GET {path} → {r.status_code}: {r.text[:300]}", r.status_code)
        return r.json()

    def _post(self, path, body=None, params=None, timeout=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            r = self._session.post(url, json=body or {}, params=params,
                                   timeout=timeout or self.timeout)
        except requests.RequestException as e:
            raise OntapError(f"POST {path} network error: {e}")
        if not r.ok:
            raise OntapError(f"POST {path} → {r.status_code}: {r.text[:300]}", r.status_code)
        return r.json()

    def _patch(self, path, body=None, params=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            r = self._session.patch(url, json=body or {}, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise OntapError(f"PATCH {path} network error: {e}")
        if not r.ok:
            raise OntapError(f"PATCH {path} → {r.status_code}: {r.text[:300]}", r.status_code)
        return r.json() if r.content else {}

    def _delete(self, path, params=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            r = self._session.delete(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise OntapError(f"DELETE {path} network error: {e}")
        if not r.ok:
            raise OntapError(f"DELETE {path} → {r.status_code}: {r.text[:300]}", r.status_code)
        return r.json() if r.content else {}

    # ── Cluster / connection test ──────────────────────────────────────────

    def test_connection(self):
        """Checks connectivity and credentials. Returns (name, version, san_optimized)."""
        data = self._get("cluster", params={"fields": "name,version,san_optimized"})
        return (
            data.get("name", ""),
            data.get("version", {}).get("full", ""),
            bool(data.get("san_optimized", False)),
        )

    def get_cluster_id(self):
        data = self._get("cluster", params={"fields": "uuid"})
        return data.get("uuid", "")

    # ── Network interfaces (LIFs) ─────────────────────────────────────────

    def _get_all_records(self, path, params):
        """Paginates over all records of an ONTAP endpoint."""
        from urllib.parse import urlparse, parse_qs
        records = []
        p = params
        url = path
        while url:
            data = self._get(url, params=p)
            records.extend(data.get("records", []))
            p = None
            next_href = ((data.get("_links") or {}).get("next") or {}).get("href", "")
            if next_href:
                parsed = urlparse(next_href)
                url = parsed.path.removeprefix("/api/").lstrip("/")
                p = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            else:
                url = None
        return records

    def get_lif_svm_map(self):
        """Returns NFS-capable LIFs: {ip_address: svm_name}.

        Filters server-side by services=data_nfs.
        """
        records = self._get_all_records(
            "network/ip/interfaces",
            params={
                "services":    "data_nfs",
                "fields":      "ip.address,svm,name,state",
                "max_records": 500,
            },
        )
        ip_svm = {}
        for rec in records:
            if rec.get("state", "up") != "up":
                continue
            addr = (rec.get("ip") or {}).get("address", "")
            svm  = (rec.get("svm") or {}).get("name", "")
            if addr and svm:
                ip_svm[addr] = svm
        log.info(f"[netapp_storage] NFS LIF map ({len(ip_svm)} entries): {ip_svm}")
        return ip_svm

    # ── SVMs ───────────────────────────────────────────────────────────────

    def list_svms(self):
        """Returns all SVMs: [{name, uuid}]."""
        return self._get_all_records(
            "svm/svms",
            params={"fields": "name,uuid", "max_records": 200},
        )

    def get_svm(self, svm_name):
        data = self._get("svm/svms", params={"name": svm_name, "fields": "uuid,name"})
        records = data.get("records", [])
        if not records:
            raise OntapError(f"SVM '{svm_name}' not found")
        return records[0]

    # ── Volumes ─────────────────────────────────────────────────────────────

    def get_volumes(self, svm_name=None):
        params = {"fields": "uuid,name,svm,nas.path,space.used,space.available", "max_records": 500}
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("storage/volumes", params=params)

    def get_volume(self, volume_uuid):
        return self._get(f"storage/volumes/{volume_uuid}",
                         params={"fields": "uuid,name,svm,nas.path,state,space"})

    # ── Snapshots ───────────────────────────────────────────────────────────

    def list_snapshots(self, volume_uuid):
        data = self._get(f"storage/volumes/{volume_uuid}/snapshots",
                         params={"fields": "uuid,name,create_time,comment,snapmirror_label"})
        return data.get("records", [])

    def create_snapshot(self, volume_uuid, snap_name, comment="", snapmirror_label=""):
        """Creates a volume snapshot. Returns job UUID (or '' on synchronous success).

        Fallback chain for ASA systems that do not support POST to volume-snapshots:
          1. storage/volumes/{uuid}/snapshots  (standard FAS/AFF/AFF-C)
          2. application/consistency-groups → CG snapshot  (ASA with CGs)
          3. private/cli/snapshot  (ASA CLI bridge)
        """
        body = {"name": snap_name}
        if comment:
            body["comment"] = comment
        if snapmirror_label:
            body["snapmirror_label"] = snapmirror_label
        try:
            resp = self._post(f"storage/volumes/{volume_uuid}/snapshots",
                              body=body, params={"return_timeout": 0})
            return (resp.get("job") or {}).get("uuid", "")
        except OntapError as exc:
            # ASA: "not supported on this platform" (code 1638644)
            if exc.status_code == 400 and ("1638644" in str(exc) or
                                            "not supported on this platform" in str(exc)):
                log.info("[netapp_storage] ASA platform: volume snapshot not supported, "
                         "trying CG/CLI fallback")
                return self._create_snapshot_asa(volume_uuid, snap_name, comment, snapmirror_label)
            raise

    def _create_snapshot_asa(self, volume_uuid, snap_name, comment="", snapmirror_label=""):
        """ASA snapshot fallback: CG snapshot, then CLI bridge.

        Returns job UUID or '' (synchronous CLI bridge returns no UUID).
        """
        # Stage 1: consistency group containing this volume
        try:
            cgs = self._get_all_records(
                "application/consistency-groups",
                {"fields": "uuid,name,volumes.uuid,svm.name", "max_records": 200},
            )
            for cg in cgs:
                vols = cg.get("volumes") or []
                if any(v.get("uuid") == volume_uuid for v in vols):
                    cg_uuid = cg["uuid"]
                    body = {"name": snap_name}
                    if comment:
                        body["comment"] = comment
                    if snapmirror_label:
                        body["snapmirror_label"] = snapmirror_label
                    resp = self._post(
                        f"application/consistency-groups/{cg_uuid}/snapshots",
                        body=body, params={"return_timeout": 0},
                    )
                    log.info(f"[netapp_storage] ASA CG snapshot created via CG '{cg.get('name')}'")
                    return (resp.get("job") or {}).get("uuid", "")
        except Exception as cg_exc:
            log.info(f"[netapp_storage] CG snapshot fallback failed: {cg_exc}")

        # Stage 2: CLI bridge (synchronous, no job UUID)
        try:
            vol = self._get(f"storage/volumes/{volume_uuid}",
                            params={"fields": "name,svm.name"})
            vol_name = vol.get("name", "")
            svm_name = (vol.get("svm") or {}).get("name", "")
            if not vol_name or not svm_name:
                raise OntapError("volume name or SVM not resolvable")
            cli_body = {"vserver": svm_name, "volume": vol_name, "snapshot": snap_name}
            if comment:
                cli_body["comment"] = comment
            self._post("private/cli/snapshot", body=cli_body)
            log.info(f"[netapp_storage] ASA Snapshot via CLI-Bridge: {svm_name}/{vol_name}/{snap_name}")
            return ""  # synchronous, no job
        except Exception as cli_exc:
            raise OntapError(
                f"ASA snapshot failed: CG method and CLI-Bridge both failed "
                f"(CLI: {cli_exc})"
            )

    def get_snapshot(self, volume_uuid, snap_uuid):
        return self._get(f"storage/volumes/{volume_uuid}/snapshots/{snap_uuid}")

    def delete_snapshot(self, volume_uuid, snap_uuid, force=False, snap_name=""):
        """Deletes a snapshot. Returns job UUID.

        force=True: pass ?force=true to ONTAP (removes snapshot even if it has dependents
        such as automatic policy snapshots). Does NOT break SnapMirror relationships.

        snap_name: snapshot name (used for ASA CLI-bridge fallback when snap_uuid alone
        is insufficient). If omitted, falls back to snap_uuid as the name.

        ASA fallback: code 1638644 → CLI bridge DELETE private/cli/snapshot.
        """
        params = {"return_timeout": 0}
        if force:
            params["force"] = "true"
        try:
            resp = self._delete(f"storage/volumes/{volume_uuid}/snapshots/{snap_uuid}",
                                params=params)
            return resp.get("job", {}).get("uuid", "")
        except OntapError as exc:
            if exc.status_code == 400 and "1638644" in str(exc):
                return self._delete_snapshot_asa(volume_uuid,
                                                 snap_name or snap_uuid,
                                                 force=force)
            raise

    def _delete_snapshot_asa(self, volume_uuid, snap_name, force=False):
        """ASA CLI-bridge fallback for snapshot deletion."""
        vol = self._get(f"storage/volumes/{volume_uuid}", params={"fields": "name,svm.name"})
        vol_name = vol.get("name", "")
        svm_name = (vol.get("svm") or {}).get("name", "")
        if not vol_name or not svm_name:
            raise OntapError("ASA snapshot delete: cannot resolve volume name/SVM")
        params = {"vserver": svm_name, "volume": vol_name, "snapshot": snap_name}
        if force:
            params["ignore-owners"] = "true"
        try:
            self._delete("private/cli/snapshot", params=params)
        except OntapError as exc:
            if exc.status_code == 404:
                pass  # already gone
            else:
                raise
        return ""

    def restore_volume_snapshot_san(self, volume_uuid, snap_name):
        """Reverts a SAN volume to a snapshot (volume revert).

        Resets the entire volume to the snapshot state.
        Prerequisite: deactivate VG on the PVE host first (vgchange -an).
        Returns job_uuid (or "" on synchronous CLI bridge call).
        """
        vol = self._get(f"storage/volumes/{volume_uuid}",
                        params={"fields": "name,svm.name"})
        vol_name = vol.get("name", "")
        svm_name = (vol.get("svm") or {}).get("name", "")
        if not vol_name or not svm_name:
            raise OntapError("volume name or SVM for revert not resolvable")
        body = {
            "vserver": svm_name,
            "volume": vol_name,
            "snapshot": snap_name,
        }
        # return_timeout=60: ONTAP waits up to 60s synchronously before returning a job UUID.
        # requests timeout=90: must exceed return_timeout to avoid a spurious network timeout.
        resp = self._post("private/cli/volume/snapshot/restore",
                          body=body, params={"return_timeout": 60}, timeout=90)
        return (resp.get("job") or {}).get("uuid", "")

    # ── Job polling ─────────────────────────────────────────────────────

    def poll_job(self, job_uuid, interval_s=3, timeout_s=300):
        """Blocks until job completes or times out. Returns job dict.

        ONTAP terminal states: success, failure, queued, running, paused.
        """
        if not job_uuid:
            return {}  # synchronous call (e.g. CLI bridge) — no job to poll
        deadline = time.monotonic() + timeout_s
        while True:
            data = self._get(f"cluster/jobs/{job_uuid}")
            state = data.get("state", "")
            if state in ("success", "failure"):
                if state == "failure":
                    raise OntapError(f"ONTAP job {job_uuid} failed: {data.get('message', '')}")
                return data
            if time.monotonic() > deadline:
                raise OntapError(f"ONTAP job {job_uuid} timed out after {timeout_s}s (state: {state})")
            time.sleep(interval_s)

    # ── Single-File Snapshot Restore (SFSR) ───────────────────────────

    def restore_file(self, svm_name, volume_name, snap_name, file_path, restore_path):
        """Restores a single file from a snapshot.

        Uses the private ONTAP CLI REST bridge.
        file_path / restore_path are paths relative to the volume root (no leading /).
        """
        body = {
            "vserver": svm_name,
            "volume": volume_name,
            "snapshot": snap_name,
            "path": f"/{file_path.lstrip('/')}",
            "restore-path": f"/{restore_path.lstrip('/')}",
        }
        # private/cli endpoint is synchronous — no job polling needed
        resp = self._post("private/cli/volume/snapshot/restore-file", body=body)
        return resp

    # ── FlexClone ─────────────────────────────────────────────────────

    def create_flexclone(self, parent_vol_uuid, snap_name, clone_name, svm_name, junction_path=None):
        """Creates a FlexClone from a snapshot.

        junction_path: NFS junction path for the clone, e.g. '/pgxclone_ab12cd34'.
        Returns (clone_volume_uuid, job_uuid).
        """
        body = {
            "name": clone_name,
            "svm": {"name": svm_name},
            "clone": {
                "is_flexclone": True,
                "parent_volume": {"uuid": parent_vol_uuid},
                "parent_snapshot": {"name": snap_name},
            },
        }
        if junction_path:
            body["nas"] = {"path": junction_path}

        resp = self._post("storage/volumes", body=body, params={"return_timeout": 0})
        vol_uuid = resp.get("uuid", "")
        job_uuid = resp.get("job", {}).get("uuid", "")
        return vol_uuid, job_uuid

    def clone_file(self, volume_uuid, source_path, dest_path, snap_name=""):
        """Clones a file within the volume (CoW, storage-offloaded).

        Uses POST /api/storage/file/clone.
        source_path / dest_path are relative to the volume root (no leading /).
        Returns job UUID (async), or "" if no job is returned.
        """
        src = f".snapshot/{snap_name}/{source_path.lstrip('/')}" if snap_name else source_path.lstrip("/")
        body = {
            "volume": {"uuid": volume_uuid},
            "source_path": src,
            "destination_path": dest_path.lstrip("/"),
        }
        resp = self._post("storage/file/clone", body=body, params={"return_timeout": 0})
        return resp.get("job", {}).get("uuid", "")

    def get_volume_by_name(self, svm_name, volume_name):
        data = self._get("storage/volumes",
                         params={"svm.name": svm_name, "name": volume_name,
                                 "fields": "uuid,name,nas.path,state"})
        records = data.get("records", [])
        if not records:
            raise OntapError(f"Volume '{volume_name}' on SVM '{svm_name}' not found")
        return records[0]

    def delete_volume(self, volume_uuid):
        """Deletes a volume. Returns job UUID. Falls back to CLI bridge on ASA (405)."""
        try:
            resp = self._delete(f"storage/volumes/{volume_uuid}", params={"return_timeout": 0})
            return (resp.get("job") or {}).get("uuid", "")
        except OntapError as exc:
            if exc.status_code != 405:
                raise
        # ASA: REST DELETE not supported — resolve name/SVM and use CLI bridge
        try:
            vol = self._get(f"storage/volumes/{volume_uuid}", params={"fields": "name,svm.name"})
            vol_name = vol.get("name", "")
            svm_name = (vol.get("svm") or {}).get("name", "")
        except OntapError:
            vol_name = ""
            svm_name = ""
        self._delete_clone_volume(volume_uuid, vol_name, svm_name)
        return ""

    # ── SnapMirror® ───────────────────────────────────────────────────

    def get_cluster_info(self):
        """Returns (name, uuid) of the cluster."""
        data = self._get("cluster", params={"fields": "name,uuid"})
        return data.get("name", ""), data.get("uuid", "")

    def list_snapmirror_relationships(self):
        """Returns all SnapMirror® relationships (unfiltered, client-side matching)."""
        return self._get_all_records("snapmirror/relationships", params={
            "fields": "uuid,state,healthy,lag_time,policy.type,"
                      "source.path,destination.path,destination.cluster.name,"
                      "transfer.end_time",
            "max_records": 200,
        })

    def trigger_snapmirror_transfer(self, relationship_uuid):
        """Starts a SnapMirror® update transfer. Returns job UUID."""
        resp = self._post(
            f"snapmirror/relationships/{relationship_uuid}/transfers",
            body={},
            params={"return_timeout": 0},
        )
        return resp.get("job", {}).get("uuid", "")

    def get_snapmirror_relationship(self, relationship_uuid):
        """Returns the current status of a SnapMirror® relationship."""
        return self._get(
            f"snapmirror/relationships/{relationship_uuid}",
            params={"fields": "uuid,state,healthy,lag_time,transfer.end_time"},
        )

    def get_volume_export_info(self, volume_uuid):
        """Returns NAS info for a volume (junction_path, export_policy)."""
        data = self._get(
            f"storage/volumes/{volume_uuid}",
            params={"fields": "nas.path,nas.export_policy,svm.name"},
        )
        nas = data.get("nas") or {}
        return {
            "junction_path": nas.get("path", ""),
            "export_policy_id": (nas.get("export_policy") or {}).get("id", ""),
            "export_policy_name": (nas.get("export_policy") or {}).get("name", ""),
            "svm_name": (data.get("svm") or {}).get("name", ""),
        }

    def list_nfs_export_rules(self, export_policy_id):
        """Lists NFS export rules for an export policy."""
        data = self._get(f"protocols/nfs/export-policies/{export_policy_id}/rules",
                         params={"fields": "index,clients,ro_rule,rw_rule,superuser"})
        return data.get("records", [])

    def add_nfs_export_rule(self, export_policy_id, client_match="0.0.0.0/0"):
        """Adds a read-only NFS export rule."""
        body = {
            "clients": [{"match": client_match}],
            "ro_rule": ["any"],
            "rw_rule": ["never"],
            "superuser": ["any"],
        }
        return self._post(f"protocols/nfs/export-policies/{export_policy_id}/rules", body=body)

    def list_nfs_lifs(self, svm_name):
        """Returns list of {name, ip} for all up NFS LIFs of the SVM."""
        records = self._get_all_records(
            "network/ip/interfaces",
            params={"services": "data_nfs", "svm.name": svm_name,
                    "fields": "name,ip.address,state", "max_records": 50},
        )
        result = []
        for rec in records:
            if rec.get("state", "up") == "up":
                addr = (rec.get("ip") or {}).get("address", "")
                if addr:
                    result.append({"name": rec.get("name", addr), "ip": addr})
        return result

    def get_nfs_lif_for_svm(self, svm_name):
        """Returns the first NFS LIF IP of the SVM."""
        lifs = self.list_nfs_lifs(svm_name)
        return lifs[0]["ip"] if lifs else ""

    # ── Volume mount/unmount ───────────────────────────────────────────

    def unmount_volume(self, volume_uuid):
        """Removes the NFS junction mount (sets nas.path to '')."""
        url = f"{self.base_url}/storage/volumes/{volume_uuid}"
        try:
            r = self._session.patch(url, json={"nas": {"path": ""}},
                                    params={"return_timeout": 30}, timeout=self.timeout)
        except requests.RequestException as e:
            raise OntapError(f"PATCH volume/{volume_uuid} network error: {e}")
        if not r.ok:
            raise OntapError(f"PATCH volume/{volume_uuid} → {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else {}

    # ── SAN: LUNs ────────────────────────────────────────────────────────────

    def list_luns(self, svm_name=None):
        """All LUNs of a cluster (or a single SVM)."""
        params = {
            "fields": "uuid,name,svm.name,location.volume.uuid,location.volume.name,"
                      "serial_number,space.size,status.state",
            "max_records": 500,
        }
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("storage/luns", params=params)

    def get_lun(self, lun_uuid):
        return self._get(
            f"storage/luns/{lun_uuid}",
            params={"fields": "uuid,name,svm.name,location.volume.uuid,"
                              "location.volume.name,serial_number,space.size,status.state"},
        )

    def clone_lun_from_snapshot(self, source_vol_uuid, snap_name, svm_name,
                                clone_vol_name,
                                poll_interval=3, poll_timeout=300):
        """Creates a FlexClone of the source volume from a snapshot and returns
        the first LUN found inside the clone volume.

        ONTAP REST storage/luns does not support snapshot references in the
        clone body — the correct approach is to FlexClone the volume and access
        the LUN within it.

        Returns (lun_uuid, clone_vol_uuid).
        """
        body = {
            "name": clone_vol_name,
            "svm": {"name": svm_name},
            "clone": {
                "is_flexclone": True,
                "parent_volume": {"uuid": source_vol_uuid},
                "parent_snapshot": {"name": snap_name},
            },
        }
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 0})
        clone_vol_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=poll_interval, timeout_s=poll_timeout)
        if not clone_vol_uuid:
            for v in self.get_volumes():
                if v.get("name") == clone_vol_name:
                    clone_vol_uuid = v.get("uuid", "")
                    break
        if not clone_vol_uuid:
            raise OntapError(f"FlexClone volume {clone_vol_name!r} not found after creation")

        lun_uuid = ""
        for lun in self.list_luns(svm_name=svm_name):
            loc_vol = ((lun.get("location") or {}).get("volume")) or {}
            if loc_vol.get("uuid") == clone_vol_uuid or loc_vol.get("name") == clone_vol_name:
                lun_uuid = lun.get("uuid", "")
                break
        if not lun_uuid:
            raise OntapError(f"No LUN found inside FlexClone volume {clone_vol_name!r}")
        return lun_uuid, clone_vol_uuid

    def clone_namespace_from_snapshot(self, source_vol_uuid, snap_name, svm_name,
                                       clone_vol_name, poll_interval=3, poll_timeout=300):
        """FlexClone of source volume from snapshot; returns (ns_uuid, clone_vol_uuid).

        Equivalent to clone_lun_from_snapshot but for NVMe namespaces.
        Used by DR NVMe restore to create a temporary clone on the secondary.
        """
        body = {
            "name": clone_vol_name,
            "svm":  {"name": svm_name},
            "clone": {
                "is_flexclone":    True,
                "parent_volume":   {"uuid": source_vol_uuid},
                "parent_snapshot": {"name": snap_name},
            },
        }
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 0})
        clone_vol_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=poll_interval, timeout_s=poll_timeout)
        if not clone_vol_uuid:
            for v in self.get_volumes():
                if v.get("name") == clone_vol_name:
                    clone_vol_uuid = v.get("uuid", "")
                    break
        if not clone_vol_uuid:
            raise OntapError(f"FlexClone volume {clone_vol_name!r} not found after creation")

        ns_uuid = ""
        for ns in self.list_nvme_namespaces(svm_name=svm_name):
            loc_vol = (ns.get("location") or {}).get("volume", {})
            if loc_vol.get("uuid") == clone_vol_uuid or loc_vol.get("name") == clone_vol_name:
                ns_uuid = ns["uuid"]
                break
        if not ns_uuid:
            raise OntapError(
                f"No NVMe namespace found inside FlexClone volume {clone_vol_name!r}")
        return ns_uuid, clone_vol_uuid

    def delete_lun(self, lun_uuid):
        """Deletes a LUN. Returns job UUID."""
        resp = self._delete(f"storage/luns/{lun_uuid}", params={"return_timeout": 0})
        return (resp.get("job") or {}).get("uuid", "")

    # ── SAN: iGroups ──────────────────────────────────────────────────────────

    def list_igroups(self, svm_name=None):
        """All iGroups (iSCSI initiator groups)."""
        params = {
            "fields": "uuid,name,svm.name,protocol,os_type,initiators.name",
            "max_records": 200,
        }
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("protocols/san/igroups", params=params)

    def create_igroup(self, svm_name, igroup_name, protocol="iscsi", os_type="linux"):
        """Creates an iGroup. Returns uuid."""
        body = {
            "name": igroup_name,
            "svm": {"name": svm_name},
            "protocol": protocol,
            "os_type": os_type,
        }
        resp = self._post("protocols/san/igroups", body=body,
                          params={"return_timeout": 15, "return_records": "true"})
        igroup_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=2, timeout_s=60)
        if not igroup_uuid:
            for ig in self.list_igroups(svm_name):
                if ig.get("name") == igroup_name:
                    igroup_uuid = ig.get("uuid", "")
                    break
        if not igroup_uuid:
            raise OntapError(f"iGroup '{igroup_name}' not found after creation")
        return igroup_uuid

    def add_igroup_initiator(self, igroup_uuid, initiator_name):
        """Adds an initiator (IQN) to an iGroup."""
        self._post(
            f"protocols/san/igroups/{igroup_uuid}/initiators",
            body={"name": initiator_name},
        )

    def remove_igroup_initiator(self, igroup_uuid, initiator_name):
        """Removes an initiator (IQN) from an iGroup (best-effort)."""
        try:
            self._delete(
                f"protocols/san/igroups/{igroup_uuid}/initiators/{initiator_name}")
        except OntapError as exc:
            log.warning(f"[netapp_storage] remove igroup initiator: {exc}")

    def delete_igroup(self, igroup_uuid):
        self._delete(f"protocols/san/igroups/{igroup_uuid}")

    # ── SAN: LUN Maps ─────────────────────────────────────────────────────

    def list_lun_maps(self, lun_uuid=None, igroup_uuid=None):
        params = {
            "fields": "lun.uuid,lun.name,igroup.uuid,igroup.name,logical_unit_number",
            "max_records": 500,
        }
        if lun_uuid:
            params["lun.uuid"] = lun_uuid
        if igroup_uuid:
            params["igroup.uuid"] = igroup_uuid
        return self._get_all_records("protocols/san/lun-maps", params=params)

    def map_lun(self, lun_uuid, igroup_uuid, svm_name=""):
        """Maps a LUN to an iGroup. Returns the response."""
        body = {"lun": {"uuid": lun_uuid}, "igroup": {"uuid": igroup_uuid}}
        if svm_name:
            body["svm"] = {"name": svm_name}
        return self._post(
            "protocols/san/lun-maps",
            body=body,
            params={"return_timeout": 15},
        )

    def unmap_lun(self, lun_uuid, igroup_uuid):
        """Removes a LUN mapping."""
        self._delete(f"protocols/san/lun-maps/{lun_uuid}/{igroup_uuid}")

    # ── SAN: iSCSI services ──────────────────────────────────────────────────

    def get_iscsi_lif_for_svm(self, svm_name):
        """Returns the first active iSCSI LIF IP of the SVM."""
        records = self._get_all_records(
            "network/ip/interfaces",
            params={"services": "data_iscsi", "svm.name": svm_name,
                    "fields": "ip.address,state", "max_records": 50},
        )
        for rec in records:
            if rec.get("state", "up") == "up":
                addr = (rec.get("ip") or {}).get("address", "")
                if addr:
                    return addr
        return ""

    def get_iscsi_target_iqn(self, svm_name):
        """Returns the iSCSI target IQN of a SVM."""
        try:
            data = self._get(
                "protocols/san/iscsi/services",
                params={"svm.name": svm_name, "fields": "target.name", "max_records": 10},
            )
            records = data.get("records", [])
            if records:
                return (records[0].get("target") or {}).get("name", "")
        except Exception:
            pass
        return ""

    def list_aggregates(self):
        """Returns all data aggregates: [{name, uuid, available_bytes, node}]."""
        records = self._get_all_records(
            "storage/aggregates",
            params={"fields": "name,uuid,space.block_storage.available,node.name",
                    "max_records": 200},
        )
        result = []
        for r in records:
            result.append({
                "name":            r.get("name", ""),
                "uuid":            r.get("uuid", ""),
                "available_bytes": (r.get("space") or {}).get("block_storage", {}).get("available", 0),
                "node":            (r.get("node") or {}).get("name", ""),
            })
        return result

    def create_volume_san(self, svm_name, vol_name, size_bytes, aggregate_name=None):
        """Creates a thin-provisioned SAN volume (no NAS export). Returns volume UUID.

        aggregate_name: optional — if omitted ONTAP auto-places via style=flexvol.
        """
        body = {
            "name": vol_name,
            "svm": {"name": svm_name},
            "size": size_bytes,
            "style": "flexvol",
            "guarantee": {"type": "none"},
            "snapshot_policy": {"name": "none"},
            "space": {"snapshot": {"reserve_percent": 0}},
        }
        if aggregate_name:
            body["aggregates"] = [{"name": aggregate_name}]
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 30})
        vol_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=3, timeout_s=180)
        if not vol_uuid:
            for v in self.get_volumes_san(svm_name):
                if v.get("name") == vol_name:
                    vol_uuid = v.get("uuid", "")
                    break
        if not vol_uuid:
            raise OntapError(f"Volume '{vol_name}' not found after creation")
        self.disable_volume_snapshots_and_arp(vol_uuid)
        return vol_uuid

    def disable_volume_snapshots_and_arp(self, vol_uuid):
        """Disable scheduled snapshots and Anti-Ransomware Protection on a volume.

        Called after provisioning to ensure no automatic ONTAP snapshots are created.
        ARP disable is best-effort — silently ignored if ARP is not installed or the
        ONTAP version does not support it.
        """
        self._patch(f"storage/volumes/{vol_uuid}", body={
            "snapshot_policy": {"name": "none"},
            "space": {"snapshot": {"reserve_percent": 0}},
        })
        try:
            self._patch(f"storage/volumes/{vol_uuid}",
                        body={"anti_ransomware": {"state": "disabled"}})
        except Exception:
            pass

    def enable_inline_compression(self, vol_uuid):
        """Enable inline compression on a volume (needed for FAS; AFF/ASA enable it by default).

        Raises OntapError on unexpected failures; callers should log and continue.
        """
        self._patch(f"storage/volumes/{vol_uuid}",
                    body={"efficiency": {"compression": "inline"}})

    def create_lun(self, svm_name, volume_name, lun_name, size_bytes, os_type="linux",
                   auto_provision_as_flexvol=False):
        """Creates a thin-provisioned LUN. Returns (lun_uuid, serial_number).

        auto_provision_as_flexvol=True: ONTAP auto-creates the containing volume (ASA).
        """
        lun_path = f"/vol/{volume_name}/{lun_name}"
        body = {
            "name": lun_path,
            "svm": {"name": svm_name},
            "os_type": os_type,
            "space": {
                "size": size_bytes,
                "guarantee": {"requested": False},
            },
        }
        if auto_provision_as_flexvol:
            body["auto_provision_as_flexvol"] = True
        resp = self._post("storage/luns", body=body, params={"return_timeout": 30})
        lun_uuid = resp.get("uuid", "")
        if not lun_uuid:
            for lun in self.list_luns(svm_name):
                if lun.get("name") == lun_path:
                    lun_uuid = lun.get("uuid", "")
                    break
        if not lun_uuid:
            raise OntapError(f"LUN '{lun_path}' not found after creation")
        detail = self.get_lun(lun_uuid)
        return lun_uuid, detail.get("serial_number", "")

    def get_lun_serial(self, lun_uuid):
        """Returns the serial number of a LUN."""
        return self.get_lun(lun_uuid).get("serial_number", "")

    # ── SAN: NVMe-oF ─────────────────────────────────────────────────────────

    def list_nvme_namespaces(self, svm_name=None):
        """All NVMe namespaces.

        Three fallback levels on 404:
        1. protocols/nvme/namespaces  (standard, ONTAP 9.8+)
        2. private/cli/nvme/namespace (older CLI bridge)
        3. protocols/nvme/subsystem-maps (universal, derives namespaces from subsystem mappings)
        """
        params = {
            "fields": "uuid,name,svm.name,location.volume.uuid,"
                      "location.volume.name,space.size,status.state",
            "max_records": 500,
        }
        if svm_name:
            params["svm.name"] = svm_name
        try:
            return self._get_all_records("protocols/nvme/namespaces", params=params)
        except OntapError as exc:
            if exc.status_code != 404:
                raise

        log.info("[netapp_storage] protocols/nvme/namespaces → 404, trying storage/namespaces")
        try:
            return self._list_nvme_namespaces_storage(svm_name)
        except OntapError:
            pass

        log.info("[netapp_storage] storage/namespaces → 404, trying CLI fallback")
        try:
            return self._list_nvme_namespaces_cli(svm_name)
        except OntapError:
            pass

        log.info("[netapp_storage] NVMe CLI fallback → 404, trying subsystem-maps fallback")
        return self._list_nvme_namespaces_via_subsystem_maps(svm_name)

    def _list_nvme_namespaces_storage(self, svm_name=None):
        """Fallback for ONTAP 9.16.1+ AFF: list namespaces via storage/namespaces.

        Normalises the response to the same dict format as list_nvme_namespaces()
        so callers can use location.volume.name/uuid interchangeably.
        The name field in storage/namespaces is the full path /vol/volname/nsname.
        Volume UUID is requested directly; parsed from path as fallback.
        """
        params = {
            "fields": "uuid,name,svm.name,space.size,status.state,"
                      "location.volume.uuid,location.volume.name",
            "max_records": 500,
        }
        if svm_name:
            params["svm.name"] = svm_name
        records = self._get_all_records("storage/namespaces", params=params)
        result = []
        for r in records:
            ns_path = r.get("name", "")          # /vol/volname/nsname
            parts   = [p for p in ns_path.split("/") if p]
            path_vol_name = parts[1] if len(parts) >= 3 else ""
            ns_name       = parts[2] if len(parts) >= 3 else (parts[-1] if parts else "")

            # Prefer API-supplied location fields; fall back to path parsing
            loc     = r.get("location") or {}
            loc_vol = loc.get("volume") or {}
            vol_uuid = loc_vol.get("uuid", "")
            vol_name = loc_vol.get("name", "") or path_vol_name

            result.append({
                "uuid":     r.get("uuid", ""),
                "name":     ns_name,
                "svm":      {"name": (r.get("svm") or {}).get("name", "")},
                "location": {
                    "volume":    {"name": vol_name, "uuid": vol_uuid},
                    "namespace": ns_name,
                },
                "space":  r.get("space", {}),
                "status": r.get("status", {}),
            })
        return result

    def _list_nvme_namespaces_cli(self, svm_name=None):
        """Fallback: NVMe namespaces via private/cli REST bridge.

        Normalises output to the same dict format as list_nvme_namespaces().
        Volume UUIDs are resolved afterwards via get_volumes().
        Raises OntapError when the CLI endpoint is also unreachable,
        so the caller can see the error in debug_info.
        """
        import uuid as _uuid_mod

        def _norm_uuid(u):
            try:
                return str(_uuid_mod.UUID(str(u))).lower()
            except Exception:
                return (u or "").lower()

        params = {"fields": "uuid,vserver,path,volume", "max_records": 500}
        if svm_name:
            params["vserver"] = svm_name
        try:
            data = self._get("private/cli/nvme/namespace", params=params)
            cli_records = data.get("records", [])
        except Exception as exc:
            log.warning(f"[netapp_storage] NVMe CLI fallback failed: {exc}")
            raise OntapError(f"NVMe CLI fallback failed: {exc}")

        if not cli_records:
            return []

        # Look up volume UUIDs in one batch
        vol_uuid_cache = {}  # (svm_name, vol_name) → uuid
        svms = {r.get("vserver", "") for r in cli_records if r.get("vserver")}
        for svm in svms:
            try:
                for v in self.get_volumes(svm_name=svm):
                    vname = v.get("name", "")
                    vuuid = v.get("uuid", "")
                    vsvm  = (v.get("svm") or {}).get("name", svm)
                    if vname and vuuid:
                        vol_uuid_cache[(vsvm, vname)] = vuuid
            except Exception:
                pass

        result = []
        for r in cli_records:
            svm  = r.get("vserver", "")
            vol  = r.get("volume", "")
            result.append({
                "uuid": _norm_uuid(r.get("uuid", "")),
                "name": r.get("path", ""),
                "svm":  {"name": svm},
                "location": {
                    "volume": {
                        "name": vol,
                        "uuid": vol_uuid_cache.get((svm, vol), ""),
                    }
                },
            })
        return result

    def _list_nvme_namespaces_via_subsystem_maps(self, svm_name=None):
        """Third fallback: derive namespaces from subsystem-maps.

        subsystem-maps knows namespace UUID and volume assignment and exists
        even when the namespace-listing endpoint is unavailable.
        Duplicates (namespace in multiple subsystems) are deduplicated.
        Raises OntapError when this endpoint is also unreachable.
        """
        import uuid as _uuid_mod

        def _norm(u):
            try:
                return str(_uuid_mod.UUID(str(u))).lower()
            except Exception:
                return (u or "").lower()

        # Request only minimal, guaranteed-existing fields;
        # volume name is derived from the namespace path (/vol/{volname}/...),
        # volume UUID is resolved via a separate get_volumes() batch.
        params = {"fields": "svm.name,namespace.uuid,namespace.name", "max_records": 500}
        if svm_name:
            params["svm.name"] = svm_name
        try:
            maps = self._get_all_records("protocols/nvme/subsystem-maps", params=params)
        except Exception as exc:
            log.warning(f"[netapp_storage] NVMe subsystem-maps fallback failed: {exc}")
            raise OntapError(f"NVMe subsystem-maps fallback failed: {exc}")

        # Build volume UUID cache.
        # Explicitly request WITHOUT nas.path — on SAN SVMs (ASA) nas.path
        # can cause volumes without NAS config to be excluded from results.
        vol_uuid_cache = {}  # (svm_name, vol_name) → uuid
        seen_svms = {(m.get("svm") or {}).get("name", "") for m in maps}
        for svm in seen_svms:
            if not svm:
                continue
            try:
                vols = self._get_all_records(
                    "storage/volumes",
                    {"svm.name": svm, "fields": "uuid,name,svm.name", "max_records": 500},
                )
                for v in vols:
                    vname = v.get("name", "")
                    vuuid = v.get("uuid", "")
                    vsvm  = (v.get("svm") or {}).get("name", svm)
                    if vname and vuuid:
                        vol_uuid_cache[(vsvm, vname)] = vuuid
            except Exception:
                pass

        seen = set()
        result = []
        for m in maps:
            ns  = m.get("namespace") or {}
            raw_uuid = ns.get("uuid") or ""
            norm_uuid = _norm(raw_uuid)
            if not norm_uuid or norm_uuid in seen:
                continue
            seen.add(norm_uuid)
            svm_found = (m.get("svm") or {}).get("name", "")
            ns_path   = ns.get("name", "")
            # Phase 1a: parse namespace path: /vol/{vol_name}/{ns_name}
            parts    = ns_path.strip("/").split("/")
            vol_name = parts[1] if len(parts) >= 2 and parts[0] == "vol" else ""
            vol_uuid = vol_uuid_cache.get((svm_found, vol_name), "")
            result.append({
                "uuid": norm_uuid,
                "name": ns_path,
                "svm":  {"name": svm_found},
                "location": {
                    "volume": {"name": vol_name, "uuid": vol_uuid}
                },
            })

        # Phase 2: enrich volume info via direct GET on namespace UUID.
        for item in result:
            if (item.get("location") or {}).get("volume", {}).get("uuid"):
                continue
            try:
                detail = self._get(
                    f"protocols/nvme/namespaces/{item['uuid']}",
                    params={"fields": "location.volume.uuid,location.volume.name,name,svm.name"},
                )
                loc = detail.get("location") or {}
                if loc.get("volume", {}).get("uuid"):
                    item["location"] = loc
                    if not item["name"] or "/" not in item["name"]:
                        item["name"] = detail.get("name", item["name"])
                    if not item["svm"]["name"]:
                        item["svm"]["name"] = (detail.get("svm") or {}).get("name", "")
                    continue
            except Exception as exc:
                log.info(f"[netapp_storage] Namespace {item['uuid']} direkt GET: {exc}")

            # Phase 2b: try namespace name as volume name.
            # NetApp ASA default: volume name == namespace name (e.g. ucnlabproxnvme_1).
            ns_bare = item["name"]  # no path — bare name
            if ns_bare and "/" not in ns_bare:
                svm_n = item["svm"]["name"]
                vol_uuid_by_name = vol_uuid_cache.get((svm_n, ns_bare), "")
                if vol_uuid_by_name:
                    item["location"] = {"volume": {"name": ns_bare, "uuid": vol_uuid_by_name}}
                    log.info(
                        f"[netapp_storage] Namespace {item['uuid']}: Volume via Name-Match "
                        f"→ {svm_n}/{ns_bare}"
                    )
                    continue

            # Phase 3: if the SVM has exactly one non-root volume, use it.
            svm_n = item["svm"]["name"]
            non_root = sorted([
                (vn, vu) for (vs, vn), vu in vol_uuid_cache.items()
                if vs == svm_n and not vn.endswith("_root")
            ])
            if len(non_root) == 1:
                vol_name_fb, vol_uuid_fb = non_root[0]
                item["location"] = {"volume": {"name": vol_name_fb, "uuid": vol_uuid_fb}}
                log.info(
                    f"[netapp_storage] Namespace {item['uuid']}: Volume via SVM-Fallback "
                    f"→ {svm_n}/{vol_name_fb}"
                )
            else:
                log.warning(
                    f"[netapp_storage] Namespace {item['uuid']}: no volume resolvable. "
                    f"SVM={svm_n}, known volumes: "
                    f"{sorted(vn for (vs, vn) in vol_uuid_cache if vs == svm_n)}"
                )

        return result

    def get_volumes_san(self, svm_name=None):
        """All volumes of a SVM without NAS fields (for SAN SVMs like ASA)."""
        params = {"fields": "uuid,name,svm.name", "max_records": 500}
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("storage/volumes", params=params)

    def list_nvme_subsystems(self, svm_name=None):
        """All NVMe subsystems (analogous to iGroups for iSCSI)."""
        params = {
            "fields": "uuid,name,svm.name,os_type,hosts.nqn",
            "max_records": 200,
        }
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("protocols/nvme/subsystems", params=params)

    def clone_namespace(self, source_ns_uuid, snap_name,
                        dest_volume_name, dest_ns_name, svm_name):
        """Clone an NVMe namespace from a snapshot (CoW).

        Returns (clone_ns_uuid, job_uuid).
        Falls back to FlexClone volume on ASA (POST protocols/nvme/namespaces → 404).
        Raises OntapError with a user-facing message when the platform supports neither.
        """
        body = {
            "name": f"/vol/{dest_volume_name}/{dest_ns_name}",
            "svm": {"name": svm_name},
            "clone": {
                "source": {
                    "uuid": source_ns_uuid,
                    "snapshot": {"name": snap_name},
                }
            },
        }
        try:
            resp = self._post("protocols/nvme/namespaces", body=body, params={"return_timeout": 15})
            ns_uuid  = resp.get("uuid", "")
            job_uuid = (resp.get("job") or {}).get("uuid", "")
            return ns_uuid, job_uuid
        except OntapError as exc:
            if exc.status_code != 404:
                raise
        log.info("[netapp_storage] protocols/nvme/namespaces POST → 404, trying FlexClone REST fallback")
        try:
            return self._clone_namespace_flexvol(snap_name, dest_volume_name, dest_ns_name, svm_name)
        except OntapError as exc:
            if exc.status_code not in (405, 404):
                raise
        log.info("[netapp_storage] FlexClone REST → 405, trying volume clone CLI bridge (ASA)")
        return self._clone_namespace_via_cli_volume_clone(snap_name, dest_volume_name, dest_ns_name, svm_name, source_ns_uuid)

    def _clone_namespace_flexvol(self, snap_name, src_volume_name, dest_ns_name, svm_name):
        """Fallback: clone NVMe namespace via FlexClone of the parent volume.

        Creates a FlexClone of src_volume_name at snap_name, locates the namespace
        inside the clone volume, and registers (ns_uuid → vol_uuid) in
        self._clone_vol_for_ns so delete_namespace() deletes the whole volume.
        Returns (clone_ns_uuid, "").
        """
        clone_vol_name = f"pgxvol_{dest_ns_name}"[:64]
        log.info(f"[netapp_storage] FlexClone: {src_volume_name}@{snap_name} → {clone_vol_name}")
        body = {
            "name": clone_vol_name,
            "svm": {"name": svm_name},
            "clone": {
                "is_flexclone": True,
                "parent_volume":   {"name": src_volume_name},
                "parent_snapshot": {"name": snap_name},
            },
        }
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 30})
        clone_vol_uuid = resp.get("uuid", "")
        job = (resp.get("job") or {}).get("uuid", "")
        if job:
            self.poll_job(job, interval_s=2, timeout_s=60)

        if not clone_vol_uuid:
            for v in self.get_volumes(svm_name=svm_name):
                if v.get("name") == clone_vol_name:
                    clone_vol_uuid = v.get("uuid", "")
                    break
        if not clone_vol_uuid:
            raise OntapError(f"FlexClone volume {clone_vol_name} not found after creation")

        for ns in self.list_nvme_namespaces(svm_name=svm_name):
            loc = (ns.get("location") or {}).get("volume", {})
            if loc.get("uuid") == clone_vol_uuid or loc.get("name") == clone_vol_name:
                ns_uuid = ns["uuid"]
                self._clone_vol_for_ns[ns_uuid] = {"uuid": clone_vol_uuid, "name": clone_vol_name, "svm": svm_name}
                log.info(f"[netapp_storage] FlexClone ns UUID: {ns_uuid} in vol {clone_vol_name}")
                return ns_uuid, ""

        try:
            self._delete_clone_volume(clone_vol_uuid, clone_vol_name, svm_name)
        except Exception:
            pass
        raise OntapError(f"No namespace found in FlexClone volume {clone_vol_name}")

    def _get_ns_info_from_subsystem_maps(self, ns_uuid, svm_name):
        """Returns (ns_path, subsystem_uuid, subsystem_name) for a namespace UUID via subsystem-maps."""
        if not ns_uuid:
            return "", "", ""
        try:
            maps = self._get_all_records(
                "protocols/nvme/subsystem-maps",
                params={
                    "namespace.uuid": ns_uuid,
                    "svm.name": svm_name,
                    "fields": "namespace.name,subsystem.uuid,subsystem.name",
                    "max_records": 5,
                },
            )
            if maps:
                sub = maps[0].get("subsystem") or {}
                return (
                    (maps[0].get("namespace") or {}).get("name", ""),
                    sub.get("uuid", ""),
                    sub.get("name", ""),
                )
        except OntapError:
            pass
        return "", "", ""

    def _clone_namespace_via_cli_volume_clone(self, snap_name, src_volume_name, dest_ns_name, svm_name, source_ns_uuid=""):
        """Fallback for ASA: clone NVMe namespace via private/cli/volume/clone bridge.

        REST POST storage/volumes → 405 on ASA, but the CLI bridge bypasses that restriction.
        Mirrors the CLI command:
            volume clone create -flexclone <name> -type RW -parent-vserver <svm>
                -parent-volume <vol> -parent-snapshot <snap> -junction-active true -foreground true
        """
        clone_vol_name = f"pgxvol_{dest_ns_name}"[:64]
        log.info(f"[netapp_storage] CLI bridge volume clone: {src_volume_name}@{snap_name} → {clone_vol_name}")

        # Pre-fetch source namespace path + subsystem before creating clone
        src_ns_path, src_subsystem_uuid, src_subsystem_name = self._get_ns_info_from_subsystem_maps(source_ns_uuid, svm_name)
        self._post(
            "private/cli/volume/clone",
            body={
                "vserver":         svm_name,
                "flexclone":       clone_vol_name,
                "type":            "RW",
                "parent-volume":   src_volume_name,
                "parent-snapshot": snap_name,
                "junction-active": True,
                "foreground":      True,
            },
            params={"return_timeout": 60},
            timeout=90,
        )

        # Look up UUID of the freshly created clone volume
        clone_vol_uuid = ""
        for v in self.get_volumes(svm_name=svm_name):
            if v.get("name") == clone_vol_name:
                clone_vol_uuid = v.get("uuid", "")
                break
        if not clone_vol_uuid:
            raise OntapError(f"CLI volume clone {clone_vol_name} not found after creation")

        # Locate the namespace inside the clone volume.
        # Strategy 0: explicitly map clone namespace to source subsystem by derived path.
        # On ASA the cloned namespace is not auto-mapped, so protocols/nvme/namespaces returns
        # nothing for the clone volume. We derive the namespace path from the source and POST it
        # into the subsystem — ONTAP then exposes the UUID via subsystem-maps.
        ns_uuid = ""
        s0_result = "skipped (no src_ns_path or subsystem)"
        if src_ns_path and src_subsystem_name:
            # On ASA, namespace.name == volume name (no /vol/ prefix).
            # Standard ONTAP uses /vol/<vol>/<ns> format — handle both.
            parts = src_ns_path.split("/")
            if len(parts) >= 3 and parts[1] == "vol":
                parts[2] = clone_vol_name
                clone_ns_path = "/".join(parts)
            else:
                clone_ns_path = clone_vol_name

            # Map clone namespace to source subsystem via POST protocols/nvme/subsystem-maps.
            # On ASA, protocols/nvme/subsystems/{uuid}/namespaces does not exist (404).
            # subsystem-maps POST accepts namespace by short name (volume name on ASA).
            map_ok = False
            try:
                self._post(
                    "protocols/nvme/subsystem-maps",
                    body={
                        "svm":       {"name": svm_name},
                        "subsystem": {"name": src_subsystem_name},
                        "namespace": {"name": clone_ns_path},
                    },
                    params={"return_timeout": 15},
                )
                s0_result = f"subsystem-maps POST ok, subsystem={src_subsystem_name}, ns={clone_ns_path}"
                map_ok = True
            except OntapError as exc:
                if exc.status_code == 409:
                    s0_result = f"already mapped (409), subsystem={src_subsystem_name}, ns={clone_ns_path}"
                    map_ok = True
                else:
                    s0_result = f"subsystem-maps POST failed: {exc}"

            # After mapping, look up namespace UUID from subsystem-maps
            if map_ok:
                try:
                    all_maps = self._get_all_records(
                        "protocols/nvme/subsystem-maps",
                        params={
                            "svm.name": svm_name,
                            "fields": "namespace.uuid,namespace.name",
                            "max_records": 500,
                        },
                    )
                    for m in all_maps:
                        if (m.get("namespace") or {}).get("name") == clone_ns_path:
                            ns_uuid = (m.get("namespace") or {}).get("uuid", "")
                            s0_result += f" → ns_uuid={ns_uuid}"
                            break
                    if not ns_uuid:
                        s0_result += f" → path {clone_ns_path!r} not in {len(all_maps)} subsystem-maps entries"
                except OntapError as exc:
                    s0_result += f" → maps lookup failed: {exc}"

        # Strategy 1: targeted REST query filtered by volume name
        s1_result = "not tried"
        s2_result = "not tried"
        s3_result = "not tried"
        if not ns_uuid:
            try:
                records = self._get_all_records(
                    "protocols/nvme/namespaces",
                    params={
                        "location.volume.name": clone_vol_name,
                        "svm.name": svm_name,
                        "fields": "uuid,name,location.volume.uuid,location.volume.name",
                        "max_records": 10,
                    },
                )
                s1_result = f"{len(records)} records"
                if records:
                    ns_uuid = records[0].get("uuid", "")
                    s1_result += f" → ns_uuid={ns_uuid}"
            except OntapError as exc:
                s1_result = f"error: {exc}"

        # Strategy 2: CLI bridge with volume filter
        if not ns_uuid:
            try:
                data = self._get(
                    "private/cli/nvme/namespace",
                    params={"vserver": svm_name, "volume": clone_vol_name,
                            "fields": "uuid,path,volume"},
                )
                s2_records = data.get("records", [])
                s2_result = f"{len(s2_records)} records: {[r.get('volume') for r in s2_records]}"
                for r in s2_records:
                    if r.get("volume") == clone_vol_name:
                        ns_uuid = r.get("uuid", "")
                        s2_result += f" → ns_uuid={ns_uuid}"
                        break
            except OntapError as exc:
                s2_result = f"error: {exc}"

        # Strategy 3: bulk scan with location match (original approach)
        if not ns_uuid:
            all_ns = self.list_nvme_namespaces(svm_name=svm_name)
            ns_summary = [(ns.get("uuid", ""), (ns.get("location") or {}).get("volume", {}).get("name", "")) for ns in all_ns]
            s3_result = f"{len(all_ns)} total; names={[x[1] for x in ns_summary]}"
            for ns in all_ns:
                loc = (ns.get("location") or {}).get("volume", {})
                if loc.get("uuid") == clone_vol_uuid or loc.get("name") == clone_vol_name:
                    ns_uuid = ns["uuid"]
                    s3_result += f" → ns_uuid={ns_uuid}"
                    break

        if ns_uuid:
            self._clone_vol_for_ns[ns_uuid] = {"uuid": clone_vol_uuid, "name": clone_vol_name, "svm": svm_name}
            return ns_uuid, ""

        try:
            self._delete_clone_volume(clone_vol_uuid, clone_vol_name, svm_name)
        except Exception:
            pass
        raise OntapError(
            f"No namespace found in CLI volume clone {clone_vol_name} "
            f"(clone_vol_uuid={clone_vol_uuid}). "
            f"S0={s0_result}; S1={s1_result}; S2={s2_result}; S3={s3_result}"
        )

    def _delete_clone_volume(self, clone_vol_uuid, clone_vol_name="", svm_name=""):
        """Delete a clone volume.

        Attempt 1: REST DELETE storage/volumes/{uuid}  (FAS/AFF)
        Attempt 2: CLI bridge offline + DELETE  (ASA — REST DELETE returns 918701)
        """
        # Attempt 1: REST DELETE (FAS/AFF)
        try:
            resp = self._delete(f"storage/volumes/{clone_vol_uuid}", params={"return_timeout": 30})
            job = (resp.get("job") or {}).get("uuid", "")
            if job:
                self.poll_job(job, interval_s=2, timeout_s=60)
            log.info(f"[netapp_storage] Clone volume {clone_vol_uuid} deleted")
            return
        except OntapError as exc:
            log.warning(f"[netapp_storage] REST delete clone volume {clone_vol_uuid} failed: {exc}")

        # Attempt 2: CLI bridge — volume must be offline before delete on ASA (error 917658).
        # PATCH private/cli/volume sets state=offline, then DELETE removes it.
        if clone_vol_name and svm_name:
            try:
                cli_params = {"vserver": svm_name, "volume": clone_vol_name}
                cli_url = f"{self.base_url}/private/cli/volume"
                r = self._session.patch(cli_url, json={"state": "offline"},
                                        params=cli_params, timeout=self.timeout)
                if not r.ok:
                    log.warning(f"[netapp_storage] CLI volume offline {clone_vol_name}: "
                                f"{r.status_code}: {r.text[:200]}")
                self._delete("private/cli/volume", params=cli_params)
                log.info(f"[netapp_storage] Clone volume {clone_vol_name} deleted via CLI bridge")
                return
            except OntapError as exc:
                log.warning(f"[netapp_storage] CLI bridge delete clone volume {clone_vol_name} failed: {exc}")

        log.warning(f"[netapp_storage] All delete attempts for clone volume "
                    f"{clone_vol_uuid} ({clone_vol_name}) failed — manual cleanup needed on ONTAP")

    def delete_namespace(self, ns_uuid):
        """Delete an NVMe namespace (or its CLI-bridge clone volume on ASA). Returns job UUID."""
        clone_info = self._clone_vol_for_ns.pop(ns_uuid, None)
        if clone_info:
            if isinstance(clone_info, dict):
                clone_vol_uuid = clone_info["uuid"]
                clone_vol_name = clone_info.get("name", "")
                svm_name       = clone_info.get("svm", "")
            else:
                clone_vol_uuid = clone_info  # legacy str path
                clone_vol_name = ""
                svm_name       = ""
            log.info(f"[netapp_storage] Deleting clone volume {clone_vol_uuid} ({clone_vol_name}) for ns {ns_uuid}")
            self._delete_clone_volume(clone_vol_uuid, clone_vol_name, svm_name)
            return ""
        try:
            resp = self._delete(f"protocols/nvme/namespaces/{ns_uuid}",
                                params={"return_timeout": 0})
            return (resp.get("job") or {}).get("uuid", "")
        except OntapError as exc:
            if exc.status_code != 404:
                raise
        # ASA R2: protocols/nvme/namespaces DELETE → 404; use storage/namespaces
        resp = self._delete(f"storage/namespaces/{ns_uuid}",
                            params={"return_timeout": 0})
        return (resp.get("job") or {}).get("uuid", "")

    def get_nvme_subsystem_for_namespace(self, ns_uuid, svm_name=None):
        """Returns the first subsystem dict that maps the given namespace UUID.

        Queries protocols/nvme/subsystem-maps with optional SVM filter.
        Returns {} if no mapping found.
        """
        params = {
            "fields": "svm.name,subsystem.uuid,subsystem.name,namespace.uuid",
            "max_records": 100,
        }
        if svm_name:
            params["svm.name"] = svm_name
        try:
            maps = self._get_all_records("protocols/nvme/subsystem-maps", params=params)
        except Exception:
            return {}
        ns_norm = ns_uuid.lower().replace("-", "")
        for m in maps:
            m_ns = (m.get("namespace") or {}).get("uuid", "")
            if m_ns.lower().replace("-", "") == ns_norm:
                return m.get("subsystem") or {}
        return {}

    def add_nvme_namespace_to_subsystem(self, subsystem_uuid, ns_uuid, svm_name=""):
        """Maps an NVMe namespace to a subsystem.

        Falls back to POST protocols/nvme/subsystem-maps on ASA R2
        (protocols/nvme/subsystems/{uuid}/namespaces → 404).
        svm_name is required for the subsystem-maps fallback.
        """
        try:
            return self._post(
                f"protocols/nvme/subsystems/{subsystem_uuid}/namespaces",
                body={"uuid": ns_uuid},
                params={"return_timeout": 15},
            )
        except OntapError as exc:
            if exc.status_code != 404:
                raise
        # ASA R2 fallback: subsystem-maps collection endpoint (requires svm)
        body = {
            "subsystem": {"uuid": subsystem_uuid},
            "namespace": {"uuid": ns_uuid},
        }
        if svm_name:
            body["svm"] = {"name": svm_name}
        return self._post(
            "protocols/nvme/subsystem-maps",
            body=body,
            params={"return_timeout": 15},
        )

    def remove_nvme_namespace_from_subsystem(self, subsystem_uuid, ns_uuid):
        """Unmaps an NVMe namespace from a subsystem (best-effort).

        ASA does not support DELETE protocols/nvme/subsystems/{uuid}/namespaces/{uuid}
        ("Unexpected argument 'namespaces'") — falls back to DELETE protocols/nvme/subsystem-maps.
        """
        try:
            self._delete(
                f"protocols/nvme/subsystems/{subsystem_uuid}/namespaces/{ns_uuid}"
            )
            return
        except OntapError as exc:
            if exc.status_code != 404:
                log.warning(f"[netapp_storage] unmap namespace from subsystem: {exc}")
                return
        # ASA fallback: use subsystem-maps collection endpoint
        try:
            self._delete(
                "protocols/nvme/subsystem-maps",
                params={"subsystem.uuid": subsystem_uuid, "namespace.uuid": ns_uuid},
            )
        except OntapError as exc:
            log.warning(f"[netapp_storage] unmap namespace via subsystem-maps: {exc}")

    def create_namespace(self, svm_name, volume_name, ns_name, size_bytes, os_type="linux",
                         aggregate_name=None):
        """Creates an NVMe namespace inside an existing volume. Returns ns_uuid.

        Fallback chain (protocols/nvme/namespaces POST → 404 on 9.16.1+):
          1. POST protocols/nvme/namespaces  (ONTAP 9.6–9.15, older AFF/ASA)
          2. POST storage/namespaces         (ONTAP 9.16.1+, AFF and ASA R2)
          3. POST private/cli/nvme/namespace (CLI bridge last resort)
        """
        body = {
            "name": f"/vol/{volume_name}/{ns_name}",
            "svm":  {"name": svm_name},
            "space": {"size": size_bytes},
            "os_type": os_type,
        }
        try:
            resp = self._post("protocols/nvme/namespaces", body=body,
                              params={"return_timeout": 30})
            ns_uuid  = resp.get("uuid", "")
            job_uuid = (resp.get("job") or {}).get("uuid", "")
            if job_uuid:
                self.poll_job(job_uuid, interval_s=2, timeout_s=120)
            if not ns_uuid:
                for ns in self.list_nvme_namespaces(svm_name=svm_name):
                    loc = (ns.get("location") or {})
                    if ((loc.get("volume") or {}).get("name") == volume_name
                            and loc.get("namespace") == ns_name):
                        ns_uuid = ns["uuid"]
                        break
            if not ns_uuid:
                raise OntapError(f"Namespace '{ns_name}' not found after creation")
            return ns_uuid
        except OntapError as exc:
            if exc.status_code == 404:
                log.info("[netapp_storage] protocols/nvme/namespaces POST → 404, "
                         "trying ASA fallback")
                return self._create_namespace_asa(svm_name, volume_name, ns_name,
                                                  size_bytes, os_type, aggregate_name)
            raise

    def _create_namespace_asa(self, svm_name, volume_name, ns_name, size_bytes,
                               os_type="linux", aggregate_name=None):
        """Fallback for NVMe namespace creation when protocols/nvme/namespaces POST → 404.

        This is triggered on ONTAP 9.16.1+ (AFF and ASA R2) where storage/namespaces
        is the primary endpoint, and on ASA classic where protocols/nvme/namespaces
        is not supported.

        Stage 1: POST storage/namespaces  (ONTAP 9.16.1+, AFF and ASA R2)
          — Requires full path /vol/volname/nsname when volume already exists (AFF).
          — ASA R2 auto-provisions the volume from the path when it doesn't exist yet.
        Stage 2: POST private/cli/nvme/namespace  (CLI bridge last resort)

        Returns ns_uuid after looking it up via the CLI bridge or subsystem-maps.
        """
        size_gb = max(1, -(-size_bytes // (1024 ** 3)))  # ceiling division

        # Stage 1: POST storage/namespaces
        # AFF requires a full path (/vol/volname/nsname); ASA R2 accepts just the name.
        # Send full path when volume_name is known — ASA R2 also accepts full paths.
        ns_name_or_path = f"/vol/{volume_name}/{ns_name}" if volume_name else ns_name
        try:
            body = {
                "name":    ns_name_or_path,
                "svm":     {"name": svm_name},
                "space":   {"size": size_bytes},
                "os_type": os_type,
            }
            resp = self._post("storage/namespaces", body=body,
                              params={"return_timeout": 30, "return_records": "true"})
            # UUID may be top-level (ASA R2) or nested under "record" (AFF 9.16.1+)
            ns_uuid  = (resp.get("uuid", "")
                        or (resp.get("record") or {}).get("uuid", ""))
            job_uuid = (resp.get("job") or {}).get("uuid", "")
            if job_uuid:
                self.poll_job(job_uuid, interval_s=2, timeout_s=120)
            if ns_uuid:
                log.info(f"[netapp_storage] storage/namespaces: {ns_name_or_path} → {ns_uuid}")
                return ns_uuid
            # UUID missing from response — look it up
            ns_uuid = self._find_namespace_uuid_after_asa_create(svm_name, volume_name, ns_name)
            if ns_uuid:
                return ns_uuid
            raise OntapError(f"Namespace '{ns_name}' not found after storage/namespaces POST")
        except OntapError as exc:
            if exc.status_code not in (400, 404, 405):
                raise
            log.info(f"[netapp_storage] storage/namespaces → {exc.status_code}; "
                     "trying private/cli/nvme/namespace")

        # Stage 2: CLI bridge
        ns_path = f"/vol/{volume_name}/{ns_name}"
        cli_body = {
            "vserver": svm_name,
            "path":    ns_path,
            "size":    f"{size_gb}g",
            "ostype":  os_type,
        }
        log.info(f"[netapp_storage] ASA CLI nvme namespace create: {ns_path} ({size_gb}G)")
        self._post("private/cli/nvme/namespace", body=cli_body,
                   params={"return_timeout": 30}, timeout=60)

        # Locate the namespace UUID after CLI creation
        ns_uuid = self._find_namespace_uuid_after_asa_create(svm_name, volume_name, ns_name)
        if not ns_uuid:
            raise OntapError(
                f"NVMe namespace '{ns_name}' not found after ASA CLI creation"
            )
        return ns_uuid

    def _find_namespace_uuid_after_asa_create(self, svm_name, volume_name, ns_name):
        """Multi-strategy UUID lookup for a namespace just created via storage/namespaces."""
        # Strategy 0: storage/namespaces by name.
        # On ONTAP 9.16.1+ AFF the name field is the full path; on ASA R2 it's the short name.
        for name_filter in (
            f"/vol/{volume_name}/{ns_name}" if volume_name else None,
            ns_name,
        ):
            if not name_filter:
                continue
            try:
                records = self._get_all_records(
                    "storage/namespaces",
                    params={"name": name_filter, "svm.name": svm_name,
                            "fields": "uuid,name", "max_records": 10},
                )
                if records:
                    return records[0].get("uuid", "")
            except OntapError:
                pass

        # Strategy 1: protocols/nvme/namespaces by volume name
        try:
            records = self._get_all_records(
                "protocols/nvme/namespaces",
                params={
                    "location.volume.name": volume_name,
                    "svm.name":             svm_name,
                    "fields":               "uuid,name",
                    "max_records":          10,
                },
            )
            for r in records:
                loc = (r.get("location") or {})
                if (loc.get("namespace") == ns_name
                        or (loc.get("volume") or {}).get("name") == volume_name):
                    return r.get("uuid", "")
        except OntapError:
            pass

        # Strategy 2: CLI bridge by volume name (proven to work on ASA R2)
        try:
            data = self._get(
                "private/cli/nvme/namespace",
                params={"vserver": svm_name, "volume": volume_name,
                        "fields": "uuid,path,volume"},
            )
            for r in data.get("records", []):
                if r.get("volume") == volume_name:
                    return r.get("uuid", "")
        except OntapError:
            pass

        # Strategy 3: bulk scan via list_nvme_namespaces (uses its own fallback chain)
        for ns in self.list_nvme_namespaces(svm_name=svm_name):
            loc = (ns.get("location") or {}).get("volume", {})
            if loc.get("name") == volume_name:
                return ns.get("uuid", "")

        return ""

    def get_namespace(self, ns_uuid):
        """Returns namespace details (location, space, os_type).

        Falls back to storage/namespaces on ASA R2 (protocols/nvme/namespaces → 404).
        """
        try:
            return self._get(f"protocols/nvme/namespaces/{ns_uuid}",
                             params={"fields": "uuid,name,location,space,os_type,svm"})
        except OntapError as exc:
            if exc.status_code != 404:
                raise
        # ASA R2: try the new endpoint
        return self._get(f"storage/namespaces/{ns_uuid}",
                         params={"fields": "uuid,name,location,space,os_type,svm"})

    def create_nvme_subsystem(self, svm_name, subsystem_name, os_type="linux"):
        """Creates an NVMe subsystem (analogous to iGroup). Returns subsystem_uuid."""
        body = {
            "name":    subsystem_name,
            "svm":     {"name": svm_name},
            "os_type": os_type,
        }
        resp = self._post("protocols/nvme/subsystems", body=body,
                          params={"return_timeout": 30})
        sub_uuid = resp.get("uuid", "")
        if not sub_uuid:
            for s in self.list_nvme_subsystems(svm_name=svm_name):
                if s.get("name") == subsystem_name:
                    sub_uuid = s["uuid"]
                    break
        if not sub_uuid:
            raise OntapError(f"NVMe subsystem '{subsystem_name}' not found after creation")
        return sub_uuid

    def get_nvme_subsystem(self, subsystem_uuid):
        """Returns subsystem details (name, uuid, hosts, target_nqn if available)."""
        try:
            return self._get(f"protocols/nvme/subsystems/{subsystem_uuid}",
                             params={"fields": "uuid,name,svm.name,os_type,hosts.nqn,target_nqn"})
        except OntapError:
            return self._get(f"protocols/nvme/subsystems/{subsystem_uuid}",
                             params={"fields": "uuid,name,svm.name,os_type,hosts.nqn"})

    def add_nvme_host_to_subsystem(self, subsystem_uuid, host_nqn):
        """Adds a host NQN to an NVMe subsystem."""
        return self._post(
            f"protocols/nvme/subsystems/{subsystem_uuid}/hosts",
            body={"nqn": host_nqn},
            params={"return_timeout": 15},
        )

    def remove_nvme_host_from_subsystem(self, subsystem_uuid, host_nqn):
        """Removes a host NQN from an NVMe subsystem (best-effort)."""
        try:
            self._delete(f"protocols/nvme/subsystems/{subsystem_uuid}/hosts/{host_nqn}")
        except OntapError as exc:
            log.warning(f"[netapp_storage] remove NVMe host from subsystem: {exc}")

    def delete_nvme_subsystem(self, subsystem_uuid):
        """Deletes an NVMe subsystem."""
        try:
            self._delete(f"protocols/nvme/subsystems/{subsystem_uuid}")
        except OntapError as exc:
            log.warning(f"[netapp_storage] delete NVMe subsystem: {exc}")

    def get_nvme_lifs_for_svm(self, svm_name):
        """Returns list of NVMe/TCP LIF IPs for the SVM."""
        records = self._get_all_records(
            "network/ip/interfaces",
            params={"services": "data_nvme_tcp", "svm.name": svm_name,
                    "fields": "ip.address,state", "max_records": 50},
        )
        return [
            (rec.get("ip") or {}).get("address", "")
            for rec in records
            if rec.get("state", "up") == "up"
            and (rec.get("ip") or {}).get("address", "")
        ]

    # ── Resize ────────────────────────────────────────────────────────────────

    def resize_volume(self, volume_uuid, new_size_bytes):
        """Grows (or shrinks for NFS) a volume to new_size_bytes."""
        url = f"{self.base_url}/storage/volumes/{volume_uuid}"
        try:
            r = self._session.patch(url, json={"size": new_size_bytes},
                                    params={"return_timeout": 30}, timeout=self.timeout)
        except Exception as exc:
            raise OntapError(f"PATCH volume/{volume_uuid} network error: {exc}")
        if not r.ok:
            body_text = r.text[:400]
            if r.status_code == 400 and "918703" in body_text:
                self._resize_volume_asa(volume_uuid, new_size_bytes)
                return
            raise OntapError(f"PATCH volume/{volume_uuid} → {r.status_code}: {body_text}")
        resp = r.json() if r.content else {}
        job = (resp.get("job") or {}).get("uuid", "")
        if job:
            self.poll_job(job, interval_s=2, timeout_s=120)

    def _resize_volume_asa(self, volume_uuid, new_size_bytes):
        import math
        vol = self._get(f"storage/volumes/{volume_uuid}", params={"fields": "name,svm.name"})
        vol_name = vol.get("name", "")
        svm_name = (vol.get("svm") or {}).get("name", "")
        if not vol_name or not svm_name:
            raise OntapError("ASA volume resize: cannot resolve volume name/SVM")
        # Round up to next full GiB — byte notation causes WAFL rounding that
        # can leave the volume smaller than expected.
        size_gb = math.ceil(new_size_bytes / (1024 ** 3))
        self._patch("private/cli/volume",
                    body={"size": f"{size_gb}g"},
                    params={"vserver": svm_name, "volume": vol_name})

    def resize_lun(self, lun_uuid, new_size_bytes):
        """Grows a LUN to new_size_bytes."""
        url = f"{self.base_url}/storage/luns/{lun_uuid}"
        try:
            r = self._session.patch(url,
                                    json={"space": {"size": new_size_bytes}},
                                    params={"return_timeout": 30}, timeout=self.timeout)
        except Exception as exc:
            raise OntapError(f"PATCH lun/{lun_uuid} network error: {exc}")
        if not r.ok:
            raise OntapError(f"PATCH lun/{lun_uuid} → {r.status_code}: {r.text[:300]}")

    def resize_namespace(self, ns_uuid, new_size_bytes):
        """Grows an NVMe namespace to new_size_bytes."""
        last_err = None
        # (path, body) — storage/storage-units uses top-level "size" (ASA R2 native)
        candidates = [
            (f"protocols/nvme/namespaces/{ns_uuid}", {"space": {"size": new_size_bytes}}),
            (f"storage/namespaces/{ns_uuid}",        {"space": {"size": new_size_bytes}}),
            (f"storage/storage-units/{ns_uuid}",     {"size": new_size_bytes}),
        ]
        for path, body in candidates:
            url = f"{self.base_url}/{path}"
            try:
                r = self._session.patch(url, json=body,
                                        params={"return_timeout": 30}, timeout=self.timeout)
            except Exception as exc:
                raise OntapError(f"PATCH {path} network error: {exc}")
            if r.ok:
                log.info(f"[netapp_storage] namespace resize succeeded via {path}")
                return
            if r.status_code == 404:
                log.info(f"[netapp_storage] PATCH {path} → 404, trying next")
                continue
            last_err = OntapError(f"PATCH {path} → {r.status_code}: {r.text[:300]}")
            log.info(f"[netapp_storage] PATCH {path} failed: {last_err}")
        # REST endpoints all failed — try CLI bridge
        try:
            self._resize_namespace_cli(ns_uuid, new_size_bytes)
            return
        except OntapError as cli_err:
            raise OntapError(
                f"{last_err or 'namespace resize failed'}; CLI bridge also failed: {cli_err}"
            ) from None

    def _resize_namespace_cli(self, ns_uuid, new_size_bytes):
        for src in (f"storage/namespaces/{ns_uuid}",
                    f"protocols/nvme/namespaces/{ns_uuid}"):
            try:
                ns = self._get(src, params={"fields": "name,svm.name"})
                break
            except OntapError:
                ns = None
        if not ns:
            raise OntapError("namespace CLI resize: cannot look up namespace")
        ns_path = ns.get("name", "")
        svm_name = (ns.get("svm") or {}).get("name", "")
        if not ns_path or not svm_name:
            raise OntapError("namespace CLI resize: cannot resolve path/SVM")
        self._patch("private/cli/vserver/nvme/namespace",
                    body={"size": f"{new_size_bytes}b"},
                    params={"vserver": svm_name, "path": ns_path})

    # ── NFS Volume provisioning ───────────────────────────────────────────────

    def create_volume_nfs(self, svm_name, vol_name, size_bytes,
                          junction_path, aggregate_name=None, export_policy="default"):
        """Creates an NFS volume with a junction path. Returns volume UUID."""
        body = {
            "name":      vol_name,
            "svm":       {"name": svm_name},
            "size":      size_bytes,
            "style":     "flexvol",
            "guarantee": {"type": "none"},
            "snapshot_policy": {"name": "none"},
            "space": {"snapshot": {"reserve_percent": 0}},
            "nas": {
                "path":          junction_path,
                "export_policy": {"name": export_policy},
            },
        }
        if aggregate_name:
            body["aggregates"] = [{"name": aggregate_name}]
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 30})
        vol_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=3, timeout_s=180)
        if not vol_uuid:
            for v in self.get_volumes(svm_name=svm_name):
                if v.get("name") == vol_name:
                    vol_uuid = v.get("uuid", "")
                    break
        if not vol_uuid:
            raise OntapError(f"NFS volume '{vol_name}' not found after creation")
        self.disable_volume_snapshots_and_arp(vol_uuid)
        return vol_uuid

    def create_export_policy(self, svm_name, policy_name):
        """Creates an NFS export policy. Returns policy id (int)."""
        body = {"name": policy_name, "svm": {"name": svm_name}}
        resp = self._post("protocols/nfs/export-policies", body=body,
                          params={"return_timeout": 15})
        policy_id = resp.get("id", 0)
        if not policy_id:
            records = self._get_all_records(
                "protocols/nfs/export-policies",
                params={"name": policy_name, "svm.name": svm_name,
                        "fields": "id", "max_records": 5},
            )
            if records:
                policy_id = records[0].get("id", 0)
        if not policy_id:
            raise OntapError(f"Export policy '{policy_name}' not found after creation")
        return policy_id

    def add_nfs_export_rule_rw(self, export_policy_id, client_match="0.0.0.0/0"):
        """Adds a read-write NFS export rule (used for provisioned datastores)."""
        body = {
            "clients":    [{"match": client_match}],
            "ro_rule":    ["any"],
            "rw_rule":    ["any"],
            "superuser":  ["any"],
        }
        return self._post(
            f"protocols/nfs/export-policies/{export_policy_id}/rules", body=body)

    def set_volume_export_policy(self, volume_uuid, policy_name):
        """Assigns an export policy to a volume by name."""
        url = f"{self.base_url}/storage/volumes/{volume_uuid}"
        try:
            r = self._session.patch(
                url,
                json={"nas": {"export_policy": {"name": policy_name}}},
                params={"return_timeout": 15},
                timeout=self.timeout,
            )
        except Exception as exc:
            raise OntapError(f"PATCH volume/{volume_uuid} export_policy: {exc}")
        if not r.ok:
            raise OntapError(
                f"PATCH volume/{volume_uuid} export_policy → {r.status_code}: {r.text[:300]}")

    def delete_export_policy(self, export_policy_id):
        """Deletes an NFS export policy (best-effort)."""
        try:
            self._delete(f"protocols/nfs/export-policies/{export_policy_id}")
        except OntapError as exc:
            log.warning(f"[netapp_storage] delete export policy {export_policy_id}: {exc}")

    # ── Recovery / DR bind helpers ─────────────────────────────────────────────

    def get_volumes_recovery(self, svm_name=None):
        """All volumes with type (rw/dp), size, and NAS path — for recovery scanning."""
        params = {
            "fields": "uuid,name,svm,type,nas.path,space.size",
            "max_records": 500,
        }
        if svm_name:
            params["svm.name"] = svm_name
        return self._get_all_records("storage/volumes", params=params)

    def get_snapmirror_dest_relationship(self, dest_svm, dest_volume_name):
        """Finds the SnapMirror relationship where dest_svm:dest_volume_name is the destination.

        Returns the first matching relationship dict, or None if not found.
        """
        try:
            records = self._get_all_records(
                "snapmirror/relationships",
                params={
                    "destination.svm.name":    dest_svm,
                    "destination.volume.name": dest_volume_name,
                    "fields": "uuid,state,healthy,lag_time,source.path,destination.path",
                    "max_records": 10,
                },
            )
            return records[0] if records else None
        except OntapError:
            # Some ONTAP versions don't support the volume.name filter — fall back
            try:
                all_rels = self._get_all_records(
                    "snapmirror/relationships",
                    params={
                        "fields": "uuid,state,healthy,lag_time,source.path,destination.path",
                        "max_records": 500,
                    },
                )
                target = f"{dest_svm}:{dest_volume_name}"
                for r in all_rels:
                    if (r.get("destination") or {}).get("path", "") == target:
                        return r
                return None
            except Exception:
                return None

    def snapmirror_break(self, relationship_uuid):
        """Breaks a SnapMirror relationship (transitions DP volume to RW).

        After break the volume is writable and can be mounted.
        Polls ONTAP until the state is 'broken_off' or times out.
        """
        self._patch(
            f"snapmirror/relationships/{relationship_uuid}",
            body={"state": "broken_off"},
            params={"return_timeout": 60},
        )
        # Poll until broken (ONTAP may return 200 before state actually changes)
        for _ in range(20):
            time.sleep(3)
            try:
                rel = self._get(
                    f"snapmirror/relationships/{relationship_uuid}",
                    params={"fields": "state"},
                )
                if rel.get("state", "") in ("broken_off", ""):
                    return
            except OntapError:
                return  # relationship may be gone after break — that's fine
        log.warning(f"[netapp_storage] SM break {relationship_uuid}: state did not confirm broken_off")

    def mount_volume(self, volume_uuid, junction_path):
        """Mounts a volume by setting its NAS junction path.

        Used after SnapMirror break when the DP volume had no mount point.
        """
        self._patch(
            f"storage/volumes/{volume_uuid}",
            body={"nas": {"path": junction_path}},
            params={"return_timeout": 30},
        )

    def get_volume_by_uuid(self, volume_uuid):
        """Return volume details by UUID."""
        return self._get(
            f"storage/volumes/{volume_uuid}",
            params={"fields": "name,svm.name,type,nas.path,space.size,state"},
        )

    def create_dp_volume(self, svm_name, vol_name, size_bytes=None):
        """Create a DP (data protection) volume for SnapMirror destination.

        Explicitly sets encrypt=False to avoid failures on clusters without
        encryption license. Returns volume UUID.
        """
        body = {
            "name":     vol_name,
            "svm":      {"name": svm_name},
            "type":     "dp",
            "guarantee":{"type": "none"},
            "snapshot_policy": {"name": "none"},
            "space":    {"snapshot": {"reserve_percent": 0}},
        }
        if size_bytes:
            body["size"] = size_bytes
        resp = self._post("storage/volumes", body=body, params={"return_timeout": 30})
        vol_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")
        if job_uuid:
            self.poll_job(job_uuid, interval_s=3, timeout_s=60)
        if not vol_uuid:
            for v in (self.get_volumes(svm_name=svm_name) or []):
                if v.get("name") == vol_name:
                    vol_uuid = v.get("uuid", "")
                    break
        return vol_uuid

    def create_snapmirror_relationship(self, source_path, dest_path,
                                       policy="MirrorAllSnapshots",
                                       progress_cb=None,
                                       create_destination=True):
        """Create a SnapMirror relationship and auto-create the destination volume.

        source_path / dest_path format: 'svm_name:volume_name'
        Cluster peering must already be established.
        progress_cb(msg): optional callback for progress messages.
        encrypt_destination: False (default) avoids failures on clusters without
                             encryption license. Set to None to inherit source setting.
        Returns relationship UUID.
        """
        def _cb(msg):
            if progress_cb:
                progress_cb(msg)

        body = {
            "source":      {"path": source_path},
            "destination": {"path": dest_path},
            "policy":      {"name": policy},
        }
        if create_destination:
            body["create_destination"] = {"enabled": True}
        # Use return_timeout=0 to get a job UUID immediately (avoids HTTP read timeout)
        _cb(f"[INFO] Sending SnapMirror relationship request to ONTAP...")
        resp = self._post("snapmirror/relationships", body=body,
                          params={"return_timeout": 0})
        rel_uuid = resp.get("uuid", "")
        job_uuid = (resp.get("job") or {}).get("uuid", "")

        if job_uuid:
            _cb(f"[INFO] ONTAP job started ({job_uuid[:8]}…) — creating destination volume and relationship...")
            start = time.monotonic()
            last_log = start
            deadline = start + 300
            while True:
                data = self._get(f"cluster/jobs/{job_uuid}")
                state = data.get("state", "")
                if state == "success":
                    _cb(f"[INFO] ONTAP job completed ({int(time.monotonic()-start)}s).")
                    break
                if state == "failure":
                    raise OntapError(
                        f"ONTAP job {job_uuid[:8]} failed: {data.get('message', 'no message')}"
                    )
                elapsed = int(time.monotonic() - start)
                if time.monotonic() - last_log >= 15:
                    _cb(f"[INFO] Still working… ({elapsed}s elapsed, state: {state})")
                    last_log = time.monotonic()
                if time.monotonic() > deadline:
                    raise OntapError(
                        f"ONTAP job {job_uuid[:8]} timed out after 300s (state: {state}). "
                        f"The operation may still complete on ONTAP — check System Manager."
                    )
                time.sleep(4)
        elif rel_uuid:
            _cb(f"[INFO] Relationship created directly (UUID: {rel_uuid[:8]}…)")

        if not rel_uuid:
            _cb(f"[INFO] Looking up relationship by destination path...")
            rels = self._get_all_records("snapmirror/relationships", params={
                "destination.path": dest_path, "fields": "uuid", "max_records": 5,
            })
            if rels:
                rel_uuid = rels[0].get("uuid", "")
        return rel_uuid

    def initialize_snapmirror(self, relationship_uuid):
        """Trigger initial SnapMirror baseline transfer."""
        try:
            self._patch(
                f"snapmirror/relationships/{relationship_uuid}",
                body={"state": "snapmirrored"},
                params={"return_timeout": 0},
            )
        except OntapError as e:
            if "already" in str(e).lower() or "409" in str(e):
                return  # already initialized
            raise
