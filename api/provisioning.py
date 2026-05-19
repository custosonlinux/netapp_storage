"""
NetApp ONTAP Provisioning API

End-to-end provisioning of iSCSI, NVMe-oF and NFS datastores:
  create / resize / add-host / remove-host / remove

All mutating operations run as background jobs (same pattern as restore/clone).
"""

import json
import shlex
import uuid as _uuid
import logging
from datetime import datetime, timezone

from pegaprox.core.db import get_db

from ..core._helpers import (
    get_endpoint, build_ontap_client, build_pve_client,
    get_ssh_creds, JobLogger, ssh_run,
)
from ..core.ontap_client import OntapError
from ..core.san_helpers import (
    get_iscsi_initiator_iqn, find_device_by_serial, _iscsi_serial_to_mapper,
    get_nvme_host_nqn, nvme_connect_all, nvme_disconnect_by_vg,
    nvme_list_devices, find_new_nvme_device,
    snapmanifest_initialize,
)

log = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat()


from ..core._helpers import PLUGIN_ID  # noqa: F401


def _require_admin():
    from flask import request
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


def _ds_to_dict(row):
    d = dict(row)
    try:
        d["pve_host_ids"] = json.loads(d.get("pve_host_ids") or "[]")
    except Exception:
        d["pve_host_ids"] = []
    return d


# ── Route handlers ────────────────────────────────────────────────────────────

def _prov_datastores():
    from flask import request
    if request.method == "GET":
        err = _require_admin()
        if err:
            return err
        db = get_db()
        rows = db.query(
            "SELECT * FROM netapp_provisioned_datastores ORDER BY created_at DESC")
        return {"datastores": [_ds_to_dict(r) for r in rows]}

    # POST — create
    err = _require_admin()
    if err:
        return err
    body = request.get_json(force=True) or {}
    required = ["name", "endpoint_id", "protocol", "pve_host_ids"]
    for f in required:
        if not body.get(f):
            return {"error": f"Required field missing: {f}"}, 400
    protocol = body["protocol"]
    if protocol not in ("iscsi", "nvme", "nfs"):
        return {"error": f"Unknown protocol: {protocol}"}, 400

    db = get_db()
    ds_id    = str(_uuid.uuid4())
    username = request.session.get("user", "unknown")
    now      = _now()
    db.execute(
        """INSERT INTO netapp_provisioned_datastores
           (id, name, endpoint_id, svm_name, volume_uuid, volume_name,
            protocol, lun_uuid, lun_path, igroup_uuid, igroup_name,
            ns_uuid, subsystem_uuid, subsystem_name,
            vg_name, lvm_type, lvm_pool_name,
            nfs_junction_path, pve_storage_id,
            pve_host_ids, size_bytes, status, error_message,
            created_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ds_id, body["name"], body["endpoint_id"],
            body.get("svm_name", ""), body.get("volume_uuid", ""),
            body.get("volume_name", ""), protocol,
            body.get("lun_uuid", ""), body.get("lun_path", ""),
            body.get("igroup_uuid", ""), body.get("igroup_name", ""),
            body.get("ns_uuid", ""), body.get("subsystem_uuid", ""),
            body.get("subsystem_name", ""),
            body.get("vg_name", ""), body.get("lvm_type", "linear"),
            body.get("lvm_pool_name", ""), body.get("nfs_junction_path", ""),
            body.get("pve_storage_id", ""),
            json.dumps(body["pve_host_ids"]),
            int(body.get("size_bytes", 0)),
            "provisioning", "", username, now, now,
        ),
    )
    job_id = _start_job(db, "provision", ds_id, username)
    _run_provision_job_async(job_id, ds_id, body, username)
    return {"id": ds_id, "job_id": job_id}, 202


def _check_vms_on_storage(db, pve_host_id, vg_name):
    """Returns list of LV names in vg_name that look like VM disks (excludes system LVs)."""
    SYSTEM_LVS = {"snapmanifest", "data", "data_tmeta", "data_tdata"}
    try:
        pve = build_pve_client(db, pve_host_id)
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host
        out = ssh_run(
            sh, su, sp,
            f"lvs --noheadings -o lv_name {shlex.quote(vg_name)} 2>/dev/null",
            capture=True, key_material=sk, timeout=15)
        return [l.strip() for l in out.strip().splitlines()
                if l.strip() and l.strip() not in SYSTEM_LVS]
    except Exception:
        return []


def _prov_remove():
    err = _require_admin()
    if err:
        return err
    from flask import request
    body      = request.get_json(force=True) or {}
    ds_id     = body.get("id")
    if not ds_id:
        return {"error": "id required"}, 400
    delete_ontap = bool(body.get("delete_ontap_objects", False))
    force        = bool(body.get("force", False))

    db  = get_db()
    row = db.query_one(
        "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404
    ds = dict(row)

    # Safety check: abort if VMs still have disks in the VG
    if not force:
        vg_name      = ds.get("vg_name", "")
        pve_host_ids = json.loads(ds.get("pve_host_ids") or "[]")
        if pve_host_ids and vg_name:
            try:
                in_use = _check_vms_on_storage(db, pve_host_ids[0], vg_name)
                if in_use:
                    return {
                        "error": "Storage still in use — remove these VM disks first",
                        "volumes": in_use,
                    }, 409
            except Exception:
                pass  # SSH unreachable — let the job handle it

    username = request.session.get("user", "unknown")
    db.execute(
        "UPDATE netapp_provisioned_datastores SET status='removing', updated_at=? WHERE id=?",
        (_now(), ds_id),
    )
    job_id = _start_job(db, "provision_remove", ds_id, username)
    _run_remove_job_async(job_id, ds_id, delete_ontap, username)
    return {"job_id": job_id}, 202


def _prov_resize():
    err = _require_admin()
    if err:
        return err
    from flask import request
    body     = request.get_json(force=True) or {}
    ds_id    = body.get("id")
    new_size = body.get("size_bytes")
    if not ds_id or not new_size:
        return {"error": "id and size_bytes required"}, 400

    db  = get_db()
    row = db.query_one(
        "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404

    username = request.session.get("user", "unknown")
    job_id   = _start_job(db, "provision_resize", ds_id, username)
    _run_resize_job_async(job_id, ds_id, int(new_size), username)
    return {"job_id": job_id}, 202


def _prov_add_host():
    err = _require_admin()
    if err:
        return err
    from flask import request
    body    = request.get_json(force=True) or {}
    ds_id   = body.get("id")
    host_id = body.get("pve_host_id")
    if not ds_id or not host_id:
        return {"error": "id and pve_host_id required"}, 400

    db  = get_db()
    row = db.query_one(
        "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404

    host_ids = json.loads(row["pve_host_ids"] or "[]")
    if host_id in host_ids:
        return {"error": "Host already connected"}, 409

    username = request.session.get("user", "unknown")
    job_id   = _start_job(db, "provision_add_host", ds_id, username)
    _run_add_host_job_async(job_id, ds_id, host_id, username)
    return {"job_id": job_id}, 202


def _prov_remove_host():
    err = _require_admin()
    if err:
        return err
    from flask import request
    body    = request.get_json(force=True) or {}
    ds_id   = body.get("id")
    host_id = body.get("host_id")
    if not ds_id or not host_id:
        return {"error": "id and host_id required"}, 400

    db  = get_db()
    row = db.query_one(
        "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if not row:
        return {"error": "Datastore not found"}, 404

    username = request.session.get("user", "unknown")
    job_id   = _start_job(db, "provision_remove_host", ds_id, username)
    _run_remove_host_job_async(job_id, ds_id, host_id, username)
    return {"job_id": job_id}, 202


def _prov_ontap_resources():
    err = _require_admin()
    if err:
        return err
    from flask import request
    endpoint_id = request.args.get("endpoint_id")
    svm_name    = request.args.get("svm_name", "")
    if not endpoint_id:
        return {"error": "endpoint_id required"}, 400

    db       = get_db()
    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    volumes = []
    try:
        vols = client.get_volumes_san(svm_name=svm_name) if svm_name else client.get_volumes(svm_name=svm_name)
        for v in vols:
            volumes.append({
                "uuid": v.get("uuid", ""),
                "name": v.get("name", ""),
                "svm":  (v.get("svm") or {}).get("name", ""),
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources volumes: {exc}")

    luns = []
    try:
        for lun in client.list_luns(svm_name=svm_name):
            luns.append({
                "uuid":        lun.get("uuid", ""),
                "name":        lun.get("name", ""),
                "volume_uuid": ((lun.get("location") or {}).get("volume") or {}).get("uuid", ""),
                "size_bytes":  (lun.get("space") or {}).get("size", 0),
                "serial":      lun.get("serial_number", ""),
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources luns: {exc}")

    igroups = []
    try:
        for ig in client.list_igroups(svm_name=svm_name):
            igroups.append({
                "uuid":       ig.get("uuid", ""),
                "name":       ig.get("name", ""),
                "protocol":   ig.get("protocol", ""),
                "os_type":    ig.get("os_type", ""),
                "initiators": [i.get("name", "") for i in (ig.get("initiators") or [])],
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources igroups: {exc}")

    nvme_subsystems = []
    try:
        for sub in client.list_nvme_subsystems(svm_name=svm_name):
            nvme_subsystems.append({
                "uuid":  sub.get("uuid", ""),
                "name":  sub.get("name", ""),
                "hosts": [h.get("nqn", "") for h in (sub.get("hosts") or [])],
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources nvme_subsystems: {exc}")

    nvme_namespaces = []
    try:
        for ns in client.list_nvme_namespaces(svm_name=svm_name):
            loc = ns.get("location") or {}
            nvme_namespaces.append({
                "uuid":        ns.get("uuid", ""),
                "name":        ns.get("name", ""),
                "volume_uuid": (loc.get("volume") or {}).get("uuid", ""),
                "size_bytes":  (ns.get("space") or {}).get("size", 0),
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources nvme_namespaces: {exc}")

    aggregates = []
    try:
        for ag in client.list_aggregates():
            aggregates.append({
                "name":            ag.get("name", ""),
                "uuid":            ag.get("uuid", ""),
                "available_bytes": ag.get("available_bytes", 0),
                "node":            ag.get("node", ""),
            })
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources aggregates: {exc}")

    nfs_lifs = []
    try:
        nfs_lifs = client.list_nfs_lifs(svm_name=svm_name) if svm_name else []
    except Exception as exc:
        log.warning(f"[netapp_storage] prov ontap-resources nfs_lifs: {exc}")

    return {
        "volumes": volumes, "luns": luns, "igroups": igroups,
        "nvme_subsystems": nvme_subsystems, "nvme_namespaces": nvme_namespaces,
        "aggregates": aggregates, "nfs_lifs": nfs_lifs,
    }


def _prov_pve_hosts():
    err = _require_admin()
    if err:
        return err
    db   = get_db()
    rows = db.query("SELECT id, name, host FROM netapp_pve_hosts ORDER BY name")
    return {"hosts": [dict(r) for r in rows]}


def _prov_svms():
    err = _require_admin()
    if err:
        return err
    from flask import request
    endpoint_id = request.args.get("endpoint_id")
    if not endpoint_id:
        return {"error": "endpoint_id required"}, 400
    db       = get_db()
    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)
    try:
        svms = client.list_svms()
        return {"svms": [{"name": s.get("name",""), "uuid": s.get("uuid","")} for s in svms]}
    except Exception as exc:
        return {"error": str(exc)}, 500


def register_routes():
    from pegaprox.api.plugins import register_plugin_route
    register_plugin_route(PLUGIN_ID, "provisioning/datastores",            _prov_datastores)
    register_plugin_route(PLUGIN_ID, "provisioning/datastores/remove",     _prov_remove)
    register_plugin_route(PLUGIN_ID, "provisioning/datastores/resize",     _prov_resize)
    register_plugin_route(PLUGIN_ID, "provisioning/datastores/add-host",   _prov_add_host)
    register_plugin_route(PLUGIN_ID, "provisioning/datastores/remove-host", _prov_remove_host)
    register_plugin_route(PLUGIN_ID, "provisioning/ontap-resources",       _prov_ontap_resources)
    register_plugin_route(PLUGIN_ID, "provisioning/pve-hosts",             _prov_pve_hosts)
    register_plugin_route(PLUGIN_ID, "provisioning/svms",                  _prov_svms)


# ── Job helpers ───────────────────────────────────────────────────────────────

def _start_job(db, job_type, ds_id, username):
    job_id = str(_uuid.uuid4())
    db.execute(
        """INSERT INTO netapp_jobs
           (id, job_type, status, progress_pct, log_json, created_by, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (job_id, job_type, "running", 0, "[]", username, _now()),
    )
    return job_id


def _finish_job(db, job_id):
    db.execute(
        "UPDATE netapp_jobs SET status='done', progress_pct=100, completed_at=? WHERE id=?",
        (_now(), job_id),
    )


def _fail_job(db, job_id):
    db.execute(
        "UPDATE netapp_jobs SET status='failed', completed_at=? WHERE id=?",
        (_now(), job_id),
    )


def _set_ds_status(db, ds_id, status, error=""):
    db.execute(
        "UPDATE netapp_provisioned_datastores SET status=?, error_message=?, updated_at=? WHERE id=?",
        (status, error, _now(), ds_id),
    )


# ── Async job launchers (stubs — logic implemented per-protocol later) ────────

def _run_provision_job_async(job_id, ds_id, params, username):
    import threading
    t = threading.Thread(
        target=_run_provision, args=(job_id, ds_id, params, username), daemon=True)
    t.start()


def _run_resize_job_async(job_id, ds_id, new_size_bytes, username):
    import threading
    t = threading.Thread(
        target=_run_resize, args=(job_id, ds_id, new_size_bytes, username), daemon=True)
    t.start()


def _run_add_host_job_async(job_id, ds_id, host_id, username):
    import threading
    t = threading.Thread(
        target=_run_add_host, args=(job_id, ds_id, host_id, username), daemon=True)
    t.start()


def _run_remove_host_job_async(job_id, ds_id, host_id, username):
    import threading
    t = threading.Thread(
        target=_run_remove_host, args=(job_id, ds_id, host_id, username), daemon=True)
    t.start()


def _run_remove_job_async(job_id, ds_id, delete_ontap, username):
    import threading
    t = threading.Thread(
        target=_run_remove, args=(job_id, ds_id, delete_ontap, username), daemon=True)
    t.start()


# ── Job implementations ───────────────────────────────────────────────────────

def _run_provision(job_id, ds_id, params, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        protocol = params.get("protocol", "")
        jlog.log(f"Provisioning {protocol} datastore '{params.get('name')}' …")
        if protocol == "iscsi":
            _provision_iscsi(ds_id, params, db, jlog)
        elif protocol == "nvme":
            _provision_nvme(ds_id, params, db, jlog)
        elif protocol == "nfs":
            _provision_nfs(ds_id, params, db, jlog)
        else:
            jlog.log(f"Protocol '{protocol}' not yet implemented.")
            _set_ds_status(db, ds_id, "error", f"Protocol not implemented: {protocol}")
            _fail_job(db, job_id)
            return
        _finish_job(db, job_id)
    except Exception as exc:
        log.error(f"[netapp_storage] provision job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _set_ds_status(db, ds_id, "error", str(exc))
        _fail_job(db, job_id)


def _provision_iscsi(ds_id, params, db, jlog):
    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    name           = params.get("name", ds_id)
    vg_name        = params.get("vg_name", "")
    lvm_type       = params.get("lvm_type", "linear")
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]
    size_bytes     = int(params.get("size_bytes", 0))
    aggregate_name = params.get("aggregate_name", "") or None

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── ONTAP: Volume ────────────────────────────────────────────────────────
    volume_uuid = params.get("volume_uuid", "")
    volume_name = params.get("volume_name", "")

    asa_mode = False
    if not volume_uuid:
        ag_info = f" on aggregate '{aggregate_name}'" if aggregate_name else " (auto-placement)"
        jlog.log(f"Creating ONTAP volume '{volume_name}' ({size_bytes} bytes){ag_info} …")
        try:
            volume_uuid = client.create_volume_san(svm_name, volume_name, size_bytes, aggregate_name=aggregate_name)
            jlog.log(f"Volume created: {volume_uuid}")
        except OntapError as exc:
            if exc.status_code == 405:
                jlog.log("ASA platform detected — volume will be auto-provisioned with LUN.")
                asa_mode = True
            else:
                raise
    else:
        vol_info    = client.get_volume(volume_uuid)
        volume_name = vol_info.get("name", volume_name)
        jlog.log(f"Using existing volume: {volume_name}")

    # ── ONTAP: LUN ───────────────────────────────────────────────────────────
    lun_uuid = params.get("lun_uuid", "")
    lun_name = params.get("lun_name", "")
    lun_path = ""
    serial   = ""

    if not lun_uuid:
        jlog.log(f"Creating LUN '{lun_name}' ({size_bytes} bytes) …")
        lun_uuid, serial = client.create_lun(svm_name, volume_name, lun_name, size_bytes,
                                             auto_provision_as_flexvol=asa_mode)
        lun_path = f"/vol/{volume_name}/{lun_name}"
        jlog.log(f"LUN created: {lun_uuid}  serial={serial}")
        # On ASA, resolve auto-provisioned volume UUID
        if asa_mode and not volume_uuid:
            try:
                lun_info = client.get_lun(lun_uuid)
                loc_vol = (lun_info.get("location") or {}).get("volume") or {}
                volume_uuid = loc_vol.get("uuid", "")
                volume_name = loc_vol.get("name", volume_name)
                jlog.log(f"Auto-provisioned volume: {volume_name} ({volume_uuid})")
            except Exception as exc:
                jlog.log(f"WARNING: could not resolve auto-provisioned volume: {exc}")
    else:
        lun_info = client.get_lun(lun_uuid)
        serial   = lun_info.get("serial_number", "")
        lun_path = lun_info.get("name", "")
        jlog.log(f"Using existing LUN: {lun_path}  serial={serial}")

    if not serial:
        raise RuntimeError("LUN serial number is empty — cannot identify multipath device")

    # ── Collect IQNs from all selected PVE hosts ──────────────────────────────
    jlog.log("Collecting iSCSI initiator IQNs from PVE hosts …")
    host_meta = {}
    for hid in pve_host_ids:
        try:
            pve = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            iqn = get_iscsi_initiator_iqn(pve.host, su, sp, sk)
            if iqn:
                host_meta[hid] = {"host": pve.host, "user": su, "pass": sp, "key": sk, "iqn": iqn}
                jlog.log(f"  {pve.host}: {iqn}")
            else:
                jlog.log(f"  WARNING: no IQN from {pve.host} — host skipped")
        except Exception as exc:
            jlog.log(f"  WARNING: cannot connect to host {hid}: {exc}")

    if not host_meta:
        raise RuntimeError("No iSCSI IQNs collected from any host")

    # ── ONTAP: iGroup ────────────────────────────────────────────────────────
    igroup_uuid = params.get("igroup_uuid", "")
    igroup_name = params.get("igroup_name", "") or f"igr-{name.replace(' ', '-').lower()}"

    if not igroup_uuid:
        jlog.log(f"Creating iGroup '{igroup_name}' …")
        igroup_uuid = client.create_igroup(svm_name, igroup_name, protocol="iscsi", os_type="linux")
        jlog.log(f"iGroup created: {igroup_uuid}")
        for m in host_meta.values():
            client.add_igroup_initiator(igroup_uuid, m["iqn"])
            jlog.log(f"  Added initiator: {m['iqn']}")
    else:
        existing_igs  = client.list_igroups(svm_name=svm_name)
        existing_ig   = next((g for g in existing_igs if g.get("uuid") == igroup_uuid), None)
        existing_inits = {i.get("name", "") for i in (existing_ig.get("initiators") or [])} if existing_ig else set()
        jlog.log(f"Using existing iGroup, adding missing initiators …")
        for m in host_meta.values():
            if m["iqn"] not in existing_inits:
                client.add_igroup_initiator(igroup_uuid, m["iqn"])
                jlog.log(f"  Added initiator: {m['iqn']}")

    # ── ONTAP: Map LUN ────────────────────────────────────────────────────────
    jlog.log("Mapping LUN to iGroup …")
    try:
        client.map_lun(lun_uuid, igroup_uuid, svm_name=svm_name)
        jlog.log("LUN mapped.")
    except Exception as exc:
        if "already" in str(exc).lower() or "409" in str(exc):
            jlog.log("LUN already mapped — continuing.")
        else:
            raise

    # Persist ONTAP object IDs before touching hosts (so remove can clean up on retry)
    db.execute(
        """UPDATE netapp_provisioned_datastores
           SET volume_uuid=?, volume_name=?, lun_uuid=?, lun_path=?,
               igroup_uuid=?, igroup_name=?, updated_at=?
           WHERE id=?""",
        (volume_uuid, volume_name, lun_uuid, lun_path,
         igroup_uuid, igroup_name, _now(), ds_id),
    )

    # ── Get iSCSI target info ─────────────────────────────────────────────────
    portal_ip  = client.get_iscsi_lif_for_svm(svm_name)
    target_iqn = client.get_iscsi_target_iqn(svm_name)
    if not portal_ip:
        raise RuntimeError(f"No active iSCSI LIF found for SVM '{svm_name}'")
    if not target_iqn:
        raise RuntimeError(f"No iSCSI target IQN found for SVM '{svm_name}'")
    jlog.log(f"iSCSI target: {target_iqn} @ {portal_ip}")

    # ── Per host: discover → login → wait for device ──────────────────────────
    ordered_hosts = [hid for hid in pve_host_ids if hid in host_meta]
    for i, hid in enumerate(ordered_hosts):
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]

        jlog.log(f"[{sh}] Discovering iSCSI target …")
        ssh_run(sh, su, sp,
                f"iscsiadm -m discovery -t sendtargets -p {shlex.quote(portal_ip)} 2>&1 || true",
                key_material=sk, timeout=30)

        jlog.log(f"[{sh}] Logging into target …")
        ssh_run(sh, su, sp,
                f"iscsiadm -m node -T {shlex.quote(target_iqn)} -p {shlex.quote(portal_ip)}"
                f" --login 2>&1 || true",
                key_material=sk, timeout=30)

        jlog.log(f"[{sh}] Waiting for multipath device (serial={serial}) …")
        ssh_run(sh, su, sp,
                "sleep 3; udevadm settle --timeout=15 2>/dev/null; "
                "multipath 2>/dev/null; sleep 2; true",
                key_material=sk, timeout=40)
        device = find_device_by_serial(sh, su, sp, sk, serial, timeout_s=60)
        jlog.log(f"[{sh}] Device ready: {device}")

        if i == 0:
            vg_q  = shlex.quote(vg_name)
            dev_q = shlex.quote(device)
            out   = ssh_run(sh, su, sp,
                            f"vgs {vg_q} 2>/dev/null && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in out:
                jlog.log(f"[{sh}] Creating PV + VG '{vg_name}' …")
                ssh_run(sh, su, sp, f"pvcreate {dev_q}", key_material=sk)
                ssh_run(sh, su, sp, f"vgcreate {vg_q} {dev_q}", key_material=sk)
                jlog.log(f"[{sh}] VG '{vg_name}' created.")

                if lvm_type == "thin":
                    pool_name = params.get("lvm_pool_name") or "data"
                    pool_q = shlex.quote(pool_name)
                    ssh_run(sh, su, sp,
                            f"lvcreate -l 95%VG --thin {vg_q}/{pool_q}",
                            key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] Thin pool '{pool_name}' created.")
                    db.execute(
                        "UPDATE netapp_provisioned_datastores SET lvm_pool_name=?, updated_at=? WHERE id=?",
                        (pool_name, _now(), ds_id),
                    )
            else:
                jlog.log(f"[{sh}] VG '{vg_name}' already exists.")

            # Create snapmanifest LV (idempotent) so snapshots work on this datastore
            from ..core.san_helpers import snapmanifest_initialize
            jlog.log(f"[{sh}] Initializing snapmanifest LV …")
            try:
                snapmanifest_initialize(sh, su, sp, sk, vg_name)
                jlog.log(f"[{sh}] snapmanifest LV ready.")
            except Exception as exc:
                jlog.log(f"[{sh}] WARNING: snapmanifest init failed: {exc}")

    # ── All hosts: pvscan --cache -aay ────────────────────────────────────────
    mapper_dev = _iscsi_serial_to_mapper(serial)
    jlog.log("Activating VG on all hosts via pvscan …")
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        try:
            ssh_run(sh, su, sp,
                    f"pvscan --cache -aay {shlex.quote(mapper_dev)} 2>/dev/null; true",
                    key_material=sk, timeout=30)
            jlog.log(f"[{sh}] pvscan done.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvscan failed: {exc}")

    # ── PVE: register storage on every host ──────────────────────────────────
    # Each standalone PVE host keeps its own storage.cfg — pvesm add must run
    # on each host individually (unlike a cluster where one node propagates).
    vg_q  = shlex.quote(vg_name)
    sid_q = shlex.quote(pve_storage_id)
    lvm_pool_name_final = params.get("lvm_pool_name") or (
        dict(db.query_one("SELECT lvm_pool_name FROM netapp_provisioned_datastores WHERE id=?",
                          (ds_id,)) or {})).get("lvm_pool_name", "") or "data"
    if lvm_type == "thin":
        pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                     f" --thinpool {shlex.quote(lvm_pool_name_final)}"
                     f" --shared 1 --content images,rootdir")
    else:
        pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                     f" --shared 1 --content images,rootdir")

    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        jlog.log(f"[{sh}] Registering PVE storage '{pve_storage_id}' …")
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                try:
                    ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] PVE storage registered.")
                except Exception as exc:
                    if "already defined" in str(exc).lower():
                        jlog.log(f"[{sh}] PVE storage already propagated from cluster.")
                    else:
                        jlog.log(f"[{sh}] WARNING: pvesm add failed: {exc}")
            else:
                jlog.log(f"[{sh}] PVE storage already exists.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm add failed: {exc}")

    _set_ds_status(db, ds_id, "active")

    # ── Register volume_mapping for each host (enables Snapshots tab) ──────────
    lvm_pool_name = params.get("lvm_pool_name") or (
        dict(db.query_one("SELECT lvm_pool_name FROM netapp_provisioned_datastores WHERE id=?",
                          (ds_id,)) or {})).get("lvm_pool_name", "")
    now = _now()
    for hid in ordered_hosts:
        mid = str(_uuid.uuid4())
        try:
            db.execute(
                """INSERT INTO netapp_volume_mapping
                   (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                    volume_uuid, volume_name, junction_path, nfs_export_ip,
                    nfs_mount_path, discovered_at,
                    storage_protocol, lun_uuid, lun_path,
                    lvm_vg_name, lvm_type, lvm_pool_name,
                    snapinfo_initialized, snapinfo_lv_name,
                    created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
                   endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
                   volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
                   lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path,
                   lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type,
                   lvm_pool_name=excluded.lvm_pool_name,
                   storage_protocol=excluded.storage_protocol,
                   snapinfo_initialized=excluded.snapinfo_initialized,
                   discovered_at=excluded.discovered_at""",
                (mid, endpoint_id, hid, pve_storage_id, svm_name,
                 volume_uuid, volume_name, "", "", "", now,
                 "iscsi", lun_uuid, lun_path,
                 vg_name, lvm_type, lvm_pool_name,
                 1, "netapp_snapmanifest", _now()),
            )
            jlog.log(f"Volume mapping registered for host {hid}.")
        except Exception as exc:
            jlog.log(f"WARNING: could not register volume mapping for host {hid}: {exc}")

    jlog.log(f"Provisioning complete. Datastore '{name}' is active.")


def _run_resize(job_id, ds_id, new_size_bytes, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        row = db.query_one(
            "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
        if not row:
            raise RuntimeError(f"Datastore {ds_id} not found")
        ds       = dict(row)
        protocol = ds.get("protocol", "")
        old_size = ds.get("size_bytes", 0)
        jlog.log(f"Resizing {protocol} datastore '{ds.get('name')}' "
                 f"from {old_size} to {new_size_bytes} bytes …")

        endpoint = get_endpoint(db, ds["endpoint_id"])
        client   = build_ontap_client(endpoint)
        vol_uuid = ds.get("volume_uuid", "")

        if protocol == "nfs":
            # NFS: only ONTAP resize needed (PVE mounts adjust automatically)
            jlog.log("Resizing ONTAP volume …")
            client.resize_volume(vol_uuid, new_size_bytes)
            jlog.log("Volume resized.")

        elif protocol == "iscsi":
            lun_uuid = ds.get("lun_uuid", "")
            vg_name  = ds.get("vg_name", "")
            pve_host_ids = json.loads(ds.get("pve_host_ids") or "[]")

            jlog.log("Resizing ONTAP volume …")
            client.resize_volume(vol_uuid, new_size_bytes)
            jlog.log("Resizing LUN …")
            client.resize_lun(lun_uuid, new_size_bytes)
            jlog.log("ONTAP objects resized.")

            # Host-side: pvresize so LVM sees the new size
            lun_serial = ""
            try:
                lun_serial = client.get_lun_serial(lun_uuid)
            except Exception as exc:
                jlog.log(f"WARNING: cannot fetch LUN serial: {exc}")

            for hid in pve_host_ids:
                try:
                    pve = build_pve_client(db, hid)
                    su, sp, sk = get_ssh_creds(pve)
                    sh = pve.host
                    jlog.log(f"[{sh}] Rescanning SCSI bus …")
                    ssh_run(sh, su, sp,
                            "for d in /sys/class/scsi_device/*/device/rescan; do "
                            "  echo 1 > $d 2>/dev/null; done; "
                            "udevadm settle --timeout=10 2>/dev/null; "
                            "multipath 2>/dev/null; true",
                            key_material=sk, timeout=30)
                    if lun_serial and vg_name:
                        mapper = _iscsi_serial_to_mapper(lun_serial)
                        jlog.log(f"[{sh}] Resizing PV {mapper} …")
                        ssh_run(sh, su, sp,
                                f"pvresize {shlex.quote(mapper)} 2>/dev/null; true",
                                key_material=sk, timeout=30)
                        jlog.log(f"[{sh}] PV resized.")
                except Exception as exc:
                    jlog.log(f"[{sh}] WARNING: host resize: {exc}")

        elif protocol == "nvme":
            ns_uuid  = ds.get("ns_uuid", "")
            vg_name  = ds.get("vg_name", "")
            pve_host_ids = json.loads(ds.get("pve_host_ids") or "[]")

            jlog.log("Resizing ONTAP volume …")
            client.resize_volume(vol_uuid, new_size_bytes)
            jlog.log("Resizing NVMe namespace …")
            client.resize_namespace(ns_uuid, new_size_bytes)
            jlog.log("ONTAP objects resized.")

            for hid in pve_host_ids:
                try:
                    pve = build_pve_client(db, hid)
                    su, sp, sk = get_ssh_creds(pve)
                    sh = pve.host
                    jlog.log(f"[{sh}] Rescanning NVMe namespaces …")
                    from ..core.san_helpers import nvme_ns_rescan
                    nvme_ns_rescan(sh, su, sp, sk)
                    if vg_name:
                        out = ssh_run(sh, su, sp,
                                      f"pvs --noheadings -o pv_name --select 'vgname={vg_name}' 2>/dev/null",
                                      capture=True, key_material=sk, timeout=15)
                        for pv in (l.strip() for l in out.splitlines() if l.strip()):
                            jlog.log(f"[{sh}] Resizing PV {pv} …")
                            ssh_run(sh, su, sp,
                                    f"pvresize {shlex.quote(pv)} 2>/dev/null; true",
                                    key_material=sk, timeout=30)
                        jlog.log(f"[{sh}] PV resized.")
                except Exception as exc:
                    jlog.log(f"[{sh}] WARNING: host resize: {exc}")

        else:
            raise RuntimeError(f"Resize not supported for protocol '{protocol}'")

        db.execute(
            "UPDATE netapp_provisioned_datastores SET size_bytes=?, updated_at=? WHERE id=?",
            (new_size_bytes, _now(), ds_id),
        )
        _finish_job(db, job_id)
        jlog.log("Resize complete.")
    except Exception as exc:
        log.error(f"[netapp_storage] resize job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _fail_job(db, job_id)


def _run_add_host(job_id, ds_id, host_id, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        row = db.query_one("SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
        if not row:
            raise RuntimeError(f"Datastore {ds_id} not found")
        ds       = dict(row)
        protocol = ds.get("protocol", "")
        jlog.log(f"Adding host to {protocol} datastore '{ds.get('name')}' …")

        if protocol == "iscsi":
            _add_host_iscsi(ds_id, ds, host_id, db, jlog)
        elif protocol == "nvme":
            _add_host_nvme(ds_id, ds, host_id, db, jlog)
        elif protocol == "nfs":
            _add_host_nfs(ds_id, ds, host_id, db, jlog)
        else:
            raise RuntimeError(f"Add-host not implemented for protocol '{protocol}'")

        _finish_job(db, job_id)
        jlog.log("Host added successfully.")
    except Exception as exc:
        log.error(f"[netapp_storage] add_host job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _fail_job(db, job_id)


def _add_host_iscsi(ds_id, ds, host_id, db, jlog):
    from ..core.san_helpers import (get_iscsi_initiator_iqn, find_device_by_serial,
                                    _iscsi_serial_to_mapper)

    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    igroup_uuid    = ds.get("igroup_uuid", "")
    lun_uuid       = ds.get("lun_uuid", "")
    vg_name        = ds.get("vg_name", "")
    lvm_type       = ds.get("lvm_type", "linear")
    lvm_pool_name  = ds.get("lvm_pool_name", "") or "data"
    pve_storage_id = ds.get("pve_storage_id", "")
    volume_uuid    = ds.get("volume_uuid", "")
    volume_name    = ds.get("volume_name", "")
    lun_path       = ds.get("lun_path", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    lun_serial = ""
    if lun_uuid:
        try:
            lun_serial = client.get_lun_serial(lun_uuid)
        except Exception as exc:
            raise RuntimeError(f"Cannot fetch LUN serial: {exc}")
    if not lun_serial:
        raise RuntimeError("LUN serial not available — cannot identify multipath device")

    portal_ip  = client.get_iscsi_lif_for_svm(svm_name)
    target_iqn = client.get_iscsi_target_iqn(svm_name)
    if not portal_ip or not target_iqn:
        raise RuntimeError(f"Cannot determine iSCSI target for SVM '{svm_name}'")
    jlog.log(f"iSCSI target: {target_iqn} @ {portal_ip}")

    pve = build_pve_client(db, host_id)
    su, sp, sk = get_ssh_creds(pve)
    sh = pve.host

    # 1. Collect IQN
    jlog.log(f"[{sh}] Collecting iSCSI IQN …")
    iqn = get_iscsi_initiator_iqn(sh, su, sp, sk)
    if not iqn:
        raise RuntimeError(f"No IQN on host {sh}")
    jlog.log(f"[{sh}] IQN: {iqn}")

    # 2. Add IQN to ONTAP iGroup (idempotent)
    if igroup_uuid:
        jlog.log(f"Adding IQN to iGroup …")
        try:
            existing_ig = next(
                (g for g in client.list_igroups(svm_name=svm_name) if g.get("uuid") == igroup_uuid),
                None)
            existing_inits = {i.get("name", "") for i in (existing_ig.get("initiators") or [])} \
                if existing_ig else set()
            if iqn not in existing_inits:
                client.add_igroup_initiator(igroup_uuid, iqn)
                jlog.log(f"IQN added to iGroup.")
            else:
                jlog.log(f"IQN already in iGroup.")
        except Exception as exc:
            jlog.log(f"WARNING: add initiator: {exc}")

    # 3. iSCSI discovery + login
    jlog.log(f"[{sh}] iSCSI discovery …")
    ssh_run(sh, su, sp,
            f"iscsiadm -m discovery -t sendtargets -p {shlex.quote(portal_ip)} 2>&1 || true",
            key_material=sk, timeout=30)
    jlog.log(f"[{sh}] iSCSI login …")
    ssh_run(sh, su, sp,
            f"iscsiadm -m node -T {shlex.quote(target_iqn)} -p {shlex.quote(portal_ip)}"
            f" --login 2>&1 || true",
            key_material=sk, timeout=30)

    # 4. Wait for multipath device
    jlog.log(f"[{sh}] Waiting for multipath device (serial={lun_serial}) …")
    ssh_run(sh, su, sp,
            "sleep 3; udevadm settle --timeout=15 2>/dev/null; "
            "multipath 2>/dev/null; sleep 2; true",
            key_material=sk, timeout=40)
    device = find_device_by_serial(sh, su, sp, sk, lun_serial, timeout_s=60)
    jlog.log(f"[{sh}] Device ready: {device}")

    # 5. pvscan --cache to activate the existing VG on this host
    mapper_dev = _iscsi_serial_to_mapper(lun_serial)
    jlog.log(f"[{sh}] Activating VG via pvscan …")
    try:
        ssh_run(sh, su, sp,
                f"pvscan --cache -aay {shlex.quote(mapper_dev)} 2>/dev/null; true",
                key_material=sk, timeout=30)
        jlog.log(f"[{sh}] pvscan done.")
    except Exception as exc:
        jlog.log(f"[{sh}] WARNING: pvscan: {exc}")

    # 6. pvesm: cluster nodes inherit storage.cfg automatically; standalone needs explicit add
    if pve_storage_id:
        vg_q  = shlex.quote(vg_name)
        sid_q = shlex.quote(pve_storage_id)
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                jlog.log(f"[{sh}] Storage not in PVE config — registering …")
                if lvm_type == "thin":
                    pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                                 f" --thinpool {shlex.quote(lvm_pool_name)}"
                                 f" --shared 1 --content images,rootdir")
                else:
                    pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                                 f" --shared 1 --content images,rootdir")
                ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                jlog.log(f"[{sh}] PVE storage registered.")
            else:
                jlog.log(f"[{sh}] PVE storage already in cluster config.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm: {exc}")

    # 7. Register volume_mapping so this host appears in Snapshots/Volume Discovery
    mid = str(_uuid.uuid4())
    try:
        db.execute(
            """INSERT INTO netapp_volume_mapping
               (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                volume_uuid, volume_name, junction_path, nfs_export_ip,
                nfs_mount_path, discovered_at,
                storage_protocol, lun_uuid, lun_path,
                lvm_vg_name, lvm_type, lvm_pool_name,
                snapinfo_initialized, snapinfo_lv_name,
                    created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
               endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
               volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
               lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path,
               lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type,
               lvm_pool_name=excluded.lvm_pool_name,
               storage_protocol=excluded.storage_protocol,
               snapinfo_initialized=excluded.snapinfo_initialized,
               discovered_at=excluded.discovered_at""",
            (mid, endpoint_id, host_id, pve_storage_id, svm_name,
             volume_uuid, volume_name, "", "", "", _now(),
             "iscsi", lun_uuid, lun_path,
             vg_name, lvm_type, lvm_pool_name,
             1, "netapp_snapmanifest", _now()),
        )
        jlog.log(f"Volume mapping registered.")
    except Exception as exc:
        jlog.log(f"WARNING: volume mapping: {exc}")

    # 8. Update pve_host_ids
    current_ids = json.loads(ds.get("pve_host_ids") or "[]")
    if host_id not in current_ids:
        current_ids.append(host_id)
        db.execute(
            "UPDATE netapp_provisioned_datastores SET pve_host_ids=?, updated_at=? WHERE id=?",
            (json.dumps(current_ids), _now(), ds_id),
        )
        jlog.log(f"Host {host_id} added to datastore record.")


def _run_remove_host(job_id, ds_id, host_id, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        row = db.query_one(
            "SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
        if not row:
            raise RuntimeError(f"Datastore {ds_id} not found")
        ds       = dict(row)
        protocol = ds.get("protocol", "")
        jlog.log(f"Removing host {host_id} from {protocol} datastore '{ds.get('name')}' …")

        if protocol == "iscsi":
            _remove_host_iscsi(ds_id, ds, host_id, db, jlog)
        elif protocol == "nvme":
            _remove_host_nvme(ds_id, ds, host_id, db, jlog)
        elif protocol == "nfs":
            _remove_host_nfs(ds_id, ds, host_id, db, jlog)
        else:
            raise RuntimeError(f"Remove-host not implemented for protocol '{protocol}'")

        _finish_job(db, job_id)
        jlog.log("Host removed.")
    except Exception as exc:
        log.error(f"[netapp_storage] remove_host job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _fail_job(db, job_id)


def _run_remove(job_id, ds_id, delete_ontap, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        row = db.query_one("SELECT * FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
        if not row:
            raise RuntimeError(f"Datastore {ds_id} not found")
        ds       = dict(row)
        protocol = ds.get("protocol", "")
        jlog.log(f"Removing {protocol} datastore '{ds.get('name')}' (delete_ontap={delete_ontap}) …")

        if protocol == "iscsi":
            _remove_iscsi(ds_id, ds, delete_ontap, db, jlog)
        elif protocol == "nvme":
            _remove_nvme(ds_id, ds, delete_ontap, db, jlog)
        elif protocol == "nfs":
            _remove_nfs(ds_id, ds, delete_ontap, db, jlog)
        else:
            jlog.log(f"Remove not implemented for protocol '{protocol}'.")
            _set_ds_status(db, ds_id, "error", "Remove not implemented for this protocol")
            _fail_job(db, job_id)
            return

        # Remove volume_mapping rows (ON DELETE CASCADE would cascade snapshots too)
        pve_storage_id = ds.get("pve_storage_id", "")
        pve_host_ids_raw = json.loads(ds.get("pve_host_ids") or "[]")
        if pve_storage_id and pve_host_ids_raw:
            for hid in pve_host_ids_raw:
                db.execute(
                    "DELETE FROM netapp_volume_mapping WHERE pve_cluster_id=? AND pve_storage_id=?",
                    (hid, pve_storage_id),
                )
        db.execute("DELETE FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
        _finish_job(db, job_id)
        jlog.log("Datastore removed.")
    except Exception as exc:
        log.error(f"[netapp_storage] remove job {job_id}: {exc}")
        jlog.log(f"ERROR: {exc}")
        _set_ds_status(db, ds_id, "error", str(exc))
        _fail_job(db, job_id)


def _remove_iscsi(ds_id, ds, delete_ontap, db, jlog):
    from ..core.san_helpers import flush_iscsi_clone_device

    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    vg_name        = ds.get("vg_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    pve_host_ids   = json.loads(ds.get("pve_host_ids") or "[]")
    lun_uuid       = ds.get("lun_uuid", "")
    volume_uuid    = ds.get("volume_uuid", "")
    igroup_uuid    = ds.get("igroup_uuid", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    target_iqn = client.get_iscsi_target_iqn(svm_name) if svm_name else ""

    # Fetch LUN serial — needed to flush the multipath device on each host
    lun_serial = ""
    if lun_uuid:
        try:
            lun_serial = client.get_lun_serial(lun_uuid)
            jlog.log(f"LUN serial for multipath flush: {lun_serial}")
        except Exception as exc:
            jlog.log(f"WARNING: could not fetch LUN serial: {exc}")

    # ── Per-host teardown ─────────────────────────────────────────────────────
    # Order matters: PVE storage config → VG deactivate → multipath flush → iSCSI logout
    # vgchange -an must complete before flushing multipath (dm device still holds the LUN open)
    for hid in pve_host_ids:
        try:
            pve = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            sh = pve.host

            # 1. Remove PVE storage entry (each standalone host keeps its own config)
            if pve_storage_id:
                jlog.log(f"[{sh}] Removing PVE storage '{pve_storage_id}' …")
                try:
                    ssh_run(sh, su, sp,
                            f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                            key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] PVE storage removed.")
                except Exception as exc:
                    jlog.log(f"[{sh}] WARNING: pvesm remove: {exc}")

            # 2. Deactivate VG — releases DM device so multipath can be flushed
            if vg_name:
                vg_q = shlex.quote(vg_name)
                jlog.log(f"[{sh}] Deactivating VG '{vg_name}' …")
                try:
                    ssh_run(sh, su, sp,
                            f"vgchange -an {vg_q} 2>/dev/null; "
                            f"udevadm settle --timeout=5 2>/dev/null; "
                            f"vgremove -f {vg_q} 2>/dev/null; "
                            f"true",
                            key_material=sk, timeout=45)
                    jlog.log(f"[{sh}] VG deactivated and removed.")
                except Exception as exc:
                    jlog.log(f"[{sh}] WARNING: VG teardown: {exc}")

            # 3. Flush multipath device + remove sdX paths (same as iSCSI clone teardown)
            if lun_serial:
                jlog.log(f"[{sh}] Flushing multipath device …")
                flush_iscsi_clone_device(sh, su, sp, sk, lun_serial)
                jlog.log(f"[{sh}] Multipath flushed.")

            # 4. iSCSI logout + delete persistent node entry
            if target_iqn:
                iqn_q = shlex.quote(target_iqn)
                jlog.log(f"[{sh}] iSCSI logout …")
                try:
                    ssh_run(sh, su, sp,
                            f"iscsiadm -m node -T {iqn_q} --logout 2>/dev/null; "
                            f"iscsiadm -m node -T {iqn_q} -o delete 2>/dev/null; "
                            f"true",
                            key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] iSCSI logged out.")
                except Exception as exc:
                    jlog.log(f"[{sh}] WARNING: iSCSI logout: {exc}")

        except Exception as exc:
            jlog.log(f"WARNING: cannot reach host {hid}: {exc}")

    # ── ONTAP cleanup ─────────────────────────────────────────────────────────
    if lun_uuid and igroup_uuid:
        jlog.log("Unmapping LUN from iGroup …")
        try:
            client.unmap_lun(lun_uuid, igroup_uuid)
            jlog.log("LUN unmapped.")
        except Exception as exc:
            jlog.log(f"WARNING: unmap (may already be unmapped): {exc}")

    if delete_ontap:
        if lun_uuid:
            jlog.log(f"Deleting LUN {lun_uuid} …")
            try:
                client.delete_lun(lun_uuid)
                jlog.log("LUN deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: LUN delete: {exc}")
        if volume_uuid:
            jlog.log(f"Deleting volume {volume_uuid} …")
            try:
                client.delete_volume(volume_uuid)
                jlog.log("Volume deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: volume delete: {exc}")
        if igroup_uuid:
            jlog.log(f"Deleting iGroup {igroup_uuid} …")
            try:
                client.delete_igroup(igroup_uuid)
                jlog.log("iGroup deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: iGroup delete: {exc}")


# ── iSCSI: remove single host ─────────────────────────────────────────────────

def _remove_host_iscsi(ds_id, ds, host_id, db, jlog):
    from ..core.san_helpers import flush_iscsi_clone_device

    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    vg_name        = ds.get("vg_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    lun_uuid       = ds.get("lun_uuid", "")
    igroup_uuid    = ds.get("igroup_uuid", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    target_iqn = client.get_iscsi_target_iqn(svm_name) if svm_name else ""
    lun_serial = ""
    if lun_uuid:
        try:
            lun_serial = client.get_lun_serial(lun_uuid)
        except Exception as exc:
            jlog.log(f"WARNING: cannot fetch LUN serial: {exc}")

    try:
        pve = build_pve_client(db, host_id)
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host

        if pve_storage_id:
            jlog.log(f"[{sh}] Removing PVE storage entry …")
            ssh_run(sh, su, sp,
                    f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                    key_material=sk, timeout=30)

        if vg_name:
            vg_q = shlex.quote(vg_name)
            jlog.log(f"[{sh}] Deactivating VG '{vg_name}' …")
            ssh_run(sh, su, sp,
                    f"vgchange -an {vg_q} 2>/dev/null; udevadm settle --timeout=5 2>/dev/null; true",
                    key_material=sk, timeout=30)

        if lun_serial:
            jlog.log(f"[{sh}] Flushing multipath device …")
            flush_iscsi_clone_device(sh, su, sp, sk, lun_serial)

        if target_iqn:
            iqn_q = shlex.quote(target_iqn)
            jlog.log(f"[{sh}] iSCSI logout …")
            ssh_run(sh, su, sp,
                    f"iscsiadm -m node -T {iqn_q} --logout 2>/dev/null; "
                    f"iscsiadm -m node -T {iqn_q} -o delete 2>/dev/null; true",
                    key_material=sk, timeout=30)
    except Exception as exc:
        jlog.log(f"WARNING: cannot reach host {host_id}: {exc}")

    # Remove IQN from iGroup
    if igroup_uuid:
        try:
            pve = build_pve_client(db, host_id)
            su, sp, sk = get_ssh_creds(pve)
            iqn = get_iscsi_initiator_iqn(pve.host, su, sp, sk)
            if iqn:
                client.remove_igroup_initiator(igroup_uuid, iqn)
                jlog.log(f"Removed IQN {iqn} from iGroup.")
        except Exception as exc:
            jlog.log(f"WARNING: remove IQN from iGroup: {exc}")

    _remove_host_from_ds_record(ds_id, host_id, pve_storage_id, db, jlog)


# ── NVMe: provision ───────────────────────────────────────────────────────────

def _provision_nvme(ds_id, params, db, jlog):
    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    name           = params.get("name", ds_id)
    vg_name        = params.get("vg_name", "")
    lvm_type       = params.get("lvm_type", "linear")
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]
    size_bytes     = int(params.get("size_bytes", 0))
    aggregate_name = params.get("aggregate_name", "") or None

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── ONTAP: Volume ────────────────────────────────────────────────────────
    volume_uuid = params.get("volume_uuid", "")
    volume_name = params.get("volume_name", "")
    asa_mode = False
    if not volume_uuid:
        ag_info = f" on aggregate '{aggregate_name}'" if aggregate_name else " (auto-placement)"
        jlog.log(f"Creating ONTAP volume '{volume_name}' ({size_bytes} bytes){ag_info} …")
        try:
            volume_uuid = client.create_volume_san(svm_name, volume_name, size_bytes,
                                                   aggregate_name=aggregate_name)
            jlog.log(f"Volume created: {volume_uuid}")
        except OntapError as exc:
            if exc.status_code == 405:
                jlog.log("ASA platform detected — volume will be auto-provisioned with namespace.")
                asa_mode = True
            else:
                raise
    else:
        vol_info    = client.get_volume(volume_uuid)
        volume_name = vol_info.get("name", volume_name)
        jlog.log(f"Using existing volume: {volume_name}")

    # ── ONTAP: Namespace ──────────────────────────────────────────────────────
    ns_uuid  = params.get("ns_uuid", "")
    ns_name  = params.get("ns_name", "") or f"ns-{name.replace(' ', '-').lower()}"
    if not ns_uuid:
        jlog.log(f"Creating NVMe namespace '{ns_name}' ({size_bytes} bytes) …")
        ns_uuid = client.create_namespace(svm_name, volume_name, ns_name, size_bytes,
                                          aggregate_name=aggregate_name if asa_mode else None)
        jlog.log(f"Namespace created: {ns_uuid}")
        # On ASA, the volume was auto-created — resolve its UUID and name
        if asa_mode and not volume_uuid:
            try:
                ns_info = client.get_namespace(ns_uuid)
                loc_vol = (ns_info.get("location") or {}).get("volume") or {}
                volume_uuid = loc_vol.get("uuid", "")
                volume_name = loc_vol.get("name", volume_name)
                jlog.log(f"Auto-provisioned volume: {volume_name} ({volume_uuid})")
            except Exception:
                # get_namespace may also 404 on ASA R2 — look up volume by name
                try:
                    vols = client._get_all_records(
                        "storage/volumes",
                        params={"svm.name": svm_name, "name": volume_name,
                                "fields": "uuid,name", "max_records": 5},
                    )
                    if vols:
                        volume_uuid = vols[0].get("uuid", "")
                        volume_name = vols[0].get("name", volume_name)
                        jlog.log(f"Auto-provisioned volume (by name): {volume_name} ({volume_uuid})")
                except Exception as exc2:
                    jlog.log(f"WARNING: could not resolve auto-provisioned volume: {exc2}")
    else:
        jlog.log(f"Using existing namespace: {ns_uuid}")

    # ── Collect Host NQNs ─────────────────────────────────────────────────────
    jlog.log("Collecting NVMe host NQNs …")
    host_meta = {}
    for hid in pve_host_ids:
        try:
            pve = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            nqn = get_nvme_host_nqn(pve.host, su, sp, sk)
            if nqn:
                host_meta[hid] = {"host": pve.host, "user": su, "pass": sp, "key": sk, "nqn": nqn}
                jlog.log(f"  {pve.host}: {nqn}")
            else:
                jlog.log(f"  WARNING: no NQN from {pve.host} — host skipped")
        except Exception as exc:
            jlog.log(f"  WARNING: cannot connect to host {hid}: {exc}")

    if not host_meta:
        raise RuntimeError("No NVMe host NQNs collected from any host")

    # ── ONTAP: Subsystem ──────────────────────────────────────────────────────
    subsystem_uuid = params.get("subsystem_uuid", "")
    subsystem_name = params.get("subsystem_name", "") or f"sub-{name.replace(' ', '-').lower()}"
    if not subsystem_uuid:
        jlog.log(f"Creating NVMe subsystem '{subsystem_name}' …")
        subsystem_uuid = client.create_nvme_subsystem(svm_name, subsystem_name)
        jlog.log(f"Subsystem created: {subsystem_uuid}")
        for m in host_meta.values():
            client.add_nvme_host_to_subsystem(subsystem_uuid, m["nqn"])
            jlog.log(f"  Added host NQN: {m['nqn']}")
    else:
        existing_sub  = client.get_nvme_subsystem(subsystem_uuid)
        existing_nqns = {h.get("nqn", "") for h in (existing_sub.get("hosts") or [])}
        jlog.log("Using existing subsystem, adding missing host NQNs …")
        for m in host_meta.values():
            if m["nqn"] not in existing_nqns:
                client.add_nvme_host_to_subsystem(subsystem_uuid, m["nqn"])
                jlog.log(f"  Added host NQN: {m['nqn']}")

    # ── ONTAP: Map namespace to subsystem ─────────────────────────────────────
    jlog.log("Mapping namespace to subsystem …")
    try:
        client.add_nvme_namespace_to_subsystem(subsystem_uuid, ns_uuid, svm_name=svm_name)
        jlog.log("Namespace mapped.")
    except Exception as exc:
        if "already" in str(exc).lower() or "409" in str(exc):
            jlog.log("Namespace already mapped — continuing.")
        else:
            raise

    # Persist ONTAP IDs before host-side work
    db.execute(
        """UPDATE netapp_provisioned_datastores
           SET volume_uuid=?, volume_name=?, ns_uuid=?,
               subsystem_uuid=?, subsystem_name=?, updated_at=?
           WHERE id=?""",
        (volume_uuid, volume_name, ns_uuid, subsystem_uuid, subsystem_name, _now(), ds_id),
    )

    # ── Get NVMe/TCP LIF IPs ──────────────────────────────────────────────────
    lif_ips = client.get_nvme_lifs_for_svm(svm_name)
    jlog.log(f"NVMe/TCP LIFs: {lif_ips}")

    # ── Per host: connect → wait for device ───────────────────────────────────
    ordered_hosts = [hid for hid in pve_host_ids if hid in host_meta]
    for i, hid in enumerate(ordered_hosts):
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]

        jlog.log(f"[{sh}] Capturing NVMe device baseline …")
        devices_before = nvme_list_devices(sh, su, sp, sk)

        jlog.log(f"[{sh}] Connecting NVMe (connect-all) …")
        nvme_connect_all(sh, su, sp, sk)

        jlog.log(f"[{sh}] Waiting for new NVMe namespace device …")
        device = find_new_nvme_device(sh, su, sp, sk, devices_before, timeout_s=60)
        jlog.log(f"[{sh}] Device ready: {device}")

        if i == 0:
            vg_q  = shlex.quote(vg_name)
            dev_q = shlex.quote(device)
            out   = ssh_run(sh, su, sp,
                            f"vgs {vg_q} 2>/dev/null && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in out:
                jlog.log(f"[{sh}] Creating PV + VG '{vg_name}' …")
                ssh_run(sh, su, sp, f"pvcreate {dev_q}", key_material=sk)
                ssh_run(sh, su, sp, f"vgcreate {vg_q} {dev_q}", key_material=sk)
                jlog.log(f"[{sh}] VG '{vg_name}' created.")

                if lvm_type == "thin":
                    pool_name = params.get("lvm_pool_name") or "data"
                    pool_q = shlex.quote(pool_name)
                    ssh_run(sh, su, sp,
                            f"lvcreate -l 95%VG --thin {vg_q}/{pool_q}",
                            key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] Thin pool '{pool_name}' created.")
                    db.execute(
                        "UPDATE netapp_provisioned_datastores SET lvm_pool_name=?, updated_at=? WHERE id=?",
                        (pool_name, _now(), ds_id),
                    )
            else:
                jlog.log(f"[{sh}] VG '{vg_name}' already exists.")

            jlog.log(f"[{sh}] Initializing snapmanifest LV …")
            try:
                snapmanifest_initialize(sh, su, sp, sk, vg_name)
                jlog.log(f"[{sh}] snapmanifest LV ready.")
            except Exception as exc:
                jlog.log(f"[{sh}] WARNING: snapmanifest init failed: {exc}")

    # ── All hosts: pvscan --cache -aay ────────────────────────────────────────
    jlog.log("Activating VG on all hosts via pvscan …")
    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        try:
            out = ssh_run(sh, su, sp,
                          f"pvs --noheadings -o pv_name --select 'vgname={vg_name}' 2>/dev/null",
                          capture=True, key_material=sk, timeout=15)
            for pv in (l.strip() for l in out.splitlines() if l.strip()):
                ssh_run(sh, su, sp,
                        f"pvscan --cache -aay {shlex.quote(pv)} 2>/dev/null; true",
                        key_material=sk, timeout=30)
            jlog.log(f"[{sh}] pvscan done.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvscan failed: {exc}")

    # ── PVE: register storage on every host ───────────────────────────────────
    vg_q  = shlex.quote(vg_name)
    sid_q = shlex.quote(pve_storage_id)
    lvm_pool_name_final = params.get("lvm_pool_name") or (
        dict(db.query_one("SELECT lvm_pool_name FROM netapp_provisioned_datastores WHERE id=?",
                          (ds_id,)) or {})).get("lvm_pool_name", "") or "data"
    if lvm_type == "thin":
        pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                     f" --thinpool {shlex.quote(lvm_pool_name_final)}"
                     f" --shared 1 --content images,rootdir")
    else:
        pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                     f" --shared 1 --content images,rootdir")

    for hid in ordered_hosts:
        m  = host_meta[hid]
        sh, su, sp, sk = m["host"], m["user"], m["pass"], m["key"]
        jlog.log(f"[{sh}] Registering PVE storage '{pve_storage_id}' …")
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                try:
                    ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                    jlog.log(f"[{sh}] PVE storage registered.")
                except Exception as exc:
                    if "already defined" in str(exc).lower():
                        jlog.log(f"[{sh}] PVE storage already propagated from cluster.")
                    else:
                        jlog.log(f"[{sh}] WARNING: pvesm add failed: {exc}")
            else:
                jlog.log(f"[{sh}] PVE storage already exists.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm add failed: {exc}")

    _set_ds_status(db, ds_id, "active")

    # ── Register volume_mapping for each host ─────────────────────────────────
    lvm_pool_name = params.get("lvm_pool_name") or (
        dict(db.query_one("SELECT lvm_pool_name FROM netapp_provisioned_datastores WHERE id=?",
                          (ds_id,)) or {})).get("lvm_pool_name", "")
    now = _now()
    for hid in ordered_hosts:
        mid = str(_uuid.uuid4())
        try:
            db.execute(
                """INSERT INTO netapp_volume_mapping
                   (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                    volume_uuid, volume_name, junction_path, nfs_export_ip,
                    nfs_mount_path, discovered_at,
                    storage_protocol, lun_uuid, lun_path,
                    lvm_vg_name, lvm_type, lvm_pool_name,
                    snapinfo_initialized, snapinfo_lv_name,
                    created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
                   endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
                   volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
                   lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path,
                   lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type,
                   lvm_pool_name=excluded.lvm_pool_name,
                   storage_protocol=excluded.storage_protocol,
                   snapinfo_initialized=excluded.snapinfo_initialized,
                   discovered_at=excluded.discovered_at""",
                (mid, endpoint_id, hid, pve_storage_id, svm_name,
                 volume_uuid, volume_name, "", "", "", now,
                 "nvme", ns_uuid, f"/vol/{volume_name}/{ns_name}",
                 vg_name, lvm_type, lvm_pool_name,
                 1, "netapp_snapmanifest", _now()),
            )
            jlog.log(f"Volume mapping registered for host {hid}.")
        except Exception as exc:
            jlog.log(f"WARNING: could not register volume mapping for host {hid}: {exc}")

    jlog.log(f"NVMe provisioning complete. Datastore '{name}' is active.")


# ── NVMe: remove ─────────────────────────────────────────────────────────────

def _remove_nvme(ds_id, ds, delete_ontap, db, jlog):
    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    vg_name        = ds.get("vg_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    pve_host_ids   = json.loads(ds.get("pve_host_ids") or "[]")
    ns_uuid        = ds.get("ns_uuid", "")
    volume_uuid    = ds.get("volume_uuid", "")
    subsystem_uuid = ds.get("subsystem_uuid", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── Per-host teardown ─────────────────────────────────────────────────────
    for hid in pve_host_ids:
        try:
            pve = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            sh = pve.host

            if pve_storage_id:
                jlog.log(f"[{sh}] Removing PVE storage '{pve_storage_id}' …")
                ssh_run(sh, su, sp,
                        f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                        key_material=sk, timeout=30)
                jlog.log(f"[{sh}] PVE storage removed.")

            if vg_name:
                vg_q = shlex.quote(vg_name)
                jlog.log(f"[{sh}] Deactivating VG '{vg_name}' …")
                ssh_run(sh, su, sp,
                        f"vgchange -an {vg_q} 2>/dev/null; "
                        f"udevadm settle --timeout=5 2>/dev/null; true",
                        key_material=sk, timeout=30)
                jlog.log(f"[{sh}] VG deactivated.")

            # Disconnect while VG is still registered so pvs can find the device
            jlog.log(f"[{sh}] Disconnecting NVMe controller …")
            nvme_disconnect_by_vg(sh, su, sp, sk, vg_name)
            jlog.log(f"[{sh}] NVMe disconnected.")

            if vg_name:
                vg_q = shlex.quote(vg_name)
                ssh_run(sh, su, sp,
                        f"vgremove -f {vg_q} 2>/dev/null; true",
                        key_material=sk, timeout=15)
                jlog.log(f"[{sh}] VG removed.")

        except Exception as exc:
            jlog.log(f"WARNING: cannot reach host {hid}: {exc}")

    # ── ONTAP cleanup ─────────────────────────────────────────────────────────
    if ns_uuid and subsystem_uuid:
        jlog.log("Unmapping namespace from subsystem …")
        try:
            client.remove_nvme_namespace_from_subsystem(subsystem_uuid, ns_uuid)
            jlog.log("Namespace unmapped.")
        except Exception as exc:
            jlog.log(f"WARNING: unmap namespace: {exc}")

    if delete_ontap:
        if ns_uuid:
            jlog.log(f"Deleting NVMe namespace {ns_uuid} …")
            try:
                client.delete_namespace(ns_uuid)
                jlog.log("Namespace deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: namespace delete: {exc}")
        if volume_uuid:
            jlog.log(f"Deleting volume {volume_uuid} …")
            try:
                client.delete_volume(volume_uuid)
                jlog.log("Volume deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: volume delete: {exc}")
        if subsystem_uuid:
            jlog.log(f"Deleting NVMe subsystem {subsystem_uuid} …")
            try:
                client.delete_nvme_subsystem(subsystem_uuid)
                jlog.log("Subsystem deleted.")
            except Exception as exc:
                jlog.log(f"WARNING: subsystem delete: {exc}")


# ── NVMe: add single host ─────────────────────────────────────────────────────

def _add_host_nvme(ds_id, ds, host_id, db, jlog):
    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    subsystem_uuid = ds.get("subsystem_uuid", "")
    ns_uuid        = ds.get("ns_uuid", "")
    vg_name        = ds.get("vg_name", "")
    lvm_type       = ds.get("lvm_type", "linear")
    lvm_pool_name  = ds.get("lvm_pool_name", "") or "data"
    pve_storage_id = ds.get("pve_storage_id", "")
    volume_uuid    = ds.get("volume_uuid", "")
    volume_name    = ds.get("volume_name", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    pve = build_pve_client(db, host_id)
    su, sp, sk = get_ssh_creds(pve)
    sh = pve.host

    # 1. Collect NQN
    jlog.log(f"[{sh}] Collecting NVMe host NQN …")
    nqn = get_nvme_host_nqn(sh, su, sp, sk)
    if not nqn:
        raise RuntimeError(f"No NQN found on host {sh}")
    jlog.log(f"[{sh}] NQN: {nqn}")

    # 2. Add NQN to ONTAP subsystem (idempotent)
    if subsystem_uuid:
        try:
            existing_sub  = client.get_nvme_subsystem(subsystem_uuid)
            existing_nqns = {h.get("nqn", "") for h in (existing_sub.get("hosts") or [])}
            if nqn not in existing_nqns:
                client.add_nvme_host_to_subsystem(subsystem_uuid, nqn)
                jlog.log(f"Host NQN added to subsystem.")
            else:
                jlog.log(f"Host NQN already in subsystem.")
        except Exception as exc:
            jlog.log(f"WARNING: add NQN to subsystem: {exc}")

    # 3. Connect NVMe
    jlog.log(f"[{sh}] Capturing NVMe device baseline …")
    devices_before = nvme_list_devices(sh, su, sp, sk)
    jlog.log(f"[{sh}] Connecting NVMe …")
    nvme_connect_all(sh, su, sp, sk)
    jlog.log(f"[{sh}] Waiting for NVMe namespace device …")
    device = find_new_nvme_device(sh, su, sp, sk, devices_before, timeout_s=60)
    jlog.log(f"[{sh}] Device ready: {device}")

    # 4. pvscan to activate existing VG on this host
    jlog.log(f"[{sh}] Activating VG via pvscan …")
    ssh_run(sh, su, sp,
            f"pvscan --cache -aay {shlex.quote(device)} 2>/dev/null; true",
            key_material=sk, timeout=30)
    jlog.log(f"[{sh}] pvscan done.")

    # 5. pvesm (if not yet in this host's storage config)
    if pve_storage_id:
        vg_q  = shlex.quote(vg_name)
        sid_q = shlex.quote(pve_storage_id)
        try:
            check = ssh_run(sh, su, sp,
                            f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                            f" && echo EXISTS || echo MISSING",
                            capture=True, key_material=sk)
            if "EXISTS" not in check:
                jlog.log(f"[{sh}] Registering PVE storage …")
                if lvm_type == "thin":
                    pvesm_cmd = (f"pvesm add lvmthin {sid_q} --vgname {vg_q}"
                                 f" --thinpool {shlex.quote(lvm_pool_name)}"
                                 f" --shared 1 --content images,rootdir")
                else:
                    pvesm_cmd = (f"pvesm add lvm {sid_q} --vgname {vg_q}"
                                 f" --shared 1 --content images,rootdir")
                ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                jlog.log(f"[{sh}] PVE storage registered.")
            else:
                jlog.log(f"[{sh}] PVE storage already in cluster config.")
        except Exception as exc:
            jlog.log(f"[{sh}] WARNING: pvesm: {exc}")

    # 6. Register volume_mapping
    ns_name = ""
    try:
        ns_info = client.get_namespace(ns_uuid)
        ns_name = ((ns_info.get("location") or {}).get("namespace") or
                   ns_info.get("name", "").split("/")[-1])
    except Exception:
        pass
    mid = str(_uuid.uuid4())
    try:
        db.execute(
            """INSERT INTO netapp_volume_mapping
               (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                volume_uuid, volume_name, junction_path, nfs_export_ip,
                nfs_mount_path, discovered_at,
                storage_protocol, lun_uuid, lun_path,
                lvm_vg_name, lvm_type, lvm_pool_name,
                snapinfo_initialized, snapinfo_lv_name,
                    created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
               endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
               volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
               lun_uuid=excluded.lun_uuid, lun_path=excluded.lun_path,
               lvm_vg_name=excluded.lvm_vg_name, lvm_type=excluded.lvm_type,
               lvm_pool_name=excluded.lvm_pool_name,
               storage_protocol=excluded.storage_protocol,
               snapinfo_initialized=excluded.snapinfo_initialized,
               discovered_at=excluded.discovered_at""",
            (mid, endpoint_id, host_id, pve_storage_id, svm_name,
             volume_uuid, volume_name, "", "", "", _now(),
             "nvme", ns_uuid, f"/vol/{volume_name}/{ns_name}",
             vg_name, lvm_type, lvm_pool_name,
             1, "netapp_snapmanifest", _now()),
        )
        jlog.log("Volume mapping registered.")
    except Exception as exc:
        jlog.log(f"WARNING: volume mapping: {exc}")

    # 7. Update pve_host_ids
    current_ids = json.loads(ds.get("pve_host_ids") or "[]")
    if host_id not in current_ids:
        current_ids.append(host_id)
        db.execute(
            "UPDATE netapp_provisioned_datastores SET pve_host_ids=?, updated_at=? WHERE id=?",
            (json.dumps(current_ids), _now(), ds_id),
        )
        jlog.log(f"Host {host_id} added to datastore record.")


# ── NVMe: remove single host ──────────────────────────────────────────────────

def _remove_host_nvme(ds_id, ds, host_id, db, jlog):
    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    vg_name        = ds.get("vg_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    subsystem_uuid = ds.get("subsystem_uuid", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    try:
        pve = build_pve_client(db, host_id)
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host

        if pve_storage_id:
            ssh_run(sh, su, sp,
                    f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                    key_material=sk, timeout=30)

        if vg_name:
            vg_q = shlex.quote(vg_name)
            ssh_run(sh, su, sp,
                    f"vgchange -an {vg_q} 2>/dev/null; udevadm settle --timeout=5 2>/dev/null; true",
                    key_material=sk, timeout=30)

        nvme_disconnect_by_vg(sh, su, sp, sk, vg_name)

        # Remove host NQN from subsystem
        if subsystem_uuid:
            nqn = get_nvme_host_nqn(sh, su, sp, sk)
            if nqn:
                try:
                    client.remove_nvme_host_from_subsystem(subsystem_uuid, nqn)
                    jlog.log(f"Removed host NQN {nqn} from subsystem.")
                except Exception as exc:
                    jlog.log(f"WARNING: remove NQN from subsystem: {exc}")
    except Exception as exc:
        jlog.log(f"WARNING: cannot reach host {host_id}: {exc}")

    _remove_host_from_ds_record(ds_id, host_id, pve_storage_id, db, jlog)


# ── NFS helpers ───────────────────────────────────────────────────────────────

def _detect_nfs_client_ip(pve, nfs_lif_ip, jlog=None):
    """Return the IP the PVE host uses to reach nfs_lif_ip via 'ip route get'.
    Falls back to pve.nfs_ip (if manually set) or pve.host.
    """
    if pve.nfs_ip:
        return pve.nfs_ip
    try:
        out = ssh_run(pve.host, pve.ssh_user, pve.ssh_password,
                      f"ip route get {shlex.quote(nfs_lif_ip)}"
                      f" 2>/dev/null | grep -oP 'src \\K[0-9.]+'",
                      capture=True, key_material=pve.ssh_key, timeout=10)
        ip = out.strip().split()[0] if out.strip() else ""
        if ip:
            return ip
    except Exception as exc:
        if jlog:
            jlog.log(f"  NOTE: ip-route auto-detect for {pve.host}: {exc} — using hostname")
    return pve.host


# ── NFS: provision ────────────────────────────────────────────────────────────

def _provision_nfs(ds_id, params, db, jlog):
    endpoint_id    = params["endpoint_id"]
    svm_name       = params.get("svm_name", "")
    name           = params.get("name", ds_id)
    pve_storage_id = params.get("pve_storage_id", "")
    pve_host_ids   = params["pve_host_ids"]
    size_bytes     = int(params.get("size_bytes", 0))
    aggregate_name = params.get("aggregate_name", "") or None
    junction_path  = params.get("nfs_junction_path", "") or f"/{name.replace(' ', '-').lower()}"
    volume_name    = params.get("volume_name", "")
    nfs_lif_ip_sel = params.get("nfs_lif_ip", "").strip()   # user-selected LIF IP

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── ONTAP: Volume with NFS export ─────────────────────────────────────────

    # Get NFS LIF IP — prefer user selection, fall back to first available LIF
    nfs_ip = nfs_lif_ip_sel or client.get_nfs_lif_for_svm(svm_name)
    if not nfs_ip:
        raise RuntimeError(f"No NFS LIF found for SVM '{svm_name}'")
    jlog.log(f"NFS LIF: {nfs_ip}")

    volume_uuid = params.get("volume_uuid", "")
    if not volume_uuid:
        ag_info = f" on aggregate '{aggregate_name}'" if aggregate_name else " (auto-placement)"
        jlog.log(f"Creating NFS volume '{volume_name}' ({size_bytes} bytes)"
                 f" junction='{junction_path}'{ag_info} …")
        # Create a dedicated export policy for this datastore
        policy_name = f"pgxpol-{name.replace(' ', '-').lower()}"[:64]
        try:
            policy_id = client.create_export_policy(svm_name, policy_name)
            jlog.log(f"Export policy '{policy_name}' created (id={policy_id}).")
        except Exception as exc:
            jlog.log(f"WARNING: could not create export policy, using default: {exc}")
            policy_name = "default"
            policy_id   = None

        # Add rw export rules — auto-detect the PVE host IP that routes to NFS LIF
        if policy_id:
            for hid in pve_host_ids:
                try:
                    pve = build_pve_client(db, hid)
                    client_ip = _detect_nfs_client_ip(pve, nfs_ip, jlog)
                    client.add_nfs_export_rule_rw(policy_id, client_ip)
                    jlog.log(f"Export rule added for {client_ip}")
                except Exception as exc:
                    jlog.log(f"  WARNING: export rule for {hid}: {exc}")

        volume_uuid = client.create_volume_nfs(svm_name, volume_name, size_bytes,
                                               junction_path,
                                               aggregate_name=aggregate_name,
                                               export_policy=policy_name)
        jlog.log(f"Volume created: {volume_uuid}")
    else:
        vol_info       = client.get_volume(volume_uuid)
        volume_name    = vol_info.get("name", volume_name)
        export_info    = client.get_volume_export_info(volume_uuid)
        junction_path  = export_info.get("junction_path", junction_path)
        policy_name    = export_info.get("export_policy_name", "default")
        jlog.log(f"Using existing NFS volume: {volume_name}  junction={junction_path}")

    # Persist ONTAP IDs
    db.execute(
        """UPDATE netapp_provisioned_datastores
           SET volume_uuid=?, volume_name=?, nfs_junction_path=?, updated_at=?
           WHERE id=?""",
        (volume_uuid, volume_name, junction_path, _now(), ds_id),
    )

    # ── PVE: register storage — NFS is cluster-wide, run pvesm add once ─────
    # In a PVE cluster, pvesm add writes to /etc/pve/storage.cfg (pmxcfs),
    # which propagates automatically. Run on the first host only.
    sid_q = shlex.quote(pve_storage_id)
    pvesm_cmd = (f"pvesm add nfs {sid_q}"
                 f" --server {shlex.quote(nfs_ip)}"
                 f" --export {shlex.quote(junction_path)}"
                 f" --content images,rootdir --options vers=3")

    try:
        pve = build_pve_client(db, pve_host_ids[0])
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host
        jlog.log(f"[{sh}] Registering NFS storage '{pve_storage_id}' …")
        check = ssh_run(sh, su, sp,
                        f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                        f" && echo EXISTS || echo MISSING",
                        capture=True, key_material=sk)
        if "EXISTS" not in check:
            ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=120)
            jlog.log(f"[{sh}] PVE storage registered.")
        else:
            jlog.log(f"[{sh}] PVE storage already exists.")
        # Pre-create snapmanifest directory so NFS snapshots work immediately
        manifest_dir = shlex.quote(f"/mnt/pve/{pve_storage_id}/.netapp-snapmanifest")
        try:
            ssh_run(sh, su, sp, f"mkdir -p {manifest_dir}", key_material=sk, timeout=15)
            jlog.log(f"[{sh}] Snapmanifest directory created.")
        except Exception as md_exc:
            jlog.log(f"[{sh}] WARNING: could not create snapmanifest dir: {md_exc}")
    except Exception as exc:
        jlog.log(f"WARNING: pvesm add: {exc}")

    _set_ds_status(db, ds_id, "active")

    # ── Register volume_mapping ───────────────────────────────────────────────
    now = _now()
    for hid in pve_host_ids:
        mid = str(_uuid.uuid4())
        try:
            db.execute(
                """INSERT INTO netapp_volume_mapping
                   (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                    volume_uuid, volume_name, junction_path, nfs_export_ip,
                    nfs_mount_path, discovered_at, storage_protocol,
                    lun_uuid, lun_path, lvm_vg_name, lvm_type, lvm_pool_name,
                    snapinfo_initialized, snapinfo_lv_name,
                    created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
                   endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
                   volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
                   junction_path=excluded.junction_path, nfs_export_ip=excluded.nfs_export_ip,
                   storage_protocol=excluded.storage_protocol,
                   discovered_at=excluded.discovered_at""",
                (mid, endpoint_id, hid, pve_storage_id, svm_name,
                 volume_uuid, volume_name, junction_path, nfs_ip,
                 f"/mnt/pve/{pve_storage_id}", now, "nfs",
                 "", "", "", "", "", 0, "", _now()),
            )
            jlog.log(f"Volume mapping registered for host {hid}.")
        except Exception as exc:
            jlog.log(f"WARNING: volume mapping for host {hid}: {exc}")

    jlog.log(f"NFS provisioning complete. Datastore '{name}' is active.")


# ── NFS: remove ───────────────────────────────────────────────────────────────

def _remove_nfs(ds_id, ds, delete_ontap, db, jlog):
    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    pve_host_ids   = json.loads(ds.get("pve_host_ids") or "[]")
    volume_uuid    = ds.get("volume_uuid", "")
    junction_path  = ds.get("nfs_junction_path", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    # ── Per-host: remove PVE storage entry ───────────────────────────────────
    for hid in pve_host_ids:
        try:
            pve = build_pve_client(db, hid)
            su, sp, sk = get_ssh_creds(pve)
            sh = pve.host
            if pve_storage_id:
                jlog.log(f"[{sh}] Removing PVE storage '{pve_storage_id}' …")
                ssh_run(sh, su, sp,
                        f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                        key_material=sk, timeout=30)
                jlog.log(f"[{sh}] PVE storage removed.")
        except Exception as exc:
            jlog.log(f"WARNING: cannot reach host {hid}: {exc}")

    # ── ONTAP cleanup ─────────────────────────────────────────────────────────
    if delete_ontap and volume_uuid:
        # Unmount (remove junction path) before deleting
        try:
            jlog.log("Unmounting NFS volume …")
            client.unmount_volume(volume_uuid)
            jlog.log("Volume unmounted.")
        except Exception as exc:
            jlog.log(f"WARNING: unmount: {exc}")

        # Delete the export policy if it was created by provisioning
        try:
            export_info = client.get_volume_export_info(volume_uuid)
            policy_name = export_info.get("export_policy_name", "")
            if policy_name and policy_name.startswith("pgxpol-"):
                policy_id = export_info.get("export_policy_id", 0)
                if policy_id:
                    client.set_volume_export_policy(volume_uuid, "default")
                    client.delete_export_policy(policy_id)
                    jlog.log(f"Export policy '{policy_name}' deleted.")
        except Exception as exc:
            jlog.log(f"WARNING: export policy cleanup: {exc}")

        jlog.log(f"Deleting NFS volume {volume_uuid} …")
        try:
            client.delete_volume(volume_uuid)
            jlog.log("Volume deleted.")
        except Exception as exc:
            jlog.log(f"WARNING: volume delete: {exc}")


# ── NFS: add/remove single host ───────────────────────────────────────────────

def _add_host_nfs(ds_id, ds, host_id, db, jlog):
    endpoint_id    = ds["endpoint_id"]
    svm_name       = ds.get("svm_name", "")
    pve_storage_id = ds.get("pve_storage_id", "")
    volume_uuid    = ds.get("volume_uuid", "")
    volume_name    = ds.get("volume_name", "")
    junction_path  = ds.get("nfs_junction_path", "")

    endpoint = get_endpoint(db, endpoint_id)
    client   = build_ontap_client(endpoint)

    nfs_ip = client.get_nfs_lif_for_svm(svm_name)
    if not nfs_ip:
        raise RuntimeError(f"No NFS LIF found for SVM '{svm_name}'")

    # Add host IP to export policy
    try:
        export_info = client.get_volume_export_info(volume_uuid)
        policy_id   = export_info.get("export_policy_id", 0)
        pve         = build_pve_client(db, host_id)
        client_ip   = _detect_nfs_client_ip(pve, nfs_ip, jlog)
        if policy_id:
            client.add_nfs_export_rule_rw(policy_id, client_ip)
            jlog.log(f"Export rule added for {client_ip}.")
    except Exception as exc:
        jlog.log(f"WARNING: export rule: {exc}")

    # Register PVE storage on host
    sid_q     = shlex.quote(pve_storage_id)
    pvesm_cmd = (f"pvesm add nfs {sid_q}"
                 f" --server {shlex.quote(nfs_ip)}"
                 f" --export {shlex.quote(junction_path)}"
                 f" --content images,rootdir --options vers=3")
    try:
        pve = build_pve_client(db, host_id)
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host
        check = ssh_run(sh, su, sp,
                        f"pvesm status {shlex.quote(pve_storage_id)} 2>/dev/null"
                        f" && echo EXISTS || echo MISSING",
                        capture=True, key_material=sk)
        if "EXISTS" not in check:
            ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=120)
            jlog.log(f"[{sh}] PVE storage registered.")
        else:
            jlog.log(f"[{sh}] PVE storage already in cluster config.")
    except Exception as exc:
        jlog.log(f"WARNING: pvesm: {exc}")

    # Register volume_mapping
    mid = str(_uuid.uuid4())
    try:
        db.execute(
            """INSERT INTO netapp_volume_mapping
               (id, endpoint_id, pve_cluster_id, pve_storage_id, svm_name,
                volume_uuid, volume_name, junction_path, nfs_export_ip,
                nfs_mount_path, discovered_at, storage_protocol,
                lun_uuid, lun_path, lvm_vg_name, lvm_type, lvm_pool_name,
                snapinfo_initialized, snapinfo_lv_name,
                    created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(pve_cluster_id, pve_storage_id) DO UPDATE SET
               endpoint_id=excluded.endpoint_id, svm_name=excluded.svm_name,
               volume_uuid=excluded.volume_uuid, volume_name=excluded.volume_name,
               junction_path=excluded.junction_path, nfs_export_ip=excluded.nfs_export_ip,
               storage_protocol=excluded.storage_protocol,
               discovered_at=excluded.discovered_at""",
            (mid, endpoint_id, host_id, pve_storage_id, svm_name,
             volume_uuid, volume_name, junction_path, nfs_ip,
             f"/mnt/pve/{pve_storage_id}", _now(), "nfs",
             "", "", "", "", "", 0, "", _now()),
        )
        jlog.log("Volume mapping registered.")
    except Exception as exc:
        jlog.log(f"WARNING: volume mapping: {exc}")

    current_ids = json.loads(ds.get("pve_host_ids") or "[]")
    if host_id not in current_ids:
        current_ids.append(host_id)
        db.execute(
            "UPDATE netapp_provisioned_datastores SET pve_host_ids=?, updated_at=? WHERE id=?",
            (json.dumps(current_ids), _now(), ds_id),
        )
        jlog.log(f"Host {host_id} added to datastore record.")


def _remove_host_nfs(ds_id, ds, host_id, db, jlog):
    pve_storage_id = ds.get("pve_storage_id", "")
    try:
        pve = build_pve_client(db, host_id)
        su, sp, sk = get_ssh_creds(pve)
        sh = pve.host
        if pve_storage_id:
            ssh_run(sh, su, sp,
                    f"pvesm remove {shlex.quote(pve_storage_id)} 2>/dev/null; true",
                    key_material=sk, timeout=30)
            jlog.log(f"[{sh}] PVE storage removed.")
    except Exception as exc:
        jlog.log(f"WARNING: cannot reach host {host_id}: {exc}")

    _remove_host_from_ds_record(ds_id, host_id, pve_storage_id, db, jlog)


# ── Shared: update DB record after host removal ───────────────────────────────

def _remove_host_from_ds_record(ds_id, host_id, pve_storage_id, db, jlog):
    """Removes host_id from pve_host_ids and cleans up volume_mapping."""
    row = db.query_one(
        "SELECT pve_host_ids FROM netapp_provisioned_datastores WHERE id=?", (ds_id,))
    if row:
        current_ids = json.loads(row["pve_host_ids"] or "[]")
        current_ids = [h for h in current_ids if h != host_id]
        db.execute(
            "UPDATE netapp_provisioned_datastores SET pve_host_ids=?, updated_at=? WHERE id=?",
            (json.dumps(current_ids), _now(), ds_id),
        )
        jlog.log(f"Host {host_id} removed from datastore record.")
    if pve_storage_id:
        db.execute(
            "DELETE FROM netapp_volume_mapping WHERE pve_cluster_id=? AND pve_storage_id=?",
            (host_id, pve_storage_id),
        )
        jlog.log("Volume mapping removed.")
