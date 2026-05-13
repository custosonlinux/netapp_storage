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
from ..core.san_helpers import (
    get_iscsi_initiator_iqn, find_device_by_serial,
    _iscsi_serial_to_mapper,
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

    return {"volumes": volumes, "luns": luns, "igroups": igroups, "aggregates": aggregates}


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
            _finish_job(db, job_id)
        else:
            jlog.log(f"Protocol '{protocol}' not yet implemented.")
            _set_ds_status(db, ds_id, "error", f"Protocol not implemented: {protocol}")
            _fail_job(db, job_id)
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

    if not volume_uuid:
        ag_info = f" on aggregate '{aggregate_name}'" if aggregate_name else " (auto-placement)"
        jlog.log(f"Creating ONTAP volume '{volume_name}' ({size_bytes} bytes){ag_info} …")
        volume_uuid = client.create_volume_san(svm_name, volume_name, size_bytes, aggregate_name=aggregate_name)
        jlog.log(f"Volume created: {volume_uuid}")
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
        lun_uuid, serial = client.create_lun(svm_name, volume_name, lun_name, size_bytes)
        lun_path = f"/vol/{volume_name}/{lun_name}"
        jlog.log(f"LUN created: {lun_uuid}  serial={serial}")
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
                ssh_run(sh, su, sp, pvesm_cmd, key_material=sk, timeout=30)
                jlog.log(f"[{sh}] PVE storage registered.")
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
                    snapinfo_initialized, snapinfo_lv_name)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                 1, "netapp_snapmanifest"),
            )
            jlog.log(f"Volume mapping registered for host {hid}.")
        except Exception as exc:
            jlog.log(f"WARNING: could not register volume mapping for host {hid}: {exc}")

    jlog.log(f"Provisioning complete. Datastore '{name}' is active.")


def _run_resize(job_id, ds_id, new_size_bytes, username):
    db = get_db()
    jlog = JobLogger(job_id, db)
    try:
        jlog.log(f"Resizing datastore {ds_id} to {new_size_bytes} bytes …")
        jlog.log("Resize not yet implemented.")
        _fail_job(db, job_id)
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
                snapinfo_initialized, snapinfo_lv_name)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
             1, "netapp_snapmanifest"),
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
        jlog.log(f"Removing host {host_id} from datastore {ds_id} …")
        jlog.log("Remove-host not yet implemented.")
        _fail_job(db, job_id)
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
