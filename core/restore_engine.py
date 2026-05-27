"""
NetApp ONTAP Restore Engine

Restore QEMU VMs and LXC containers from a volume snapshot.

SFSR:      ONTAP restore-file per disk image — no mount needed
FlexClone: clone → NFS mount → qemu-img/dd → unmount → delete
"""

import json
import os
import uuid
import shlex
import logging
import threading
import time
from datetime import datetime, timezone

from pegaprox.core.db import get_db

from .ontap_client import OntapError
from ._helpers import (
    load_plugin_config, get_endpoint, get_mapping, get_snapshot_record,
    build_ontap_client, build_pve_client,
    get_ssh_creds, ssh_run, JobLogger, JobCancelledError, check_cancel,
)
from ._job_registry import register as _reg_register, unregister as _reg_unregister

log = logging.getLogger(__name__)


def start_restore_job(job_id, params, username):
    method = params.get("method", "sfsr")
    if method == "dr":
        target = _run_restore_dr
    elif method == "sfsr":
        target = _run_restore_sfsr
    elif method == "san":
        target = _run_restore_san
    elif method == "san_single":
        target = _run_restore_san_single
    else:
        target = _run_restore_flexclone
    t = threading.Thread(target=target, args=(job_id, params, username), daemon=True)
    t.start()
    _reg_register(job_id, t)


# ── SFSR ──────────────────────────────────────────────────────────────────────

def _run_restore_sfsr(job_id, params, username):
    db = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id = params["snapshot_id"]
    vmid = int(params["vmid"])

    try:
        snap = get_snapshot_record(db, snapshot_id)
        mapping = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client = build_ontap_client(endpoint)

        mgr = build_pve_client(db, snap["pve_cluster_id"])
        node = snap["node"] or ""
        if not node:
            try:
                node = mgr.find_vm_node(vmid) or ""
            except Exception:
                pass
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        pve_host = _resolve_node_host(mgr, node)

        vm_types = json.loads(snap.get("vm_types_json") or "{}")
        vm_type = vm_types.get(str(vmid), "qemu")

        # ── VM/CT stoppen ─────────────────────────────────────────────
        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)

        # ── Manifest lesen ────────────────────────────────────────────
        manifest = _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key)
        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks = vm_entry.get("disks", [])
        snap_name = snap["snap_name"]

        total = len(disks)
        jlog.log(f"Restoring {total} disk(s) via SFSR from snapshot '{snap_name}' …")

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            file_path = disk["file"]
            # PVE dir-storage keeps disks under images/ on the volume
            ontap_path = f"images/{file_path.lstrip('/')}"
            jlog.log(f"  [{i}/{total}] {ontap_path}")
            # Ensure target directory exists (removed together with the VM)
            nfs_dir = os.path.dirname(f"{mapping['nfs_mount_path']}/{ontap_path}")
            ssh_run(pve_host, pve_user, pve_pass,
                    f"mkdir -p {shlex.quote(nfs_dir)}", key_material=pve_key)
            client.restore_file(
                svm_name=mapping["svm_name"],
                volume_name=mapping["volume_name"],
                snap_name=snap_name,
                file_path=ontap_path,
                restore_path=ontap_path,
            )
            _set_progress(db, job_id, int(i / total * 80))

        # ── Restore VM config ─────────────────────────────────────────
        jlog.log("Restoring VM config …")
        _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                        pve_host, pve_user, pve_pass, pve_key)
        _set_progress(db, job_id, 90)

        # ── Rescan + starten ──────────────────────────────────────────
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)

        _finish_job(db, job_id)
        jlog.log(f"SFSR restore for {vm_type.upper()} {vmid} completed.")

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
    except Exception as exc:
        log.error(f"[netapp_storage] SFSR job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
    finally:
        _reg_unregister(job_id)


# ── FlexClone-Copy ─────────────────────────────────────────────────────────────

def _run_restore_flexclone(job_id, params, username):
    db = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id = params["snapshot_id"]
    vmid = int(params["vmid"])
    cfg = load_plugin_config()
    clone_mount_base = cfg.get("flexclone_mount_base", "/mnt/pegaprox-clone")

    clone_vol_uuid = None
    clone_mount_point = None
    snap = None

    try:
        snap = get_snapshot_record(db, snapshot_id)
        mapping = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client = build_ontap_client(endpoint)

        mgr = build_pve_client(db, snap["pve_cluster_id"])
        node = snap["node"] or ""
        if not node:
            try:
                node = mgr.find_vm_node(vmid) or ""
            except Exception:
                pass
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        pve_host = _resolve_node_host(mgr, node)

        vm_types = json.loads(snap.get("vm_types_json") or "{}")
        vm_type = vm_types.get(str(vmid), "qemu")
        snap_name = snap["snap_name"]
        clone_name = f"pgxclone_{job_id[:8]}"
        clone_junction = f"/{clone_name}"

        # ── VM/CT stoppen ─────────────────────────────────────────────
        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)

        # ── FlexClone anlegen ─────────────────────────────────────────
        jlog.log(f"FlexClone '{clone_name}' from snapshot '{snap_name}' …")
        clone_vol_uuid, clone_job_uuid = client.create_flexclone(
            parent_vol_uuid=mapping["volume_uuid"],
            snap_name=snap_name,
            clone_name=clone_name,
            svm_name=mapping["svm_name"],
            junction_path=clone_junction,
        )
        if clone_job_uuid:
            poll_cfg = load_plugin_config()
            client.poll_job(clone_job_uuid,
                            interval_s=poll_cfg.get("job_poll_interval_s", 3),
                            timeout_s=poll_cfg.get("job_poll_timeout_s", 300))
        jlog.log("FlexClone ready.")
        _set_progress(db, job_id, 20)

        # ── Clone mounten ─────────────────────────────────────────────
        clone_mount_point = f"{clone_mount_base}/{clone_name}"
        nfs_server = endpoint["host"]
        jlog.log(f"Mounting clone at {pve_host}:{clone_mount_point} …")
        ssh_run(pve_host, pve_user, pve_pass,
                f"mkdir -p {shlex.quote(clone_mount_point)}",
                key_material=pve_key)
        ssh_run(pve_host, pve_user, pve_pass,
                f"mount -t nfs -o ro,soft,timeo=30 "
                f"{shlex.quote(nfs_server + ':' + clone_junction)} "
                f"{shlex.quote(clone_mount_point)}",
                key_material=pve_key)
        _set_progress(db, job_id, 35)

        # ── Disk-Dateien kopieren ─────────────────────────────────────
        manifest = _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key)
        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks = vm_entry.get("disks", [])
        target_base = mapping["nfs_mount_path"]

        total = len(disks)
        jlog.log(f"Copying {total} disk(s) …")
        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            file_path = disk["file"]
            src = f"{clone_mount_point}/images/{file_path.lstrip('/')}"
            dst = f"{target_base}/images/{file_path.lstrip('/')}"
            jlog.log(f"  [{i}/{total}] {file_path}")

            if vm_type == "qemu":
                # qcow2/raw → qcow2
                ssh_run(pve_host, pve_user, pve_pass,
                        f"qemu-img convert -p -O qcow2 {shlex.quote(src)} {shlex.quote(dst)}",
                        timeout=3600, key_material=pve_key)
            else:
                # LXC: subvolumes/raw-Files direkt kopieren
                ssh_run(pve_host, pve_user, pve_pass,
                        f"cp --sparse=always {shlex.quote(src)} {shlex.quote(dst)}",
                        timeout=3600, key_material=pve_key)
            _set_progress(db, job_id, 35 + int(i / total * 45))

        # ── Config + Rescan + Start ───────────────────────────────────
        jlog.log("Restoring VM config …")
        _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                        pve_host, pve_user, pve_pass, pve_key)
        _set_progress(db, job_id, 88)
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)
        _set_progress(db, job_id, 95)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
    except Exception as exc:
        log.error(f"[netapp_storage] FlexClone job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")

    finally:
        _flexclone_cleanup(job_id, clone_mount_point, clone_vol_uuid, snap,
                           jlog, db)
        _reg_unregister(job_id)

    if not _job_failed(db, job_id):
        _finish_job(db, job_id)
        jlog.log(f"FlexClone restore for {vmid} completed.")


# ── SAN-Restore (Volume Revert) ───────────────────────────────────────────────

def _run_restore_san(job_id, params, username):
    """SAN restore via ONTAP volume snapshot revert.

    Stops ALL VMs in the volume, reverts the ONTAP volume, then restarts them.

    1. Stop all VMs in the volume (from snapshot manifest or VG LV scan)
    2. Deactivate LVM VG on all PVE hosts
    3. Revert ONTAP volume to snapshot
    4. Reactivate LVM VG on all PVE hosts
    5. Restore PVE configs for all reverted VMs
    6. Start all VMs that were running before
    """
    db = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id = params["snapshot_id"]
    vmid = int(params["vmid"])  # selected VM — used as fallback if manifest is empty

    try:
        snap = get_snapshot_record(db, snapshot_id)
        mapping = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client = build_ontap_client(endpoint)

        mgr = build_pve_client(db, snap["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)

        vm_types_map = json.loads(snap.get("vm_types_json") or "{}")
        snap_name = snap["snap_name"]
        vg_name = mapping.get("lvm_vg_name", "")

        if not vg_name:
            raise RuntimeError(
                "lvm_vg_name not set in mapping — SAN restore not possible. "
                "Re-run discovery."
            )

        # Collect all VMIDs in this volume; fall back to just the selected VM
        all_vmids = json.loads(snap.get("vmids_json") or "[]")
        if not all_vmids:
            all_vmids = [vmid]

        # ── 1. Stop all VMs in the volume ────────────────────────────
        port = getattr(mgr, "port", 8006)
        stopped_vms = []   # (vmid, vm_type, node) — will be restarted after revert
        for vid in all_vmids:
            vtype = vm_types_map.get(str(vid), "qemu")
            vt = "qemu" if vtype == "qemu" else "lxc"
            try:
                vnode = mgr.find_vm_node(vid) or ""
                if not vnode:
                    jlog.log(f"WARNING: cannot locate VM {vid} — skipping")
                    continue
                r = mgr._api_get(
                    f"https://{mgr.host}:{port}/api2/json/nodes/{vnode}/{vt}/{vid}/status/current"
                )
                if not r.ok:
                    continue
                status = r.json().get("data", {}).get("status", "stopped")
                if status != "stopped":
                    jlog.log(f"Stopping {vtype.upper()} {vid} …")
                    _vm_stop(mgr, vnode, vid, vtype)
                stopped_vms.append((vid, vtype, vnode))
            except Exception as exc:
                jlog.log(f"WARNING: could not stop VM {vid}: {exc}")
        _set_progress(db, job_id, 20)

        # ── 2. Deactivate VG on all PVE hosts ────────────────────────
        from .san_helpers import vg_deactivate, vg_rescan_and_activate
        pve_host_ids = []
        try:
            ds_row = db.query_one(
                "SELECT pve_host_ids FROM netapp_provisioned_datastores WHERE volume_uuid=?",
                (mapping["volume_uuid"],)
            )
            if ds_row:
                pve_host_ids = json.loads(ds_row.get("pve_host_ids") or "[]")
        except Exception:
            pass

        if not pve_host_ids:
            # Fallback: primary host only
            primary_node = (stopped_vms[0][2] if stopped_vms
                            else snap.get("node") or "")
            primary_host = _resolve_node_host(mgr, primary_node)
            pve_host_ids = [snap["pve_cluster_id"]]
            jlog.log(f"Deactivating LVM VG '{vg_name}' on {primary_host} …")
            vg_deactivate(primary_host, pve_user, pve_pass, pve_key, vg_name)
        else:
            for hid in pve_host_ids:
                try:
                    h = build_pve_client(db, hid)
                    hu, hp, hk = get_ssh_creds(h)
                    jlog.log(f"[{h.host}] Deactivating LVM VG '{vg_name}' …")
                    vg_deactivate(h.host, hu, hp, hk, vg_name)
                except Exception as exc:
                    jlog.log(f"WARNING: VG deactivate on host {hid}: {exc}")
        _set_progress(db, job_id, 35)

        # ── 3. ONTAP Volume Revert ────────────────────────────────────
        jlog.log(f"Reverting ONTAP volume to snapshot '{snap_name}' …")
        job_uuid = client.restore_volume_snapshot_san(mapping["volume_uuid"], snap_name)
        if job_uuid:
            poll_cfg = load_plugin_config()
            client.poll_job(
                job_uuid,
                interval_s=poll_cfg.get("job_poll_interval_s", 3),
                timeout_s=poll_cfg.get("job_poll_timeout_s", 300),
            )
        jlog.log("Volume revert completed.")
        _set_progress(db, job_id, 60)

        # ── 4. Reactivate VG on all PVE hosts ────────────────────────
        primary_host = _resolve_node_host(mgr,
                                          stopped_vms[0][2] if stopped_vms
                                          else snap.get("node") or "")
        for hid in pve_host_ids:
            try:
                h = build_pve_client(db, hid)
                hu, hp, hk = get_ssh_creds(h)
                jlog.log(f"[{h.host}] Reactivating LVM VG '{vg_name}' …")
                vg_rescan_and_activate(h.host, hu, hp, hk, vg_name)
            except Exception as exc:
                jlog.log(f"WARNING: VG reactivate on host {hid}: {exc}")
        _set_progress(db, job_id, 75)

        # ── 5. Restore PVE configs for all VMs ───────────────────────
        for (vid, vtype, vnode) in stopped_vms:
            try:
                vhost = _resolve_node_host(mgr, vnode)
                _restore_config(snap, mapping, vid, vtype, vnode, mgr,
                                vhost, pve_user, pve_pass, pve_key)
                jlog.log(f"Config restored for {vtype.upper()} {vid}.")
            except Exception as exc:
                jlog.log(f"WARNING: config restore for VM {vid}: {exc}")
        _set_progress(db, job_id, 88)

        # ── 6. Start all VMs ─────────────────────────────────────────
        for (vid, vtype, vnode) in stopped_vms:
            jlog.log(f"Starting {vtype.upper()} {vid} …")
            _vm_start(mgr, vnode, vid, vtype)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] SAN restore job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _finish_job(db, job_id)
    jlog.log(f"Volume revert completed — {len(stopped_vms)} VM(s) restarted.")


# ── SAN Single-VM Restore (temp clone → LV copy) ──────────────────────────────

def _cleanup_san_clone(client, protocol,
                       temp_lun_uuid, igroup_uuid,
                       temp_ns_uuid, subsystem_uuid,
                       temp_iscsi_clone_vol_uuid="", jlog=None):
    """Unmaps and deletes a temporary clone LUN/volume or namespace."""
    if protocol == "iscsi" and temp_lun_uuid:
        if igroup_uuid:
            try:
                client.unmap_lun(temp_lun_uuid, igroup_uuid)
            except Exception as exc:
                log.warning(f"[netapp_storage] unmap clone LUN: {exc}")
        if temp_iscsi_clone_vol_uuid:
            try:
                client.delete_volume(temp_iscsi_clone_vol_uuid)
                if jlog:
                    jlog.log("Clone volume removed.")
            except Exception as exc:
                log.warning(f"[netapp_storage] delete clone volume: {exc}")
        else:
            try:
                client.delete_lun(temp_lun_uuid)
                if jlog:
                    jlog.log("Clone LUN removed.")
            except Exception as exc:
                log.warning(f"[netapp_storage] delete clone LUN: {exc}")
    elif protocol == "nvme" and temp_ns_uuid:
        if subsystem_uuid:
            try:
                client.remove_nvme_namespace_from_subsystem(subsystem_uuid, temp_ns_uuid)
            except Exception as exc:
                log.warning(f"[netapp_storage] unmap clone NS: {exc}")
        try:
            client.delete_namespace(temp_ns_uuid)
            if jlog:
                jlog.log("Clone namespace removed.")
        except Exception as exc:
            log.warning(f"[netapp_storage] delete clone namespace: {exc}")


def _run_restore_san_single(job_id, params, username):
    """SAN single-VM restore: clone volume from snapshot, copy only the target VM's LVs.

    Unlike full volume revert, only the target VM is stopped and only its LVs
    are overwritten. Other VMs on the same datastore keep running.

    Flow:
      1. Stop target VM
      2. Clone LUN/namespace from snapshot on ONTAP (temp pgxclone_*)
      3. Map clone to PVE host, vgimportclone → temp VG
      4. For each of the VM's LVs: dd from temp VG → live VG (overwrite)
      5. Deactivate + delete temp VG, unmap + delete clone
      6. Restore VM config from manifest
      7. Start VM
    """
    db   = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id    = params["snapshot_id"]
    vmid           = int(params["vmid"])

    temp_lun_uuid             = ""
    temp_ns_uuid              = ""
    temp_iscsi_clone_vol_uuid = ""
    temp_iscsi_serial         = ""
    temp_vg_name              = ""
    igroup_uuid               = ""
    subsystem_uuid            = ""
    pve_host       = ""
    pve_user       = "root"
    pve_pass       = ""
    pve_key        = ""
    protocol       = "nvme"
    client         = None

    try:
        snap     = get_snapshot_record(db, snapshot_id)
        mapping  = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client   = build_ontap_client(endpoint)

        mgr      = build_pve_client(db, snap["pve_cluster_id"])
        node     = snap.get("node") or ""
        if not node:
            try:
                node = mgr.find_vm_node(vmid) or ""
            except Exception:
                pass
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        pve_host = _resolve_node_host(mgr, node)

        vm_types  = json.loads(snap.get("vm_types_json") or "{}")
        vm_type   = vm_types.get(str(vmid), "qemu")
        vg_name   = mapping["lvm_vg_name"]
        lvm_type  = mapping.get("lvm_type", "linear")
        pool_name = mapping.get("lvm_pool_name", "")
        svm_name  = mapping["svm_name"]
        vol_uuid  = mapping["volume_uuid"]
        protocol  = mapping.get("storage_protocol", "nvme")
        snap_name = snap["snap_name"]

        if not vg_name:
            raise RuntimeError("lvm_vg_name not set in mapping — re-run discovery")

        poll_cfg = load_plugin_config()

        # ── 1. Load manifest → disk list ─────────────────────────────
        jlog.log("Reading manifest …")
        manifest = _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key)
        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks    = vm_entry.get("disks", [])
        if not disks:
            raise RuntimeError(f"No disk entries in manifest for VM {vmid}")
        _set_progress(db, job_id, 8)

        # ── 2. Stop VM ────────────────────────────────────────────────
        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)
        _ensure_vmid_placeholder(pve_host, pve_user, pve_pass, pve_key, vmid, vm_type)
        _set_progress(db, job_id, 15)

        # ── 3. Clone LUN/namespace on ONTAP ──────────────────────────
        vol_info = client.get_volume(vol_uuid)
        vol_name = vol_info.get("name", "")
        if not vol_name:
            raise RuntimeError(f"Cannot resolve volume name for UUID {vol_uuid}")

        temp_clone_name = f"pgxclone_{job_id[:8]}"
        device = ""

        if protocol == "iscsi":
            jlog.log(f"Cloning volume from snapshot '{snap_name}' (iSCSI) …")
            temp_lun_uuid, temp_iscsi_clone_vol_uuid = client.clone_lun_from_snapshot(
                vol_uuid, snap_name, svm_name, temp_clone_name,
                poll_interval=poll_cfg.get("job_poll_interval_s", 3),
                poll_timeout=poll_cfg.get("job_poll_timeout_s", 300),
            )
            jlog.log(f"Volume clone created: {temp_clone_name}")

            lun_uuid = mapping.get("lun_uuid", "")
            existing_maps = client.list_lun_maps(lun_uuid=lun_uuid) if lun_uuid else []
            if not existing_maps:
                raise RuntimeError("No igroup mapping found for main LUN")
            igroup_uuid = existing_maps[0]["igroup"]["uuid"]
            jlog.log("Mapping clone LUN to iSCSI igroup …")
            client.map_lun(temp_lun_uuid, igroup_uuid, svm_name)

            from .san_helpers import rescan_iscsi, find_device_by_serial
            jlog.log("Rescanning iSCSI sessions …")
            rescan_iscsi(pve_host, pve_user, pve_pass, pve_key)
            temp_lun_info     = client.get_lun(temp_lun_uuid)
            temp_serial       = temp_lun_info.get("serial_number", "")
            temp_iscsi_serial = temp_serial
            if not temp_serial:
                raise RuntimeError("Cannot determine serial number of clone LUN")
            jlog.log(f"Waiting for clone device (serial: {temp_serial}) …")
            device = find_device_by_serial(
                pve_host, pve_user, pve_pass, pve_key, temp_serial, timeout_s=60)

        elif protocol == "nvme":
            jlog.log(f"Cloning NVMe namespace from snapshot '{snap_name}' …")
            from .san_helpers import nvme_list_devices, nvme_ns_rescan, find_new_nvme_device
            # Snapshot of host devices taken before clone creation — the clone namespace
            # may already be subsystem-mapped when clone_namespace() returns (CLI bridge path),
            # so we must capture the baseline before the namespace appears on the host.
            devices_before = nvme_list_devices(pve_host, pve_user, pve_pass, pve_key)

            namespaces = client.list_nvme_namespaces(svm_name=svm_name)
            main_ns = next(
                (ns for ns in namespaces
                 if (ns.get("location") or {}).get("volume", {}).get("uuid") == vol_uuid),
                None,
            )
            # Fallback: match by volume name when UUID is not returned by the API
            if not main_ns:
                main_ns = next(
                    (ns for ns in namespaces
                     if (ns.get("location") or {}).get("volume", {}).get("name") == vol_name),
                    None,
                )
            if not main_ns:
                raise RuntimeError(
                    f"Cannot find NVMe namespace for volume {vol_uuid} — re-run discovery")
            main_ns_uuid = main_ns["uuid"]

            subsystem = client.get_nvme_subsystem_for_namespace(main_ns_uuid, svm_name=svm_name)
            if not subsystem:
                raise RuntimeError("No NVMe subsystem found for main namespace")
            subsystem_uuid = subsystem["uuid"]

            temp_ns_uuid, ns_job = client.clone_namespace(
                main_ns_uuid, snap_name, vol_name, temp_clone_name, svm_name)
            if ns_job:
                client.poll_job(ns_job,
                                interval_s=poll_cfg.get("job_poll_interval_s", 3),
                                timeout_s=poll_cfg.get("job_poll_timeout_s", 300))
            if not temp_ns_uuid:
                raise RuntimeError("clone_namespace returned no UUID — check ONTAP logs")

            # On ASA, volume clone inherits the parent's subsystem mappings — the clone
            # namespace is already visible in the subsystem. Skip mapping in that case.
            clone_already_mapped = bool(
                client.get_nvme_subsystem_for_namespace(temp_ns_uuid, svm_name=svm_name))
            if clone_already_mapped:
                jlog.log("Clone namespace already in subsystem (ASA volume clone) …")
            else:
                jlog.log("Mapping clone namespace to NVMe subsystem …")
                client.add_nvme_namespace_to_subsystem(subsystem_uuid, temp_ns_uuid, svm_name=svm_name)

            jlog.log("Rescanning NVMe controllers …")
            nvme_ns_rescan(pve_host, pve_user, pve_pass, pve_key)
            jlog.log("Waiting for clone namespace device …")
            device = find_new_nvme_device(
                pve_host, pve_user, pve_pass, pve_key, devices_before, timeout_s=60)
        else:
            raise RuntimeError(f"Unsupported SAN protocol for single restore: {protocol}")

        jlog.log(f"Clone device: {device}")
        _set_progress(db, job_id, 35)

        # ── 4. vgimportclone → temp VG ────────────────────────────────
        jlog.log(f"Importing clone VG from {device} …")
        from .san_helpers import (vg_import_clone, activate_lv_for_restore,
                                  cleanup_restore_vg, lv_copy)
        temp_vg_name = vg_import_clone(
            pve_host, pve_user, pve_pass, pve_key, device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")
        _set_progress(db, job_id, 45)

        # ── 5. Overwrite each VM LV in the live VG ────────────────────
        total = len(disks)
        jlog.log(f"Restoring {total} disk(s) for VM {vmid} …")

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk.get("file", "")
            src_lv   = os.path.basename(old_file.split(":")[-1]) if old_file else ""
            if not src_lv:
                jlog.log(f"  [{i}/{total}] skipping disk with no file path")
                continue

            jlog.log(f"  [{i}/{total}] restoring {src_lv} …")

            from .san_helpers import get_lv_size_bytes, create_lv

            # Activate source LV in temp VG
            activate_lv_for_restore(
                pve_host, pve_user, pve_pass, pve_key,
                temp_vg_name, src_lv, lvm_type, pool_name)

            # Create target LV if it doesn't exist (e.g. VM was deleted after snapshot)
            dst_size = get_lv_size_bytes(
                pve_host, pve_user, pve_pass, pve_key, vg_name, src_lv)
            if not dst_size:
                src_size = get_lv_size_bytes(
                    pve_host, pve_user, pve_pass, pve_key, temp_vg_name, src_lv)
                if not src_size:
                    raise RuntimeError(
                        f"Cannot determine size for {temp_vg_name}/{src_lv}")
                jlog.log(f"  Creating {vg_name}/{src_lv} ({src_size} B) …")
                create_lv(pve_host, pve_user, pve_pass, pve_key,
                          vg_name, src_lv, src_size, lvm_type, pool_name)

            # Overwrite via dd — VM is stopped so no deactivation needed
            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, src_lv, jlog)

            _set_progress(db, job_id, 45 + int(i / max(total, 1) * 35))

        # ── 6. Cleanup temp VG + clone ────────────────────────────────
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""
        _set_progress(db, job_id, 82)

        jlog.log("Removing temporary clone LUN/namespace …")
        _cleanup_san_clone(client, protocol,
                           temp_lun_uuid, igroup_uuid,
                           temp_ns_uuid, subsystem_uuid,
                           temp_iscsi_clone_vol_uuid, jlog)
        if protocol == "iscsi" and temp_iscsi_serial and pve_host:
            from .san_helpers import flush_iscsi_clone_device
            flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
        temp_lun_uuid = temp_ns_uuid = temp_iscsi_clone_vol_uuid = temp_iscsi_serial = ""
        _set_progress(db, job_id, 88)

        # After clone cleanup the NVMe device disappears; refresh LVM so the
        # target VG devices are still active when the VM starts.
        from .san_helpers import vg_rescan_and_activate
        try:
            vg_rescan_and_activate(pve_host, pve_user, pve_pass, pve_key, vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] vg rescan after cleanup failed: {exc}")

        # ── 7. Restore VM config + start ─────────────────────────────
        jlog.log("Restoring VM config …")
        _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                        pve_host, pve_user, pve_pass, pve_key)
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        if temp_vg_name:
            try:
                from .san_helpers import cleanup_restore_vg
                cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            except Exception as ce:
                log.warning(f"[netapp_storage] single restore cancel cleanup VG failed: {ce}")
        if client and (temp_lun_uuid or temp_ns_uuid or temp_iscsi_clone_vol_uuid):
            try:
                _cleanup_san_clone(client, protocol,
                                   temp_lun_uuid, igroup_uuid,
                                   temp_ns_uuid, subsystem_uuid,
                                   temp_iscsi_clone_vol_uuid)
            except Exception as ce:
                log.warning(f"[netapp_storage] single restore cancel cleanup clone failed: {ce}")
            if protocol == "iscsi" and temp_iscsi_serial and pve_host:
                try:
                    from .san_helpers import flush_iscsi_clone_device
                    flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
                except Exception as ce:
                    log.warning(f"[netapp_storage] flush multipath on cancel failed: {ce}")
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] SAN single restore job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        if temp_vg_name:
            try:
                from .san_helpers import cleanup_restore_vg
                cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            except Exception as ce:
                log.warning(f"[netapp_storage] single restore cleanup VG failed: {ce}")
        if client and (temp_lun_uuid or temp_ns_uuid or temp_iscsi_clone_vol_uuid):
            try:
                _cleanup_san_clone(client, protocol,
                                   temp_lun_uuid, igroup_uuid,
                                   temp_ns_uuid, subsystem_uuid,
                                   temp_iscsi_clone_vol_uuid)
            except Exception as ce:
                log.warning(f"[netapp_storage] single restore cleanup clone failed: {ce}")
            if protocol == "iscsi" and temp_iscsi_serial and pve_host:
                try:
                    from .san_helpers import flush_iscsi_clone_device
                    flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
                except Exception as ce:
                    log.warning(f"[netapp_storage] flush multipath on error failed: {ce}")
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _finish_job(db, job_id)
    jlog.log(f"SAN single-VM restore for {vm_type.upper()} {vmid} completed.")


def _run_restore_dr_iscsi(job_id, params, username, db, jlog, mapping):
    """
    DR restore for iSCSI datastores from SnapMirror® secondary.

    Flow:
      1. Load manifest from DB, stop VM
      2. FlexClone from SnapMirror snapshot on secondary
      3. Create temp igroup on secondary, map clone LUN
      4. Single-path iSCSI connect from PVE host to secondary portal
      5. vgimportclone → temp VG, dd LVs to primary VG
      6. Cleanup: deactivate temp VG, flush device, logout iSCSI
      7. Delete temp igroup + clone volume on secondary
      8. Restore VM config, start VM
    """
    from ._helpers import get_endpoint, build_ontap_client, get_ssh_creds
    from .san_helpers import (connect_iscsi_target, disconnect_iscsi_target,
                               find_device_by_serial, flush_iscsi_clone_device,
                               vg_import_clone, activate_lv_for_restore, lv_copy,
                               cleanup_restore_vg, get_lv_size_bytes, create_lv,
                               vg_rescan_and_activate)

    relationship_id = params["relationship_id"]
    snap_name       = params["snap_name"]
    vmid            = int(params["vmid"])
    vm_type         = params.get("vm_type", "qemu")

    vg_name         = mapping["lvm_vg_name"]
    lvm_type        = mapping.get("lvm_type", "linear")
    pool_name       = mapping.get("lvm_pool_name", "")

    # Cleanup-state — touched only when the resource is actually created
    secondary_client   = None
    temp_lun_uuid      = ""
    temp_clone_vol_uuid = ""
    temp_igroup_uuid   = ""
    temp_igroup_name   = ""
    sec_portal         = ""
    sec_target_iqn     = ""
    temp_vg_name       = ""
    temp_iscsi_serial  = ""
    pve_host = pve_user = pve_pass = pve_key = ""

    try:
        rel = db.query_one(
            "SELECT * FROM netapp_snapmirror_relationships WHERE id=?",
            (relationship_id,)
        )
        if not rel:
            raise RuntimeError(f"SnapMirror relationship '{relationship_id}' not found")
        rel = dict(rel)
        if not rel.get("dest_endpoint_id") or not rel.get("dest_volume_uuid"):
            raise RuntimeError(
                "Secondary endpoint or volume UUID missing — run SnapMirror scan first.")

        secondary_ep     = get_endpoint(db, rel["dest_endpoint_id"])
        secondary_client = build_ontap_client(secondary_ep)
        dest_svm         = rel["dest_svm"]
        dest_vol_uuid    = rel["dest_volume_uuid"]

        mgr      = build_pve_client(db, mapping["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        node = ""
        try:
            node = mgr.find_vm_node(vmid) or ""
        except Exception:
            pass
        pve_host = _resolve_node_host(mgr, node) or mgr.host

        poll_cfg        = load_plugin_config()
        poll_interval   = poll_cfg.get("job_poll_interval_s", 3)
        poll_timeout    = poll_cfg.get("job_poll_timeout_s", 300)

        # ── 1. Manifest (from DB) + stop VM ──────────────────────────────────
        # For iSCSI the manifest is stored in the snapshot record in the DB.
        # Find the snapshot record for this relationship + snap_name.
        snap_row = db.query_one(
            "SELECT * FROM netapp_snapshots WHERE mapping_id=? AND snap_name=? "
            "ORDER BY created_at DESC LIMIT 1",
            (mapping["id"], snap_name),
        )
        if snap_row:
            snap = dict(snap_row)
            manifest = _load_manifest(snap, mapping, node, mgr,
                                      pve_host, pve_user, pve_pass, pve_key)
            vm_type  = json.loads(snap.get("vm_types_json") or "{}").get(str(vmid), vm_type)
        else:
            jlog.log("Snapshot record not found in DB — will restore all LVs found in clone VG.")
            manifest = {"vms": [{"vmid": vmid, "disks": [], "vm_type": vm_type}]}

        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks    = vm_entry.get("disks", [])
        vm_type  = vm_entry.get("vm_type", vm_type)

        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)
        _ensure_vmid_placeholder(pve_host, pve_user, pve_pass, pve_key, vmid, vm_type)
        _set_progress(db, job_id, 10)

        # ── 2. FlexClone from SnapMirror snapshot on secondary ───────────────
        temp_clone_name = f"pgxdrclone_{job_id[:8]}"
        jlog.log(f"Cloning volume from secondary snapshot '{snap_name}' …")
        temp_lun_uuid, temp_clone_vol_uuid = secondary_client.clone_lun_from_snapshot(
            dest_vol_uuid, snap_name, dest_svm, temp_clone_name,
            poll_interval=poll_interval, poll_timeout=poll_timeout,
        )
        jlog.log(f"Secondary clone volume created: {temp_clone_name}")
        _set_progress(db, job_id, 22)

        # ── 3. Temp igroup on secondary, map clone LUN ───────────────────────
        jlog.log("Getting host IQN …")
        from .san_helpers import get_iscsi_initiator_iqn
        host_iqn = get_iscsi_initiator_iqn(pve_host, pve_user, pve_pass, pve_key)
        if not host_iqn:
            raise RuntimeError(f"Cannot determine iSCSI IQN of PVE host {pve_host}")

        temp_igroup_name = f"pgxdr_{job_id[:8]}"
        jlog.log(f"Creating temporary igroup '{temp_igroup_name}' on secondary …")
        temp_igroup_uuid = secondary_client.create_igroup(
            dest_svm, temp_igroup_name, protocol="iscsi")
        secondary_client.add_igroup_initiator(temp_igroup_uuid, host_iqn)
        secondary_client.map_lun(temp_lun_uuid, temp_igroup_uuid, dest_svm)
        jlog.log("Clone LUN mapped to temporary igroup.")
        _set_progress(db, job_id, 32)

        # ── 4. iSCSI connect PVE host → secondary ────────────────────────────
        sec_portal     = secondary_client.get_iscsi_lif_for_svm(dest_svm)
        sec_target_iqn = secondary_client.get_iscsi_target_iqn(dest_svm)
        if not sec_portal or not sec_target_iqn:
            raise RuntimeError(
                f"Cannot determine secondary iSCSI portal or target IQN "
                f"(portal={sec_portal!r}, iqn={sec_target_iqn!r})")

        jlog.log(f"Connecting host to secondary iSCSI {sec_portal} / {sec_target_iqn} …")
        connect_iscsi_target(pve_host, pve_user, pve_pass, pve_key,
                             sec_portal, sec_target_iqn)

        lun_info          = secondary_client.get_lun(temp_lun_uuid)
        temp_iscsi_serial = lun_info.get("serial_number", "")
        if not temp_iscsi_serial:
            raise RuntimeError("Cannot determine serial number of clone LUN on secondary")

        jlog.log(f"Waiting for clone device (serial: {temp_iscsi_serial}) …")
        device = find_device_by_serial(
            pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial, timeout_s=90)
        jlog.log(f"Clone device: {device}")
        _set_progress(db, job_id, 42)

        # ── 5. vgimportclone → temp VG, dd LVs ──────────────────────────────
        jlog.log(f"Importing clone VG from {device} …")
        temp_vg_name = vg_import_clone(pve_host, pve_user, pve_pass, pve_key,
                                       device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")
        _set_progress(db, job_id, 50)

        total = len(disks)
        jlog.log(f"Restoring {total} disk(s) for VM {vmid} …")
        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk.get("file", "")
            src_lv   = os.path.basename(old_file.split(":")[-1]) if old_file else ""
            if not src_lv:
                jlog.log(f"  [{i}/{total}] skipping disk with no file path")
                continue

            jlog.log(f"  [{i}/{total}] restoring {src_lv} …")
            activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                    temp_vg_name, src_lv, lvm_type, pool_name)

            dst_size = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                         vg_name, src_lv)
            if not dst_size:
                src_size = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                              temp_vg_name, src_lv)
                if not src_size:
                    raise RuntimeError(f"Cannot determine size for {temp_vg_name}/{src_lv}")
                jlog.log(f"  Creating {vg_name}/{src_lv} ({src_size} B) …")
                create_lv(pve_host, pve_user, pve_pass, pve_key,
                          vg_name, src_lv, src_size, lvm_type, pool_name)
            else:
                # PVE deactivates LVs on VM stop — re-activate before dd
                activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                        vg_name, src_lv, lvm_type, pool_name)

            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, src_lv, jlog)
            _set_progress(db, job_id, 50 + int(i / max(total, 1) * 30))

        # ── 6. Cleanup: temp VG, iSCSI session, temp igroup + clone volume ───
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""
        _set_progress(db, job_id, 83)

        jlog.log("Flushing clone device and disconnecting from secondary …")
        flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
        temp_iscsi_serial = ""
        disconnect_iscsi_target(pve_host, pve_user, pve_pass, pve_key,
                                sec_portal, sec_target_iqn)
        sec_portal = sec_target_iqn = ""

        jlog.log("Removing temporary igroup and clone volume on secondary …")
        try:
            secondary_client.delete_igroup(temp_igroup_uuid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI: delete temp igroup: {exc}")
        temp_igroup_uuid = ""

        try:
            secondary_client.unmount_volume(temp_clone_vol_uuid)
        except Exception:
            pass
        try:
            del_job = secondary_client.delete_volume(temp_clone_vol_uuid)
            if del_job:
                secondary_client.poll_job(del_job, timeout_s=120)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI: delete clone volume: {exc}")
        temp_clone_vol_uuid = ""
        _set_progress(db, job_id, 88)

        # Refresh primary VG after clone cleanup
        try:
            vg_rescan_and_activate(pve_host, pve_user, pve_pass, pve_key, vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI: vg rescan after cleanup: {exc}")

        # ── 7. Restore config + start VM ─────────────────────────────────────
        if snap_row:
            jlog.log("Restoring VM config …")
            _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                            pve_host, pve_user, pve_pass, pve_key)
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        _dr_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                          pve_host, pve_user, pve_pass, pve_key,
                          temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn)
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] DR iSCSI restore job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        _dr_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                          pve_host, pve_user, pve_pass, pve_key,
                          temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn)
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _finish_job(db, job_id)
    jlog.log(f"DR iSCSI restore for {vm_type.upper()} {vmid} completed.")


def _dr_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                      pve_host, pve_user, pve_pass, pve_key,
                      temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn):
    """Best-effort cleanup after DR iSCSI restore error or cancel."""
    from .san_helpers import (cleanup_restore_vg, flush_iscsi_clone_device,
                               disconnect_iscsi_target)
    if temp_vg_name and pve_host:
        try:
            cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI cleanup VG: {exc}")
    if temp_iscsi_serial and pve_host:
        flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
    if sec_portal and sec_target_iqn and pve_host:
        disconnect_iscsi_target(pve_host, pve_user, pve_pass, pve_key,
                                sec_portal, sec_target_iqn)
    if secondary_client and temp_igroup_uuid:
        try:
            secondary_client.delete_igroup(temp_igroup_uuid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI cleanup igroup: {exc}")
    if secondary_client and temp_clone_vol_uuid:
        try:
            secondary_client.unmount_volume(temp_clone_vol_uuid)
        except Exception:
            pass
        try:
            del_job = secondary_client.delete_volume(temp_clone_vol_uuid)
            if del_job:
                secondary_client.poll_job(del_job, timeout_s=60)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR iSCSI cleanup clone volume: {exc}")


def _run_restore_dr_nvme(job_id, params, username, db, jlog, mapping):
    """
    DR restore for NVMe-oF datastores from SnapMirror® secondary.

    Flow:
      1. Load manifest from DB, stop VM
      2. FlexClone from SnapMirror snapshot on secondary
      3. Create temp NVMe subsystem on secondary, add host NQN, map clone namespace
      4. NVMe connect from PVE host to secondary portals
      5. vgimportclone → temp VG, dd LVs to primary VG
      6. Cleanup: deactivate temp VG, disconnect NVMe, delete temp subsystem + clone volume
      7. Restore VM config, start VM
    """
    from ._helpers import get_endpoint, build_ontap_client, get_ssh_creds
    from .san_helpers import (nvme_list_devices, find_new_nvme_device,
                               nvme_connect_to_subsystem, nvme_disconnect_by_subsystem_name,
                               vg_import_clone, activate_lv_for_restore, lv_copy,
                               cleanup_restore_vg, get_lv_size_bytes, create_lv,
                               vg_rescan_and_activate, get_nvme_host_nqn)

    relationship_id = params["relationship_id"]
    snap_name       = params["snap_name"]
    vmid            = int(params["vmid"])
    vm_type         = params.get("vm_type", "qemu")

    vg_name   = mapping["lvm_vg_name"]
    lvm_type  = mapping.get("lvm_type", "linear")
    pool_name = mapping.get("lvm_pool_name", "")

    secondary_client    = None
    temp_ns_uuid        = ""
    temp_clone_vol_uuid = ""
    temp_subsystem_uuid = ""
    temp_subsystem_name = ""
    temp_vg_name        = ""
    pve_host = pve_user = pve_pass = pve_key = ""

    try:
        rel = db.query_one(
            "SELECT * FROM netapp_snapmirror_relationships WHERE id=?",
            (relationship_id,)
        )
        if not rel:
            raise RuntimeError(f"SnapMirror relationship '{relationship_id}' not found")
        rel = dict(rel)
        if not rel.get("dest_endpoint_id") or not rel.get("dest_volume_uuid"):
            raise RuntimeError(
                "Secondary endpoint or volume UUID missing — run SnapMirror scan first.")

        secondary_ep     = get_endpoint(db, rel["dest_endpoint_id"])
        secondary_client = build_ontap_client(secondary_ep)
        dest_svm         = rel["dest_svm"]
        dest_vol_uuid    = rel["dest_volume_uuid"]

        mgr = build_pve_client(db, mapping["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        node = ""
        try:
            node = mgr.find_vm_node(vmid) or ""
        except Exception:
            pass
        pve_host = _resolve_node_host(mgr, node) or mgr.host

        poll_cfg      = load_plugin_config()
        poll_interval = poll_cfg.get("job_poll_interval_s", 3)
        poll_timeout  = poll_cfg.get("job_poll_timeout_s", 300)

        # ── 1. Manifest + stop VM ────────────────────────────────────────────
        snap_row = db.query_one(
            "SELECT * FROM netapp_snapshots WHERE mapping_id=? AND snap_name=? "
            "ORDER BY created_at DESC LIMIT 1",
            (mapping["id"], snap_name),
        )
        if snap_row:
            snap     = dict(snap_row)
            manifest = _load_manifest(snap, mapping, node, mgr,
                                      pve_host, pve_user, pve_pass, pve_key)
            vm_type  = json.loads(snap.get("vm_types_json") or "{}").get(str(vmid), vm_type)
        else:
            jlog.log("Snapshot record not found in DB — will restore all LVs found in clone VG.")
            manifest = {"vms": [{"vmid": vmid, "disks": [], "vm_type": vm_type}]}

        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks    = vm_entry.get("disks", [])
        vm_type  = vm_entry.get("vm_type", vm_type)

        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)
        _ensure_vmid_placeholder(pve_host, pve_user, pve_pass, pve_key, vmid, vm_type)
        _set_progress(db, job_id, 10)

        # ── 2. FlexClone from SnapMirror snapshot on secondary ───────────────
        temp_clone_name = f"pgxdrclone_{job_id[:8]}"
        jlog.log(f"Cloning volume from secondary snapshot '{snap_name}' …")
        temp_ns_uuid, temp_clone_vol_uuid = secondary_client.clone_namespace_from_snapshot(
            dest_vol_uuid, snap_name, dest_svm, temp_clone_name,
            poll_interval=poll_interval, poll_timeout=poll_timeout,
        )
        jlog.log(f"Secondary clone volume created: {temp_clone_name}")
        _set_progress(db, job_id, 22)

        # ── 3. Temp NVMe subsystem on secondary, map clone namespace ─────────
        jlog.log("Getting host NQN …")
        host_nqn = get_nvme_host_nqn(pve_host, pve_user, pve_pass, pve_key)
        if not host_nqn:
            raise RuntimeError(f"Cannot determine NVMe NQN of PVE host {pve_host}")

        temp_subsystem_name = f"pgxdr_{job_id[:8]}"
        jlog.log(f"Creating temporary NVMe subsystem '{temp_subsystem_name}' on secondary …")
        temp_subsystem_uuid = secondary_client.create_nvme_subsystem(
            dest_svm, temp_subsystem_name)
        secondary_client.add_nvme_host_to_subsystem(temp_subsystem_uuid, host_nqn)
        secondary_client.add_nvme_namespace_to_subsystem(
            temp_subsystem_uuid, temp_ns_uuid, svm_name=dest_svm)
        jlog.log("Clone namespace mapped to temporary subsystem.")
        _set_progress(db, job_id, 32)

        # ── 4. NVMe connect PVE host → secondary ─────────────────────────────
        sec_lif_ips = [ip for ip in secondary_client.get_nvme_lifs_for_svm(dest_svm) if ip]
        if not sec_lif_ips:
            raise RuntimeError(
                f"No NVMe/TCP data LIF found on secondary SVM '{dest_svm}'")

        sub_info      = secondary_client.get_nvme_subsystem(temp_subsystem_uuid)
        subsystem_nqn = sub_info.get("target_nqn", "")

        devices_before = nvme_list_devices(pve_host, pve_user, pve_pass, pve_key)

        if subsystem_nqn:
            jlog.log(f"Connecting host to secondary NVMe portals {sec_lif_ips} …")
            nvme_connect_to_subsystem(pve_host, pve_user, pve_pass, pve_key,
                                      sec_lif_ips, subsystem_nqn)
        else:
            jlog.log("WARNING: subsystem NQN unavailable from API — skipping direct connect; "
                     "waiting for auto-discovery")

        jlog.log("Waiting for clone namespace device …")
        device = find_new_nvme_device(
            pve_host, pve_user, pve_pass, pve_key, devices_before, timeout_s=60)
        jlog.log(f"Clone device: {device}")
        _set_progress(db, job_id, 42)

        # ── 5. vgimportclone → temp VG, dd LVs ──────────────────────────────
        jlog.log(f"Importing clone VG from {device} …")
        temp_vg_name = vg_import_clone(pve_host, pve_user, pve_pass, pve_key,
                                       device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")
        _set_progress(db, job_id, 50)

        total = len(disks)
        jlog.log(f"Restoring {total} disk(s) for VM {vmid} …")
        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk.get("file", "")
            src_lv   = os.path.basename(old_file.split(":")[-1]) if old_file else ""
            if not src_lv:
                jlog.log(f"  [{i}/{total}] skipping disk with no file path")
                continue

            jlog.log(f"  [{i}/{total}] restoring {src_lv} …")
            activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                    temp_vg_name, src_lv, lvm_type, pool_name)

            dst_size = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                         vg_name, src_lv)
            if not dst_size:
                src_size = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                              temp_vg_name, src_lv)
                if not src_size:
                    raise RuntimeError(f"Cannot determine size for {temp_vg_name}/{src_lv}")
                jlog.log(f"  Creating {vg_name}/{src_lv} ({src_size} B) …")
                create_lv(pve_host, pve_user, pve_pass, pve_key,
                          vg_name, src_lv, src_size, lvm_type, pool_name)
            else:
                # PVE deactivates LVs on VM stop — re-activate before dd
                activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                        vg_name, src_lv, lvm_type, pool_name)

            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, src_lv, jlog)
            _set_progress(db, job_id, 50 + int(i / max(total, 1) * 30))

        # ── 6. Cleanup ────────────────────────────────────────────────────────
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""
        _set_progress(db, job_id, 83)

        jlog.log("Disconnecting NVMe session to secondary …")
        nvme_disconnect_by_subsystem_name(pve_host, pve_user, pve_pass, pve_key,
                                          temp_subsystem_name)

        jlog.log("Removing temporary NVMe subsystem and clone volume on secondary …")
        secondary_client.delete_nvme_subsystem(temp_subsystem_uuid)
        temp_subsystem_uuid = ""

        try:
            secondary_client.unmount_volume(temp_clone_vol_uuid)
        except Exception:
            pass
        try:
            del_job = secondary_client.delete_volume(temp_clone_vol_uuid)
            if del_job:
                secondary_client.poll_job(del_job, timeout_s=120)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe: delete clone volume: {exc}")
        temp_clone_vol_uuid = ""
        _set_progress(db, job_id, 88)

        try:
            vg_rescan_and_activate(pve_host, pve_user, pve_pass, pve_key, vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe: vg rescan after cleanup: {exc}")

        # ── 7. Restore config + start VM ─────────────────────────────────────
        if snap_row:
            jlog.log("Restoring VM config …")
            _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                            pve_host, pve_user, pve_pass, pve_key)
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        _dr_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                         pve_host, pve_user, pve_pass, pve_key,
                         temp_vg_name, temp_subsystem_name)
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] DR NVMe restore job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        _dr_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                         pve_host, pve_user, pve_pass, pve_key,
                         temp_vg_name, temp_subsystem_name)
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _finish_job(db, job_id)
    jlog.log(f"DR NVMe restore for {vm_type.upper()} {vmid} completed.")


def _dr_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                     pve_host, pve_user, pve_pass, pve_key,
                     temp_vg_name, temp_subsystem_name):
    """Best-effort cleanup after DR NVMe restore error or cancel."""
    from .san_helpers import cleanup_restore_vg, nvme_disconnect_by_subsystem_name
    if temp_vg_name and pve_host:
        try:
            cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe cleanup VG: {exc}")
    if temp_subsystem_name and pve_host:
        try:
            nvme_disconnect_by_subsystem_name(pve_host, pve_user, pve_pass, pve_key,
                                              temp_subsystem_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe cleanup disconnect: {exc}")
    if secondary_client and temp_subsystem_uuid:
        secondary_client.delete_nvme_subsystem(temp_subsystem_uuid)
    if secondary_client and temp_clone_vol_uuid:
        try:
            secondary_client.unmount_volume(temp_clone_vol_uuid)
        except Exception:
            pass
        try:
            del_job = secondary_client.delete_volume(temp_clone_vol_uuid)
            if del_job:
                secondary_client.poll_job(del_job, timeout_s=60)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe cleanup clone volume: {exc}")


# ── DR restore (mount secondary volume directly) ───────────────────────────────

def _run_restore_dr(job_id, params, username):
    """
    Restore from SnapMirror® secondary volume.
    NFS: mounts DP volume read-only, copies files from .snapshot/{snap_name}/.
    iSCSI: FlexClone on secondary, single-path iSCSI connect, dd LVs, cleanup.
    """
    db = get_db()
    jlog = JobLogger(job_id, db)

    mapping_id = params["mapping_id"]
    from ._helpers import get_mapping
    mapping = get_mapping(db, mapping_id)
    protocol = mapping.get("storage_protocol", "nfs")

    if protocol == "iscsi":
        _run_restore_dr_iscsi(job_id, params, username, db, jlog, mapping)
        return

    if protocol == "nvme":
        _run_restore_dr_nvme(job_id, params, username, db, jlog, mapping)
        return

    relationship_id = params["relationship_id"]
    snap_name = params["snap_name"]
    vmid = int(params["vmid"])
    cfg = load_plugin_config()
    dr_mount_base = cfg.get("flexclone_mount_base", "/mnt/pegaprox-clone")

    dr_mount_point = None

    try:
        from .snapmirror import ensure_secondary_nfs_export

        mgr = build_pve_client(db, mapping["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        pve_host = _resolve_node_host(mgr, "")

        # ── VM stoppen ────────────────────────────────────────────────
        node = ""
        try:
            node = mgr.find_vm_node(vmid) or ""
        except Exception:
            pass
        if not pve_host:
            pve_host = mgr.host

        vm_types = {}
        vm_type = params.get("vm_type", "qemu")
        jlog.log(f"Stopping {vm_type.upper()} {vmid} …")
        _vm_stop(mgr, node, vmid, vm_type)
        _ensure_vmid_placeholder(pve_host, pve_user, pve_pass, pve_key, vmid, vm_type)

        # ── Ensure NFS export ─────────────────────────────────────────
        jlog.log("Checking NFS export on secondary system …")
        nfs_ip, junction_path, created = ensure_secondary_nfs_export(db, relationship_id)
        if created:
            jlog.log("NFS export rule created.")
        if not nfs_ip or not junction_path:
            raise RuntimeError(
                "Secondary volume has no NFS IP or junction path. "
                "Check prerequisites in README."
            )

        # ── Mount secondary volume ─────────────────────────────────────
        dr_mount_point = f"{dr_mount_base}/dr-{job_id[:8]}"
        nfs_src = f"{nfs_ip}:{junction_path}"
        jlog.log(f"Mounting secondary volume {nfs_src} at {pve_host}:{dr_mount_point} …")
        ssh_run(pve_host, pve_user, pve_pass,
                f"mkdir -p {shlex.quote(dr_mount_point)}",
                key_material=pve_key)
        ssh_run(pve_host, pve_user, pve_pass,
                f"mount -t nfs -o ro,soft,timeo=30 "
                f"{shlex.quote(nfs_src)} {shlex.quote(dr_mount_point)}",
                key_material=pve_key)
        _set_progress(db, job_id, 20)

        # ── Manifest lesen ────────────────────────────────────────────
        manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
        snap_base = f"{dr_mount_point}/.snapshot/{snap_name}"
        manifest_path = f"{snap_base}/{manifest_subdir}/{snap_name}/manifest.json"

        jlog.log("Reading manifest …")
        try:
            out = ssh_run(pve_host, pve_user, pve_pass,
                          f"cat {shlex.quote(manifest_path)}",
                          capture=True, key_material=pve_key)
            import json as _json
            manifest = _json.loads(out)
        except Exception:
            manifest = {"vms": [{"vmid": vmid, "disks": [], "vm_type": vm_type}]}
            jlog.log("Manifest not found — searching for disk files automatically.")

        vm_entry = _find_vm_in_manifest(manifest, vmid)
        disks = vm_entry.get("disks", [])
        vm_type = vm_entry.get("vm_type", vm_type)
        target_base = mapping["nfs_mount_path"]

        # ── Disk-Dateien kopieren ─────────────────────────────────────
        total = len(disks)
        if total == 0:
            jlog.log("No disks in manifest — searching .snapshot directory …")
            try:
                find_cmd = (
                    f"find {shlex.quote(snap_base + '/images')} "
                    f"-name '*.qcow2' -o -name '*.raw' 2>/dev/null | head -20"
                )
                out = ssh_run(pve_host, pve_user, pve_pass, find_cmd, capture=True, key_material=pve_key)
                found_files = [l.strip() for l in out.splitlines() if l.strip()]
                disks = [{"file": f.replace(snap_base + "/images/", "")} for f in found_files]
                total = len(disks)
            except Exception:
                pass

        jlog.log(f"{total} Disk(s) being copied from secondary system …")
        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            file_path = disk["file"]
            src = f"{snap_base}/images/{file_path.lstrip('/')}"
            dst = f"{target_base}/images/{file_path.lstrip('/')}"
            jlog.log(f"  [{i}/{total}] {file_path}")
            ssh_run(pve_host, pve_user, pve_pass,
                    f"mkdir -p {shlex.quote(os.path.dirname(dst))}",
                    key_material=pve_key)
            if vm_type == "qemu":
                ssh_run(pve_host, pve_user, pve_pass,
                        f"qemu-img convert -p -O qcow2 {shlex.quote(src)} {shlex.quote(dst)}",
                        timeout=3600, key_material=pve_key)
            else:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"cp --sparse=always {shlex.quote(src)} {shlex.quote(dst)}",
                        timeout=3600, key_material=pve_key)
            _set_progress(db, job_id, 20 + int(i / max(total, 1) * 65))

        # ── Config + Rescan + Start ───────────────────────────────────
        jlog.log("Restoring VM config …")
        conf_src = f"{snap_base}/{manifest_subdir}/{snap_name}/{vmid}.conf"
        conf_dir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_dst = f"/etc/pve/{conf_dir}/{vmid}.conf"
        try:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"cp {shlex.quote(conf_src)} {shlex.quote(conf_dst)}",
                    key_material=pve_key)
        except Exception:
            jlog.log("Config file not found on secondary — skipped.")

        _set_progress(db, job_id, 88)
        _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
    except Exception as exc:
        log.error(f"[netapp_storage] DR restore job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")

    finally:
        if dr_mount_point and pve_host:
            try:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"umount -f {shlex.quote(dr_mount_point)} 2>/dev/null || true",
                        key_material=pve_key)
                ssh_run(pve_host, pve_user, pve_pass,
                        f"rmdir {shlex.quote(dr_mount_point)} 2>/dev/null || true",
                        key_material=pve_key)
            except Exception as e:
                log.warning(f"[netapp_storage] DR cleanup unmount failed: {e}")
        _reg_unregister(job_id)

    if not _job_failed(db, job_id):
        _finish_job(db, job_id)
        jlog.log(f"DR restore for {vm_type.upper()} {vmid} completed.")


def _flexclone_cleanup(job_id, clone_mount_point, clone_vol_uuid, snap, jlog, db):
    """Unmount and delete FlexClone. Always call in finally block."""
    pve_host, pve_user, pve_pass, pve_key = "", "root", "", ""
    if snap:
        try:
            mgr = build_pve_client(db, snap["pve_cluster_id"])
            pve_host = _resolve_node_host(mgr, snap.get("node", ""))
            pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        except Exception:
            pass

    if clone_mount_point and pve_host:
        try:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"umount -f {shlex.quote(clone_mount_point)} 2>/dev/null || true",
                    key_material=pve_key)
            ssh_run(pve_host, pve_user, pve_pass,
                    f"rmdir {shlex.quote(clone_mount_point)} 2>/dev/null || true",
                    key_material=pve_key)
        except Exception as e:
            log.warning(f"[netapp_storage] cleanup unmount failed: {e}")

    if clone_vol_uuid and snap:
        try:
            mapping = get_mapping(db, snap["mapping_id"])
            endpoint = get_endpoint(db, mapping["endpoint_id"])
            client = build_ontap_client(endpoint)
            client.unmount_volume(clone_vol_uuid)
            del_job = client.delete_volume(clone_vol_uuid)
            if del_job:
                client.poll_job(del_job, timeout_s=120)
            jlog.log("FlexClone deleted.")
        except Exception as e:
            log.warning(f"[netapp_storage] clone deletion failed: {e}")


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _resolve_node_host(mgr, node_name):
    if not mgr:
        return node_name or ""
    try:
        r = mgr._api_get(f"{mgr._base}/cluster/status")
        if r.ok:
            for item in r.json().get("data", []):
                if item.get("type") == "node" and item.get("name") == node_name:
                    ip = item.get("ip", "")
                    if ip:
                        return ip
    except Exception:
        pass
    return getattr(mgr, "host", None) or node_name or ""


def _vm_stop(mgr, node, vmid, vm_type="qemu"):
    vt = "qemu" if vm_type == "qemu" else "lxc"
    port = getattr(mgr, "port", 8006)
    try:
        r = mgr._api_get(
            f"https://{mgr.host}:{port}/api2/json/nodes/{node}/{vt}/{vmid}/status/current"
        )
        if not r.ok:
            return  # VM does not exist
        if r.json().get("data", {}).get("status") == "stopped":
            return
    except Exception:
        return
    try:
        mgr._api_post(f"https://{mgr.host}:{port}/api2/json/nodes/{node}/{vt}/{vmid}/status/stop")
        for _ in range(30):
            time.sleep(2)
            r = mgr._api_get(
                f"https://{mgr.host}:{port}/api2/json/nodes/{node}/{vt}/{vmid}/status/current"
            )
            if r.ok and r.json().get("data", {}).get("status") == "stopped":
                return
    except Exception as e:
        log.warning(f"[netapp_storage] VM-Stop {vmid}: {e}")


def _vm_start(mgr, node, vmid, vm_type="qemu"):
    try:
        vt = "qemu" if vm_type == "qemu" else "lxc"
        port = getattr(mgr, "port", 8006)
        mgr._api_post(f"https://{mgr.host}:{port}/api2/json/nodes/{node}/{vt}/{vmid}/status/start")
    except Exception as e:
        log.warning(f"[netapp_storage] VM-Start {vmid}: {e}")


def _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key):
    """Read the manifest — exact NFS path, then DB fallback, then search in .snapshot directory."""
    manifest_path = snap.get("manifest_path", "")

    # SAN snapshots: manifest is on the snapmanifest LV but always also in the DB.
    # Read from DB directly (snapmanifest LV inaccessible after volume revert).
    # Accept snapmanifest: (current), snapmeta: and snapinfo: (legacy) for compat.
    if (manifest_path.startswith("snapmanifest:") or manifest_path.startswith("snapmeta:")
            or manifest_path.startswith("snapinfo:")
            or manifest_path.startswith("db:") or not manifest_path):
        manifest_json = snap.get("manifest_json", "")
        if manifest_json:
            return json.loads(manifest_json)
        raise RuntimeError("Manifest not available (not on NFS/snapmanifest or in DB)")

    # NFS via SSH — exact path (normal plugin snapshots)
    try:
        out = ssh_run(pve_host, pve_user, pve_pass,
                      f"cat {shlex.quote(manifest_path)}",
                      capture=True, key_material=pve_key)
        return json.loads(out)
    except Exception as ssh_err:
        log.warning(f"[netapp_storage] manifest exact path failed: {ssh_err}")

    # DB fallback
    manifest_json = snap.get("manifest_json", "")
    if manifest_json:
        return json.loads(manifest_json)

    # Search for most recent manifest in .snapshot directory.
    # Useful for ONTAP-native snapshots (hourly.0, daily.0 etc.) that contain
    # all PegaProx manifests present at that time.
    snap_manifest_dir = os.path.dirname(os.path.dirname(manifest_path))
    if "/.snapshot/" in snap_manifest_dir:
        try:
            out = ssh_run(pve_host, pve_user, pve_pass,
                          f"find {shlex.quote(snap_manifest_dir)} -name manifest.json 2>/dev/null "
                          f"| sort | tail -1",
                          capture=True, key_material=pve_key)
            found = out.strip()
            if found:
                out2 = ssh_run(pve_host, pve_user, pve_pass,
                               f"cat {shlex.quote(found)}",
                               capture=True, key_material=pve_key)
                log.info(f"[netapp_storage] Manifest found via search: {found}")
                return json.loads(out2)
        except Exception as find_err:
            log.warning(f"[netapp_storage] manifest search failed: {find_err}")

    raise RuntimeError(f"Manifest not found in: {snap_manifest_dir}")


def _find_vm_in_manifest(manifest, vmid):
    for entry in manifest.get("vms", []):
        if entry.get("vmid") == vmid:
            return entry
    raise RuntimeError(f"VM {vmid} not found in snapshot manifest")


def _ensure_vmid_placeholder(pve_host, pve_user, pve_pass, pve_key, vmid, vm_type):
    """Creates a minimal .conf to lock the VMID in PVE before disk copy starts.

    PVE reserves a VMID as soon as a config file exists — even a stub prevents
    auto-assignment of the same ID to a new VM during a long-running restore.
    No-op if the config file already exists (VM was just stopped, not deleted).
    """
    conf_dir = "qemu-server" if vm_type == "qemu" else "lxc"
    conf_path = shlex.quote(f"/etc/pve/{conf_dir}/{vmid}.conf")
    if vm_type == "qemu":
        placeholder = f"# restore in progress\nmemory: 512\ncores: 1\n"
    else:
        placeholder = f"# restore in progress\nhostname: restore-{vmid}\nmemory: 512\nostype: unmanaged\n"
    try:
        # Only write if no config exists yet (VM was deleted before DR restore)
        ssh_run(pve_host, pve_user, pve_pass,
                f"[ -f {conf_path} ] || cat > {conf_path}",
                stdin_data=placeholder.encode(), key_material=pve_key, timeout=10)
        log.info(f"[netapp_storage] VMID {vmid} placeholder ensured")
    except Exception as exc:
        log.warning(f"[netapp_storage] VMID {vmid} placeholder failed: {exc}")


def _restore_config(snap, mapping, vmid, vm_type, node, mgr,
                    pve_host, pve_user, pve_pass, pve_key):
    """Writes the saved config back to /etc/pve/{qemu-server|lxc}/<vmid>.conf."""
    manifest_path = snap.get("manifest_path", "")

    if (manifest_path.startswith("db:") or manifest_path.startswith("snapmanifest:")
            or manifest_path.startswith("snapmeta:") or manifest_path.startswith("snapinfo:")
            or not manifest_path):
        # Reconstruct from DB manifest and write directly
        manifest = json.loads(snap.get("manifest_json", "{}"))
        vm_entry = _find_vm_in_manifest(manifest, vmid)
        # Use the original config from the manifest
        conf_data = _conf_from_manifest_entry(vm_entry)
        conf_dir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_dst = f"/etc/pve/{conf_dir}/{vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_dst)}",
                stdin_data=conf_data.encode(), key_material=pve_key)
    else:
        conf_src = manifest_path.replace("manifest.json", f"{vmid}.conf")
        conf_dir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_dst = f"/etc/pve/{conf_dir}/{vmid}.conf"
        try:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"cp {shlex.quote(conf_src)} {shlex.quote(conf_dst)}",
                    key_material=pve_key)
        except Exception:
            # Fallback: reconstruct from DB manifest
            manifest = json.loads(snap.get("manifest_json", "{}"))
            vm_entry = _find_vm_in_manifest(manifest, vmid)
            conf_data = _conf_from_manifest_entry(vm_entry)
            ssh_run(pve_host, pve_user, pve_pass,
                    f"cat > {shlex.quote(conf_dst)}",
                    stdin_data=conf_data.encode(), key_material=pve_key)


_CONF_SKIP_KEYS = {"digest"}  # PVE adds digest but does not accept it in .conf


def _conf_from_manifest_entry(vm_entry):
    """Reconstructs .conf content from a manifest VM entry."""
    raw = vm_entry.get("raw_config", {})
    if raw:
        lines = []
        for k, v in sorted(raw.items()):
            if isinstance(v, (dict, list)) or k in _CONF_SKIP_KEYS:
                continue
            lines.append(f"{k}: {v}")
        return "\n".join(lines) + "\n"
    # Fallback for older snapshots without raw_config: disk lines only
    lines = []
    for disk in vm_entry.get("disks", []):
        lines.append(f"{disk['key']}: {disk['storage']}:{disk['file']}")
    return "\n".join(lines) + "\n"


def _rescan_and_start(mgr, node, vmid, vm_type, pve_host, pve_user, pve_pass, pve_key):
    """Run qm/pct rescan, then start the VM/CT."""
    try:
        if vm_type == "qemu":
            ssh_run(pve_host, pve_user, pve_pass,
                    f"qm rescan {vmid} 2>/dev/null || true", key_material=pve_key)
        else:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"pct rescan {vmid} 2>/dev/null || true", key_material=pve_key)
    except Exception as e:
        log.warning(f"[netapp_storage] rescan {vmid}: {e}")
    _vm_start(mgr, node, vmid, vm_type)


def _set_progress(db, job_id, pct):
    db.execute("UPDATE netapp_jobs SET progress_pct=? WHERE id=?", (pct, job_id))


def _finish_job(db, job_id):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE netapp_jobs SET status='done', progress_pct=100, completed_at=? WHERE id=?",
        (now, job_id),
    )


def _fail_job(db, job_id):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE netapp_jobs SET status='failed', completed_at=? WHERE id=?",
        (now, job_id),
    )


def _cancel_job(db, job_id):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE netapp_jobs SET status='cancelled', completed_at=? WHERE id=?",
        (now, job_id),
    )


def _job_failed(db, job_id):
    row = db.query_one("SELECT status FROM netapp_jobs WHERE id=?", (job_id,))
    return row and row["status"] == "failed"
