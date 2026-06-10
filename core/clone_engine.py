"""
NetApp ONTAP Clone Engine

Clones a VM from a volume snapshot:
  1. Read manifest from snapshot
  2. Clone disk files via ONTAP File Clone API (CoW, POST /api/storage/file/clone)
  3. Write new VM config to Proxmox (SSH)
  4. Optionally start the VM
"""

import json
import re
import os
import shlex
import random
import logging
import threading
from datetime import datetime, timezone

from pegaprox.core.db import get_db

from ._helpers import (
    load_plugin_config, get_endpoint, get_mapping, get_snapshot_record,
    build_ontap_client, build_pve_client,
    get_ssh_creds, ssh_run, JobLogger, JobCancelledError, check_cancel,
)
from ._job_registry import register as _reg_register, unregister as _reg_unregister
from .restore_engine import (
    _load_manifest, _find_vm_in_manifest, _vm_start,
    _set_progress as _re_set_progress, _finish_job as _re_finish_job,
    _fail_job as _re_fail_job, _job_failed as _re_job_failed,
    _resolve_node_host as _re_resolve_node_host,
)

log = logging.getLogger(__name__)

_CONF_SKIP = {"digest"}
_DISK_KEYS = ("scsi", "virtio", "ide", "sata", "efidisk", "tpmstate", "rootfs", "mp")


def start_clone_job(job_id, params, username):
    t = threading.Thread(target=_run_clone, args=(job_id, params, username), daemon=True)
    t.start()
    _reg_register(job_id, t)


def start_clone_san_job(job_id, params, username):
    t = threading.Thread(target=_run_clone_san, args=(job_id, params, username), daemon=True)
    t.start()
    _reg_register(job_id, t)


def _run_clone(job_id, params, username):
    db = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id      = params["snapshot_id"]
    src_vmid         = int(params["src_vmid"])
    new_vmid         = int(params["new_vmid"])
    target_node      = params.get("target_node", "")
    new_name         = params.get("new_name", "")
    start_after      = bool(params.get("start_after", False))
    network_isolated = bool(params.get("network_isolated", False))

    conf_path_reserved = ""
    pve_host = ""
    pve_user = "root"
    pve_pass = ""
    pve_key  = ""

    try:
        snap    = get_snapshot_record(db, snapshot_id)
        mapping = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client  = build_ontap_client(endpoint)

        mgr  = build_pve_client(db, snap["pve_cluster_id"])
        node = snap["node"] or ""
        if not node:
            try:
                node = mgr.find_vm_node(src_vmid) or target_node
            except Exception:
                node = target_node

        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        eff_node = target_node or node
        pve_host = _resolve_node_host(mgr, eff_node)

        vm_types = json.loads(snap.get("vm_types_json") or "{}")
        vm_type  = vm_types.get(str(src_vmid), "qemu")

        # ── Manifest lesen ─────────────────────────────────────────────
        jlog.log("Reading manifest …")
        manifest = _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key)
        vm_entry = _find_vm_in_manifest(manifest, src_vmid)
        disks    = vm_entry.get("disks", [])
        snap_name = snap["snap_name"]

        if not disks:
            raise RuntimeError(f"No disks in manifest for VM {src_vmid}")

        # ── Reserve VMID before long disk operation ────────────────────
        conf_path_reserved = _reserve_vmid(
            pve_host, pve_user, pve_pass, pve_key, new_vmid, vm_type, jlog)

        # ── Create target directory ────────────────────────────────────
        target_dir = f"{mapping['nfs_mount_path']}/images/{new_vmid}"
        ssh_run(pve_host, pve_user, pve_pass,
                f"mkdir -p {shlex.quote(target_dir)}", key_material=pve_key)

        # ── Clone disks via ONTAP File Clone API (CoW) ────────────────
        check_cancel(job_id)
        jlog.log(f"File-Clone: {len(disks)} disk(s) for VM {src_vmid} → {new_vmid} …")
        poll_cfg = load_plugin_config()
        new_disk_map = {}

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk["file"]
            new_file = _remap_disk_path(old_file, src_vmid, new_vmid)
            src_path = f"images/{old_file.lstrip('/')}"
            dst_path = f"images/{new_file.lstrip('/')}"

            jlog.log(f"  [{i}/{len(disks)}] {os.path.basename(src_path)}"
                     f" → {os.path.basename(dst_path)}")
            job_uuid = client.clone_file(mapping["volume_uuid"], src_path, dst_path, snap_name)
            if job_uuid:
                client.poll_job(
                    job_uuid,
                    interval_s=poll_cfg.get("job_poll_interval_s", 3),
                    timeout_s=poll_cfg.get("job_poll_timeout_s", 300),
                )
            new_disk_map[old_file] = new_file

        _set_progress(db, job_id, 70)

        # ── Build and write new VM config ──────────────────────────────
        eff_name = new_name or f"clone-{vm_entry.get('name', src_vmid)}"
        jlog.log(f"Building VM config … (name: {eff_name!r})")
        raw_conf = vm_entry.get("raw_config", {})
        conf_str = _build_clone_config(
            raw_conf, src_vmid, new_vmid,
            mapping["pve_storage_id"], new_disk_map,
            eff_name, vm_type,
            network_isolated=network_isolated,
        )
        name_key = "hostname" if vm_type == "lxc" else "name"
        conf_lines = [l for l in conf_str.splitlines() if not l.startswith(f"{name_key}:")]
        conf_lines.append(f"{name_key}: {eff_name}")
        conf_str = "\n".join(conf_lines) + "\n"

        conf_subdir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_path   = f"/etc/pve/{conf_subdir}/{new_vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_path)}",
                stdin_data=conf_str.encode(), key_material=pve_key)
        jlog.log(f"Config written: {conf_path}")

        if eff_name:
            safe_name = re.sub(r'[^a-zA-Z0-9\-\.]', '-', eff_name).strip('-') or f"vm-{new_vmid}"
            if vm_type == "qemu":
                ssh_run(pve_host, pve_user, pve_pass,
                        f"qm set {new_vmid} --name {shlex.quote(safe_name)}",
                        key_material=pve_key)
            else:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"pct set {new_vmid} --hostname {shlex.quote(safe_name)}",
                        key_material=pve_key)

        _set_progress(db, job_id, 90)

        if start_after:
            jlog.log(f"Starting {vm_type.upper()} {new_vmid} …")
            _vm_start(mgr, eff_node, new_vmid, vm_type)

        _finish_job(db, job_id)
        jlog.log(f"Clone completed: {vm_type.upper()} {src_vmid} → {new_vmid}")

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        if conf_path_reserved and pve_host:
            try:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"rm -f {shlex.quote(conf_path_reserved)}", key_material=pve_key)
            except Exception:
                pass
    except Exception as exc:
        log.error(f"[netapp_storage] Clone job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        if conf_path_reserved and pve_host:
            try:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"rm -f {shlex.quote(conf_path_reserved)}", key_material=pve_key)
            except Exception:
                pass
    finally:
        _reg_unregister(job_id)


# ── SAN Clone ─────────────────────────────────────────────────────────────────

def _run_clone_san(job_id, params, username):
    """SAN Clone: clone a VM from an ONTAP snapshot via LUN/namespace copy.

    Flow:
      1. Read manifest from DB
      2. Clone LUN (iSCSI) or namespace (NVMe-oF) from the ONTAP snapshot
      3. Map clone to PVE host, rescan, import as temp VG (vgimportclone)
      4. For each disk: create new LV in main VG, dd copy from temp VG
      5. Deactivate + delete temp clone LUN/namespace
      6. Write VM config (remapped VMID), start if requested
    """
    db   = get_db()
    jlog = JobLogger(job_id, db)

    snapshot_id      = params["snapshot_id"]
    src_vmid         = int(params["src_vmid"])
    new_vmid         = int(params["new_vmid"])
    target_node      = params.get("target_node", "")
    new_name         = params.get("new_name", "")
    start_after      = bool(params.get("start_after", False))
    network_isolated = bool(params.get("network_isolated", False))

    temp_lun_uuid             = ""
    temp_iscsi_clone_vol_uuid = ""
    temp_iscsi_serial         = ""
    temp_ns_uuid              = ""
    temp_vg_name              = ""
    igroup_uuid               = ""
    temp_igroup_uuid          = ""
    subsystem_uuid            = ""
    conf_path_reserved     = ""
    pve_host  = ""
    pve_user  = "root"
    pve_pass  = ""
    pve_key   = ""
    protocol  = "iscsi"
    client    = None

    try:
        snap     = get_snapshot_record(db, snapshot_id)
        mapping  = get_mapping(db, snap["mapping_id"])
        endpoint = get_endpoint(db, mapping["endpoint_id"])
        client   = build_ontap_client(endpoint)

        mgr      = build_pve_client(db, snap["pve_cluster_id"])
        node     = snap.get("node") or target_node
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        eff_node = target_node or node
        pve_host = _resolve_node_host(mgr, eff_node)

        vm_types = json.loads(snap.get("vm_types_json") or "{}")
        vm_type  = vm_types.get(str(src_vmid), "qemu")

        vg_name   = mapping["lvm_vg_name"]
        lvm_type  = mapping.get("lvm_type", "linear")
        pool_name = mapping.get("lvm_pool_name", "")
        svm_name  = mapping["svm_name"]
        vol_uuid  = mapping["volume_uuid"]
        protocol  = mapping.get("storage_protocol", "iscsi")
        snap_name = snap["snap_name"]

        poll_cfg  = load_plugin_config()

        # ── 1. Read manifest from DB ───────────────────────────────────
        jlog.log("Reading manifest …")
        manifest_deferred = False
        vm_entry = None
        disks    = None

        try:
            manifest = _load_manifest(snap, mapping, node, mgr, pve_host, pve_user, pve_pass, pve_key)
            vm_entry = _find_vm_in_manifest(manifest, src_vmid)
            disks    = vm_entry.get("disks", [])
        except RuntimeError:
            # Native SAN snapshot: manifest not in DB. Will read from snapmanifest LV
            # inside the temp clone VG after vgimportclone (correct snapshot-time state).
            jlog.log("Manifest not in DB — will read from snapmanifest LV after import …")
            manifest_deferred = True

        _set_progress(db, job_id, 10)

        # ── 2. Resolve volume name ─────────────────────────────────────
        check_cancel(job_id)
        vol_info = client.get_volume(vol_uuid)
        vol_name = vol_info.get("name", "")
        if not vol_name:
            raise RuntimeError(f"Cannot resolve volume name for UUID {vol_uuid}")

        temp_clone_name = f"pgxclone_{job_id[:8]}"

        # ── 3a. iSCSI: clone LUN ───────────────────────────────────────
        if protocol == "iscsi":
            jlog.log(f"Cloning volume from snapshot '{snap_name}' (iSCSI) …")
            temp_lun_uuid, temp_iscsi_clone_vol_uuid = client.clone_lun_from_snapshot(
                vol_uuid, snap_name, svm_name, temp_clone_name,
                poll_interval=poll_cfg.get("job_poll_interval_s", 3),
                poll_timeout=poll_cfg.get("job_poll_timeout_s", 300),
            )
            jlog.log(f"Volume clone created: {temp_clone_name}")

            # Map clone LUN to a temporary single-host igroup so that other
            # PVE hosts sharing the same iSCSI igroup never see the clone LUN.
            # If the IQN cannot be fetched, fall back to the main igroup.
            lun_uuid = mapping.get("lun_uuid", "")
            existing_maps = client.list_lun_maps(lun_uuid=lun_uuid) if lun_uuid else []
            if not existing_maps:
                raise RuntimeError("No igroup mapping found for main LUN")
            main_igroup_uuid = existing_maps[0]["igroup"]["uuid"]
            igroup_uuid = main_igroup_uuid

            from .san_helpers import get_iscsi_initiator_iqn
            initiator_iqn = get_iscsi_initiator_iqn(pve_host, pve_user, pve_pass, pve_key)
            if initiator_iqn:
                temp_igroup_name = f"pgxclone-{job_id[:8]}"
                jlog.log(f"Creating temp igroup '{temp_igroup_name}' for {pve_host} only …")
                try:
                    temp_igroup_uuid = client.create_igroup(svm_name, temp_igroup_name, "iscsi")
                    client.add_igroup_initiator(temp_igroup_uuid, initiator_iqn)
                    igroup_uuid = temp_igroup_uuid
                except Exception as exc:
                    jlog.log(f"Temp igroup failed ({exc}) — using main igroup (all hosts see clone LUN) …")
                    if temp_igroup_uuid:
                        try:
                            client.delete_igroup(temp_igroup_uuid)
                        except Exception:
                            pass
                        temp_igroup_uuid = ""
                    igroup_uuid = main_igroup_uuid
            else:
                jlog.log("IQN not found — mapping clone LUN to main igroup …")

            jlog.log("Mapping clone LUN to iSCSI igroup …")
            client.map_lun(temp_lun_uuid, igroup_uuid, svm_name)

            # Rescan + find device by serial
            from .san_helpers import rescan_iscsi, find_device_by_serial
            jlog.log("Rescanning iSCSI sessions …")
            rescan_iscsi(pve_host, pve_user, pve_pass, pve_key)
            temp_lun_info    = client.get_lun(temp_lun_uuid)
            temp_serial      = temp_lun_info.get("serial_number", "")
            temp_iscsi_serial = temp_serial
            if not temp_serial:
                raise RuntimeError("Cannot determine serial number of clone LUN")
            jlog.log(f"Waiting for clone device (serial: {temp_serial}) …")
            device = find_device_by_serial(
                pve_host, pve_user, pve_pass, pve_key, temp_serial, timeout_s=60)

        # ── 3b. NVMe-oF: clone namespace ──────────────────────────────
        elif protocol == "nvme":
            jlog.log(f"Cloning NVMe namespace from snapshot '{snap_name}' …")
            from .san_helpers import (nvme_list_devices, nvme_ns_rescan,
                                      find_new_nvme_device)
            # Baseline captured before clone creation — CLI bridge on ASA maps the namespace
            # to the subsystem immediately, so we must snapshot devices before clone_namespace().
            devices_before = nvme_list_devices(pve_host, pve_user, pve_pass, pve_key)

            namespaces = client.list_nvme_namespaces(svm_name=svm_name)
            main_ns = next(
                (ns for ns in namespaces
                 if (ns.get("location") or {}).get("volume", {}).get("uuid") == vol_uuid),
                None,
            )
            if not main_ns:
                main_ns = next(
                    (ns for ns in namespaces
                     if (ns.get("location") or {}).get("volume", {}).get("name") == vol_name),
                    None,
                )
            if not main_ns:
                raise RuntimeError(
                    f"Cannot find NVMe namespace for volume {vol_uuid}. "
                    "Re-run discovery or check SVM."
                )
            main_ns_uuid = main_ns["uuid"]

            subsystem = client.get_nvme_subsystem_for_namespace(main_ns_uuid, svm_name=svm_name)
            if not subsystem:
                raise RuntimeError("No NVMe subsystem found for main namespace")
            subsystem_uuid = subsystem["uuid"]

            temp_ns_uuid, ns_job = client.clone_namespace(
                main_ns_uuid, snap_name, vol_name, temp_clone_name, svm_name
            )
            if ns_job:
                client.poll_job(ns_job,
                                interval_s=poll_cfg.get("job_poll_interval_s", 3),
                                timeout_s=poll_cfg.get("job_poll_timeout_s", 300))
            if not temp_ns_uuid:
                raise RuntimeError("clone_namespace returned no UUID — check ONTAP logs")
            jlog.log(f"Namespace clone created: {temp_clone_name}")

            # ASA volume clone inherits subsystem mapping — skip if already mapped
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
            raise RuntimeError(f"Unsupported SAN protocol for clone: {protocol}")

        jlog.log(f"Clone device: {device}")
        _set_progress(db, job_id, 30)

        # ── 4. vgimportclone → temp VG ────────────────────────────────
        check_cancel(job_id)
        jlog.log(f"Importing clone VG from {device} …")
        from .san_helpers import (vg_import_clone, activate_lv_for_restore,
                                  cleanup_restore_vg, get_lv_size_bytes, create_lv,
                                  lv_copy, snapmanifest_read_manifest)
        temp_vg_name = vg_import_clone(
            pve_host, pve_user, pve_pass, pve_key, device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")

        # ── 4b. Read manifest from snapmanifest LV (native snapshot) ──
        if manifest_deferred:
            jlog.log("Reading manifest from snapmanifest LV in clone VG …")
            try:
                manifest = snapmanifest_read_manifest(
                    pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
                vm_entry = _find_vm_in_manifest(manifest, src_vmid)
                disks    = vm_entry.get("disks", [])
                jlog.log(f"Manifest loaded: {len(disks)} disk(s) for VM {src_vmid}")
            except Exception as exc:
                # Last resort: read current VM config from PVE
                jlog.log(f"snapmanifest read failed ({exc}) — using current PVE VM config …")
                disks, vm_type, raw_cfg = _disks_from_pve(
                    mgr, src_vmid, mapping["pve_storage_id"], eff_node)
                vm_entry = {"vmid": src_vmid, "disks": disks,
                            "vm_type": vm_type, "name": str(src_vmid), "raw_config": raw_cfg}

        if not disks:
            raise RuntimeError(f"No disks found for VM {src_vmid}")

        # ── 4c. Reserve VMID before long disk copy ─────────────────────
        conf_path_reserved = _reserve_vmid(
            pve_host, pve_user, pve_pass, pve_key, new_vmid,
            vm_entry.get("vm_type", vm_type), jlog)

        # ── 5. For each disk: lvcreate + dd copy ──────────────────────
        check_cancel(job_id)
        total        = len(disks)
        new_disk_map = {}
        jlog.log(f"Copying {total} disk(s) for VM {src_vmid} → {new_vmid} …")

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk["file"]
            src_lv   = os.path.basename(old_file.split(":")[-1])
            new_lv   = _remap_disk_path(src_lv, src_vmid, new_vmid)
            new_disk_map[old_file] = new_lv

            jlog.log(f"  [{i}/{total}] {src_lv} → {new_lv}")

            # Activate source LV in temp VG
            activate_lv_for_restore(
                pve_host, pve_user, pve_pass, pve_key,
                temp_vg_name, src_lv, lvm_type, pool_name)

            # Get size from temp VG
            size_bytes = get_lv_size_bytes(
                pve_host, pve_user, pve_pass, pve_key, temp_vg_name, src_lv)
            if size_bytes == 0:
                raise RuntimeError(
                    f"Cannot determine size of {temp_vg_name}/{src_lv}")

            # Create target LV in main VG
            create_lv(pve_host, pve_user, pve_pass, pve_key,
                      vg_name, new_lv, size_bytes, lvm_type, pool_name)

            # Block copy
            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, new_lv, jlog)

            _set_progress(db, job_id, 30 + int(i / max(total, 1) * 50))

        # ── 6. Deactivate + remove temp VG ────────────────────────────
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""
        _set_progress(db, job_id, 82)

        # ── 7. Unmap + delete temp LUN/namespace ──────────────────────
        jlog.log("Removing temporary clone LUN/namespace …")
        _cleanup_san_clone(client, protocol,
                           temp_lun_uuid, igroup_uuid,
                           temp_ns_uuid, subsystem_uuid,
                           temp_iscsi_clone_vol_uuid, jlog,
                           temp_igroup_uuid=temp_igroup_uuid)
        if protocol == "iscsi" and temp_iscsi_serial and pve_host:
            from .san_helpers import flush_iscsi_clone_device
            flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
        temp_lun_uuid = temp_ns_uuid = temp_iscsi_clone_vol_uuid = temp_iscsi_serial = temp_igroup_uuid = ""

        # ── 8. Write VM config ─────────────────────────────────────────
        eff_name = new_name or f"san-clone-{vm_entry.get('name', src_vmid)}"
        jlog.log(f"Writing VM config … (name: {eff_name!r})")
        raw_conf = vm_entry.get("raw_config", {})
        conf_str = _build_clone_config(
            raw_conf, src_vmid, new_vmid,
            mapping["pve_storage_id"], new_disk_map,
            eff_name, vm_type,
            network_isolated=network_isolated,
        )
        name_key   = "hostname" if vm_type == "lxc" else "name"
        conf_lines = [l for l in conf_str.splitlines() if not l.startswith(f"{name_key}:")]
        conf_lines.append(f"{name_key}: {eff_name}")
        conf_str   = "\n".join(conf_lines) + "\n"

        conf_subdir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_path   = f"/etc/pve/{conf_subdir}/{new_vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_path)}",
                stdin_data=conf_str.encode(), key_material=pve_key)
        jlog.log(f"Config written: {conf_path}")

        if eff_name:
            safe_name = re.sub(r'[^a-zA-Z0-9\-\.]', '-', eff_name).strip('-') or f"vm-{new_vmid}"
            if vm_type == "qemu":
                ssh_run(pve_host, pve_user, pve_pass,
                        f"qm set {new_vmid} --name {shlex.quote(safe_name)}",
                        key_material=pve_key)
            else:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"pct set {new_vmid} --hostname {shlex.quote(safe_name)}",
                        key_material=pve_key)

        _set_progress(db, job_id, 92)

        # ── 9. Optionally start VM ─────────────────────────────────────
        if start_after:
            jlog.log(f"Starting {vm_type.upper()} {new_vmid} …")
            _vm_start(mgr, eff_node, new_vmid, vm_type)

        _finish_job(db, job_id)
        jlog.log(f"SAN clone completed: {vm_type.upper()} {src_vmid} → {new_vmid}")

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        if temp_vg_name and pve_host:
            try:
                from .san_helpers import cleanup_restore_vg
                cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            except Exception as ce:
                log.warning(f"[netapp_storage] SAN clone cancel cleanup VG failed: {ce}")
        if client and (temp_lun_uuid or temp_ns_uuid or temp_iscsi_clone_vol_uuid or temp_igroup_uuid):
            try:
                _cleanup_san_clone(client, protocol,
                                   temp_lun_uuid, igroup_uuid,
                                   temp_ns_uuid, subsystem_uuid,
                                   temp_iscsi_clone_vol_uuid,
                                   temp_igroup_uuid=temp_igroup_uuid)
            except Exception as ce:
                log.warning(f"[netapp_storage] SAN clone cancel cleanup LUN/NS failed: {ce}")
            if protocol == "iscsi" and temp_iscsi_serial and pve_host:
                try:
                    from .san_helpers import flush_iscsi_clone_device
                    flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
                except Exception as ce:
                    log.warning(f"[netapp_storage] flush multipath on cancel failed: {ce}")
        if conf_path_reserved and pve_host:
            try:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"rm -f {shlex.quote(conf_path_reserved)}", key_material=pve_key)
            except Exception:
                pass
    except Exception as exc:
        log.error(f"[netapp_storage] SAN clone job {job_id} failed: {exc}")
        _fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        # Best-effort cleanup
        if temp_vg_name and pve_host:
            try:
                from .san_helpers import cleanup_restore_vg
                cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            except Exception as ce:
                log.warning(f"[netapp_storage] SAN clone cleanup VG failed: {ce}")
        if client and (temp_lun_uuid or temp_ns_uuid or temp_iscsi_clone_vol_uuid or temp_igroup_uuid):
            try:
                _cleanup_san_clone(client, protocol,
                                   temp_lun_uuid, igroup_uuid,
                                   temp_ns_uuid, subsystem_uuid,
                                   temp_iscsi_clone_vol_uuid,
                                   temp_igroup_uuid=temp_igroup_uuid)
            except Exception as ce:
                log.warning(f"[netapp_storage] SAN clone cleanup LUN/NS failed: {ce}")
            if protocol == "iscsi" and temp_iscsi_serial and pve_host:
                try:
                    from .san_helpers import flush_iscsi_clone_device
                    flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
                except Exception as ce:
                    log.warning(f"[netapp_storage] flush multipath on error failed: {ce}")
        if conf_path_reserved and pve_host:
            try:
                ssh_run(pve_host, pve_user, pve_pass,
                        f"rm -f {shlex.quote(conf_path_reserved)}", key_material=pve_key)
            except Exception:
                pass
    finally:
        _reg_unregister(job_id)


def _cleanup_san_clone(client, protocol,
                       temp_lun_uuid, igroup_uuid,
                       temp_ns_uuid, subsystem_uuid,
                       temp_iscsi_clone_vol_uuid="", jlog=None,
                       temp_igroup_uuid=""):
    """Unmaps the temporary clone LUN/namespace and deletes the ONTAP object.

    temp_igroup_uuid: if set, this igroup was created solely for the clone
    and is deleted after the LUN/volume is gone.
    """
    if protocol == "iscsi" and temp_lun_uuid:
        if igroup_uuid:
            try:
                client.unmap_lun(temp_lun_uuid, igroup_uuid)
            except Exception as exc:
                log.warning(f"[netapp_storage] unmap clone LUN: {exc}")
        if temp_iscsi_clone_vol_uuid:
            # LUN lives inside a FlexClone volume — delete the volume
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
            client.remove_nvme_namespace_from_subsystem(subsystem_uuid, temp_ns_uuid)
        try:
            client.delete_namespace(temp_ns_uuid)
            if jlog:
                jlog.log("Clone namespace removed.")
        except Exception as exc:
            log.warning(f"[netapp_storage] delete clone namespace: {exc}")

    # Delete temp igroup (created for this clone only, now empty after LUN/volume removal)
    if temp_igroup_uuid:
        try:
            client.delete_igroup(temp_igroup_uuid)
            if jlog:
                jlog.log("Temp igroup removed.")
        except Exception as exc:
            log.warning(f"[netapp_storage] delete temp igroup {temp_igroup_uuid}: {exc}")


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

_DISK_KEY_PREFIXES = ("scsi", "virtio", "ide", "sata", "efidisk", "tpmstate", "rootfs", "mp")


def _reserve_vmid(pve_host, pve_user, pve_pass, pve_key, new_vmid, vm_type, jlog=None):
    """Write a placeholder config to block the VMID in PVE immediately.

    Returns the config path so the error handler can remove it on failure.
    The real config written at the end of the job overwrites this placeholder.
    """
    subdir = "qemu-server" if vm_type == "qemu" else "lxc"
    path   = f"/etc/pve/{subdir}/{new_vmid}.conf"
    ssh_run(pve_host, pve_user, pve_pass,
            f"cat > {shlex.quote(path)}",
            stdin_data=b"name: clone-in-progress\nlock: clone\n",
            key_material=pve_key)
    if jlog:
        jlog.log(f"VMID {new_vmid} reserved in PVE ({subdir})")
    return path


def _disks_from_pve(mgr, vmid, storage_id, node):
    """Read disk list and raw config for vmid from PVE API.

    Used as fallback when no manifest is available (native SAN snapshots).
    Returns (disks, vm_type, raw_config).
    """
    vm_type = "qemu"
    cfg = {}
    try:
        node_name = node or mgr.find_vm_node(vmid) or ""
        for vtype in ("qemu", "lxc"):
            ep = "qemu" if vtype == "qemu" else "lxc"
            r = mgr._api_get(f"{mgr._base}/nodes/{node_name}/{ep}/{vmid}/config")
            if r.ok:
                cfg = r.json().get("data", {})
                vm_type = vtype
                break
    except Exception as exc:
        raise RuntimeError(f"Cannot read VM {vmid} config from PVE: {exc}")
    if not cfg:
        raise RuntimeError(f"VM {vmid} config not found in PVE")

    disks = []
    for k, v in cfg.items():
        if any(k.startswith(p) for p in _DISK_KEY_PREFIXES) and f"{storage_id}:" in str(v):
            lv_name = str(v).split(f"{storage_id}:")[1].split(",")[0].strip()
            disks.append({"file": lv_name})

    return disks, vm_type, cfg


def _remap_disk_path(old_file, old_vmid, new_vmid):
    """Replaces VMID in disk paths: '100/vm-100-disk-0.qcow2' → '101/vm-101-disk-0.qcow2'."""
    result = old_file
    old_s, new_s = str(old_vmid), str(new_vmid)
    # Leading directory
    if result.startswith(old_s + "/"):
        result = new_s + "/" + result[len(old_s) + 1:]
    # Filename parts: vm-N- and subvol-N-
    result = result.replace(f"-{old_s}-", f"-{new_s}-")
    return result


def _random_mac():
    return "52:54:00:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
    )


def _build_clone_config(raw_conf, old_vmid, new_vmid, storage_id, disk_map, new_name, vm_type, network_isolated=False):
    """Builds the .conf string for the cloned VM."""
    lines = []
    for k, v in sorted(raw_conf.items()):
        if isinstance(v, (dict, list)) or k in _CONF_SKIP:
            continue
        v = str(v)

        # Replace disk references
        if any(k.startswith(p) for p in _DISK_KEYS) and f"{storage_id}:" in v:
            for old_f, new_f in disk_map.items():
                v = v.replace(f"{storage_id}:{old_f}", f"{storage_id}:{new_f}")

        # Regenerate MAC addresses and optionally disconnect network
        if k.startswith("net"):
            v = re.sub(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', lambda m: _random_mac(), v)
            if network_isolated and ',link_down=1' not in v:
                v = v + ',link_down=1'

        # Set name
        if k == "name" and new_name and vm_type == "qemu":
            v = new_name
        if k == "hostname" and new_name and vm_type == "lxc":
            v = new_name

        lines.append(f"{k}: {v}")

    if new_name and vm_type == "qemu" and not any(l.startswith("name:") for l in lines):
        lines.append(f"name: {new_name}")
    if new_name and vm_type == "lxc" and not any(l.startswith("hostname:") for l in lines):
        lines.append(f"hostname: {new_name}")
    return "\n".join(lines) + "\n"


def _resolve_node_host(mgr, node_name):
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


# ── DR clone (secondary volume → new VM) ────────────────────────────────────

def start_dr_clone_job(job_id, params, username):
    t = threading.Thread(target=_run_dr_clone, args=(job_id, params, username), daemon=True)
    t.start()
    _reg_register(job_id, t)


def _run_dr_clone_iscsi(job_id, params, username, db, jlog, mapping):
    """
    DR Clone for iSCSI datastores from SnapMirror® secondary.

    Flow:
      1. Read manifest from DB, reserve new VMID
      2. FlexClone from SnapMirror snapshot on secondary
      3. Temp igroup on secondary, map clone LUN
      4. Single-path iSCSI connect from PVE host to secondary
      5. vgimportclone → temp VG
      6. For each disk: lvcreate with remapped name + dd copy to primary VG
      7. Cleanup: deactivate temp VG, flush device, logout iSCSI,
         delete temp igroup + clone volume on secondary
      8. Write new VM config, optionally start VM
    """
    from ._helpers import get_endpoint, build_ontap_client, get_ssh_creds
    from .san_helpers import (connect_iscsi_target, disconnect_iscsi_target,
                               find_device_by_serial, flush_iscsi_clone_device,
                               vg_import_clone, activate_lv_for_restore, lv_copy,
                               cleanup_restore_vg, get_lv_size_bytes, create_lv,
                               vg_rescan_and_activate, get_iscsi_initiator_iqn)

    relationship_id = params["relationship_id"]
    snap_name       = params["snap_name"]
    src_vmid        = int(params["src_vmid"])
    new_vmid        = int(params["new_vmid"])
    new_name        = params.get("new_name", "")
    start_after     = bool(params.get("start_after", False))

    vg_name   = mapping["lvm_vg_name"]
    lvm_type  = mapping.get("lvm_type", "linear")
    pool_name = mapping.get("lvm_pool_name", "")

    secondary_client    = None
    temp_lun_uuid       = ""
    temp_clone_vol_uuid = ""
    temp_igroup_uuid    = ""
    sec_portal          = ""
    sec_target_iqn      = ""
    temp_vg_name        = ""
    temp_iscsi_serial   = ""
    conf_path_reserved  = ""
    pve_host = pve_user = pve_pass = pve_key = ""

    try:
        rel = db.query_one(
            "SELECT * FROM netapp_snapmirror_relationships WHERE id=?",
            (relationship_id,))
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
        pve_host = _re_resolve_node_host(mgr, "") or getattr(mgr, "host", "")

        poll_cfg      = load_plugin_config()
        poll_interval = poll_cfg.get("job_poll_interval_s", 3)
        poll_timeout  = poll_cfg.get("job_poll_timeout_s", 300)

        # ── 1. Manifest from DB ───────────────────────────────────────────────
        snap_row = db.query_one(
            "SELECT * FROM netapp_snapshots WHERE mapping_id=? AND snap_name=? "
            "ORDER BY created_at DESC LIMIT 1",
            (mapping["id"], snap_name),
        )
        if snap_row:
            snap = dict(snap_row)
            import json as _json
            manifest = _json.loads(snap.get("manifest_json", "{}"))
            vm_type  = _json.loads(snap.get("vm_types_json") or "{}").get(str(src_vmid), "qemu")
        else:
            jlog.log("Snapshot not in DB — disk list will be derived from clone VG.")
            manifest = {"vms": [{"vmid": src_vmid, "disks": [], "vm_type": "qemu"}]}
            vm_type  = "qemu"

        vm_entry = _find_vm_in_manifest(manifest, src_vmid)
        disks    = vm_entry.get("disks", [])
        vm_type  = vm_entry.get("vm_type", vm_type)

        # Reserve new VMID immediately
        conf_path_reserved = _reserve_vmid(
            pve_host, pve_user, pve_pass, pve_key, new_vmid, vm_type, jlog)
        _re_set_progress(db, job_id, 8)

        # ── 2. FlexClone on secondary ────────────────────────────────────────
        temp_clone_name = f"pgxdrclone_{job_id[:8]}"
        jlog.log(f"Cloning volume from secondary snapshot '{snap_name}' …")
        temp_lun_uuid, temp_clone_vol_uuid = secondary_client.clone_lun_from_snapshot(
            dest_vol_uuid, snap_name, dest_svm, temp_clone_name,
            poll_interval=poll_interval, poll_timeout=poll_timeout,
        )
        jlog.log(f"Secondary clone volume created: {temp_clone_name}")
        _re_set_progress(db, job_id, 20)

        # ── 3. Temp igroup on secondary, map clone LUN ───────────────────────
        jlog.log("Getting host IQN …")
        host_iqn = get_iscsi_initiator_iqn(pve_host, pve_user, pve_pass, pve_key)
        if not host_iqn:
            raise RuntimeError(f"Cannot determine iSCSI IQN of PVE host {pve_host}")

        temp_igroup_name = f"pgxdr_{job_id[:8]}"
        jlog.log(f"Creating temporary igroup '{temp_igroup_name}' on secondary …")
        temp_igroup_uuid = secondary_client.create_igroup(
            dest_svm, temp_igroup_name, protocol="iscsi")
        secondary_client.add_igroup_initiator(temp_igroup_uuid, host_iqn)
        secondary_client.map_lun(temp_lun_uuid, temp_igroup_uuid, dest_svm)
        _re_set_progress(db, job_id, 28)

        # ── 4. iSCSI connect PVE host → secondary ────────────────────────────
        sec_portal     = secondary_client.get_iscsi_lif_for_svm(dest_svm)
        sec_target_iqn = secondary_client.get_iscsi_target_iqn(dest_svm)
        if not sec_portal or not sec_target_iqn:
            raise RuntimeError(
                f"Cannot determine secondary iSCSI portal or target IQN "
                f"(portal={sec_portal!r}, iqn={sec_target_iqn!r})")

        jlog.log(f"Connecting to secondary iSCSI {sec_portal} / {sec_target_iqn} …")
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
        _re_set_progress(db, job_id, 38)

        # ── 5. vgimportclone → temp VG ───────────────────────────────────────
        jlog.log(f"Importing clone VG from {device} …")
        temp_vg_name = vg_import_clone(pve_host, pve_user, pve_pass, pve_key,
                                       device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")

        # If manifest had no disks, derive them from the temp VG
        if not disks:
            jlog.log("Deriving disk list from clone VG …")
            from .san_helpers import get_vg_lv_map
            lv_map = get_vg_lv_map(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            disks = [{"file": lv} for lv in lv_map if str(src_vmid) in lv]
            if not disks:
                disks = [{"file": lv} for lv in lv_map]
            jlog.log(f"{len(disks)} disk(s) found in clone VG.")
        _re_set_progress(db, job_id, 45)

        # ── 6. For each disk: create new LV + dd copy ────────────────────────
        total        = len(disks)
        new_disk_map = {}
        jlog.log(f"Copying {total} disk(s): VM {src_vmid} → {new_vmid} …")

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk.get("file", "")
            src_lv   = os.path.basename(old_file.split(":")[-1]) if old_file else ""
            if not src_lv:
                continue
            new_lv = _remap_disk_path(src_lv, src_vmid, new_vmid)
            new_disk_map[old_file] = new_lv
            jlog.log(f"  [{i}/{total}] {src_lv} → {new_lv}")

            activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                    temp_vg_name, src_lv, lvm_type, pool_name)
            size_bytes = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                           temp_vg_name, src_lv)
            if not size_bytes:
                raise RuntimeError(f"Cannot determine size of {temp_vg_name}/{src_lv}")

            create_lv(pve_host, pve_user, pve_pass, pve_key,
                      vg_name, new_lv, size_bytes, lvm_type, pool_name)
            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, new_lv, jlog)
            _re_set_progress(db, job_id, 45 + int(i / max(total, 1) * 35))

        # ── 7. Cleanup ────────────────────────────────────────────────────────
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""

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
            log.warning(f"[netapp_storage] DR clone: delete temp igroup: {exc}")
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
            log.warning(f"[netapp_storage] DR clone: delete clone volume: {exc}")
        temp_clone_vol_uuid = ""
        _re_set_progress(db, job_id, 85)

        try:
            vg_rescan_and_activate(pve_host, pve_user, pve_pass, pve_key, vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR clone: vg rescan: {exc}")

        # ── 8. Write VM config ────────────────────────────────────────────────
        eff_name = new_name or f"dr-clone-{vm_entry.get('name', src_vmid)}"
        jlog.log(f"Writing VM config … (name: {eff_name!r})")
        raw_conf = vm_entry.get("raw_config", {})
        conf_str = _build_clone_config(
            raw_conf, src_vmid, new_vmid,
            mapping["pve_storage_id"], new_disk_map, eff_name, vm_type,
        )
        name_key   = "hostname" if vm_type == "lxc" else "name"
        conf_lines = [l for l in conf_str.splitlines() if not l.startswith(f"{name_key}:")]
        conf_lines.append(f"{name_key}: {eff_name}")
        conf_str   = "\n".join(conf_lines) + "\n"

        conf_subdir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_path   = f"/etc/pve/{conf_subdir}/{new_vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_path)}",
                stdin_data=conf_str.encode(), key_material=pve_key)
        conf_path_reserved = ""
        jlog.log(f"Config written: {conf_path}")
        _re_set_progress(db, job_id, 92)

        if start_after:
            node = ""
            try:
                node = mgr.find_vm_node(new_vmid) or ""
            except Exception:
                pass
            jlog.log(f"Starting {vm_type.upper()} {new_vmid} …")
            _vm_start(mgr, node, new_vmid, vm_type)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        _dr_clone_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                                pve_host, pve_user, pve_pass, pve_key,
                                temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn,
                                conf_path_reserved)
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] DR-Clone iSCSI job {job_id} failed: {exc}")
        _re_fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        _dr_clone_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                                pve_host, pve_user, pve_pass, pve_key,
                                temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn,
                                conf_path_reserved)
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _re_finish_job(db, job_id)
    jlog.log(f"DR-Clone iSCSI {vm_type.upper()} {src_vmid} → {new_vmid} completed.")


def _dr_clone_iscsi_cleanup(secondary_client, temp_igroup_uuid, temp_clone_vol_uuid,
                             pve_host, pve_user, pve_pass, pve_key,
                             temp_vg_name, temp_iscsi_serial, sec_portal, sec_target_iqn,
                             conf_path_reserved=""):
    """Best-effort cleanup after DR iSCSI clone error or cancel."""
    from .san_helpers import (cleanup_restore_vg, flush_iscsi_clone_device,
                               disconnect_iscsi_target)
    if temp_vg_name and pve_host:
        try:
            cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR clone cleanup VG: {exc}")
    if temp_iscsi_serial and pve_host:
        flush_iscsi_clone_device(pve_host, pve_user, pve_pass, pve_key, temp_iscsi_serial)
    if sec_portal and sec_target_iqn and pve_host:
        disconnect_iscsi_target(pve_host, pve_user, pve_pass, pve_key,
                                sec_portal, sec_target_iqn)
    if secondary_client and temp_igroup_uuid:
        try:
            secondary_client.delete_igroup(temp_igroup_uuid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR clone cleanup igroup: {exc}")
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
            log.warning(f"[netapp_storage] DR clone cleanup clone volume: {exc}")
    if conf_path_reserved and pve_host:
        try:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"rm -f {shlex.quote(conf_path_reserved)} 2>/dev/null || true",
                    key_material=pve_key, timeout=10)
        except Exception:
            pass


def _run_dr_clone_nvme(job_id, params, username, db, jlog, mapping):
    """
    DR Clone for NVMe-oF datastores from SnapMirror® secondary.

    Flow:
      1. Read manifest from DB, reserve new VMID
      2. FlexClone from SnapMirror snapshot on secondary
      3. Temp NVMe subsystem on secondary, add host NQN, map clone namespace
      4. NVMe connect from PVE host to secondary portals
      5. vgimportclone → temp VG
      6. For each disk: create new LV with remapped VMID + dd copy to primary VG
      7. Cleanup: deactivate temp VG, disconnect NVMe, delete temp subsystem + clone volume
      8. Write new VM config, optionally start VM
    """
    from ._helpers import get_endpoint, build_ontap_client, get_ssh_creds
    from .san_helpers import (nvme_list_devices, find_new_nvme_device,
                               nvme_connect_to_subsystem, nvme_disconnect_by_subsystem_name,
                               vg_import_clone, activate_lv_for_restore, lv_copy,
                               cleanup_restore_vg, get_lv_size_bytes, create_lv,
                               vg_rescan_and_activate, get_nvme_host_nqn, get_vg_lv_map)

    relationship_id = params["relationship_id"]
    snap_name       = params["snap_name"]
    src_vmid        = int(params["src_vmid"])
    new_vmid        = int(params["new_vmid"])
    new_name        = params.get("new_name", "")
    start_after     = bool(params.get("start_after", False))

    vg_name   = mapping["lvm_vg_name"]
    lvm_type  = mapping.get("lvm_type", "linear")
    pool_name = mapping.get("lvm_pool_name", "")

    secondary_client    = None
    temp_ns_uuid        = ""
    temp_clone_vol_uuid = ""
    temp_subsystem_uuid = ""
    temp_subsystem_name = ""
    temp_vg_name        = ""
    conf_path_reserved  = ""
    pve_host = pve_user = pve_pass = pve_key = ""

    try:
        rel = db.query_one(
            "SELECT * FROM netapp_snapmirror_relationships WHERE id=?",
            (relationship_id,))
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
        pve_host = _re_resolve_node_host(mgr, "") or getattr(mgr, "host", "")

        poll_cfg      = load_plugin_config()
        poll_interval = poll_cfg.get("job_poll_interval_s", 3)
        poll_timeout  = poll_cfg.get("job_poll_timeout_s", 300)

        # ── 1. Manifest from DB, reserve VMID ───────────────────────────────
        snap_row = db.query_one(
            "SELECT * FROM netapp_snapshots WHERE mapping_id=? AND snap_name=? "
            "ORDER BY created_at DESC LIMIT 1",
            (mapping["id"], snap_name),
        )
        if snap_row:
            snap = dict(snap_row)
            import json as _json
            manifest = _json.loads(snap.get("manifest_json", "{}"))
            vm_type  = _json.loads(snap.get("vm_types_json") or "{}").get(str(src_vmid), "qemu")
        else:
            jlog.log("Snapshot not in DB — disk list will be derived from clone VG.")
            manifest = {"vms": [{"vmid": src_vmid, "disks": [], "vm_type": "qemu"}]}
            vm_type  = "qemu"

        vm_entry = _find_vm_in_manifest(manifest, src_vmid)
        disks    = vm_entry.get("disks", [])
        vm_type  = vm_entry.get("vm_type", vm_type)

        conf_path_reserved = _reserve_vmid(
            pve_host, pve_user, pve_pass, pve_key, new_vmid, vm_type, jlog)
        _re_set_progress(db, job_id, 8)

        # ── 2. FlexClone on secondary ────────────────────────────────────────
        temp_clone_name = f"pgxdrclone_{job_id[:8]}"
        jlog.log(f"Cloning volume from secondary snapshot '{snap_name}' …")
        temp_ns_uuid, temp_clone_vol_uuid = secondary_client.clone_namespace_from_snapshot(
            dest_vol_uuid, snap_name, dest_svm, temp_clone_name,
            poll_interval=poll_interval, poll_timeout=poll_timeout,
        )
        jlog.log(f"Secondary clone volume created: {temp_clone_name}")
        _re_set_progress(db, job_id, 20)

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
        _re_set_progress(db, job_id, 30)

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
            jlog.log("WARNING: subsystem NQN unavailable — waiting for auto-discovery")

        jlog.log("Waiting for clone namespace device …")
        device = find_new_nvme_device(
            pve_host, pve_user, pve_pass, pve_key, devices_before, timeout_s=60)
        jlog.log(f"Clone device: {device}")
        _re_set_progress(db, job_id, 40)

        # ── 5. vgimportclone → temp VG ───────────────────────────────────────
        jlog.log(f"Importing clone VG from {device} …")
        temp_vg_name = vg_import_clone(pve_host, pve_user, pve_pass, pve_key,
                                       device, vg_name)
        jlog.log(f"Clone VG imported as '{temp_vg_name}'")

        if not disks:
            jlog.log("Deriving disk list from clone VG …")
            lv_map = get_vg_lv_map(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
            disks = [{"file": lv} for lv in lv_map if str(src_vmid) in lv]
            if not disks:
                disks = [{"file": lv} for lv in lv_map]
            jlog.log(f"{len(disks)} disk(s) found in clone VG.")
        _re_set_progress(db, job_id, 48)

        # ── 6. For each disk: create new LV + dd copy ────────────────────────
        total        = len(disks)
        new_disk_map = {}
        jlog.log(f"Copying {total} disk(s): VM {src_vmid} → {new_vmid} …")

        for i, disk in enumerate(disks, 1):
            check_cancel(job_id)
            old_file = disk.get("file", "")
            src_lv   = os.path.basename(old_file.split(":")[-1]) if old_file else ""
            if not src_lv:
                continue
            new_lv = _remap_disk_path(src_lv, src_vmid, new_vmid)
            new_disk_map[old_file] = new_lv
            jlog.log(f"  [{i}/{total}] {src_lv} → {new_lv}")

            activate_lv_for_restore(pve_host, pve_user, pve_pass, pve_key,
                                    temp_vg_name, src_lv, lvm_type, pool_name)
            size_bytes = get_lv_size_bytes(pve_host, pve_user, pve_pass, pve_key,
                                           temp_vg_name, src_lv)
            if not size_bytes:
                raise RuntimeError(f"Cannot determine size of {temp_vg_name}/{src_lv}")

            create_lv(pve_host, pve_user, pve_pass, pve_key,
                      vg_name, new_lv, size_bytes, lvm_type, pool_name)
            lv_copy(pve_host, pve_user, pve_pass, pve_key,
                    temp_vg_name, src_lv, vg_name, new_lv, jlog)
            _re_set_progress(db, job_id, 48 + int(i / max(total, 1) * 32))

        # ── 7. Cleanup ────────────────────────────────────────────────────────
        jlog.log(f"Cleaning up clone VG '{temp_vg_name}' …")
        cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        temp_vg_name = ""
        _re_set_progress(db, job_id, 83)

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
            log.warning(f"[netapp_storage] DR NVMe clone: delete clone volume: {exc}")
        temp_clone_vol_uuid = ""
        _re_set_progress(db, job_id, 86)

        try:
            vg_rescan_and_activate(pve_host, pve_user, pve_pass, pve_key, vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe clone: vg rescan: {exc}")

        # ── 8. Write VM config ────────────────────────────────────────────────
        eff_name = new_name or f"dr-clone-{vm_entry.get('name', src_vmid)}"
        jlog.log(f"Writing VM config … (name: {eff_name!r})")
        raw_conf = vm_entry.get("raw_config", {})
        conf_str = _build_clone_config(
            raw_conf, src_vmid, new_vmid,
            mapping["pve_storage_id"], new_disk_map, eff_name, vm_type,
        )
        name_key   = "hostname" if vm_type == "lxc" else "name"
        conf_lines = [l for l in conf_str.splitlines() if not l.startswith(f"{name_key}:")]
        conf_lines.append(f"{name_key}: {eff_name}")
        conf_str   = "\n".join(conf_lines) + "\n"

        conf_subdir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_path   = f"/etc/pve/{conf_subdir}/{new_vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_path)}",
                stdin_data=conf_str.encode(), key_material=pve_key)
        conf_path_reserved = ""
        jlog.log(f"Config written: {conf_path}")
        _re_set_progress(db, job_id, 92)

        if start_after:
            node = ""
            try:
                node = mgr.find_vm_node(new_vmid) or ""
            except Exception:
                pass
            jlog.log(f"Starting {vm_type.upper()} {new_vmid} …")
            _vm_start(mgr, node, new_vmid, vm_type)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
        _dr_clone_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                               pve_host, pve_user, pve_pass, pve_key,
                               temp_vg_name, temp_subsystem_name, conf_path_reserved)
        _reg_unregister(job_id)
        return
    except Exception as exc:
        log.error(f"[netapp_storage] DR-Clone NVMe job {job_id} failed: {exc}")
        _re_fail_job(db, job_id)
        jlog.log(f"ERROR: {exc}")
        _dr_clone_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                               pve_host, pve_user, pve_pass, pve_key,
                               temp_vg_name, temp_subsystem_name, conf_path_reserved)
        _reg_unregister(job_id)
        return

    _reg_unregister(job_id)
    _re_finish_job(db, job_id)
    jlog.log(f"DR-Clone NVMe {vm_type.upper()} {src_vmid} → {new_vmid} completed.")


def _dr_clone_nvme_cleanup(secondary_client, temp_subsystem_uuid, temp_clone_vol_uuid,
                            pve_host, pve_user, pve_pass, pve_key,
                            temp_vg_name, temp_subsystem_name, conf_path_reserved=""):
    """Best-effort cleanup after DR NVMe clone error or cancel."""
    from .san_helpers import cleanup_restore_vg, nvme_disconnect_by_subsystem_name
    if temp_vg_name and pve_host:
        try:
            cleanup_restore_vg(pve_host, pve_user, pve_pass, pve_key, temp_vg_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe clone cleanup VG: {exc}")
    if temp_subsystem_name and pve_host:
        try:
            nvme_disconnect_by_subsystem_name(pve_host, pve_user, pve_pass, pve_key,
                                              temp_subsystem_name)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe clone cleanup disconnect: {exc}")
    if secondary_client and temp_subsystem_uuid:
        try:
            secondary_client.delete_nvme_subsystem(temp_subsystem_uuid)
        except Exception as exc:
            log.warning(f"[netapp_storage] DR NVMe clone cleanup subsystem: {exc}")
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
            log.warning(f"[netapp_storage] DR NVMe clone cleanup volume: {exc}")
    if conf_path_reserved and pve_host:
        try:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"rm -f {shlex.quote(conf_path_reserved)} 2>/dev/null || true",
                    key_material=pve_key, timeout=10)
        except Exception:
            pass


def _run_dr_clone(job_id, params, username):
    """
    Clone from SnapMirror® secondary volume.
    NFS: mounts DP volume read-only, copies disk files with new VMID.
    iSCSI: FlexClone on secondary, single-path iSCSI connect, dd LVs to new LVs.
    NVMe: FlexClone on secondary, temp subsystem, NVMe connect, dd LVs to new LVs.
    """
    db = get_db()
    jlog = JobLogger(job_id, db)

    mapping_id = params["mapping_id"]
    mapping    = get_mapping(db, mapping_id)
    protocol   = mapping.get("storage_protocol", "nfs")

    if protocol == "iscsi":
        _run_dr_clone_iscsi(job_id, params, username, db, jlog, mapping)
        return

    if protocol == "nvme":
        _run_dr_clone_nvme(job_id, params, username, db, jlog, mapping)
        return

    relationship_id = params["relationship_id"]
    snap_name       = params["snap_name"]
    src_vmid        = int(params["src_vmid"])
    new_vmid        = int(params["new_vmid"])
    new_name        = params.get("new_name", "")
    start_after     = bool(params.get("start_after", False))
    cfg             = load_plugin_config()
    dr_mount_base   = cfg.get("flexclone_mount_base", "/mnt/pegaprox-clone")
    dr_mount_point  = None
    pve_host        = ""
    pve_user        = "root"
    pve_pass        = ""
    pve_key         = ""

    try:
        from .snapmirror import ensure_secondary_nfs_export

        mgr     = build_pve_client(db, mapping["pve_cluster_id"])
        pve_user, pve_pass, pve_key = get_ssh_creds(mgr)
        pve_host = _re_resolve_node_host(mgr, "") or getattr(mgr, "host", "")

        # ── Ensure NFS export ─────────────────────────────────────────
        jlog.log("Checking NFS export on secondary system …")
        nfs_ip, junction_path, mounted = ensure_secondary_nfs_export(db, relationship_id)
        if mounted:
            jlog.log(f"NFS export rule created on secondary.")
        jlog.log(f"Secondary NFS: {nfs_ip}:{junction_path}")
        if not nfs_ip or not junction_path:
            raise RuntimeError(
                "Secondary volume has no NFS IP or junction path. "
                "Check prerequisites in README."
            )

        # ── Mount secondary volume ────────────────────────────────────
        dr_mount_point = f"{dr_mount_base}/dr-clone-{job_id[:8]}"
        nfs_src = f"{nfs_ip}:{junction_path}"
        jlog.log(f"Mounting secondary volume {nfs_src} at {pve_host}:{dr_mount_point} …")
        ssh_run(pve_host, pve_user, pve_pass,
                f"mkdir -p {shlex.quote(dr_mount_point)}", key_material=pve_key)
        ssh_run(pve_host, pve_user, pve_pass,
                f"mount -t nfs -o ro,soft,timeo=30 "
                f"{shlex.quote(nfs_src)} {shlex.quote(dr_mount_point)}",
                key_material=pve_key)
        _re_set_progress(db, job_id, 15)

        # ── Manifest lesen ────────────────────────────────────────────
        manifest_subdir = cfg.get("manifest_subdir", ".netapp-snapmanifest")
        snap_base       = f"{dr_mount_point}/.snapshot/{snap_name}"
        manifest_path   = f"{snap_base}/{manifest_subdir}/{snap_name}/manifest.json"
        jlog.log("Reading manifest …")
        try:
            out = ssh_run(pve_host, pve_user, pve_pass,
                          f"cat {shlex.quote(manifest_path)}",
                          capture=True, key_material=pve_key)
            manifest = json.loads(out)
        except Exception:
            manifest = {"vms": [{"vmid": src_vmid, "disks": [], "vm_type": "qemu"}]}
            jlog.log("Manifest not found — disk files will be auto-discovered.")

        try:
            vm_entry = _find_vm_in_manifest(manifest, src_vmid)
        except RuntimeError:
            jlog.log(f"VM {src_vmid} not in manifest — trying auto-discovery …")
            vm_entry = {"vmid": src_vmid, "disks": [], "vm_type": "qemu"}
        disks   = vm_entry.get("disks", [])
        vm_type = vm_entry.get("vm_type", "qemu")

        if not disks:
            jlog.log("Searching .snapshot directory for disk files …")
            try:
                out = ssh_run(
                    pve_host, pve_user, pve_pass,
                    f"find {shlex.quote(snap_base+'/images/'+str(src_vmid))} "
                    f"-maxdepth 1 \\( -name '*.qcow2' -o -name '*.raw' \\) 2>/dev/null | head -20",
                    capture=True, key_material=pve_key,
                )
                found = [l.strip() for l in out.splitlines() if l.strip()]
                base  = snap_base + "/images/"
                disks = [{"file": f.replace(base, "")} for f in found]
                jlog.log(f"{len(disks)} disk(s) found via auto-discovery.")
            except Exception:
                pass

        if not disks:
            # Diagnostic: show which VMIDs actually exist in this snapshot
            try:
                diag = ssh_run(
                    pve_host, pve_user, pve_pass,
                    f"ls {shlex.quote(snap_base + '/images/')} 2>/dev/null | head -30",
                    capture=True, key_material=pve_key,
                )
                avail = [l.strip() for l in diag.splitlines() if l.strip()]
                if avail:
                    jlog.log(f"VMIDs present in snapshot '{snap_name}': {', '.join(avail)}")
                else:
                    jlog.log(f"Snapshot '{snap_name}' contains no VM images at all — "
                             "the snapshot may predate this VM or target the wrong volume.")
            except Exception:
                pass
            raise RuntimeError(
                f"VM {src_vmid} has no disk files in snapshot '{snap_name}'. "
                "Take a new snapshot on the primary to include this VM, "
                "or check that the correct SnapMirror volume is selected."
            )

        _re_set_progress(db, job_id, 25)

        # ── Copy disks with remapped VMID ───────────────────────────────
        total        = len(disks)
        new_disk_map = {}
        jlog.log(f"DR-Clone: {total} disk(s) for VM {src_vmid} → {new_vmid} …")

        for i, disk in enumerate(disks, 1):
            old_file = disk["file"]
            new_file = _remap_disk_path(old_file, src_vmid, new_vmid)
            src = f"{snap_base}/images/{old_file.lstrip('/')}"
            dst = f"{mapping['nfs_mount_path']}/images/{new_file.lstrip('/')}"
            jlog.log(f"  [{i}/{total}] {os.path.basename(old_file)} → {os.path.basename(new_file)}")
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
            new_disk_map[old_file] = new_file
            _re_set_progress(db, job_id, 25 + int(i / max(total, 1) * 55))

        # ── Neue VM-Config ────────────────────────────────────────────
        eff_name = new_name or f"dr-clone-{vm_entry.get('name', src_vmid)}"
        jlog.log(f"Building VM config … (name: {eff_name!r})")
        raw_conf = vm_entry.get("raw_config", {})
        conf_str = _build_clone_config(
            raw_conf, src_vmid, new_vmid,
            mapping["pve_storage_id"], new_disk_map, eff_name, vm_type,
        )
        name_key   = "hostname" if vm_type == "lxc" else "name"
        conf_lines = [l for l in conf_str.splitlines() if not l.startswith(f"{name_key}:")]
        conf_lines.append(f"{name_key}: {eff_name}")
        conf_str   = "\n".join(conf_lines) + "\n"

        conf_subdir = "qemu-server" if vm_type == "qemu" else "lxc"
        conf_path   = f"/etc/pve/{conf_subdir}/{new_vmid}.conf"
        ssh_run(pve_host, pve_user, pve_pass,
                f"cat > {shlex.quote(conf_path)}",
                stdin_data=conf_str.encode(), key_material=pve_key)
        jlog.log(f"Config written: {conf_path}")

        safe_name = re.sub(r'[^a-zA-Z0-9\-\.]', '-', eff_name).strip('-') or f"vm-{new_vmid}"
        if vm_type == "qemu":
            ssh_run(pve_host, pve_user, pve_pass,
                    f"qm set {new_vmid} --name {shlex.quote(safe_name)}",
                    key_material=pve_key)
        else:
            ssh_run(pve_host, pve_user, pve_pass,
                    f"pct set {new_vmid} --hostname {shlex.quote(safe_name)}",
                    key_material=pve_key)

        _re_set_progress(db, job_id, 90)

        if start_after:
            node = ""
            try:
                node = mgr.find_vm_node(new_vmid) or ""
            except Exception:
                pass
            jlog.log(f"Starting {vm_type.upper()} {new_vmid} …")
            _vm_start(mgr, node, new_vmid, vm_type)

    except JobCancelledError:
        jlog.log("Job cancelled by user")
        _cancel_job(db, job_id)
    except Exception as exc:
        log.error(f"[netapp_storage] DR-Clone job {job_id} failed: {exc}")
        _re_fail_job(db, job_id)
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
                log.warning(f"[netapp_storage] DR-Clone cleanup failed: {e}")
        _reg_unregister(job_id)

    if not _re_job_failed(db, job_id):
        _re_finish_job(db, job_id)
        jlog.log(f"DR-Clone {vm_type.upper()} {src_vmid} → {new_vmid} completed.")
