# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] – 2026-05-29

### Added
- **Import VMs from Datastore** *(Beta)* — adopt an existing ONTAP volume (iSCSI / NVMe-oF / NFS) with live VMs into the plugin without reprovisioning.
  Scans for LUNs / namespaces, auto-detects LVM VG, reads the snapmanifest, reconstructs VM inventory (VMIDs, names, disk layout), handles VMID conflicts with rename + disk file/LV rename, and registers the datastore. Covers cluster migrations, storage takeovers, and SnapMirror DR failover scenarios.
- **NVMe-oF end-to-end provisioning** — full provisioning wizard for NVMe-oF datastores (namespace + subsystem + NQN mapping), with automatic `nvme connect-all` handling, zombie controller cleanup, and sysfs-based device detection.
- **NVMe-oF DR clone** — clone VMs directly from a SnapMirror secondary using NVMe-oF, with `dd` progress output to the job log.
- **Plugin self-update** *(Settings → ⬆️ Plugin Update)* — check GitHub for the latest stable release or latest dev/main branch commit; apply updates with one click (downloads ZIP, replaces plugin files, preserves `config.json`). Displays release tag, publish date, and release notes excerpt.
- **Deploy Wizard** — integrated as a floating modal in Settings for first-time setup.
- **Live ONTAP volume size hint** — shows current ONTAP volume size in the resize and provisioning dialogs for iSCSI and NVMe-oF.
- **NFS provisioning** — snapmanifest directory (`.netapp-snapmanifest/`) created automatically after NFS provisioning.
- **pvscan --cache -aay** — used consistently across provisioning and bind for reliable VG activation on all cluster nodes.

### Changed
- **UI overhaul** — all inline expanding forms converted to floating modal overlays with backdrop click and Escape key dismissal:
  Provision New, Mount existing (Bind), Import VMs from Datastore, Create Snapshot, Add/Edit Schedule, Add NetApp System, Add PVE Host, Deploy Wizard.
- **Tab consolidation** — SnapMirror visibility + Storage Discovery merged into the unified Storage tab; Datastore Recovery/Import merged into the Restore tab.
- **Emoji icons** on all section headings (tabs, card-titles, sub-headers) for visual orientation; i18n-safe implementation using separate `<span>` elements.
- **Renamed** "VM Import from Manifest" → "📥 Import VMs from Datastore".
- **NVMe bind** — idempotent rebind: detects and reuses existing subsystem/iGroup by name on repeated bind attempts; disconnects stale controllers before reconnecting.

### Fixed
- NVMe bind: sysfs-based device detection for zombie controllers (`nvme list` JSON parsing, baseline-diff tracking).
- iSCSI bind: align VG detection with provisioning pattern (`pvscan --cache -aay`); handle `/dev/dm-N` device paths.
- iSCSI bind: VG name backfilled from `volume_mapping` when auto-detected; `vg_name` no longer required in the API request.
- VM Import: disk file / LV renaming when VMID changes during import (prevents stale disk references after VMID conflict resolution).
- VM Import: ONTAP snapshots that reference old disk names after VMID rename now produce a warning in the import log.
- Tab visibility: orphaned `</div>` tags from form removal broke tab-snapshots, tab-schedules, tab-restore, tab-clone, and tab-storage layout — all fixed.
- Tab icons stripped by `applyI18n()` — fixed by separating emoji into `<span aria-hidden="true">` and applying `data-i18n` only to the text `<span>`.
- NFS recovery: dedicated NFS LIF endpoint, automatic LIF selector update on SVM change, default-all host selection.
- Capacity display for imported (bound) datastores in the Storage tab.

## [0.9.8] – 2026-05-13

### Added
- **Provisioning tab** — end-to-end iSCSI datastore setup directly from the UI:
  - Wizard (3 steps): protocol/endpoint/SVM → ONTAP volume/LUN/iGroup → PVE hosts/VG/storage ID
  - Reuse existing ONTAP objects (volumes, LUNs, iGroups) or create new ones
  - Linear (thick) and thin-provisioned LVM VG support
  - Automatic per-host iSCSI discovery, login, multipath device wait, pvcreate/vgcreate, pvscan activation, and `pvesm` storage registration
  - Remove datastore: pvesm remove, VG deactivate, iSCSI logout, optional ONTAP LUN/volume delete
- **SnapMirror® visibility** — scan and display SnapMirror relationships per ONTAP endpoint; trigger update transfers; list secondary snapshots
- **SnapMirror DR restore/clone** — restore or clone VMs from a secondary SnapMirror volume (NFS)
- **SAN snapmanifest** — dedicated 64 MB ext4 LV inside the VG stores the VM manifest inside every ONTAP snapshot, enabling restore/clone from ONTAP-native snapshots
- **DR clone** — clone VMs from a SnapMirror secondary directly into the primary cluster
- **Job cancellation** — cancel a running job between steps; automatic cleanup of partial work (temp clones, imported VGs, reserved VMIDs)
- **SMTP / email notifications** — per-schedule notifications on job completion (all / failures only / success only)
- **Multi-VM snapshot** — snapshot multiple VMs on the same mapping in one operation
- **ONTAP-native snapshot visibility** — shows snapshots not created by this plugin; supports restore and clone from them

### Fixed
- **KI-001 resolved** — ASA NVMe: Single VM Restore and Clone now use `POST /api/private/cli/volume/clone` + `protocols/nvme/subsystem-maps` instead of the unavailable REST namespace clone endpoint
- iSCSI WWID formula corrected to NAA type-6 (3 + `600a0980` + hex(serial)) — multipath device was not found with the previous formula
- `flush_iscsi_clone_device`: now uses computed WWID (from serial) instead of sysfs serial read; also flushes SCSI layer via `/proc/scsi/scsi` or `scsi_device` sysfs delete
- iSCSI clone: temp igroup created as single-host igroup to prevent LUN visibility on other cluster nodes during restore/clone
- Route registration in `provisioning.py` migrated from `bp.route()` to `register_plugin_route()` — fixes "No module named pegaprox.core.plugin_router" on fresh installs
- `_execute_schedule`: uses `build_pve_client()` instead of the always-empty `cluster_managers` dict
- `_vms_for_mapping`: uses storage content API instead of listing all cluster VMs
- Retention import path corrected: `from ..core._helpers` (was: `from .._helpers`)

## [0.9.0] – 2026-05-05

### Added
- Full management UI (6 tabs: Snapshots, Schedules, VM-Restore, VM-Clone, Jobs, Settings)
- Internationalization: DE, EN, FR, ES, PT, KO, IT
- VM-Clone via ONTAP File Clone CoW (near-instant, no data transfer)
- Scheduled snapshots with cron expressions, retention policy and SnapMirror labels
- Auto-discovery of ONTAP volumes mapped to Proxmox NFS datastores
- Proxmox host management (standalone hosts without PVE cluster)
- ONTAP-native snapshot visibility (snapshots not created by this plugin)
- Manifest system: VM configs and disk inventory stored inside the snapshot
- Support for Proxmox LXC containers alongside QEMU VMs
- Snapshot consistency levels: crash-consistent, app-consistent (fsfreeze), suspend

### Changed
- Snapshot naming convention: `NPP_{user_input}` for manual, `NPP_{YYYYMMDD}_{HHMM}[_{schedule}]` for scheduled
- Restore and Clone split into separate engines and API routes
- Requires PegaProx ≥ 0.9.9

## [0.2.0] – 2026-04-01

### Added
- Initial snapshot creation and deletion
- Single-VM restore via SFSR (Single-File Snapshot Restore)
- FlexClone-based restore (full copy via qemu-img)
- Basic job tracking

## [0.1.0] – 2026-03-01

### Added
- Initial plugin skeleton
- ONTAP REST API client
- Volume mapping management
