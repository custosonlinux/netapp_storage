# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] – Unreleased

### Added

**Disaster Recovery — Peer-to-Peer Sync (v3.0 architecture):**
- **DR Peer Sync** — replaces the previous NFS config-volume approach with direct plugin-to-plugin HTTPS communication. Single-row `netapp_dr_peer` configuration; shared sync token (`X-DR-Sync-Token` header); background heartbeat every 30 s and DB sync every 60 s (PRIMARY only). Roles: `PRIMARY` / `SECONDARY` / `STANDALONE` (legacy `MASTER`/`DR_SLAVE` migrated automatically).
- New endpoints: `dr/peer/status`, `dr/peer/configure`, `dr/peer/remove`, `dr/peer/sync/push`, `dr/peer/heartbeat`, `dr/peer/sync/receive`, `dr/peer/role-notify`.

**UI — Snapshot Timeline (§5 Signature-Element):**
- **Timeline ribbon** — SVG-based horizontal timeline above the snapshot table; Day/Week/Month/Year zoom; ● dots for existing snapshots (hover = dark tooltip, click = row highlight + flash animation); △ triangles for scheduled future runs (visible when a single datastore is selected and a SnapMirror relationship exists); orange retention band; "now" marker; "+N earlier" overflow indicator.

**UI — Snapshot Table:**
- **Virtual scrolling** — windowed row rendering above 80 rows with spacer TRs for correct scroll position; sticky header; `_vsSelectedKeys` Set preserves bulk selection state across viewport boundaries when rows leave the DOM.
- **Mobile card layout** — `@media (max-width: 680px)`: `thead` hidden, each `tr[data-snap-key]` displayed as a block card; all `td` elements carry `data-label` attributes rendered as column headers via CSS `::before`; timeline ribbon hidden on mobile.
- **Relative timestamps** — `created_at` and `discovered_at` shown as relative text (`3 hours ago`) with absolute ISO-8601 date/time as tooltip.
- **Status vocabulary** — unified `statusBadge()` helper with consistent icon + colour for `done`, `running`, `pending`, `failed`, `cancelling`, `cancelled`; i18n keys `badge_*` for all 7 locales.
- **Monospace technical identifiers** — volume names, SVM names, VMIDs, node names, snapshot names, and ONTAP job IDs rendered in `<code>` throughout the UI.
- **Empty states as CTAs** — all empty tables now show a hero icon and a contextual call-to-action button ("Create Snapshot", "Add Schedule", "Add NetApp System", etc.) instead of a plain "nothing here" message.

**UI — Safety & Confirmations:**
- **Danger modal — Restore** — full confirmation dialog: type the snapshot name to confirm; VM blast-radius list; optional "create safety snapshot first" checkbox (default: on); Danger-style confirm button.
- **Danger modal — Delete** — type the snapshot name to confirm; affected VM list.
- **Blast-radius in Create Snapshot** — when a multi-VM datastore is selected, a notice shows all VMs covered by the snapshot.
- **Audit log** — `netapp_audit_log` DB table logs every destructive action (delete, restore) with user, timestamp, target object, result, and ONTAP job ID. Visible in **Jobs → Audit** section.
- **Actionable error toasts** — error toasts stay visible for 12 s (up from 4.5 s); ✕ close button; "Show details" toggle exposes the full ONTAP JSON response in a monospace `<pre>` block. `apiFetch` populates `err.detail` automatically for all non-2xx responses that carry extra JSON fields.
- **Retention warning** — inline alert in the schedule wizard when reducing the retention count would immediately schedule existing snapshots for deletion on the next run.

**UI — Schedule Wizard:**
- 6-step wizard replaces the flat add-schedule form: ① Basics (name + datastore), ② Schedule & Retention (frequency, time, count, live next-run preview), ③ VMs & Scripts (consistency, VM selection, pre/post hooks as accordion), ④ SnapMirror (auto-skipped with greyed pill if no relationship configured), ⑤ Notifications (SMTP recipients, notify-on, test button), ⑥ Summary (read-only table before save).
- Live next-run preview in step ② shows the next 10 execution times computed from the cron expression.
- All wizard strings added to i18n for all 7 locales.

**UI — Snapshot Tab:**
- SnapMirror policy labels endpoint (`snapmirror/policy-labels?mapping_id=…`) returns `has_relationship`, `labels[]`, source/destination info, `policy_type`, and `healthy`. Displayed as green/yellow SnapMirror® badge in the create-snapshot modal.
- Search now matches against VM names (via `s.vm_names`) in addition to snapshot names.

**UI — Accessibility (§11):**
- `trapFocus(el)` — Tab/Shift-Tab focus cycle is trapped within each open modal; first focusable element receives focus automatically on modal open.
- Global Escape handler — closes the topmost open modal (logViewModal → deleteConfirmModal → restoreConfirmModal → addScheduleForm) in z-order.
- `role="dialog" aria-modal="true"` added to all 4 main modals.
- `aria-live="polite" aria-atomic="true"` on the `#toast` region for screen-reader announcements.

### Changed
- **Snapshot table sort** — `created_at` now sorted using `Date.parse()` instead of lexicographic string comparison; timestamps sort correctly regardless of format.
- **Restore / Clone buttons** — "Full Restore" renamed to "Restore"; a separate "Clone" button appears next to it in the snapshot row actions; both navigate to the respective tab with the snapshot pre-selected.
- **`snapmirror.*` snapshots filtered** — snapshots whose names begin with `snapmirror.` are removed from all API responses; they are never shown in the UI or acted upon.
- **Create Snapshot modal** — redesigned as 960 px single-column layout; "Volume Mapping" label changed to "Datastore"; PVE Cluster/Node fields removed (not relevant to snapshot scope); VM list enlarged; SnapMirror section shown conditionally only when a relationship exists.
- **DR NFS config-volume sync removed** — approximately 900 lines of NFS config-volume sync code removed; replaced by the peer-to-peer sync architecture described above.

### Fixed
- **Timeline tooltip white background** — tooltip used `var(--bg-card,#fff)` which fell back to white in some themes; replaced with hardcoded dark values (`background: #1e293b; color: #e2e8f0`).
- **Timeline dot click with virtual scroll** — `tlClick()` previously only searched the DOM for `tr[data-snap-key]` rows, missing rows that were not rendered in the current virtual scroll window. Now computes `sc.scrollTop = idx * _vsRowH` to scroll the target into view, then defers `_vsRenderRows` by 40 ms so the row is in the DOM before the highlight flash fires.
- **DR background threads: `BlockingSwitchOutError` under gevent** — peer sync background thread now uses `gevent.spawn()` instead of a bare OS thread.
- **DR peer endpoints bypass CSRF and session auth** — `/peer/` routes are exempted from PegaProx session authentication and CSRF validation; they authenticate via the shared sync token.

## [1.1.2] – 2026-06-08

### Fixed
- **Edit NetApp System** — ONTAP endpoints could not be updated without deleting and re-adding them. Added `endpoints/update` API route and edit modal in the UI (name, host, username, password, SSL verify, SAN-only flag). Password field is optional — leave blank to keep the existing encrypted credential.
- **Endpoint list missing `skip_nfs` field** — `_list_endpoints` did not include `skip_nfs` in the SELECT query; the field was silently absent from API responses, causing the edit form to misread the current SAN-only setting.
- **AES-256-GCM decryption error message blank** — `InvalidTag` exceptions have an empty `str()` representation; the error logged on a failed credential decrypt was cryptically blank. The log message now includes the exception type name so the cause is identifiable.

## [1.1.1] – 2026-06-02

### Fixed
- **NVMe +Add Host: device not found after 60s** — `_add_host_nvme` used `find_new_nvme_device` which only detected brand-new devices. When the host NQN was already in the subsystem (e.g. from a previous run), `nvme connect-all` created no new device and the job timed out. Fixed by using `find_nvme_device_for_subsystem_nqn` (NQN-based lookup via `nvme list-subsys` + sysfs) and direct per-LIF connect instead of `connect-all`.
- **NVMe datastores lose connection after host reboot** — Plugin did not write NVMe LIF IPs to `/etc/nvme/discovery.conf` on PVE hosts. After a reboot, `nvme connect-all` could not find datastores whose LIFs were not already listed. Plugin now calls `ensure_nvme_discovery_entries()` during both initial NVMe provisioning and `+Add Host`, matching each LIF to the correct host interface by /16 subnet. Idempotent — only missing entries are appended.

## [1.1.0] – 2026-05-29

### Added
- **Import VMs from Datastore** *(Beta)* — adopt an existing ONTAP volume (iSCSI / NVMe-oF / NFS) with live VMs into the plugin without reprovisioning.
  Scans for LUNs / namespaces, auto-detects LVM VG, reads the snapmanifest, reconstructs VM inventory (VMIDs, names, disk layout), handles VMID conflicts with rename + disk file/LV rename, and registers the datastore. Covers cluster migrations, storage takeovers, and SnapMirror DR failover scenarios.
- **NVMe-oF end-to-end provisioning** — full provisioning wizard for NVMe-oF datastores (namespace + subsystem + NQN mapping), with automatic `nvme connect-all` handling, zombie controller cleanup, and sysfs-based device detection.
- **NVMe-oF DR clone** — clone VMs directly from a SnapMirror secondary using NVMe-oF, with `dd` progress output to the job log.
- **Plugin self-update** *(Settings → ⬆️ Plugin Update)* — check GitHub for the latest stable release or latest dev/main branch commit; apply updates with one click (downloads ZIP, replaces plugin files, preserves `config.json`). Displays release tag, publish date, and release notes excerpt.
- **Deploy Wizard** — integrated as a floating modal in Settings for first-time setup.
  Guides through 5 steps: System check → PVE Hosts → Packages → NetApp → Ready.
  - PVE nodes imported directly from PegaProx cluster configuration — no re-entry required.
  - SSH public key pushed automatically to every imported node using the cluster password.
  - Combined ONTAP setup: enter admin credentials → plugin creates a dedicated `pegaprox` account
    on ONTAP and registers the endpoint in one step; admin password is never stored.
  - Auto-creates PegaProx service user home directory if missing (direct mkdir → sudo fallback).
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
- **Add NetApp System** — Settings dialog now uses the same flow as the Deploy Wizard: enter admin credentials, plugin creates the ONTAP account and registers the endpoint in one step; admin password never stored.

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
- Deploy Wizard: ONTAP user creation now treats HTTP 409 (duplicate entry) as "already exists" — system can be registered even if the account was created outside the plugin.
- Deploy Wizard: `created_at` / `updated_at` NOT NULL constraint for `netapp_pve_hosts` and `netapp_endpoints` filled correctly on insert.

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
