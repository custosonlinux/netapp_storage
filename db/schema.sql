-- NetApp ONTAP Plugin Schema
-- Runs in the central pegaprox.db (CREATE TABLE IF NOT EXISTS is idempotent).

CREATE TABLE IF NOT EXISTS netapp_endpoints (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    host            TEXT NOT NULL,
    username        TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    ssl_verify      INTEGER NOT NULL DEFAULT 1,
    skip_nfs        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- PVE hosts: direct PVE credentials for auto-discovery.
-- Independent of PegaProx cluster_managers.
CREATE TABLE IF NOT EXISTS netapp_pve_hosts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    host            TEXT NOT NULL,           -- PVE IP or FQDN
    port            INTEGER NOT NULL DEFAULT 8006,
    username        TEXT NOT NULL DEFAULT 'root@pam',
    password_encrypted TEXT NOT NULL,
    ssl_verify      INTEGER NOT NULL DEFAULT 0,
    nfs_ip          TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);

-- Auto-discovery cache: populated by the plugin, not manually.
-- One row per discovered storage (PVE storage ID ↔ ONTAP volume).
CREATE TABLE IF NOT EXISTS netapp_volume_mapping (
    id              TEXT PRIMARY KEY,
    endpoint_id     TEXT NOT NULL REFERENCES netapp_endpoints(id) ON DELETE CASCADE,
    pve_cluster_id  TEXT NOT NULL,
    pve_storage_id  TEXT NOT NULL,
    svm_name        TEXT NOT NULL,
    volume_uuid     TEXT NOT NULL,
    volume_name     TEXT NOT NULL,
    junction_path   TEXT NOT NULL,
    nfs_export_ip        TEXT NOT NULL DEFAULT '',
    nfs_mount_path       TEXT NOT NULL DEFAULT '',
    discovered_at        TEXT NOT NULL,
    storage_protocol     TEXT NOT NULL DEFAULT 'nfs',
    lun_uuid             TEXT NOT NULL DEFAULT '',
    lun_path             TEXT NOT NULL DEFAULT '',
    lvm_vg_name          TEXT NOT NULL DEFAULT '',
    lvm_type             TEXT NOT NULL DEFAULT '',
    lvm_pool_name        TEXT NOT NULL DEFAULT '',
    snapinfo_initialized INTEGER NOT NULL DEFAULT 0,
    snapinfo_lv_name     TEXT NOT NULL DEFAULT 'netapp_snapmanifest',
    created_at           TEXT NOT NULL DEFAULT '',
    UNIQUE(pve_cluster_id, pve_storage_id)
);

CREATE TABLE IF NOT EXISTS netapp_snapshots (
    id              TEXT PRIMARY KEY,
    mapping_id      TEXT NOT NULL REFERENCES netapp_volume_mapping(id) ON DELETE CASCADE,
    snap_name       TEXT NOT NULL,
    ontap_snap_uuid TEXT,
    consistency     TEXT NOT NULL DEFAULT 'crash',
    pve_cluster_id  TEXT NOT NULL,
    node            TEXT NOT NULL,
    vmids_json      TEXT NOT NULL DEFAULT '[]',
    vm_types_json   TEXT NOT NULL DEFAULT '{}',
    manifest_path   TEXT NOT NULL DEFAULT '',
    manifest_json   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending',
    error           TEXT DEFAULT '',
    schedule_id     TEXT DEFAULT '',
    label           TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    completed_at    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS netapp_jobs (
    id              TEXT PRIMARY KEY,
    job_type        TEXT NOT NULL,
    snapshot_id     TEXT,
    vmid            INTEGER,
    node            TEXT,
    status          TEXT NOT NULL DEFAULT 'running',
    progress_pct    INTEGER DEFAULT 0,
    log_json        TEXT DEFAULT '[]',
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    completed_at    TEXT DEFAULT ''
);

-- Schedules for automatic snapshots.
-- SnapMirror® relationship cache: populated by the plugin, not manually.
CREATE TABLE IF NOT EXISTS netapp_snapmirror_relationships (
    id                  TEXT PRIMARY KEY,
    source_endpoint_id  TEXT NOT NULL,
    source_volume_uuid  TEXT NOT NULL,
    source_svm          TEXT NOT NULL,
    source_volume       TEXT NOT NULL,
    dest_endpoint_id    TEXT NOT NULL DEFAULT '',
    dest_cluster_name   TEXT NOT NULL DEFAULT '',
    dest_svm            TEXT NOT NULL,
    dest_volume         TEXT NOT NULL,
    dest_volume_uuid    TEXT NOT NULL DEFAULT '',
    dest_nfs_ip         TEXT NOT NULL DEFAULT '',
    dest_junction_path  TEXT NOT NULL DEFAULT '',
    relationship_uuid   TEXT NOT NULL,
    policy_type         TEXT NOT NULL DEFAULT '',
    state               TEXT NOT NULL DEFAULT '',
    healthy             INTEGER NOT NULL DEFAULT 1,
    lag_time            TEXT NOT NULL DEFAULT '',
    last_transfer_time  TEXT NOT NULL DEFAULT '',
    last_scanned_at     TEXT NOT NULL,
    UNIQUE(relationship_uuid)
);

-- Single-row config table for SMTP/email notifications (id is always 'default').
CREATE TABLE IF NOT EXISTS netapp_smtp_config (
    id                 TEXT PRIMARY KEY DEFAULT 'default',
    host               TEXT NOT NULL DEFAULT '',
    port               INTEGER NOT NULL DEFAULT 587,
    username           TEXT NOT NULL DEFAULT '',
    password_encrypted TEXT NOT NULL DEFAULT '',
    from_address       TEXT NOT NULL DEFAULT '',
    encryption         TEXT NOT NULL DEFAULT 'starttls',
    enabled            INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL DEFAULT ''
);

-- Provisioning: datastores managed end-to-end by this plugin.
-- Tracks ONTAP objects + host-side state so the plugin can resize/remove cleanly.
CREATE TABLE IF NOT EXISTS netapp_provisioned_datastores (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL DEFAULT '',          -- user-visible label
    endpoint_id         TEXT NOT NULL REFERENCES netapp_endpoints(id) ON DELETE RESTRICT,
    svm_name            TEXT NOT NULL DEFAULT '',
    volume_uuid         TEXT NOT NULL DEFAULT '',
    volume_name         TEXT NOT NULL DEFAULT '',
    protocol            TEXT NOT NULL DEFAULT 'iscsi',     -- iscsi | nvme | nfs
    -- iSCSI-specific
    lun_uuid            TEXT NOT NULL DEFAULT '',
    lun_path            TEXT NOT NULL DEFAULT '',
    igroup_uuid         TEXT NOT NULL DEFAULT '',
    igroup_name         TEXT NOT NULL DEFAULT '',
    -- NVMe-oF-specific
    ns_uuid             TEXT NOT NULL DEFAULT '',
    subsystem_uuid      TEXT NOT NULL DEFAULT '',
    subsystem_name      TEXT NOT NULL DEFAULT '',
    -- SAN: LVM
    vg_name             TEXT NOT NULL DEFAULT '',
    lvm_type            TEXT NOT NULL DEFAULT 'linear',    -- linear | thin
    lvm_pool_name       TEXT NOT NULL DEFAULT '',
    -- NFS-specific
    nfs_junction_path   TEXT NOT NULL DEFAULT '',
    -- PVE integration
    pve_storage_id      TEXT NOT NULL DEFAULT '',          -- pvesm storage name
    pve_host_ids        TEXT NOT NULL DEFAULT '[]',        -- JSON array of netapp_pve_hosts.id
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    -- Lifecycle
    status              TEXT NOT NULL DEFAULT 'active',    -- provisioning | active | error | removing
    error_message       TEXT NOT NULL DEFAULT '',
    imported_from       TEXT NOT NULL DEFAULT '',          -- '' | 'recovery_bind' | 'import'
    created_by          TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL DEFAULT ''
);

-- ── Disaster Recovery ─────────────────────────────────────────────────────

-- Plugin-wide config: role (MASTER/DR_SLAVE/DR_TEST) and NFS config volume
CREATE TABLE IF NOT EXISTS netapp_plugin_config (
    id                TEXT PRIMARY KEY DEFAULT 'default',
    role              TEXT NOT NULL DEFAULT 'MASTER',      -- MASTER | DR_SLAVE | DR_TEST
    role_forced       INTEGER NOT NULL DEFAULT 0,          -- 1 = admin override, 0 = auto-detected
    config_volume_id  TEXT NOT NULL DEFAULT '',            -- netapp_volume_mapping.id
    config_mount_path TEXT NOT NULL DEFAULT '',            -- local NFS mount path for config volume
    last_role_check   TEXT NOT NULL DEFAULT '',
    updated_at        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS netapp_dr_sites (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    endpoint_id     TEXT NOT NULL REFERENCES netapp_endpoints(id) ON DELETE RESTRICT,
    pve_host_ids    TEXT NOT NULL DEFAULT '[]',
    description     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS netapp_dr_plans (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    dr_site_id       TEXT NOT NULL REFERENCES netapp_dr_sites(id) ON DELETE RESTRICT,
    state            TEXT NOT NULL DEFAULT 'standby',  -- standby | failover_running | failed_over | failback_running
    notes            TEXT NOT NULL DEFAULT '',
    last_failover_at TEXT NOT NULL DEFAULT '',
    last_test_at     TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS netapp_dr_plan_entries (
    id                  TEXT PRIMARY KEY,
    plan_id             TEXT NOT NULL REFERENCES netapp_dr_plans(id) ON DELETE CASCADE,
    source_endpoint_id  TEXT NOT NULL,
    source_svm          TEXT NOT NULL,
    source_volume       TEXT NOT NULL,
    snapmirror_rel_uuid TEXT NOT NULL DEFAULT '',
    dr_endpoint_id      TEXT NOT NULL DEFAULT '',
    dr_svm              TEXT NOT NULL DEFAULT '',
    dr_volume           TEXT NOT NULL DEFAULT '',
    dr_pve_storage_id   TEXT NOT NULL DEFAULT '',
    dr_pve_host_ids     TEXT NOT NULL DEFAULT '[]',
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS netapp_dr_vm_groups (
    id                TEXT PRIMARY KEY,
    plan_id           TEXT NOT NULL REFERENCES netapp_dr_plans(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    group_type        TEXT NOT NULL DEFAULT 'standard',  -- core | standard
    sort_order        INTEGER NOT NULL DEFAULT 0,
    start_mode        TEXT NOT NULL DEFAULT 'auto',      -- auto | manual (core always auto)
    startup_delay_sec INTEGER NOT NULL DEFAULT 30,
    max_parallel      INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS netapp_dr_vm_assignments (
    id          TEXT PRIMARY KEY,
    group_id    TEXT NOT NULL REFERENCES netapp_dr_vm_groups(id) ON DELETE CASCADE,
    vmid        INTEGER NOT NULL,
    vm_name     TEXT NOT NULL DEFAULT '',
    target_node TEXT NOT NULL DEFAULT '',
    start_order INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);

-- ── Snapshot Schedules ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS netapp_snapshot_schedules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    mapping_id      TEXT NOT NULL REFERENCES netapp_volume_mapping(id) ON DELETE CASCADE,
    vmids_json      TEXT NOT NULL DEFAULT '[]',
    cron_expr       TEXT NOT NULL,
    retention_count INTEGER NOT NULL DEFAULT 7,
    consistency     TEXT NOT NULL DEFAULT 'crash',
    enabled         INTEGER NOT NULL DEFAULT 1,
    label           TEXT DEFAULT '',
    pre_script      TEXT DEFAULT '',
    post_script     TEXT DEFAULT '',
    last_run_at     TEXT DEFAULT '',
    last_run_status TEXT DEFAULT '',
    notify_enabled  INTEGER NOT NULL DEFAULT 0,
    notify_on       TEXT NOT NULL DEFAULT 'all',
    notify_recipients TEXT NOT NULL DEFAULT '',
    sync_vmids      INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
