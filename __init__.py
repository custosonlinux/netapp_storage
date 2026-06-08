"""
NetApp ONTAP Snapshot / Restore Plugin for PegaProx

Registers all API routes, initialises the DB tables, and mounts a
management UI under /netapp-snapshots inside the Flask app.

Requires: requests, sshpass or SSH key auth for PVE nodes.
"""

import os
import logging

from pegaprox.core.db import get_db

log = logging.getLogger(__name__)

PLUGIN_NAME = "NetApp Storage"
PLUGIN_DIR  = os.path.dirname(os.path.abspath(__file__))
# Must match the directory name — PegaProx uses the folder name as the plugin ID.
PLUGIN_ID   = os.path.basename(PLUGIN_DIR)


def _migrate_dr_v3(db):
    """Recreate netapp_dr_plans without FK constraint on dr_site_id (v3.0 peer sync)."""
    try:
        # Check if the table has an FK reference to netapp_dr_sites
        row = db.query_one("SELECT sql FROM sqlite_master WHERE type='table' AND name='netapp_dr_plans'")
        if not row:
            return  # table doesn't exist yet, schema.sql will create it correctly
        ddl = (dict(row).get("sql") or "").lower()
        if "references netapp_dr_sites" not in ddl:
            return  # already migrated
        log.info("[netapp_storage] Migrating netapp_dr_plans — removing FK constraint on dr_site_id …")
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute("""
            CREATE TABLE IF NOT EXISTS netapp_dr_plans_new (
                id               TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                dr_site_id       TEXT NOT NULL DEFAULT '',
                state            TEXT NOT NULL DEFAULT 'standby',
                notes            TEXT NOT NULL DEFAULT '',
                last_failover_at TEXT NOT NULL DEFAULT '',
                last_test_at     TEXT NOT NULL DEFAULT '',
                created_by       TEXT NOT NULL,
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL
            )
        """)
        db.execute("INSERT INTO netapp_dr_plans_new SELECT id,name,COALESCE(dr_site_id,''),state,notes,last_failover_at,last_test_at,created_by,created_at,updated_at FROM netapp_dr_plans")
        db.execute("DROP TABLE netapp_dr_plans")
        db.execute("ALTER TABLE netapp_dr_plans_new RENAME TO netapp_dr_plans")
        db.execute("PRAGMA foreign_keys = ON")
        log.info("[netapp_storage] netapp_dr_plans FK migration done")
    except Exception as exc:
        log.warning(f"[netapp_storage] DR v3 plan migration failed: {exc}")
        try:
            db.execute("PRAGMA foreign_keys = ON")
        except Exception:
            pass


def _migrate_dr_v2(db):
    """Drop old DR schema (v1, identified by sync_host column) and recreate fresh."""
    try:
        rows = db.query("PRAGMA table_info(netapp_dr_sites)")
        cols = {r["name"] for r in (rows or [])}
        if "sync_host" in cols:
            log.info("[netapp_storage] Migrating DR schema to v2 — dropping old DR tables …")
            for tbl in [
                "netapp_dr_vm_assignments", "netapp_dr_vm_groups",
                "netapp_dr_plan_entries", "netapp_dr_plans",
                "netapp_dr_sites", "netapp_dr_jobs",
            ]:
                try:
                    db.execute(f"DROP TABLE IF EXISTS {tbl}")
                except Exception:
                    pass
            log.info("[netapp_storage] Old DR tables dropped — new schema will be created from schema.sql")
    except Exception as exc:
        log.warning(f"[netapp_storage] DR v2 migration check failed: {exc}")


def _init_db():
    """Creates plugin tables in the central pegaprox.db (idempotent).

    Also runs ALTER TABLE migrations for existing installations missing new columns.
    """
    schema_path = os.path.join(PLUGIN_DIR, "db", "schema.sql")
    try:
        with open(schema_path) as f:
            sql = f.read()
        db = get_db()
        _migrate_dr_v2(db)  # drop old DR schema before creating new tables
        _migrate_dr_v3(db)  # remove FK constraint on dr_site_id
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                db.execute(stmt)

        # Migrations: add columns missing in older installations
        _add_column_if_missing(db, "netapp_volume_mapping", "nfs_export_ip",  "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "nfs_mount_path", "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "discovered_at",  "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshots", "vm_types_json", "TEXT NOT NULL DEFAULT '{}'")
        _add_column_if_missing(db, "netapp_snapshots", "manifest_json", "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshots", "schedule_id", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshots", "label", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshots", "ontap_snap_uuid", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshots", "error", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "label", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "snapmirror_update",    "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "notify_enabled",       "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "notify_on",            "TEXT NOT NULL DEFAULT 'all'")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "notify_recipients",    "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "pre_script",  "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "post_script", "TEXT DEFAULT ''")
        _add_column_if_missing(db, "netapp_snapshot_schedules", "sync_vmids",  "INTEGER NOT NULL DEFAULT 0")

        _add_column_if_missing(db, "netapp_pve_hosts",  "nfs_ip",        "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_endpoints", "skip_nfs",      "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "netapp_endpoints", "san_optimized", "INTEGER NOT NULL DEFAULT 0")

        # v2: plugin_config new columns (config via PVE SSH)
        _add_column_if_missing(db, "netapp_plugin_config", "config_storage_id",   "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_plugin_config", "config_pve_host_ids", "TEXT NOT NULL DEFAULT '[]'")

        # v1.1: recovery bind
        _add_column_if_missing(db, "netapp_provisioned_datastores", "imported_from",
                               "TEXT NOT NULL DEFAULT ''")

        # v1.2: DR site SSH test log + sync password
        _add_column_if_missing(db, "netapp_dr_sites", "last_test_at",          "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_dr_sites", "last_test_result",       "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_dr_sites", "sync_password_encrypted","TEXT NOT NULL DEFAULT ''")

        # SAN extension (iSCSI / NVMe-oF)
        _add_column_if_missing(db, "netapp_volume_mapping", "storage_protocol",     "TEXT NOT NULL DEFAULT 'nfs'")
        _add_column_if_missing(db, "netapp_volume_mapping", "lun_uuid",              "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "lun_path",              "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "lvm_vg_name",           "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "lvm_type",              "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "lvm_pool_name",         "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(db, "netapp_volume_mapping", "snapinfo_initialized",  "INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(db, "netapp_volume_mapping", "snapinfo_lv_name",      "TEXT NOT NULL DEFAULT 'netapp_snapmanifest'")
        _add_column_if_missing(db, "netapp_volume_mapping", "created_at",            "TEXT NOT NULL DEFAULT ''")

        log.info("[netapp_storage] DB tables initialised")
    except Exception as e:
        log.error(f"[netapp_storage] DB init failed: {e}")
        raise


def _add_column_if_missing(db, table, column, col_def):
    try:
        rows = db.query(f"PRAGMA table_info({table})")
        existing = {r["name"] for r in rows}
        if column not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            log.info(f"[netapp_storage] Added column {table}.{column}")
    except Exception as e:
        log.warning(f"[netapp_storage] Migration {table}.{column} failed: {e}")


def register(app):
    """Called by PegaProx when the plugin is activated."""
    _init_db()

    from .api.snapshots import register_routes as reg_snap
    from .api.restore import register_routes as reg_restore
    from .api.schedules import register_routes as reg_schedules, start_scheduler
    from .api.clone import register_routes as reg_clone
    from .api.snapmirror import register_routes as reg_snapmirror
    from .api.settings import register_routes as reg_settings
    from .api.provisioning import register_routes as reg_provisioning
    from .api.recovery import register_routes as reg_recovery
    from .api.setup import register_routes as reg_setup
    from .api.dr import register_routes as reg_dr

    reg_snap()
    reg_restore()
    reg_schedules()
    reg_clone()
    reg_snapmirror()
    reg_settings()
    reg_provisioning()
    reg_recovery()
    reg_setup()
    reg_dr()
    start_scheduler()

    log.info(f"[PLUGINS] {PLUGIN_NAME} registriert (UI: /api/plugins/netapp_storage/api/ui)")
