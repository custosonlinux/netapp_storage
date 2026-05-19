"""
Settings API — SMTP / email notification configuration + DB export/import.

  settings/smtp           GET   – load SMTP config (password omitted)
  settings/smtp/save      POST  – save SMTP config
  settings/smtp/test      POST  – test SMTP connection with stored config
  settings/export         GET   – download all netapp_* tables as JSON
  settings/import         POST  – restore from exported JSON (idempotent upsert)
"""

import smtplib
import ssl
import email.mime.text
import email.mime.multipart
import json
import logging
from datetime import datetime, timezone

from flask import request, jsonify, Response
from pegaprox.core.db import get_db
from pegaprox.api.plugins import register_plugin_route

log = logging.getLogger(__name__)
from ..core._helpers import PLUGIN_ID  # noqa: F401


def _require_admin():
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get("user", "")
    users = load_users()
    if users.get(username, {}).get("role") != ROLE_ADMIN:
        return {"error": "Admin access required"}, 403
    return None


def _ensure_smtp_row(db):
    existing = db.query_one("SELECT id FROM netapp_smtp_config WHERE id='default'")
    if not existing:
        db.execute(
            "INSERT INTO netapp_smtp_config (id, updated_at) VALUES ('default', ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )


def _smtp_get():
    db = get_db()
    _ensure_smtp_row(db)
    row = db.query_one("SELECT * FROM netapp_smtp_config WHERE id='default'")
    d = dict(row)
    return jsonify({
        'host':         d.get('host', ''),
        'port':         d.get('port', 587),
        'username':     d.get('username', ''),
        'from_address': d.get('from_address', ''),
        'encryption':   d.get('encryption', 'starttls'),
        'enabled':      bool(d.get('enabled', 0)),
        'has_password': bool(d.get('password_encrypted', '')),
    })


def _smtp_save():
    err = _require_admin()
    if err:
        return err
    db = get_db()
    _ensure_smtp_row(db)
    data = request.get_json() or {}
    now = datetime.now(timezone.utc).isoformat()

    host         = data.get('host', '').strip()
    port         = int(data.get('port') or 587)
    username     = data.get('username', '').strip()
    from_address = data.get('from_address', '').strip()
    encryption   = data.get('encryption', 'starttls')
    enabled      = 1 if data.get('enabled') else 0

    if encryption not in ('starttls', 'ssl', 'none'):
        return jsonify({'error': 'Invalid encryption value'}), 400

    if data.get('password'):
        pw_enc = db._encrypt(data['password'])
        db.execute(
            "UPDATE netapp_smtp_config "
            "SET host=?,port=?,username=?,password_encrypted=?,"
            "from_address=?,encryption=?,enabled=?,updated_at=? WHERE id='default'",
            (host, port, username, pw_enc, from_address, encryption, enabled, now),
        )
    else:
        db.execute(
            "UPDATE netapp_smtp_config "
            "SET host=?,port=?,username=?,from_address=?,encryption=?,enabled=?,updated_at=? "
            "WHERE id='default'",
            (host, port, username, from_address, encryption, enabled, now),
        )
    log.info("[netapp_storage] SMTP config saved")
    return jsonify({'success': True})


def _smtp_test():
    err = _require_admin()
    if err:
        return err
    db = get_db()
    _ensure_smtp_row(db)
    row = db.query_one("SELECT * FROM netapp_smtp_config WHERE id='default'")
    d = dict(row)
    host       = d.get('host', '').strip()
    port       = int(d.get('port') or 587)
    username   = d.get('username', '').strip()
    password   = db._decrypt(d.get('password_encrypted', ''))
    encryption = d.get('encryption', 'starttls')

    if not host:
        return jsonify({'success': False, 'error': 'SMTP host not configured'})

    try:
        _test_smtp_connection(host, port, username, password, encryption)
        return jsonify({'success': True})
    except Exception as exc:
        log.warning(f"[netapp_storage] SMTP test failed: {exc}")
        return jsonify({'success': False, 'error': str(exc)})


def _test_smtp_connection(host, port, username, password, encryption):
    ctx = ssl.create_default_context()
    if encryption == 'ssl':
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=10) as s:
            if username and password:
                s.login(username, password)
    elif encryption == 'starttls':
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            if username and password:
                s.login(username, password)
    else:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            if username and password:
                s.login(username, password)


def send_job_notification(schedule_name, job_status, snap_name,
                          recipients_csv, notify_on, log_lines=None):
    """Send a snapshot job result notification email.

    Called from the snapshot engine after a scheduled job finishes.
    Recipients is a comma-separated string.  notify_on is 'all', 'failed', or 'success'.
    """
    if not recipients_csv or not recipients_csv.strip():
        return
    if notify_on == 'failed' and job_status != 'failed':
        return
    if notify_on == 'success' and job_status != 'done':
        return

    try:
        db = get_db()
        _ensure_smtp_row(db)
        row = db.query_one("SELECT * FROM netapp_smtp_config WHERE id='default'")
        d = dict(row)
        if not d.get('enabled'):
            return
        host       = d.get('host', '').strip()
        port       = int(d.get('port') or 587)
        username   = d.get('username', '').strip()
        password   = db._decrypt(d.get('password_encrypted', ''))
        encryption = d.get('encryption', 'starttls')
        from_addr  = d.get('from_address', '') or username
        if not host:
            return

        status_str = 'Success' if job_status == 'done' else job_status.capitalize()
        subject = f"[PegaProx] Snapshot {status_str}: {schedule_name} — {snap_name}"
        body_lines = [
            f"Schedule:  {schedule_name}",
            f"Snapshot:  {snap_name}",
            f"Status:    {status_str}",
            "",
        ]
        if log_lines:
            body_lines.append("--- Log ---")
            for entry in log_lines[-30:]:
                ts  = entry.get('ts', '')
                msg = entry.get('msg', str(entry))
                body_lines.append(f"{ts}  {msg}")

        body = "\n".join(body_lines)
        recipients = [r.strip() for r in recipients_csv.split(',') if r.strip()]

        msg = email.mime.multipart.MIMEMultipart()
        msg['From']    = from_addr
        msg['To']      = ', '.join(recipients)
        msg['Subject'] = subject
        msg.attach(email.mime.text.MIMEText(body, 'plain', 'utf-8'))

        _send_smtp(host, port, username, password, encryption, from_addr, recipients, msg.as_string())
        log.info(f"[netapp_storage] Notification sent for schedule '{schedule_name}' ({job_status})")
    except Exception as exc:
        log.warning(f"[netapp_storage] Notification send failed: {exc}")


def _send_smtp(host, port, username, password, encryption, from_addr, recipients, raw_message):
    ctx = ssl.create_default_context()
    if encryption == 'ssl':
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
            if username and password:
                s.login(username, password)
            s.sendmail(from_addr, recipients, raw_message)
    elif encryption == 'starttls':
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            if username and password:
                s.login(username, password)
            s.sendmail(from_addr, recipients, raw_message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            if username and password:
                s.login(username, password)
            s.sendmail(from_addr, recipients, raw_message)


def _notify_test():
    """Send a test notification to the supplied recipients."""
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    recipients_csv = data.get('recipients', '').strip()
    if not recipients_csv:
        return jsonify({'success': False, 'error': 'No recipients provided'})

    db = get_db()
    _ensure_smtp_row(db)
    row = db.query_one("SELECT * FROM netapp_smtp_config WHERE id='default'")
    d = dict(row)
    host       = d.get('host', '').strip()
    port       = int(d.get('port') or 587)
    username   = d.get('username', '').strip()
    password   = db._decrypt(d.get('password_encrypted', ''))
    encryption = d.get('encryption', 'starttls')
    from_addr  = d.get('from_address', '').strip() or username

    if not host:
        return jsonify({'success': False, 'error': 'SMTP host not configured'})

    recipients = [r.strip() for r in recipients_csv.split(',') if r.strip()]
    now_str = datetime.now(timezone.utc).isoformat()

    msg = email.mime.multipart.MIMEMultipart()
    msg['From']    = from_addr
    msg['To']      = ', '.join(recipients)
    msg['Subject'] = '[PegaProx] Test notification — NetApp ONTAP plugin'
    body = (
        "This is a test notification from the PegaProx NetApp ONTAP plugin.\n\n"
        f"Sent: {now_str}\n"
        "If you received this email, SMTP notifications are configured correctly."
    )
    msg.attach(email.mime.text.MIMEText(body, 'plain', 'utf-8'))

    try:
        _send_smtp(host, port, username, password, encryption, from_addr, recipients, msg.as_string())
        log.info(f"[netapp_storage] Test notification sent to {recipients_csv}")
        return jsonify({'success': True})
    except Exception as exc:
        log.warning(f"[netapp_storage] Test notification failed: {exc}")
        return jsonify({'success': False, 'error': str(exc)})


# Tables exported in dependency order (parents before children so import doesn't
# hit FK constraints on a fresh DB).
_EXPORT_TABLES = [
    'netapp_endpoints',
    'netapp_pve_hosts',
    'netapp_smtp_config',
    'netapp_volume_mapping',
    'netapp_provisioned_datastores',
    'netapp_snapshot_schedules',
]


def _db_export():
    err = _require_admin()
    if err:
        return err
    db = get_db()
    payload = {
        'version': '1',
        'plugin':  'netapp_storage',
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'tables': {},
    }
    for table in _EXPORT_TABLES:
        rows = db.query(f"SELECT * FROM {table}")
        payload['tables'][table] = [dict(r) for r in rows]

    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filename = f'netapp_storage_backup_{ts}.json'
    return Response(
        json.dumps(payload, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


def _db_import():
    err = _require_admin()
    if err:
        return err

    # Accept both JSON body and multipart file upload
    if request.content_type and 'multipart' in request.content_type:
        f = request.files.get('file')
        if not f:
            return jsonify({'error': 'No file uploaded'}), 400
        try:
            payload = json.load(f)
        except Exception as exc:
            return jsonify({'error': f'Invalid JSON: {exc}'}), 400
    else:
        try:
            payload = request.get_json(force=True) or {}
        except Exception as exc:
            return jsonify({'error': f'Invalid JSON: {exc}'}), 400

    if payload.get('plugin') != 'netapp_storage':
        return jsonify({'error': 'Backup file is not from the netapp_storage plugin'}), 400
    if str(payload.get('version')) != '1':
        return jsonify({'error': f"Unsupported backup version: {payload.get('version')}"}), 400

    tables = payload.get('tables', {})
    db = get_db()
    stats = {}

    for table in _EXPORT_TABLES:
        rows = tables.get(table, [])
        if not rows:
            stats[table] = 0
            continue
        inserted = 0
        for row in rows:
            cols = ', '.join(row.keys())
            placeholders = ', '.join(['?' for _ in row])
            sql = f'INSERT OR REPLACE INTO {table} ({cols}) VALUES ({placeholders})'
            try:
                db.execute(sql, list(row.values()))
                inserted += 1
            except Exception as exc:
                log.warning(f'[netapp_storage] import: skipped row in {table}: {exc}')
        stats[table] = inserted

    total = sum(stats.values())
    log.info(f'[netapp_storage] DB import: {total} rows restored — {stats}')
    return jsonify({'success': True, 'rows_imported': total, 'per_table': stats})


def register_routes():
    register_plugin_route(PLUGIN_ID, 'settings/smtp',           _smtp_get)
    register_plugin_route(PLUGIN_ID, 'settings/smtp/save',      _smtp_save)
    register_plugin_route(PLUGIN_ID, 'settings/smtp/test',      _smtp_test)
    register_plugin_route(PLUGIN_ID, 'settings/notify-test',    _notify_test)
    register_plugin_route(PLUGIN_ID, 'settings/export',         _db_export)
    register_plugin_route(PLUGIN_ID, 'settings/import',         _db_import)
