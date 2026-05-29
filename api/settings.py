"""
Settings API — SMTP / email notification configuration + DB export/import + plugin updater.

  settings/smtp           GET   – load SMTP config (password omitted)
  settings/smtp/save      POST  – save SMTP config
  settings/smtp/test      POST  – test SMTP connection with stored config
  settings/export         GET   – download all netapp_* tables as JSON
  settings/import         POST  – restore from exported JSON (idempotent upsert)
  settings/update/info    GET   – check GitHub for latest release / branch commits
  settings/update/apply   POST  – download and apply a plugin update from GitHub
"""

import os
import smtplib
import ssl
import email.mime.text
import email.mime.multipart
import json
import logging
from datetime import datetime, timezone

# Plugin directory (two levels up from this file: api/ → netapp_storage/)
_PLUGIN_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GITHUB_REPO = "custosonlinux/netapp_storage"
_GITHUB_API  = "https://api.github.com"

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


def _log_severity(msg):
    """Classify a job log message as 'err', 'warn', or 'info'."""
    ml = msg.lower()
    if ml.startswith("error:") or ml.startswith("err:") or "error" in ml[:12]:
        return "err"
    if ml.startswith("warning:") or ml.startswith("warn:") or "warn" in ml[:12]:
        return "warn"
    return "info"


def _format_lag(s):
    """Convert ISO 8601 duration (P0DT4H23M5S) to a human-readable string."""
    import re
    if not s:
        return "–"
    m = re.match(r'P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?', s)
    if not m:
        return s
    parts = []
    if m.group(1): parts.append(f"{m.group(1)}d")
    if m.group(2): parts.append(f"{m.group(2)}h")
    if m.group(3): parts.append(f"{m.group(3)}m")
    if m.group(4): parts.append(f"{int(float(m.group(4)))}s")
    return " ".join(parts) if parts else "0s"


def _build_notification_email(subject, schedule_name, snap_name, job_status, log_lines=None,
                               extra_rows=None, vm_list=None, datastore=None):
    """
    Returns (html_body, plain_body).

    Builds an HTML email with:
    - Colour-coded status banner (green / amber / red)
    - Summary table
    - Dark terminal block with [INFO]/[WARN]/[ERR]-tagged log lines
    """
    # ── Determine overall severity ────────────────────────────────────────────
    entries = []
    if log_lines:
        for entry in log_lines[-50:]:
            ts  = entry.get('ts', '')[:19].replace('T', ' ')
            msg = entry.get('msg', str(entry))
            sev = _log_severity(msg)
            entries.append((ts, sev, msg))

    has_err  = any(s == "err"  for _, s, _ in entries)
    has_warn = any(s == "warn" for _, s, _ in entries)
    is_done  = job_status == 'done'

    if not is_done or has_err:
        overall = "err"
    elif has_warn:
        overall = "warn"
    else:
        overall = "ok"

    # ── Visual config per overall status ─────────────────────────────────────
    _cfg = {
        "ok":   dict(banner="#16a34a", icon="✓", label="Snapshot Successful",
                     dot_color="#16a34a", dot_label="Success"),
        "warn": dict(banner="#d97706", icon="⚠", label="Snapshot Completed with Warnings",
                     dot_color="#d97706", dot_label="Success (with warnings)"),
        "err":  dict(banner="#dc2626", icon="✗", label="Snapshot Failed",
                     dot_color="#dc2626", dot_label="Failed"),
    }
    cfg = _cfg[overall]

    status_label = "Success" if is_done else "Failed"

    # ── Summary rows ─────────────────────────────────────────────────────────
    summary_rows = [
        ("Schedule",  schedule_name),
        ("Snapshot",  snap_name),
        ("Datastore", datastore) if datastore else None,
        ("Status",    f'<span style="color:{cfg["dot_color"]};font-weight:700">● {cfg["dot_label"]}</span>'),
    ]
    summary_rows = [r for r in summary_rows if r is not None]
    if vm_list:
        def _vm_badge(vm):
            vmid = vm.get("vmid", "?")
            name = vm.get("name", "")
            vtype = (vm.get("vm_type") or "qemu").upper()
            label = f"{vtype} {vmid}" + (f" — {name}" if name else "")
            bg = "#1d4ed8" if vtype == "QEMU" else "#6d28d9"
            return (f'<span style="display:inline-block;background:{bg};color:#fff;'
                    f'border-radius:4px;padding:1px 6px;font-size:11px;margin:1px 2px 1px 0">'
                    f'{label}</span>')
        vm_html = "".join(_vm_badge(v) for v in vm_list)
        summary_rows.append(("VMs", vm_html))
    if extra_rows:
        summary_rows.extend(extra_rows)

    summary_html = "".join(
        f'<tr>'
        f'<td style="padding:7px 12px 7px 0;color:#6b7280;white-space:nowrap;vertical-align:top">{k}</td>'
        f'<td style="padding:7px 0;font-weight:500;word-break:break-all">{v}</td>'
        f'</tr>'
        for k, v in summary_rows
    )

    # ── Log lines HTML ────────────────────────────────────────────────────────
    _sev_color = {"err": "#f87171", "warn": "#fbbf24", "info": "#a3e4b0"}
    _sev_tag   = {"err": "[ERR] ", "warn": "[WARN]", "info": "[INFO]"}

    def _esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    log_rows_html = ""
    if entries:
        for ts, sev, msg in entries:
            color = _sev_color[sev]
            tag   = _sev_tag[sev]
            log_rows_html += (
                f'<div style="margin:1px 0">'
                f'<span style="color:#6b7280;user-select:none">{_esc(ts)} </span>'
                f'<span style="color:{color};font-weight:700;user-select:none">{tag} </span>'
                f'<span style="color:{color if sev != "info" else "#d1fae5"}">{_esc(msg)}</span>'
                f'</div>'
            )
    else:
        log_rows_html = '<div style="color:#6b7280;font-style:italic">No log entries.</div>'

    # ── Full HTML ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif">
<div style="max-width:680px;margin:0 auto">

  <!-- Status banner -->
  <div style="background:{cfg['banner']};border-radius:8px 8px 0 0;padding:22px 28px;color:#fff">
    <div style="font-size:22px;font-weight:700">{cfg['icon']}&nbsp; {cfg['label']}</div>
    <div style="font-size:13px;opacity:.85;margin-top:4px">NetApp ONTAP Storage Plugin · PegaProx</div>
  </div>

  <!-- Summary card -->
  <div style="background:#fff;padding:24px 28px;border-left:1px solid #e5e7eb;border-right:1px solid #e5e7eb">
    <table style="width:100%;border-collapse:collapse">
      {summary_html}
    </table>
  </div>

  <!-- Log terminal -->
  <div style="background:#0f172a;border-radius:0 0 8px 8px;padding:20px 24px">
    <div style="font-size:11px;font-weight:700;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-bottom:12px">
      Job Log
    </div>
    <div style="font-family:'Courier New',Courier,monospace;font-size:11.5px;line-height:1.65">
      {log_rows_html}
    </div>
  </div>

  <!-- Footer -->
  <div style="text-align:center;font-size:11px;color:#9ca3af;margin-top:14px">
    PegaProx NetApp ONTAP Plugin
  </div>

</div>
</body>
</html>"""

    # ── Plain-text fallback ───────────────────────────────────────────────────
    plain_lines = [
        subject,
        "=" * len(subject),
        "",
        f"Schedule  : {schedule_name}",
        f"Snapshot  : {snap_name}",
    ]
    if datastore:
        plain_lines.append(f"Datastore : {datastore}")
    plain_lines.append(f"Status    : {status_label}")
    if vm_list:
        vm_labels = [
            f"{(v.get('vm_type') or 'qemu').upper()} {v.get('vmid','?')}"
            + (f" ({v['name']})" if v.get('name') else "")
            for v in vm_list
        ]
        plain_lines.append(f"VMs      : {', '.join(vm_labels)}")
    plain_lines.append("")
    if entries:
        plain_lines.append("--- Log ---")
        for ts, sev, msg in entries:
            plain_lines.append(f"{ts}  {_sev_tag[sev]}  {msg}")

    return html, "\n".join(plain_lines)


def send_job_notification(schedule_name, job_status, snap_name,
                          recipients_csv, notify_on, log_lines=None, vm_list=None,
                          datastore=None, snapmirror_info=None):
    """Send a snapshot job result notification email.

    Called from the snapshot engine after a scheduled job finishes.
    Recipients is a comma-separated string.  notify_on is 'all', 'failed', or 'success'.

    snapmirror_info: optional dict with keys exists, dest_cluster, dest_svm, dest_volume,
                     state, healthy, lag_time, last_transfer_time  (from the DB relationship
                     row for this volume).  Shown as an extra summary row in the email.
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
        subject    = f"[PegaProx] Snapshot {status_str}: {schedule_name} — {snap_name}"

        # Build SnapMirror extra row for the summary card
        extra_rows = []
        if snapmirror_info and snapmirror_info.get("exists"):
            sm = snapmirror_info
            dest     = sm.get("dest_cluster") or sm.get("dest_svm") or "?"
            state    = sm.get("state") or "?"
            lag_str  = _format_lag(sm.get("lag_time") or "")
            last_t   = (sm.get("last_transfer_time") or "")[:16].replace("T", " ")
            if not sm.get("healthy") or state in ("broken_off", "broken-off"):
                color, icon = "#dc2626", "✗"
            elif state == "snapmirrored":
                color, icon = "#16a34a", "⟳"
            else:
                color, icon = "#d97706", "⚠"
            sm_val = (
                f'<span style="color:{color};font-weight:700">{icon} {dest}</span>'
                f' <span style="color:#6b7280;font-size:12px">({state}, lag: {lag_str}'
                f'{", last: " + last_t if last_t else ""})</span>'
            )
            extra_rows.append(("SnapMirror®", sm_val))
        elif snapmirror_info and not snapmirror_info.get("exists"):
            extra_rows.append(("SnapMirror®", '<span style="color:#6b7280">– not configured</span>'))

        html_body, plain_body = _build_notification_email(
            subject, schedule_name, snap_name, job_status, log_lines,
            extra_rows=extra_rows if extra_rows else None,
            vm_list=vm_list, datastore=datastore)

        recipients = [r.strip() for r in recipients_csv.split(',') if r.strip()]
        msg = email.mime.multipart.MIMEMultipart('alternative')
        msg['From']    = from_addr
        msg['To']      = ', '.join(recipients)
        msg['Subject'] = subject
        msg.attach(email.mime.text.MIMEText(plain_body, 'plain', 'utf-8'))
        msg.attach(email.mime.text.MIMEText(html_body,  'html',  'utf-8'))

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

    subject = '[PegaProx] Test notification — NetApp ONTAP plugin'
    fake_log = [
        {"ts": now_str, "msg": "SMTP connection test initiated"},
        {"ts": now_str, "msg": "If you received this email, notifications are configured correctly."},
    ]
    fake_vms = [
        {"vmid": 100, "name": "web-prod-01",  "vm_type": "qemu"},
        {"vmid": 101, "name": "db-prod-01",   "vm_type": "qemu"},
        {"vmid": 200, "name": "alpine-proxy", "vm_type": "lxc"},
    ]
    html_body, plain_body = _build_notification_email(
        subject, "— test —", "— test —", "done", fake_log,
        extra_rows=[("Sent", now_str)], vm_list=fake_vms,
        datastore="nfs-prod-01",
    )
    msg = email.mime.multipart.MIMEMultipart('alternative')
    msg['From']    = from_addr
    msg['To']      = ', '.join(recipients)
    msg['Subject'] = subject
    msg.attach(email.mime.text.MIMEText(plain_body, 'plain', 'utf-8'))
    msg.attach(email.mime.text.MIMEText(html_body,  'html',  'utf-8'))

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


# ── Plugin Updater ────────────────────────────────────────────────────────────

def _get_current_version():
    """Read version from manifest.json."""
    manifest = os.path.join(_PLUGIN_DIR, 'manifest.json')
    try:
        with open(manifest) as f:
            return json.load(f).get('version', 'unknown')
    except Exception:
        return 'unknown'


def _gh_request(path):
    """Make a GitHub API GET request, returns parsed JSON or raises."""
    import urllib.request
    url = f"{_GITHUB_API}{path}"
    req = urllib.request.Request(
        url,
        headers={
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'netapp-ontap-plugin/updater',
        },
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _update_info():
    """GET — return current version + GitHub release/branch info."""
    result = {
        'current_version': _get_current_version(),
        'release': None,
        'branches': {},
    }

    # Latest release
    try:
        data = _gh_request(f"/repos/{_GITHUB_REPO}/releases/latest")
        result['release'] = {
            'tag':          data.get('tag_name', ''),
            'name':         data.get('name', ''),
            'published_at': data.get('published_at', ''),
            'url':          data.get('html_url', ''),
            'body':         (data.get('body') or '')[:600],
        }
    except Exception as exc:
        result['release'] = {'error': str(exc)}

    # Latest commit on main and dev branches
    for branch in ('main', 'dev'):
        try:
            data = _gh_request(f"/repos/{_GITHUB_REPO}/commits/{branch}")
            result['branches'][branch] = {
                'sha':     data['sha'][:8],
                'sha_full': data['sha'],
                'date':    data['commit']['committer']['date'],
                'message': data['commit']['message'].splitlines()[0][:120],
            }
        except Exception as exc:
            result['branches'][branch] = {'error': str(exc)}

    return jsonify(result)


def _update_apply():
    """POST {branch: 'main'|'dev'} — download ZIP from GitHub and overwrite plugin files."""
    err = _require_admin()
    if err:
        return err

    import urllib.request
    import urllib.error
    import zipfile
    import tempfile
    import shutil

    data    = request.get_json() or {}
    branch  = data.get('branch', 'main')
    if branch not in ('main', 'dev'):
        return jsonify({'error': 'Invalid branch — must be main or dev'}), 400

    zip_url = f"https://github.com/{_GITHUB_REPO}/archive/refs/heads/{branch}.zip"
    tmp_zip = None

    try:
        # ── 1. Download archive ──────────────────────────────────────────────
        log.info(f"[netapp_storage] Downloading update from {zip_url}")
        req = urllib.request.Request(zip_url, headers={'User-Agent': 'netapp-ontap-plugin/updater'})
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            tmp_zip = tmp.name
            with urllib.request.urlopen(req, timeout=90) as r:
                shutil.copyfileobj(r, tmp)

        # ── 2. Extract + copy ────────────────────────────────────────────────
        # Files / dirs that must never be overwritten (user data)
        _SKIP_FILES = {'config.json'}
        _SKIP_DIRS  = {'__pycache__'}

        copied = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(tmp_zip) as zf:
                zf.extractall(tmp_dir)

            # GitHub zips always have one top-level folder (repo-branch/)
            entries = os.listdir(tmp_dir)
            if not entries:
                return jsonify({'error': 'Downloaded archive is empty'}), 500
            src_root = os.path.join(tmp_dir, entries[0])

            for root, dirs, files in os.walk(src_root):
                # Prune dirs we don't want to recurse into
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

                rel_root  = os.path.relpath(root, src_root)
                dest_root = os.path.join(_PLUGIN_DIR, rel_root) if rel_root != '.' else _PLUGIN_DIR
                os.makedirs(dest_root, exist_ok=True)

                for fname in files:
                    if fname in _SKIP_FILES or fname.endswith('.pyc'):
                        continue
                    src_f  = os.path.join(root, fname)
                    dest_f = os.path.join(dest_root, fname)
                    shutil.copy2(src_f, dest_f)
                    rel_path = os.path.join(rel_root, fname) if rel_root != '.' else fname
                    copied.append(rel_path)

        log.info(f"[netapp_storage] Update applied from '{branch}': {len(copied)} files replaced")
        return jsonify({
            'success':       True,
            'branch':        branch,
            'files_updated': len(copied),
            'message':       (
                f'Plugin updated from branch \'{branch}\'. '
                'Please restart PegaProx to activate the new version.'
            ),
        })

    except Exception as exc:
        log.error(f"[netapp_storage] Update apply failed: {exc}")
        return jsonify({'error': str(exc)}), 500
    finally:
        if tmp_zip and os.path.exists(tmp_zip):
            try:
                os.unlink(tmp_zip)
            except Exception:
                pass


def register_routes():
    register_plugin_route(PLUGIN_ID, 'settings/smtp',           _smtp_get)
    register_plugin_route(PLUGIN_ID, 'settings/smtp/save',      _smtp_save)
    register_plugin_route(PLUGIN_ID, 'settings/smtp/test',      _smtp_test)
    register_plugin_route(PLUGIN_ID, 'settings/notify-test',    _notify_test)
    register_plugin_route(PLUGIN_ID, 'settings/export',         _db_export)
    register_plugin_route(PLUGIN_ID, 'settings/import',         _db_import)
    register_plugin_route(PLUGIN_ID, 'settings/update/info',    _update_info)
    register_plugin_route(PLUGIN_ID, 'settings/update/apply',   _update_apply)
