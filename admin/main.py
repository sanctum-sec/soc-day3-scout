import os
import sys
import json
import secrets
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "/home/ubuntu/app")

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from storage.db import (
    get_feed_health, get_ioc_totals, get_top_queried,
    get_broadcast_queue_depth
)

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "scout2026")
LOG_PATH   = Path(os.getenv("LOG_DIR", "/home/ubuntu/app/logs")) / "security.log"

app = FastAPI(title="Scout Admin", docs_url=None, redoc_url=None)
security = HTTPBasic()


def require_auth(creds: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(creds.username, ADMIN_USER)
    ok_pass = secrets.compare_digest(creds.password, ADMIN_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return creds.username


def render_feed_health(rows):
    if not rows:
        return "<p>No feed data yet.</p>"
    html = "<table><tr><th>Feed</th><th>Last Run</th><th>Status</th><th>Count</th><th>Error</th></tr>"
    for r in rows:
        status_cls = "ok" if r.get("status") == "ok" else "err"
        html += (
            f"<tr class='{status_cls}'>"
            f"<td>{r.get('feed_name','')}</td>"
            f"<td>{r.get('ran_at','')}</td>"
            f"<td>{r.get('status','')}</td>"
            f"<td>{r.get('count_added',0)}</td>"
            f"<td>{r.get('error_msg') or ''}</td>"
            f"</tr>"
        )
    html += "</table>"
    return html


def render_totals(rows):
    if not rows:
        return "<p>No data.</p>"
    html = "<table><tr><th>Type</th><th>Count</th></tr>"
    for r in rows:
        html += f"<tr><td>{r.get('ioc_type','')}</td><td>{r.get('count',0)}</td></tr>"
    html += "</table>"
    return html


def render_top_queried(rows):
    if not rows:
        return "<p>No queries yet.</p>"
    html = "<table><tr><th>#</th><th>IOC</th><th>Queries</th></tr>"
    for i, r in enumerate(rows, 1):
        html += f"<tr><td>{i}</td><td>{r.get('ioc_value','')}</td><td>{r.get('count',0)}</td></tr>"
    html += "</table>"
    return html


def render_security_log():
    if not LOG_PATH.exists():
        return "<p>No security log yet.</p>"
    lines = LOG_PATH.read_text().splitlines()[-50:]
    if not lines:
        return "<p>Empty log.</p>"
    html = "<table><tr><th>Time</th><th>Event</th><th>Detail</th><th>IP</th></tr>"
    for line in reversed(lines):
        try:
            e = json.loads(line)
            html += (
                f"<tr><td>{e.get('time','')}</td>"
                f"<td>{e.get('event','')}</td>"
                f"<td>{e.get('detail','')}</td>"
                f"<td>{e.get('ip','')}</td></tr>"
            )
        except Exception:
            html += f"<tr><td colspan='4'>{line}</td></tr>"
    html += "</table>"
    return html


@app.get("/", response_class=HTMLResponse)
def dashboard(_: str = Depends(require_auth)):
    feed_html    = render_feed_health(get_feed_health())
    totals_html  = render_totals(get_ioc_totals())
    top_html     = render_top_queried(get_top_queried(10))
    queue_depth  = get_broadcast_queue_depth()
    sec_html     = render_security_log()
    now          = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scout Admin</title>
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; }}
  .tabs {{ display: flex; gap: 10px; margin-bottom: 20px; }}
  .tab {{ cursor: pointer; padding: 8px 20px; background: #21262d; border: 1px solid #30363d;
          border-radius: 6px; color: #c9d1d9; }}
  .tab.active {{ background: #58a6ff; color: #0d1117; }}
  .panel {{ display: none; }}
  .panel.active {{ display: block; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
  th, td {{ border: 1px solid #30363d; padding: 6px 12px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr.ok td:nth-child(3) {{ color: #3fb950; }}
  tr.err td:nth-child(3) {{ color: #f85149; }}
  .stat {{ display: inline-block; background: #161b22; border: 1px solid #30363d;
           border-radius: 8px; padding: 12px 24px; margin: 8px; text-align: center; }}
  .stat-num {{ font-size: 2em; color: #58a6ff; }}
  .stat-lbl {{ font-size: 0.8em; color: #8b949e; }}
  .refresh {{ color: #8b949e; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>Scout CTI — Admin Dashboard</h1>
<p class="refresh">Last updated: {now} &nbsp;|&nbsp;
  <span hx-get="/" hx-trigger="every 10s" hx-swap="outerHTML" hx-target="body">
    Auto-refresh every 10s
  </span>
</p>

<div class="stat">
  <div class="stat-num">{queue_depth}</div>
  <div class="stat-lbl">Broadcast Queue</div>
</div>

<div class="tabs">
  <div class="tab active" onclick="showTab('ops',this)">Operational</div>
  <div class="tab" onclick="showTab('sec',this)">Security</div>
</div>

<div id="ops" class="panel active">
  <h2>Feed Health</h2>
  {feed_html}
  <h2>IOC Totals by Type</h2>
  {totals_html}
  <h2>Top 10 Queried IOCs Today</h2>
  {top_html}
</div>

<div id="sec" class="panel">
  <h2>Last 50 Security Events</h2>
  {sec_html}
</div>

<script>
function showTab(id, el) {{
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  el.classList.add('active');
}}
</script>
</body>
</html>"""
