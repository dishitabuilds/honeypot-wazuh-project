"""
report.py — generates a standalone HTML threat report from stored events.

Written to /data/reports/ on a schedule (and on demand via GET /api/report).
Kept dependency-free (plain HTML string) so it opens anywhere and can be
printed to PDF from a browser.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from pathlib import Path

from . import db

REPORT_DIR = os.getenv("REPORT_DIR", "/data/reports")


def _rows_html(rows, cols):
    body = ""
    for r in rows:
        body += "<tr>" + "".join(f"<td>{r.get(c, '')}</td>" for c in cols) + "</tr>"
    return body


def build_html() -> str:
    s = db.summary()
    creds = db.top_credentials(10)
    cmds = db.top_commands(10)
    rules = db.alerts_by_rule()
    ips = db.top_ips(10)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Honeypot Threat Report — {now}</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;max-width:900px;margin:32px auto;
   padding:0 20px;color:#1a2233;line-height:1.5}}
 h1{{font-size:22px;margin-bottom:4px}} h2{{font-size:15px;margin-top:28px;
   border-bottom:2px solid #eee;padding-bottom:6px}}
 .k{{display:inline-block;min-width:120px;margin:6px 18px 6px 0}}
 .k b{{display:block;font-size:26px;font-family:ui-monospace,monospace}}
 .k span{{font-size:12px;color:#667}}
 table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
 th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}}
 th{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#889}}
 code{{font-family:ui-monospace,monospace;font-size:12px}}
 .foot{{margin-top:32px;font-size:11px;color:#889}}
</style></head><body>
<h1>Honeypot Threat Report</h1>
<div style="color:#667;font-size:13px">Generated {now}</div>
<h2>Summary</h2>
<div>
 <div class="k"><b>{s['total_events']}</b><span>Total events</span></div>
 <div class="k"><b>{s['failed_logins']}</b><span>Failed logins</span></div>
 <div class="k"><b>{s['breaches']}</b><span>Breaches</span></div>
 <div class="k"><b>{s['commands']}</b><span>Commands</span></div>
 <div class="k"><b>{s['unique_ips']}</b><span>Unique IPs</span></div>
 <div class="k"><b>{s['top_level']}</b><span>Top level</span></div>
</div>
<h2>Alerts raised</h2>
<table><tr><th>Rule</th><th>Description</th><th>Level</th><th>MITRE</th><th>Hits</th></tr>
{_rows_html(rules, ['rule_id','rule_desc','level','mitre','hits'])}</table>
<h2>Top source IPs</h2>
<table><tr><th>IP</th><th>Country</th><th>Org</th><th>Events</th><th>Abuse</th></tr>
{_rows_html(ips, ['ip','country','org','events','abuse_score'])}</table>
<h2>Top credentials tried</h2>
<table><tr><th>Username</th><th>Password</th><th>Attempts</th></tr>
{_rows_html(creds, ['username','password','attempts'])}</table>
<h2>Top commands</h2>
<table><tr><th>Command</th><th>Count</th></tr>
{_rows_html(cmds, ['command','n'])}</table>
<div class="foot">Multi-protocol Honeypot &amp; Real-Time Threat Analytics — automated report.</div>
</body></html>"""


def write_report() -> str:
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    fn = datetime.now(timezone.utc).strftime("report-%Y%m%d-%H%M.html")
    path = os.path.join(REPORT_DIR, fn)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html())
    return path
