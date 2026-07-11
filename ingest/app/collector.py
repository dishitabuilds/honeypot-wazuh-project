"""
collector.py — tails honeypot log files, parses each event, runs detection +
enrichment, persists it, and pushes it to connected dashboards over WebSocket.

Cowrie writes newline-delimited JSON (cowrie.json). Dionaea writes a text log;
we parse the lines we care about. Both files are read from a shared Docker
volume mounted read-only into this container.

Every stored event carries two identity fields:
  honeypot — which sensor captured it ("cowrie" | "dionaea")
  protocol — the service the attacker actually spoke
             (ssh, telnet, ftp, http, smb, mssql, mysql, epmap, sip, tftp, …)
"""
from __future__ import annotations
import asyncio
import json
import os
import re
from datetime import datetime, timezone

import httpx

from . import db, enrich, alerts
from .detect import detect, top_detection

COWRIE_LOG = os.getenv("COWRIE_LOG", "/logs/cowrie/cowrie.json")
DIONAEA_LOG = os.getenv("DIONAEA_LOG", "/logs/dionaea/dionaea.log")
WEBTRAP_LOG = os.getenv("WEBTRAP_LOG", "/logs/webtrap/webtrap.json")

# Dionaea identifies the service by the *local port* of an accepted connection,
# not by name — map container-side ports to protocols.
DIONAEA_PORTS = {
    21: "ftp", 42: "nameserver", 69: "tftp", 80: "http", 135: "epmap",
    443: "https", 445: "smb", 1433: "mssql", 1723: "pptp", 3306: "mysql",
    5060: "sip", 5061: "sip", 11211: "memcache", 27017: "mongo",
}

# "[DDMMYYYY HH:MM:SS] module /path/file.py:line-level: message"
_DIO_TS = re.compile(r"^\[(?P<d>\d{2})(?P<m>\d{2})(?P<y>\d{4}) (?P<t>\d{2}:\d{2}:\d{2})\]")

# One line per accepted connection (the accept/close repeats are skipped):
# "connection 0x… accept/tcp/none [10.0.0.4:21->1.2.3.4:37744] state: none->established"
_DIO_EST = re.compile(
    r"connection 0x\w+ accept/(?P<transport>\w+)/\S+ "
    r"\[(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)->(?P<src_ip>[\d.]+):(?P<src_port>\d+)\] "
    r"state: none->established"
)

# FTP module echoes each command once at ftp.py:225:
# "ftp /dionaea/ftp.py:225-debug: processing line 'b'PASS test@test.com''"
_DIO_FTP = re.compile(r" ftp /dionaea/ftp\.py:225.*processing line 'b'(?P<line>[^']*)'")
_FTP_CMDS = {"RETR", "STOR", "DELE", "MKD", "RMD", "SITE"}

# Lines worth raising even without structured parsing (exploits, malware, tools)
_DIO_KEYWORDS = ("stored binary", "ms17-010", "eternalblue", "ms08-067", "bluekeep",
                 "shellcode", "meterpreter", "reverse_shell", "metasploit", "sqlmap", "hydra")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _tail(path: str):
    """Yield new lines appended to `path`, tolerating the file not existing yet
    and being rotated/truncated."""
    while not os.path.exists(path):
        await asyncio.sleep(1.0)
    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line.rstrip("\n")
            continue
        await asyncio.sleep(0.5)
        try:
            if os.stat(path).st_ino != inode or os.path.getsize(path) < f.tell():
                f.close()
                f = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            await asyncio.sleep(1.0)


# ---------- Cowrie ----------

# Only cowrie.session.connect carries "protocol" (ssh|telnet); remember it per
# session so every later event in that session is labelled correctly.
_cowrie_proto: dict[str, str] = {}


def _row_from_cowrie(ev: dict) -> dict:
    sess = ev.get("session")
    proto = ev.get("protocol")
    if proto in ("ssh", "telnet"):
        if sess:
            _cowrie_proto[sess] = proto
    else:
        proto = _cowrie_proto.get(sess) or ("telnet" if ev.get("dst_port") == 2223 else "ssh")
    if ev.get("eventid") == "cowrie.session.closed":
        _cowrie_proto.pop(sess, None)
    if len(_cowrie_proto) > 4096:  # bound memory if closes are ever missed
        _cowrie_proto.pop(next(iter(_cowrie_proto)))
    return {
        "ts": ev.get("timestamp") or _now(),
        "honeypot": "cowrie",
        "protocol": proto,
        "event_type": ev.get("eventid"),
        "src_ip": ev.get("src_ip"),
        "src_port": ev.get("src_port"),
        "dst_port": ev.get("dst_port"),
        "session": ev.get("session"),
        "username": ev.get("username"),
        "password": ev.get("password"),
        "command": ev.get("input"),
        "message": ev.get("message") if isinstance(ev.get("message"), str) else None,
        "sensor": ev.get("sensor"),
        "raw": json.dumps(ev)[:4000],
    }


# ---------- Webtrap (self-written HTTP honeypot) ----------

def _row_from_webtrap(ev: dict) -> dict:
    method = ev.get("method", "") or ""
    path = ev.get("path", "") or ""
    kind = ev.get("eventid", "") or "webtrap.request"
    user, pwd = ev.get("username"), ev.get("password")
    if kind == "webtrap.credential":
        message = f"login {user or '?'}:{pwd or '?'} @ {method} {path}"
        command = None
    else:
        ua = ev.get("user_agent", "") or ""
        message = f"{method} {path}" + (f"  UA:{ua}" if ua else "")
        command = f"{method} {path}".strip()
    return {
        "ts": ev.get("timestamp") or _now(),
        "honeypot": "webtrap",
        "protocol": "http",
        "event_type": kind,
        "src_ip": ev.get("src_ip"),
        "src_port": ev.get("src_port"),
        "dst_port": 80,
        "username": user,
        "password": pwd,
        "command": command,
        "message": message[:500],
        "raw": json.dumps(ev)[:4000],
    }


# ---------- Dionaea ----------

def _dio_ts(line: str) -> str:
    """Use the log's own timestamp (UTC in the container) instead of ingest time."""
    m = _DIO_TS.match(line)
    if not m:
        return _now()
    return f"{m.group('y')}-{m.group('m')}-{m.group('d')}T{m.group('t')}+00:00"


class DionaeaParser:
    """Stateful line parser: connections give us protocol + attacker IP; the FTP
    module lines carry no address, so credentials are attributed to the most
    recent FTP connection (fine at honeypot concurrency)."""

    def __init__(self):
        self._ftp_ip: str | None = None
        self._ftp_user: str | None = None

    def parse(self, line: str) -> dict | None:
        m = _DIO_EST.search(line)
        if m:
            port = int(m.group("dst_port"))
            proto = DIONAEA_PORTS.get(port, f"port-{port}")
            if proto == "ftp":
                self._ftp_ip = m.group("src_ip")
            return {
                "ts": _dio_ts(line),
                "honeypot": "dionaea",
                "protocol": proto,
                "event_type": "dionaea.connection",
                "src_ip": m.group("src_ip"),
                "src_port": int(m.group("src_port")),
                "dst_port": port,
                "message": f"{proto} connection ({m.group('transport')})",
                "raw": line[:4000],
            }

        m = _DIO_FTP.search(line)
        if m:
            parts = m.group("line").split(None, 1)
            cmd = (parts[0] if parts else "").upper()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd == "USER":
                self._ftp_user = arg or None
                return None                      # wait for PASS: one event per attempt
            if cmd == "PASS":
                row = {
                    "ts": _dio_ts(line),
                    "honeypot": "dionaea",
                    "protocol": "ftp",
                    "event_type": "dionaea.ftp.login",
                    "src_ip": self._ftp_ip,
                    "dst_port": 21,
                    "username": self._ftp_user,
                    "password": arg or None,
                    "message": f"FTP login {self._ftp_user or '?'}:{arg or '?'}",
                    "raw": line[:4000],
                }
                self._ftp_user = None
                return row
            if cmd in _FTP_CMDS:
                return {
                    "ts": _dio_ts(line),
                    "honeypot": "dionaea",
                    "protocol": "ftp",
                    "event_type": "dionaea.ftp.command",
                    "src_ip": self._ftp_ip,
                    "dst_port": 21,
                    "command": m.group("line")[:300],
                    "message": f"FTP command: {m.group('line')[:200]}",
                    "raw": line[:4000],
                }
            return None

        low = line.lower()
        if any(k in low for k in _DIO_KEYWORDS):
            module = line.split("] ", 1)[-1].split(" ", 1)[0] if "] " in line else ""
            proto = {"smbd": "smb", "smb": "smb", "ftp": "ftp", "mysqld": "mysql",
                     "mssqld": "mssql", "httpd": "http"}.get(module, "unknown")
            return {
                "ts": _dio_ts(line),
                "honeypot": "dionaea",
                "protocol": proto,
                "event_type": "dionaea.download.complete" if "stored binary" in low
                              else "dionaea.alert",
                "message": line.split("] ", 1)[-1][:500],
                "raw": line[:4000],
            }
        return None


class Pipeline:
    def __init__(self, broadcast):
        self._broadcast = broadcast          # async fn(dict) -> None
        self._client = httpx.AsyncClient()
        self._dionaea = DionaeaParser()

    async def _handle(self, honeypot: str, row: dict):
        dets = detect(honeypot, {**row, "eventid": row.get("event_type"),
                                 "input": row.get("command"),
                                 "message": row.get("message")})
        top = top_detection(dets)
        if top:
            row.update({
                "severity": top["severity"], "level": top["level"],
                "rule_id": top["rule_id"], "rule_desc": top["desc"],
                "mitre": top["mitre"], "tactic": top["tactic"],
                "category": top["category"],
            })
        else:
            row["level"] = 0
            row["severity"] = "info"

        # enrich the source IP (cached after first lookup)
        intel = await enrich.enrich_ip(self._client, row.get("src_ip"))
        if intel:
            row["country"] = intel.get("country")
            row["country_code"] = intel.get("country_code")

        row["id"] = db.insert_event(row)
        row["all_rules"] = dets
        await self._broadcast(row)
        await alerts.maybe_alert(self._client, row)

    async def run_cowrie(self):
        async for line in _tail(COWRIE_LOG):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            await self._handle("cowrie", _row_from_cowrie(ev))

    async def run_dionaea(self):
        async for line in _tail(DIONAEA_LOG):
            row = self._dionaea.parse(line)
            if row:
                await self._handle("dionaea", row)

    async def run_webtrap(self):
        async for line in _tail(WEBTRAP_LOG):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            await self._handle("webtrap", _row_from_webtrap(ev))

    async def ingest_synthetic(self, ev: dict):
        """Entry point for the simulator to push a synthetic event through the
        exact same detection/enrichment/persist/broadcast pipeline."""
        eid = str(ev.get("eventid", ""))
        hp = ev.get("honeypot") or (
            "cowrie" if eid.startswith("cowrie.")
            else "webtrap" if eid.startswith("webtrap.")
            else "dionaea")
        if hp == "cowrie":
            row = _row_from_cowrie(ev)
        elif hp == "webtrap":
            row = _row_from_webtrap(ev)
        else:
            row = {"ts": _now(), "honeypot": "dionaea",
                   "protocol": ev.get("protocol", "unknown"),
                   "event_type": eid, "src_ip": ev.get("src_ip"),
                   "src_port": ev.get("src_port"), "dst_port": ev.get("dst_port"),
                   "username": ev.get("username"), "password": ev.get("password"),
                   "command": ev.get("command"), "message": ev.get("message"),
                   "sensor": ev.get("sensor"), "raw": json.dumps(ev)[:4000]}
        await self._handle(hp, row)
