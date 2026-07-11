"""
collector.py — tails honeypot log files, parses each event, runs detection +
enrichment, persists it, and pushes it to connected dashboards over WebSocket.

Cowrie writes newline-delimited JSON (cowrie.json). Dionaea writes a text log;
we parse the lines we care about. Both files are read from a shared Docker
volume mounted read-only into this container.
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

# dionaea text line: "<timestamp> <level> <module> <message>"
_DIO_CONN = re.compile(r"connection.*?(?P<proto>smb|ftp|http|mssql|mysql|epmap).*?(?P<ip>\d+\.\d+\.\d+\.\d+)", re.I)


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


def _row_from_cowrie(ev: dict) -> dict:
    return {
        "ts": ev.get("timestamp") or _now(),
        "protocol": "cowrie",
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


def _row_from_dionaea(line: str) -> dict | None:
    m = _DIO_CONN.search(line)
    if not m:
        return None
    return {
        "ts": _now(),
        "protocol": "dionaea",
        "event_type": f"dionaea.{m.group('proto').lower()}.connection",
        "src_ip": m.group("ip"),
        "message": line[:500],
        "raw": line[:4000],
    }


class Pipeline:
    def __init__(self, broadcast):
        self._broadcast = broadcast          # async fn(dict) -> None
        self._client = httpx.AsyncClient()

    async def _handle(self, protocol: str, row: dict):
        dets = detect(protocol, {**row, "eventid": row.get("event_type"),
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
            row = _row_from_dionaea(line)
            if row:
                await self._handle("dionaea", row)

    async def ingest_synthetic(self, ev: dict):
        """Entry point for the simulator to push a synthetic event through the
        exact same detection/enrichment/persist/broadcast pipeline."""
        proto = ev.get("protocol", "cowrie")
        if proto == "cowrie":
            row = _row_from_cowrie(ev)
        else:
            row = {"ts": _now(), "protocol": proto,
                   "event_type": ev.get("eventid"), "src_ip": ev.get("src_ip"),
                   "message": ev.get("message"), "raw": json.dumps(ev)[:4000]}
        await self._handle(proto, row)
