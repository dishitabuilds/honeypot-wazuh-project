"""
db.py — thin SQLite persistence layer for captured honeypot events,
raised alerts, and cached IP threat-intel enrichment.

Single-process access (the collector and API run in the same event loop),
guarded by a lock so the background collector and request handlers don't
interleave writes.
"""
from __future__ import annotations
import json
import sqlite3
import threading
from pathlib import Path

_LOCK = threading.Lock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    protocol    TEXT,
    event_type  TEXT,
    src_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    session     TEXT,
    username    TEXT,
    password    TEXT,
    command     TEXT,
    message     TEXT,
    sensor      TEXT,
    severity    TEXT,
    level       INTEGER DEFAULT 0,
    rule_id     INTEGER,
    rule_desc   TEXT,
    mitre       TEXT,
    tactic      TEXT,
    category    TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip     ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type   ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_level  ON events(level);

CREATE TABLE IF NOT EXISTS ip_intel (
    ip           TEXT PRIMARY KEY,
    country      TEXT,
    country_code TEXT,
    city         TEXT,
    lat          REAL,
    lon          REAL,
    isp          TEXT,
    org          TEXT,
    asn          TEXT,
    abuse_score  INTEGER,
    is_tor       INTEGER DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    hits         INTEGER DEFAULT 0
);
"""


def init(db_path: str = "/data/honeypot.db") -> None:
    global _conn
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(db_path, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    with _LOCK:
        _conn.executescript(SCHEMA)
        _conn.commit()


def insert_event(row: dict) -> int:
    cols = ("ts", "protocol", "event_type", "src_ip", "src_port", "dst_port",
            "session", "username", "password", "command", "message", "sensor",
            "severity", "level", "rule_id", "rule_desc", "mitre", "tactic",
            "category", "raw")
    vals = [row.get(c) for c in cols]
    with _LOCK:
        cur = _conn.execute(
            f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            vals,
        )
        _conn.commit()
        return cur.lastrowid


def _rows(sql: str, params=()) -> list[dict]:
    with _LOCK:
        return [dict(r) for r in _conn.execute(sql, params).fetchall()]


def _one(sql: str, params=()):
    with _LOCK:
        r = _conn.execute(sql, params).fetchone()
        return dict(r) if r else None


# ---- read helpers used by the API ----

def recent_events(limit: int = 100, min_level: int = 0) -> list[dict]:
    return _rows(
        "SELECT * FROM events WHERE level >= ? ORDER BY id DESC LIMIT ?",
        (min_level, limit),
    )


def summary() -> dict:
    s = _one("""
        SELECT
          COUNT(*)                                                   AS total_events,
          SUM(event_type IN ('cowrie.session.connect'))             AS connections,
          SUM(event_type = 'cowrie.login.failed')                   AS failed_logins,
          SUM(event_type = 'cowrie.login.success')                  AS breaches,
          SUM(event_type = 'cowrie.command.input')                  AS commands,
          COUNT(DISTINCT src_ip)                                    AS unique_ips,
          MAX(level)                                                AS top_level
        FROM events
    """) or {}
    for k in ("total_events", "connections", "failed_logins", "breaches",
              "commands", "unique_ips", "top_level"):
        s[k] = s.get(k) or 0
    return s


def top_credentials(limit: int = 10) -> list[dict]:
    return _rows("""
        SELECT username, password,
               SUM(event_type='cowrie.login.success') AS success,
               COUNT(*) AS attempts
        FROM events
        WHERE event_type IN ('cowrie.login.failed','cowrie.login.success')
        GROUP BY username, password
        ORDER BY attempts DESC LIMIT ?
    """, (limit,))


def top_commands(limit: int = 12) -> list[dict]:
    return _rows("""
        SELECT command, COUNT(*) AS n, MAX(level) AS level
        FROM events WHERE event_type='cowrie.command.input' AND command IS NOT NULL
        GROUP BY command ORDER BY n DESC LIMIT ?
    """, (limit,))


def alerts_by_rule() -> list[dict]:
    return _rows("""
        SELECT rule_id, rule_desc, severity, MAX(level) AS level,
               mitre, COUNT(*) AS hits
        FROM events WHERE rule_id IS NOT NULL
        GROUP BY rule_id ORDER BY level DESC, hits DESC
    """)


def mitre_breakdown() -> list[dict]:
    return _rows("""
        SELECT mitre, COUNT(*) AS n, MAX(level) AS level
        FROM events WHERE mitre IS NOT NULL AND mitre != ''
        GROUP BY mitre ORDER BY n DESC
    """)


def timeseries(bucket_seconds: int = 60) -> list[dict]:
    # group events into time buckets for the activity chart
    return _rows("""
        SELECT strftime('%Y-%m-%dT%H:%M:00Z', ts) AS bucket,
               COUNT(*) AS total,
               SUM(level >= 10) AS critical,
               SUM(event_type='cowrie.login.failed') AS failed_logins
        FROM events GROUP BY bucket ORDER BY bucket
    """)


def severity_distribution() -> list[dict]:
    return _rows("""
        SELECT severity, COUNT(*) AS n
        FROM events WHERE severity IS NOT NULL
        GROUP BY severity
    """)


def protocol_split() -> list[dict]:
    return _rows("""
        SELECT protocol, COUNT(*) AS n
        FROM events WHERE protocol IS NOT NULL
        GROUP BY protocol ORDER BY n DESC
    """)


def recent_sessions(limit: int = 14) -> list[dict]:
    return _rows("""
        SELECT e.session, e.protocol, e.src_ip,
               MIN(e.ts) AS first_seen, MAX(e.ts) AS last_seen,
               COUNT(*) AS events,
               MAX(e.event_type='cowrie.login.success') AS breach,
               MAX(e.level) AS top_level,
               i.country_code AS country_code, i.country AS country,
               (SELECT command FROM events c WHERE c.session=e.session
                  AND c.command IS NOT NULL ORDER BY c.level DESC LIMIT 1) AS top_cmd,
               SUM(e.event_type='cowrie.login.failed') AS failed
        FROM events e LEFT JOIN ip_intel i ON e.src_ip = i.ip
        WHERE e.session IS NOT NULL
        GROUP BY e.session ORDER BY last_seen DESC LIMIT ?
    """, (limit,))


def top_ips(limit: int = 20) -> list[dict]:
    return _rows("""
        SELECT e.src_ip AS ip, COUNT(*) AS events, MAX(e.level) AS top_level,
               i.country, i.country_code, i.city, i.lat, i.lon, i.org, i.abuse_score
        FROM events e LEFT JOIN ip_intel i ON e.src_ip = i.ip
        WHERE e.src_ip IS NOT NULL
        GROUP BY e.src_ip ORDER BY events DESC LIMIT ?
    """, (limit,))


def geo_points() -> list[dict]:
    return _rows("""
        SELECT i.ip, i.country, i.country_code, i.city, i.lat, i.lon,
               i.abuse_score, COUNT(e.id) AS events
        FROM ip_intel i JOIN events e ON e.src_ip = i.ip
        WHERE i.lat IS NOT NULL
        GROUP BY i.ip
    """)


# ---- ip intel cache ----

def get_intel(ip: str):
    return _one("SELECT * FROM ip_intel WHERE ip = ?", (ip,))


def upsert_intel(ip: str, data: dict, ts: str) -> None:
    with _LOCK:
        existing = _conn.execute("SELECT ip FROM ip_intel WHERE ip=?", (ip,)).fetchone()
        if existing:
            _conn.execute("""
                UPDATE ip_intel SET country=?, country_code=?, city=?, lat=?, lon=?,
                    isp=?, org=?, asn=?, abuse_score=?, is_tor=?, last_seen=?,
                    hits=hits+1 WHERE ip=?""",
                (data.get("country"), data.get("country_code"), data.get("city"),
                 data.get("lat"), data.get("lon"), data.get("isp"), data.get("org"),
                 data.get("asn"), data.get("abuse_score"), int(data.get("is_tor", 0)),
                 ts, ip))
        else:
            _conn.execute("""
                INSERT INTO ip_intel (ip, country, country_code, city, lat, lon, isp,
                    org, asn, abuse_score, is_tor, first_seen, last_seen, hits)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (ip, data.get("country"), data.get("country_code"), data.get("city"),
                 data.get("lat"), data.get("lon"), data.get("isp"), data.get("org"),
                 data.get("asn"), data.get("abuse_score"), int(data.get("is_tor", 0)),
                 ts, ts))
        _conn.commit()
