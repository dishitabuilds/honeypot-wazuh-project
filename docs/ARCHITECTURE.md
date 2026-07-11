# Architecture

## Data flow

```
attacker → honeypot → shared volume → collector → detect → enrich → SQLite → API/WebSocket → dashboard
```

1. **Capture.** Cowrie writes newline-delimited JSON (`cowrie.json`); Dionaea writes a text log.
   Both land on Docker volumes shared read-only with the analytics container.
2. **Collect.** `collector.py` tails both files (tolerating rotation/truncation), parses each
   line, and normalises it into a common event row.
3. **Detect.** `detect.py` applies the project's Wazuh rule logic — porting
   `config/cowrie_rules.xml` and `config/dionaea_rules.xml` — assigning a severity level, rule
   id, description, and MITRE ATT&CK technique/tactic. A sliding-window tracker raises the
   brute-force correlation alert (≥5 failed logins / 60 s per IP).
4. **Enrich.** `enrich.py` geolocates each source IP (ip-api) and, if an API key is set, adds
   AbuseIPDB reputation + Tor flags. Results are cached per IP.
5. **Store.** `db.py` persists events and IP intel to SQLite (`/data/honeypot.db`).
6. **Serve.** `main.py` (FastAPI) exposes the REST API, pushes every new event over WebSocket,
   and serves the dashboard.

## Components

| File | Responsibility |
|------|----------------|
| `ingest/app/collector.py` | log tailing + event normalisation + pipeline orchestration |
| `ingest/app/detect.py` | detection rules, severity, MITRE mapping, brute-force correlation |
| `ingest/app/enrich.py` | GeoIP + reputation enrichment (cached) |
| `ingest/app/db.py` | SQLite schema + queries powering the API |
| `ingest/app/alerts.py` | Telegram/email notifications on high-severity events |
| `ingest/app/report.py` | HTML threat-report generation |
| `ingest/app/simulate.py` | synthetic attack generator for testing/demos |
| `ingest/app/main.py` | FastAPI app: REST + WebSocket + dashboard host |
| `ingest/dashboard/index.html` | single-file live dashboard (no external deps) |

## Detection → alert mapping

| Honeypot event | Rule | Level | MITRE |
|----------------|------|-------|-------|
| `cowrie.session.connect` | 100102 | 7 | T1078 |
| `cowrie.client.version` | 100112 | 6 | T1046 |
| `cowrie.login.failed` | 100101 (+100108 pw, +100111 default acct) | 5–7 | T1110 / T1078 |
| ≥5 failed / 60 s | 100107 | 8 | T1110 |
| `cowrie.login.success` | 100150 (breach) | 10 | T1078 |
| `cowrie.command.input` | 100103 | 8 | T1059 |
| command matches wget/curl/nc | 100104 | 10 | T1105 |
| `cowrie.session.file_download` | 100105 | 12 | T1105 |
| Dionaea SMB/FTP/HTTP connection | 100201/100206/100207 | 5–6 | T1046 |
| Dionaea malware stored | 100205 | 12 | T1204 |
| Dionaea known exploit (MS17-010…) | 100208 | 10 | T1210 |

## Why a custom pipeline *and* Wazuh?

The lightweight FastAPI service runs anywhere (even a laptop), boots in seconds, and gives a
purpose-built dashboard — ideal for development, demos, and understanding the detection logic.
Wazuh is the production analytics tier: durable indexed storage, correlation at scale, active
response, and a hardened multi-user UI. Both consume the **same rule definitions**, so what you
see locally matches what fires in production.
