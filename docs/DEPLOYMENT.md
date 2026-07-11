# Deployment Guide

Covers three levels: (1) the local Docker stack, (2) an internet-facing sensor on a cloud VPS,
and (3) the full **Wazuh SIEM** server-side integration for production.

---

## 1. Local stack (development / demo)

```bash
cp .env.example .env
docker compose up -d --build
```

Services:

| Container | Host ports | Notes |
|-----------|-----------|-------|
| `hp-cowrie` | 2222 (SSH), 2223 (Telnet) | fake shell |
| `hp-dionaea` | 2121→21, 8445→445, 8088→80, 11433→1433, 13306→3306 | non-standard host ports so nothing on your machine conflicts (Windows reserves 445; a local MySQL takes 3306) |
| `hp-analytics` | 8080 | dashboard + API |

Data persists in `./data` (SQLite DB + generated reports). Wipe with `docker compose down -v`.

---

## 2. Internet-facing sensor (cloud VPS)

The point of a honeypot is to catch **real** attackers, so it must be reachable on the ports
they scan. Use a small, **disposable** VPS (DigitalOcean/Hetzner/AWS Lightsail) that contains
nothing else of value.

**a. Move your real SSH admin port first** — you're about to give port 22 to the honeypot.

```bash
# on the VPS, edit /etc/ssh/sshd_config:  Port 62222
sudo systemctl restart ssh          # reconnect on :62222 before continuing
```

**b. Map the honeypots to the real ports** attackers expect. Override in
`docker-compose.override.yml`:

```yaml
services:
  cowrie:
    ports: ["22:2222", "23:2223"]        # real SSH/Telnet
  dionaea:
    ports: ["445:445", "21:21", "80:80", "1433:1433", "3306:3306"]
```

**c. Never expose the dashboard publicly.** Bind it to localhost and reach it over an SSH
tunnel, or put an authenticating reverse proxy (Caddy/Nginx + basic-auth + TLS) in front:

```yaml
  analytics:
    ports: ["127.0.0.1:8080:8080"]       # localhost only
```
```bash
# from your laptop:
ssh -L 8080:localhost:8080 admin@vps -p 62222   # then open http://localhost:8080
```

**d. Firewall** — allow the honeypot ports + your admin port only:

```bash
sudo ufw allow 62222/tcp && sudo ufw allow 22 && sudo ufw allow 23 \
  && sudo ufw allow 445 && sudo ufw allow 80 && sudo ufw enable
```

**e. Enrichment + alerting** — set `ABUSEIPDB_KEY` and `TELEGRAM_TOKEN`/`TELEGRAM_CHAT_ID`
in `.env` so real attacker IPs get reputation scores and you get pinged on breaches.

---

## 3. Full Wazuh SIEM (server-side)

For an enterprise-grade analytics tier, replace (or run alongside) the lightweight service with
a real Wazuh deployment. This is the "server side" of the classic architecture.

### 3.1 Install the manager stack (one server, ~6 GB RAM)

```bash
sudo bash scripts/install_wazuh.sh          # Wazuh 4.7 all-in-one: manager + indexer + dashboard
# dashboard at https://<server-ip>:443  (admin / generated password)
```

Components installed:

| Component | Role |
|-----------|------|
| **wazuh-manager** | ingests agent logs, runs decoders + rules, generates alerts, active response |
| **wazuh-indexer** | OpenSearch — stores and searches alerts |
| **wazuh-dashboard** | visualisation, MITRE mapping, drill-down |

### 3.2 Load the custom honeypot rules

Copy this repo's rules to the manager and restart it:

```bash
sudo cp config/cowrie_rules.xml    /var/ossec/etc/rules/local_cowrie_rules.xml
sudo cp config/dionaea_rules.xml   /var/ossec/etc/rules/local_dionaea_rules.xml
sudo systemctl restart wazuh-manager
# validate: sudo /var/ossec/bin/wazuh-logtest
```

These add rule IDs `100100–100215` (SSH brute-force, default-account logins, suspicious
commands, malware capture, known exploits) each mapped to MITRE ATT&CK.

### 3.3 Install an agent on each honeypot host

```bash
sudo bash scripts/install_wazuh_agent.sh    # set WAZUH_MANAGER_IP inside first
```

The agent ships the honeypot logs to the manager via the `localfile` blocks in
[`config/ossec.conf`](../config/ossec.conf):

```xml
<localfile><log_format>json</log_format>
  <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location></localfile>
<localfile><log_format>syslog</log_format>
  <location>/opt/dionaea/log/dionaea/dionaea.log</location></localfile>
```

### 3.4 Recommended server-side tuning

- **Index retention** — create an ISM policy so honeypot indices roll over/delete (they fill fast).
- **Active response** — auto-block brute-forcers: bind Wazuh's `firewall-drop` to rule `100107`.
- **Dashboards** — build saved visualisations for top source IPs, credential heatmaps, MITRE coverage.
- **Backups** — snapshot `/var/ossec/etc/` (rules, decoders, keys) and the indexer.
- **TLS + auth** — change default passwords; restrict dashboard `:443` to a VPN/bastion.

---

## Operations cheatsheet

```bash
docker compose ps                 # status
docker compose logs -f analytics  # pipeline logs
docker compose restart analytics  # reload after code changes
docker compose down               # stop (keep data)
docker compose down -v            # stop + wipe volumes
curl -X POST "localhost:8080/api/simulate?sessions=15"   # demo traffic
curl -o report.html localhost:8080/api/report            # pull a report
```
