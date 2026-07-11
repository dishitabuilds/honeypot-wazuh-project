# Project Checklist — Multi-protocol Honeypot & Real-Time Threat Analytics

A living checklist to (a) track the multi-protocol upgrade and (b) plan the rest of
the work that turns this into a strong ~2-month B.Tech CSE final-year project.

Legend: `[x]` done · `[~]` partial/in progress · `[ ]` to do

---

## 0. Multi-protocol upgrade — DONE this pass

The goal was to make the **"multi-protocol"** claim in the title real, not cosmetic.
Before this pass the analytics pipeline effectively saw only SSH (Cowrie) plus a single
shallow "a Dionaea connection happened" regex; every other service collapsed together.

- [x] **Fixed a real capture bug** — `DIONAEA_LOG` pointed at `/logs/dionaea/dionaea.log`
      but the file is at `/logs/dionaea/dionaea/dionaea.log`. Live Dionaea capture had
      *never* worked; Dionaea only ever appeared via the simulator. Corrected in
      `docker-compose.yml`.
- [x] **Per-protocol Dionaea parser** (`ingest/app/collector.py`) — reconstructs the real
      service (ftp/http/smb/mssql/mysql/…) from the accepted connection's port, captures
      **FTP `USER`/`PASS` credentials** and file-transfer commands, and uses the **log's own
      timestamp** instead of ingest time.
- [x] **`honeypot` vs `protocol` split** — every event now records *which sensor* caught it
      and *which service the attacker spoke*. New DB column + indexes.
- [x] **Backward-compatible DB migration** (`ingest/app/db.py`) — old rows that stored the
      sensor name in `protocol` are split into `honeypot` + a real inferred protocol, so
      history stays usable.
- [x] **Per-protocol detection rules** (`ingest/app/detect.py`) — protocol-specific
      connection rules, FTP credential (100216) + FTP brute-force (100217) correlation, and
      an aggressive multi-service scan tracker (100210).
- [x] **XML ↔ Python parity** — added rules 100216/100217 to `config/dionaea_rules.xml` so
      the local pipeline and the Wazuh manager stay in sync.
- [x] **Multi-protocol simulator** (`ingest/app/simulate.py`) — ~1/3 of generated sessions
      now target FTP/HTTP/SMB/MSSQL/MySQL with realistic per-service behaviour.
- [x] **API** — `/api/events?protocol=` filter; richer `/api/protocols` (sensor, unique IPs,
      worst severity per protocol).
- [x] **Dashboard** — new **Protocol coverage** panel, a 7th KPI ("Protocols hit"), a
      per-protocol tag on every feed row, and protocol filter chips on the live feed.
- [x] **Report** — protocol-coverage table added to the generated HTML report.
- [x] **Docs** — README + module walkthrough updated to match the new behaviour.
- [x] **Verified end-to-end** — real `curl` FTP/HTTP attacks and the simulator both produce
      correctly-tagged, per-protocol, rule-annotated events on the live dashboard.
- [x] **Fixed KPI count-up bug** — the animation could render negative numbers when the
      frame clock wasn't monotonic; progress is now clamped.

---

## 1. Deepen "multi-protocol" further

- [x] **Self-written HTTP honeypot (WebTrap).** `webhoneypot/` — a from-scratch, dependency-free
      (stdlib-only) low-interaction HTTP sensor that serves decoy WordPress / phpMyAdmin / admin
      panels and exposed `.env` / `.git`, and logs every request path, User-Agent, and submitted
      credential as clean JSON. This is the "I built my own sensor, not just wired up two
      off-the-shelf ones" story, and because I control the log format the HTTP parsing is exact.
      Verified end-to-end: real `curl`/`sqlmap` attacks are captured with credentials, exploit,
      and scanner-UA detection, and it appears as a third sensor in the dashboard.
- [x] **HTTP request parsing** — delivered via WebTrap (path, method, User-Agent, query, creds).
      Dionaea's own text log doesn't record these (it only emits a `max_num_fields` warning), so a
      purpose-built sensor is the right call rather than scraping Dionaea's HTTP debug lines.
- [x] **New detection rules, single-sourced** — `config/webtrap_rules.xml` (rules 100301–100306:
      recon / credential-harvest / scanner-tool / exploit / aggressive-scan correlation) flows
      through `scripts/gen_rules.py` into the catalog automatically — proof the single-sourcing
      pays off: add a sensor's XML, regenerate, and `detect.py` + the dashboard just work.
- [x] **Per-protocol drill-down** — clicking a Protocol-coverage card (or a feed chip) filters
      the live feed to that protocol by **querying the backend** (`/api/events?protocol=`), so it
      shows that protocol's real history, not just the in-memory buffer. Verified via a headless
      click test (HTTP card → 44 http events, card + chip synced).
- [ ] **SMB exploit decoding / MSSQL·MySQL login capture from Dionaea** — still connection-level.
      Dionaea's text log doesn't expose these cleanly; the deeper path is parsing Dionaea's
      `dionaea.sqlite` (a separate, heavier integration) or adding purpose-built sensors like the
      WebTrap one. Lower priority now that a third real protocol/sensor is fully covered.

---

## 2. Harden it (own the limitations before the panel finds them)

Directly from the project's own "Known limitations" section:

- [x] **Fixed the stored-XSS gap** — both the client dashboard (every attacker/third-party
      string now runs through `esc()`: usernames, passwords, commands, `src_ip`, geo, session,
      MITRE) and the **server-side HTML report** (`report.py` now `html.escape`s every cell).
      Verified: a `<script>` FTP username renders as `&lt;script&gt;` in the report.
- [x] **Dashboard authentication** — env-gated HTTP Basic auth (`DASH_USER`/`DASH_PASS`) in a
      FastAPI middleware; `/api/health` stays exempt for the container healthcheck. Off by
      default (open local demo), enforced when set. Verified 401/200 behaviour.
- [x] **Data retention / rotation + tracker eviction** — `RETENTION_DAYS` purges old events on
      a schedule; correlation trackers now `prune()` aged-out per-IP state so an internet-facing
      sensor doesn't grow without bound.
- [x] **Alert retry buffer** — failed Telegram/email sends go to a bounded retry deque and are
      re-attempted on the next alert; SMTP send moved off the event loop
      (`asyncio.to_thread`) so ingestion never blocks.
- [x] **Rule single-sourcing** — rule severity levels and MITRE mappings are now generated
      from `config/*.xml` into `ingest/app/rules.py` (`scripts/gen_rules.py`); `detect.py` looks
      them up instead of hard-coding them. A parity test + `gen_rules.py --check` in CI fail the
      build if the catalog drifts from the XML. This surfaced and fixed a real drift (rule 100215
      had tactic `TA0002` in the XML vs the correct `TA0042` in Python) and pulled the local-only
      breach rule 100150 back into the XML. Descriptions stay per-surface (French in the SIEM
      XML, English on the dashboard) by design.

---

## 3. Make it a strong final-year project (the ~2-month plan)

Depth, real data, and measured results are what a panel rewards.

### Real-world data (highest value — start early, runs in background)
- [ ] Deploy the sensor on a cheap/free VPS with real ports (22/21/80/445) exposed.
- [ ] Collect **3–4 weeks** of genuine internet attack traffic.
- [ ] Write the results chapter from real numbers: top source countries, most-tried
      credentials, busiest hours, protocols targeted, malware hashes observed.

### One "CSE-grade" technical contribution (pick ONE)
- [ ] **ML anomaly / bot detection** — cluster attacker sessions by command/credential
      sequences (TF-IDF + k-means, or Isolation Forest on session features) to separate bots
      from human attackers. Classic, defensible, curriculum-friendly.
- [ ] **Session replay + kill-chain reconstruction** — group a session's events into a
      timeline (connect → brute-force → breach → recon → payload) shown as a kill chain.
- [ ] **Attacker/campaign clustering** — same credential lists or command sequences across
      different IPs ⇒ same botnet campaign; add a "campaigns" view.

### Evaluation chapter (this is what makes it a *study*, not a demo)
- [ ] Measure **detection latency** (log line → dashboard) and publish the number.
- [ ] Measure **throughput** (events/sec) using the simulator as a load generator.
- [ ] Map observed rules onto the **MITRE ATT&CK matrix** (export a Navigator layer JSON).
- [ ] **Compare your lightweight pipeline vs the full Wazuh stack** — RAM/CPU footprint and
      detection parity on the same log set. This is the project's thesis: *why* the custom
      pipeline exists.

### Engineering credibility
- [x] **pytest unit tests for `detect.py`** — 28 tests pinning rule IDs, severity bands, MITRE
      mappings, and the brute-force/scan correlation (`ingest/tests/test_detect.py`).
- [x] **GitHub Actions CI** — runs the tests, validates `docker compose config`, and builds the
      analytics image on every push/PR (`.github/workflows/ci.yml`).
- [ ] A **smoke test** that boots the full stack and asserts the API responds (extend the CI
      `build` job to `docker compose up` + `curl /api/health`).

### Deliverables
- [ ] IEEE-format report: problem → related work (T-Pot, Wazuh, honeypot papers) →
      architecture → implementation → real-world results → evaluation → limitations/future work.
- [ ] 5-minute **demo video** (the walkthrough already has the script) as a demo-day fallback.
- [ ] Clean git history + a tagged release.

---

## If you only do three things
1. **Deploy it to the internet** for real attack data.
2. **Add the ML session-clustering** contribution.
3. **Write the evaluation** with real latency/throughput/footprint numbers.

Those three convert "I integrated tools well" into "I ran a measured security study on a
system I built" — exactly what a final-year panel wants to hear.
