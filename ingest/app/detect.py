"""
detect.py — detection logic ported from the project's Wazuh rules
(config/cowrie_rules.xml, config/dionaea_rules.xml).

Each honeypot event is evaluated and, when it matches, annotated with:
  severity level (0-15, Wazuh scale), a rule id, a human description,
  the MITRE ATT&CK technique/tactic, and a category.

This lets the analytics service raise the same alerts a Wazuh manager would,
without needing the full 6 GB SIEM stack running locally.

Severity levels and MITRE mappings are NOT hard-coded here — they come from the
generated `rules` catalog (app/rules.py), which is produced from the same XML
the Wazuh manager loads (scripts/gen_rules.py). This module only decides *which*
rule an event fires and gives it a dashboard-facing English description.
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Optional

from .rules import RULES

# Wazuh alert level -> severity band used by the dashboard
def band(level: int) -> str:
    if level >= 10:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 6:
        return "medium"
    if level >= 3:
        return "low"
    return "info"

DEFAULT_ACCOUNTS = {"root", "admin", "test", "user", "ubuntu", "centos", "guest", "oracle", "pi"}
SUSPICIOUS_CMD = ("wget", "curl", "nc ", "netcat", "nmap", "scp", "tftp", "ncat")
DOWNLOAD_HINT = (".sh", ".bin", ".elf", "miner", "malware", "payload", "busybox")


class Detection:
    __slots__ = ("rule_id", "level", "desc", "mitre", "tactic", "category", "band")

    def __init__(self, rule_id, desc, category=""):
        meta = RULES.get(rule_id)
        if meta is None:
            # every rule detect.py can fire must exist in the generated catalog;
            # if this trips, add the rule to config/*.xml and regenerate.
            raise KeyError(f"rule {rule_id} missing from catalog — run scripts/gen_rules.py")
        self.rule_id = rule_id
        self.level = meta["level"]
        self.mitre = meta["mitre"]
        self.tactic = meta["tactic"]
        self.desc = desc
        self.category = category
        self.band = band(self.level)

    def as_dict(self):
        return {
            "rule_id": self.rule_id, "level": self.level, "desc": self.desc,
            "mitre": self.mitre, "tactic": self.tactic,
            "category": self.category, "severity": self.band,
        }


class BruteForceTracker:
    """Sliding-window counter of events per source IP — drives the correlation
    rules (SSH brute force 100107, FTP brute force 100217, aggressive scan 100210)."""
    def __init__(self, threshold: int = 5, window: int = 60):
        self.threshold = threshold
        self.window = window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._fired: dict[str, float] = {}

    def record_failure(self, ip: str) -> bool:
        now = time.time()
        dq = self._hits[ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold:
            # avoid re-firing more than once per window
            if now - self._fired.get(ip, 0) > self.window:
                self._fired[ip] = now
                return True
        return False

    def prune(self, now: float | None = None) -> None:
        """Drop IPs whose activity has fully aged out, so an internet-facing
        sensor doesn't accumulate one deque per source IP forever."""
        now = now or time.time()
        for ip in list(self._hits):
            dq = self._hits[ip]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if not dq:
                del self._hits[ip]
        for ip in list(self._fired):
            if now - self._fired[ip] > self.window:
                del self._fired[ip]


_bruteforce = BruteForceTracker()                      # SSH/Telnet fails  (100107)
_ftp_bruteforce = BruteForceTracker()                  # FTP logins        (100217)
_scan = BruteForceTracker(threshold=10, window=120)    # any connections   (100210)
_web_scan = BruteForceTracker(threshold=15, window=60)  # web requests      (100306)


def prune_trackers() -> None:
    """Evict aged-out state from every correlation tracker (called periodically)."""
    for t in (_bruteforce, _ftp_bruteforce, _scan, _web_scan):
        t.prune()


def detect_cowrie(ev: dict) -> list[Detection]:
    """Return the detections a Cowrie event triggers."""
    out: list[Detection] = []
    eid = ev.get("eventid", "")

    if eid == "cowrie.session.connect":
        out.append(Detection(100102, "Honeypot session established", "access"))
    elif eid == "cowrie.client.version":
        out.append(Detection(100112, "SSH client detected (possible scan)", "recon"))
    elif eid == "cowrie.login.failed":
        out.append(Detection(100101, "SSH/Telnet login attempt", "credential-access"))
        if ev.get("password"):
            out.append(Detection(100108, "Password captured on failed login", "credential-access"))
        if (ev.get("username") or "").lower() in DEFAULT_ACCOUNTS:
            out.append(Detection(100111, "Login attempt with default account", "credential-access"))
        if _bruteforce.record_failure(ev.get("src_ip", "")):
            out.append(Detection(100107, "Brute-force attack (>=5 fails / 60s)", "credential-access"))
    elif eid == "cowrie.login.success":
        # the honeypot let a weak credential in — the actual breach
        out.append(Detection(100150, "Honeypot breach — weak credential accepted", "access"))
    elif eid == "cowrie.command.input":
        cmd = ev.get("input", "") or ""
        out.append(Detection(100103, "Command executed in session", "execution"))
        low = cmd.lower()
        if any(s in low for s in SUSPICIOUS_CMD):
            out.append(Detection(100104, "Suspicious network command (wget/curl/nc)", "malware"))
    elif eid == "cowrie.session.file_download":
        out.append(Detection(100105, "File download via honeypot", "malware"))
    elif eid == "cowrie.direct-tcpip.request":
        out.append(Detection(100106, "SSH tunneling attempt", "tunneling"))

    return out


# Per-protocol connection rules: protocol -> (rule_id, description).
# Levels/MITRE come from the generated catalog via the rule_id.
_DIO_CONN_RULES = {
    "smb":   (100201, "Inbound SMB connection (probe)"),
    "ftp":   (100206, "Inbound FTP connection"),
    "http":  (100207, "Inbound HTTP connection"),
    "https": (100207, "Inbound HTTPS connection"),
    "mssql": (100209, "MSSQL database service scan"),
    "mysql": (100209, "MySQL database service scan"),
    "epmap": (100209, "RPC endpoint-mapper probe"),
    "sip":   (100209, "SIP/VoIP service probe"),
    "tftp":  (100209, "TFTP service probe"),
}


def detect_dionaea(ev: dict) -> list[Detection]:
    """Return the detections a Dionaea event triggers (per-protocol)."""
    out: list[Detection] = []
    eid = ev.get("eventid", "") or ""
    proto = (ev.get("protocol") or "").lower()
    msg = (ev.get("message") or ev.get("raw") or "").lower()

    if eid == "dionaea.connection":
        rid, desc = _DIO_CONN_RULES.get(proto, (100209, f"Service probe on {proto}"))
        out.append(Detection(rid, desc, "recon"))
        if _scan.record_failure(ev.get("src_ip", "") or ""):
            out.append(Detection(100210, "Aggressive scanning (>=10 conns / 120s)", "recon"))
    elif eid == "dionaea.ftp.login":
        out.append(Detection(100216, "FTP credential captured", "credential-access"))
        if (ev.get("username") or "").lower() in DEFAULT_ACCOUNTS:
            out.append(Detection(100111, "Login attempt with default account", "credential-access"))
        if _ftp_bruteforce.record_failure(ev.get("src_ip", "") or ""):
            out.append(Detection(100217, "FTP brute-force attack (>=5 logins / 60s)", "credential-access"))
    elif eid == "dionaea.ftp.command":
        cmd = (ev.get("input") or ev.get("command") or "").upper()
        if cmd.startswith(("RETR", "STOR")):
            out.append(Detection(100211, "FTP file transfer on honeypot", "malware"))
        else:
            out.append(Detection(100206, "FTP command executed", "recon"))
    elif eid == "dionaea.download.complete" or "stored binary" in msg:
        out.append(Detection(100205, "Malware sample captured", "malware"))

    # keyword rules apply to any dionaea event's message
    if any(x in msg for x in ("ms17-010", "eternalblue", "ms08-067", "bluekeep")):
        out.append(Detection(100208, "Known Windows exploit attempt", "exploit"))
    if any(x in msg for x in ("meterpreter", "shellcode", "reverse_shell")):
        out.append(Detection(100214, "Shellcode / advanced payload captured", "malware"))
    if any(x in msg for x in ("metasploit", "sqlmap", "hydra", "medusa")):
        out.append(Detection(100215, "Attack tool fingerprint detected", "tooling"))

    return out


# webtrap event kind -> (rule_id, description, category)
_WEBTRAP_RULES = {
    "webtrap.request":    (100301, "HTTP request to decoy web server", "recon"),
    "webtrap.recon":      (100302, "Sensitive path / admin panel probed", "recon"),
    "webtrap.credential": (100303, "Credentials submitted to decoy login", "credential-access"),
    "webtrap.scanner":    (100304, "Automated scanner / attack tool detected", "tooling"),
    "webtrap.exploit":    (100305, "Web exploit / traversal attempt", "exploit"),
}


def detect_webtrap(ev: dict) -> list[Detection]:
    """Detections for the self-written HTTP honeypot (webhoneypot/)."""
    out: list[Detection] = []
    eid = ev.get("eventid", "") or ""
    rid, desc, cat = _WEBTRAP_RULES.get(eid, _WEBTRAP_RULES["webtrap.request"])
    out.append(Detection(rid, desc, cat))
    # a credential submission on a fake login is worth capturing the default-account signal too
    if eid == "webtrap.credential" and (ev.get("username") or "").lower() in DEFAULT_ACCOUNTS:
        out.append(Detection(100111, "Login attempt with default account", "credential-access"))
    if _web_scan.record_failure(ev.get("src_ip", "") or ""):
        out.append(Detection(100306, "Aggressive web scanning (many requests / 60s)", "recon"))
    return out


def detect(honeypot: str, ev: dict) -> list[dict]:
    if honeypot == "cowrie":
        dets = detect_cowrie(ev)
    elif honeypot == "webtrap":
        dets = detect_webtrap(ev)
    else:
        dets = detect_dionaea(ev)
    return [d.as_dict() for d in dets]


def top_detection(dets: list[dict]) -> Optional[dict]:
    """Highest-severity detection for an event (drives the row's badge/severity)."""
    if not dets:
        return None
    return max(dets, key=lambda d: d["level"])
