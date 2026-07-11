"""
detect.py — detection logic ported from the project's Wazuh rules
(config/cowrie_rules.xml, config/dionaea_rules.xml).

Each honeypot event is evaluated and, when it matches, annotated with:
  severity level (0-15, Wazuh scale), a rule id, a human description,
  the MITRE ATT&CK technique/tactic, and a category.

This lets the analytics service raise the same alerts a Wazuh manager would,
without needing the full 6 GB SIEM stack running locally.
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Optional

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

    def __init__(self, rule_id, level, desc, mitre="", tactic="", category=""):
        self.rule_id = rule_id
        self.level = level
        self.desc = desc
        self.mitre = mitre
        self.tactic = tactic
        self.category = category
        self.band = band(level)

    def as_dict(self):
        return {
            "rule_id": self.rule_id, "level": self.level, "desc": self.desc,
            "mitre": self.mitre, "tactic": self.tactic,
            "category": self.category, "severity": self.band,
        }


class BruteForceTracker:
    """Sliding-window counter of failed logins per source IP (rule 100107 / 100210)."""
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


_bruteforce = BruteForceTracker()


def detect_cowrie(ev: dict) -> list[Detection]:
    """Return the detections a Cowrie event triggers."""
    out: list[Detection] = []
    eid = ev.get("eventid", "")

    if eid == "cowrie.session.connect":
        out.append(Detection(100102, 7, "Honeypot session established", "T1078", "TA0001", "access"))
    elif eid == "cowrie.client.version":
        out.append(Detection(100112, 6, "SSH client detected (possible scan)", "T1046", "TA0007", "recon"))
    elif eid == "cowrie.login.failed":
        out.append(Detection(100101, 5, "SSH/Telnet login attempt", "T1110", "TA0006", "credential-access"))
        if ev.get("password"):
            out.append(Detection(100108, 6, "Password captured on failed login", "T1110", "TA0006", "credential-access"))
        if (ev.get("username") or "").lower() in DEFAULT_ACCOUNTS:
            out.append(Detection(100111, 7, "Login attempt with default account", "T1078", "TA0001", "credential-access"))
        if _bruteforce.record_failure(ev.get("src_ip", "")):
            out.append(Detection(100107, 8, "Brute-force attack (>=5 fails / 60s)", "T1110", "TA0006", "credential-access"))
    elif eid == "cowrie.login.success":
        # Improvement over the original ruleset: flag the actual breach.
        out.append(Detection(100150, 10, "Honeypot breach — weak credential accepted", "T1078", "TA0001", "access"))
    elif eid == "cowrie.command.input":
        cmd = ev.get("input", "") or ""
        out.append(Detection(100103, 8, "Command executed in session", "T1059", "TA0002", "execution"))
        low = cmd.lower()
        if any(s in low for s in SUSPICIOUS_CMD):
            out.append(Detection(100104, 10, "Suspicious network command (wget/curl/nc)", "T1105", "TA0011", "malware"))
    elif eid == "cowrie.session.file_download":
        out.append(Detection(100105, 12, "File download via honeypot", "T1105", "TA0011", "malware"))
    elif eid == "cowrie.direct-tcpip.request":
        out.append(Detection(100106, 12, "SSH tunneling attempt", "T1572", "TA0011", "tunneling"))

    return out


def detect_dionaea(ev: dict) -> list[Detection]:
    """Return the detections a Dionaea event triggers (text-log driven)."""
    out: list[Detection] = []
    msg = (ev.get("message") or ev.get("raw") or "").lower()

    if "connection" in msg:
        if "smb" in msg:
            out.append(Detection(100201, 5, "Suspicious SMB activity", "T1046", "TA0007", "recon"))
        elif "ftp" in msg:
            out.append(Detection(100206, 6, "Inbound FTP connection", "T1046", "TA0007", "recon"))
        elif "http" in msg:
            out.append(Detection(100207, 6, "Inbound HTTP/HTTPS connection", "T1046", "TA0007", "recon"))
    if "stored binary" in msg or "download" in msg:
        out.append(Detection(100205, 12, "Malware sample captured", "T1204", "TA0002", "malware"))
    if any(x in msg for x in ("ms17-010", "eternalblue", "ms08-067", "bluekeep")):
        out.append(Detection(100208, 10, "Known Windows exploit attempt", "T1210", "TA0008", "exploit"))
    if any(x in msg for x in ("meterpreter", "shellcode", "reverse_shell")):
        out.append(Detection(100214, 11, "Shellcode / advanced payload captured", "T1204", "TA0002", "malware"))

    return out


def detect(protocol: str, ev: dict) -> list[dict]:
    dets = detect_cowrie(ev) if protocol == "cowrie" else detect_dionaea(ev)
    return [d.as_dict() for d in dets]


def top_detection(dets: list[dict]) -> Optional[dict]:
    """Highest-severity detection for an event (drives the row's badge/severity)."""
    if not dets:
        return None
    return max(dets, key=lambda d: d["level"])
