"""
enrich.py — threat-intelligence enrichment for attacker IPs.

Geolocation via ip-api.com (free, no key). Optional reputation scoring via
AbuseIPDB when ABUSEIPDB_KEY is set. Results are cached in the ip_intel table
so each IP is looked up only once.

Private / lab addresses (the Docker network we test with) are labelled locally
instead of hitting the geo API, since they have no public location.
"""
from __future__ import annotations
import ipaddress
import os
from datetime import datetime, timezone

import httpx

from . import db

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "").strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


async def _geo(client: httpx.AsyncClient, ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
    try:
        r = await client.get(url, timeout=6)
        j = r.json()
        if j.get("status") == "success":
            return {
                "country": j.get("country"), "country_code": j.get("countryCode"),
                "city": j.get("city"), "lat": j.get("lat"), "lon": j.get("lon"),
                "isp": j.get("isp"), "org": j.get("org"), "asn": j.get("as"),
            }
    except Exception:
        pass
    return {}


async def _abuseipdb(client: httpx.AsyncClient, ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=6,
        )
        d = r.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore"),
            "is_tor": 1 if d.get("isTor") else 0,
        }
    except Exception:
        return {}


async def enrich_ip(client: httpx.AsyncClient, ip: str) -> dict | None:
    """Look up + cache intel for one IP. Returns the stored record."""
    if not ip:
        return None
    cached = db.get_intel(ip)
    if cached:
        return cached

    if _is_private(ip):
        data = {"country": "Lab network", "country_code": "LAB",
                "city": "Docker", "lat": None, "lon": None,
                "isp": "internal", "org": "honeynet", "asn": "-",
                "abuse_score": None, "is_tor": 0}
    else:
        data = await _geo(client, ip)
        data.update(await _abuseipdb(client, ip))

    db.upsert_intel(ip, data, _now())
    return db.get_intel(ip)
