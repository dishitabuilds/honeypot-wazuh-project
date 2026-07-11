"""
alerts.py — outbound notifications for high-severity detections.

Sends a Telegram message (and/or SMTP email) when an event crosses the
configured alert level. Fully optional: with no credentials set, alerting is a
no-op so the stack runs fine out of the box.

Delivery never blocks ingestion: a failed send is pushed onto a small bounded
retry buffer and re-attempted on the next alert, so a transient Telegram/SMTP
outage doesn't silently drop alerts (nor stall the pipeline).
"""
from __future__ import annotations
import asyncio
import os
import smtplib
from collections import deque
from email.message import EmailMessage

import httpx

ALERT_LEVEL = int(os.getenv("ALERT_LEVEL", "10"))
RETRY_MAX = int(os.getenv("ALERT_RETRY_MAX", "50"))       # bound: drop oldest past this
RETRY_ATTEMPTS = int(os.getenv("ALERT_RETRY_ATTEMPTS", "5"))

# (text, remaining_attempts) messages awaiting redelivery
_retry: deque[tuple[str, int]] = deque(maxlen=RETRY_MAX)

TG_TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()
TG_CHAT = os.getenv("TELEGRAM_CHAT_ID", "").strip()

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
ALERT_TO = os.getenv("ALERT_TO", "").strip()


def _format(ev: dict) -> str:
    return (
        f"\U0001F6A8 Honeypot alert — level {ev.get('level')}\n"
        f"{ev.get('rule_desc')}\n"
        f"IP: {ev.get('src_ip')}  ({ev.get('country') or '?'})\n"
        f"Type: {ev.get('event_type')}\n"
        f"MITRE: {ev.get('mitre')}\n"
        f"Detail: {ev.get('command') or ev.get('username') or ev.get('message') or ''}"
    )


async def _deliver(client: httpx.AsyncClient, text: str) -> bool:
    """Attempt all configured channels. Returns True only if every enabled
    channel succeeded, so a partial failure gets retried."""
    ok = True
    if TG_TOKEN and TG_CHAT:
        try:
            r = await client.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT, "text": text}, timeout=6,
            )
            ok = ok and r.status_code < 400
        except Exception:
            ok = False
    if SMTP_HOST and ALERT_TO:
        try:
            msg = EmailMessage()
            msg["Subject"] = "[Honeypot] high-severity alert"
            msg["From"] = SMTP_USER or "honeypot@localhost"
            msg["To"] = ALERT_TO
            msg.set_content(text)
            await asyncio.to_thread(_send_email, msg)
        except Exception:
            ok = False
    return ok


def _send_email(msg: EmailMessage) -> None:
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as s:
        s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


async def _flush_retries(client: httpx.AsyncClient) -> None:
    for _ in range(len(_retry)):
        text, attempts = _retry.popleft()
        if not await _deliver(client, text) and attempts > 1:
            _retry.append((text, attempts - 1))     # requeue with one fewer try


async def maybe_alert(client: httpx.AsyncClient, ev: dict) -> None:
    await _flush_retries(client)                     # opportunistic redelivery
    if (ev.get("level") or 0) < ALERT_LEVEL:
        return
    if not ((TG_TOKEN and TG_CHAT) or (SMTP_HOST and ALERT_TO)):
        return                                       # alerting not configured
    text = _format(ev)
    if not await _deliver(client, text):
        _retry.append((text, RETRY_ATTEMPTS))
