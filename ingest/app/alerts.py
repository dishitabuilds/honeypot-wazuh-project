"""
alerts.py — outbound notifications for high-severity detections.

Sends a Telegram message (and/or SMTP email) when an event crosses the
configured alert level. Fully optional: with no credentials set, alerting is a
no-op so the stack runs fine out of the box.
"""
from __future__ import annotations
import os
import smtplib
from email.message import EmailMessage

import httpx

ALERT_LEVEL = int(os.getenv("ALERT_LEVEL", "10"))

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


async def maybe_alert(client: httpx.AsyncClient, ev: dict) -> None:
    if (ev.get("level") or 0) < ALERT_LEVEL:
        return
    text = _format(ev)
    if TG_TOKEN and TG_CHAT:
        try:
            await client.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT, "text": text}, timeout=6,
            )
        except Exception:
            pass
    if SMTP_HOST and ALERT_TO:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[Honeypot] Level {ev.get('level')} — {ev.get('rule_desc')}"
            msg["From"] = SMTP_USER or "honeypot@localhost"
            msg["To"] = ALERT_TO
            msg.set_content(text)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as s:
                s.starttls()
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        except Exception:
            pass
