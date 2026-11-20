"""
Skyhawk Security Operations — Unified Notification Module
Handles email (SendGrid), SMS (Twilio), and in-app (MongoDB) notifications.
Expo push delivery is handled by the durable outbox worker in job_worker.py.

Development can omit external channels. Production configuration validation
requires email and SMS credentials before the API starts.
"""
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

logger = logging.getLogger("skyhawk.notifications")

# ── SendGrid ──────────────────────────────────────────────────────────────────
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM_EMAIL", "noreply@skyhawksecurity.com")
EMAIL_ENABLED     = bool(SENDGRID_API_KEY)

# ── Twilio ────────────────────────────────────────────────────────────────────
TWILIO_SID    = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM   = os.environ.get("TWILIO_FROM_NUMBER", "")
SMS_ENABLED   = bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM)

def log_status() -> None:
    """Log which notification channels are active at startup."""
    logger.info(
        "Notification channels: email=%s sms=%s",
        "enabled" if EMAIL_ENABLED else "disabled (SENDGRID_API_KEY missing)",
        "enabled" if SMS_ENABLED else "disabled (TWILIO_* vars missing)",
    )


async def send_email(
    to: str,
    subject: str,
    body_html: str,
    body_text: Optional[str] = None,
) -> bool:
    """Send a transactional email via SendGrid. Returns True on success."""
    if not EMAIL_ENABLED:
        logger.debug("Email not configured — skipping message")
        return False
    payload = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": SENDGRID_FROM},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": body_text or ""},
            {"type": "text/html", "value": body_html},
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
                json=payload,
            )
        if response.status_code >= 300:
            logger.warning("SendGrid rejected a message with status %s", response.status_code)
            return False
        return True
    except httpx.HTTPError as exc:
        logger.warning("SendGrid delivery failed: %s", type(exc).__name__)
        return False


async def send_sms(to_phone: str, body: str) -> bool:
    """Send an SMS via Twilio. Returns True on success."""
    if not SMS_ENABLED:
        logger.debug("SMS not configured — skipping to %s", to_phone)
        return False
    if not to_phone or not to_phone.strip():
        return False
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json",
                auth=(TWILIO_SID, TWILIO_TOKEN),
                data={"Body": body, "From": TWILIO_FROM, "To": to_phone},
            )
        if response.status_code >= 300:
            logger.warning("Twilio rejected a message with status %s", response.status_code)
            return False
        return True
    except httpx.HTTPError as exc:
        logger.warning("Twilio delivery failed: %s", type(exc).__name__)
        return False


# ── In-App Notifications ──────────────────────────────────────────────────────

async def save_inapp(
    db,
    user_ids: list,
    title: str,
    body: str,
    category: str = "general",
    link: Optional[str] = None,
) -> None:
    """Persist in-app notification records for one or more users."""
    if not user_ids:
        return
    now = datetime.now(timezone.utc).isoformat()
    docs = [
        {
            "id": str(uuid.uuid4()),
            "user_id": uid,
            "title": title,
            "body": body,
            "category": category,
            "link": link,
            "read": False,
            "created_at": now,
        }
        for uid in user_ids
    ]
    try:
        await db.notifications.insert_many(docs)
    except Exception as exc:
        logger.warning("In-app notification save failed: %s", exc)


# ── Email Templates ───────────────────────────────────────────────────────────

_BASE_STYLE = """
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #000; color: #fff; padding: 40px 20px; max-width: 600px; margin: 0 auto;
"""

def email_template(title: str, body_lines: list, cta_text: str = "", cta_link: str = "") -> str:
    """Wrap content in a simple dark-themed Skyhawk email shell."""
    body_html = "".join(f"<p style='color:#D1D5DB;line-height:1.6;margin:8px 0'>{l}</p>" for l in body_lines)
    cta = (
        f"<a href='{cta_link}' style='display:inline-block;background:#3B82F6;color:#fff;"
        f"padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin-top:20px'>"
        f"{cta_text}</a>"
        if cta_text and cta_link else ""
    )
    return f"""
    <div style='{_BASE_STYLE}'>
      <div style='background:#111;border:1px solid #1F2937;border-radius:12px;padding:32px;'>
        <h1 style='color:#fff;font-size:20px;margin:0 0 8px'>🦅 Skyhawk Security</h1>
        <hr style='border:none;border-top:1px solid #1F2937;margin:16px 0'>
        <h2 style='color:#fff;font-size:18px;margin:0 0 16px'>{title}</h2>
        {body_html}
        {cta}
        <hr style='border:none;border-top:1px solid #1F2937;margin:24px 0 16px'>
        <p style='color:#4B5563;font-size:12px;margin:0'>
          Skyhawk Security Operations · This is an automated message.
        </p>
      </div>
    </div>
    """
