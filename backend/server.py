"""Skyhawk Security Operations - Backend API
JWT-based authentication, shift management, time clock, wallet, incidents, payroll, announcements.
"""
import asyncio
import io
import re
import os
import hmac
import uuid
import json
import base64
import hashlib
import logging
import secrets
import mimetypes
import time
import struct
from pathlib import Path
from urllib.parse import quote, unquote
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Annotated, Literal
from contextlib import asynccontextmanager

import jwt
import bcrypt
from cryptography.fernet import Fernet
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Query, Request, Response, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError, ServerSelectionTimeoutError  # noqa: F401
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas as pdf_canvas
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
import sentry_sdk
import notifications as notif
from object_storage import ObjectStorage
from jobs import enqueue as enqueue_job

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

def _require_env(key: str) -> str:
    """Read a required environment variable; fail fast with a clear message if absent."""
    v = os.environ.get(key)
    if not v:
        raise RuntimeError(
            f"Required environment variable '{key}' is not set. "
            "Set it in your deployment environment (Openship -> api service -> Environment, "
            "or backend/.env locally) and restart."
        )
    return v


MONGO_URL = _require_env("MONGO_URL")
DB_NAME = _require_env("DB_NAME")
JWT_SECRET = _require_env("JWT_SECRET")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_MINUTES = int(os.environ.get("ACCESS_TOKEN_MINUTES", "15"))
MANAGER_SESSION_HOURS = int(os.environ.get("MANAGER_SESSION_HOURS", "8"))
REFRESH_TOKEN_DAYS = int(os.environ.get("REFRESH_TOKEN_DAYS", "30"))
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
ALLOW_PUBLIC_REGISTRATION = os.environ.get("ALLOW_PUBLIC_REGISTRATION", "false").strip().lower() == "true"
SESSION_COOKIE_NAME = os.environ.get(
    "SESSION_COOKIE_NAME",
    "__Host-disptchr_session" if IS_PRODUCTION else "disptchr_session",
)
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true" if IS_PRODUCTION else "false").strip().lower() == "true"
CORS_ORIGINS = [origin.strip() for origin in os.environ.get(
    "CORS_ORIGINS",
    "http://127.0.0.1:5050,http://localhost:5050,http://127.0.0.1:3000,http://localhost:3000",
).split(",") if origin.strip()]
RATE_LIMIT_STORAGE_URI = os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://").strip()
if IS_PRODUCTION and RATE_LIMIT_STORAGE_URI == "memory://":
    raise RuntimeError("RATE_LIMIT_STORAGE_URI must use shared Redis storage in production")
CONTROL_PANEL_API_KEY = os.environ.get("CONTROL_PANEL_API_KEY", "")
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "").strip()
SENTRY_DSN = os.environ.get("SENTRY_DSN", "").strip()
DISPATCH_PHONE = os.environ.get("DISPATCH_PHONE", "").strip()
if DISPATCH_PHONE and not re.fullmatch(r"\+[1-9]\d{7,14}", DISPATCH_PHONE):
    raise RuntimeError("DISPATCH_PHONE must use E.164 format, for example +14165551234")

_configured_pii_key = os.environ.get("PII_ENCRYPTION_KEY", "").strip()
if IS_PRODUCTION and not _configured_pii_key:
    raise RuntimeError("Required environment variable 'PII_ENCRYPTION_KEY' is not set in production")
if not _configured_pii_key:
    _configured_pii_key = base64.urlsafe_b64encode(
        hashlib.sha256(f"{JWT_SECRET}:local-pii".encode()).digest()
    ).decode()
try:
    pii_cipher = Fernet(_configured_pii_key.encode())
except (TypeError, ValueError) as exc:
    raise RuntimeError("PII_ENCRYPTION_KEY must be a valid Fernet key") from exc

UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
(UPLOAD_DIR / "paystubs").mkdir(exist_ok=True)
(UPLOAD_DIR / "attachments").mkdir(exist_ok=True)
storage = ObjectStorage(UPLOAD_DIR, IS_PRODUCTION)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_UPLOAD_TYPES = {
    "image/jpeg", "image/png", "image/webp", "image/heic",
    "application/pdf",
}

RESET_TOKEN_TTL_MINUTES = 30
OAUTH_SCHEME = "bearer"

if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, environment=APP_ENV, traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1")))

if IS_PRODUCTION:
    if len(JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET must contain at least 32 characters in production")
    for required_key in (
        "CONTROL_PANEL_API_KEY", "METRICS_TOKEN", "SENDGRID_API_KEY", "SENDGRID_FROM_EMAIL",
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER", "DISPATCH_PHONE",
    ):
        _require_env(required_key)
    if not CORS_ORIGINS or any("localhost" in origin or "127.0.0.1" in origin for origin in CORS_ORIGINS):
        raise RuntimeError("CORS_ORIGINS must contain only production HTTPS origins in production")
    if any(not origin.startswith("https://") for origin in CORS_ORIGINS):
        raise RuntimeError("Every production CORS origin must use HTTPS")

HTTP_REQUESTS = Counter("disptchr_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram("disptchr_http_request_duration_seconds", "HTTP request duration", ["method", "route"])

SENSITIVE_USER_FIELDS = (
    "_id", "hashed_password", "sin", "sin_encrypted", "direct_deposit",
    "direct_deposit_encrypted", "mfa_secret_encrypted", "mfa_recovery_hashes", "mfa_last_step",
)
SENSITIVE_USER_PROJECTION = dict.fromkeys(SENSITIVE_USER_FIELDS, False)


def safe_user_document(user: dict) -> dict:
    safe = dict(user)
    safe.pop("_id", None)
    for field in SENSITIVE_USER_PROJECTION:
        safe.pop(field, None)
    return safe


def encrypt_private_value(value: str) -> str:
    return pii_cipher.encrypt(value.encode("utf-8")).decode("ascii")

class _JSONFormatter(logging.Formatter):
    """Emit one JSON object per log line for easy machine parsing."""
    _SKIP = frozenset(logging.LogRecord.__dict__) | {
        "args", "msg", "message", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        doc: dict = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.message,
        }
        if record.exc_info:
            doc["exception"] = self.formatException(record.exc_info)
        extra = {k: v for k, v in record.__dict__.items() if k not in self._SKIP}
        if extra:
            doc["extra"] = extra
        return json.dumps(doc)


_handler = logging.StreamHandler()
_handler.setFormatter(_JSONFormatter())
logging.root.handlers = [_handler]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("skyhawk")

client = AsyncIOMotorClient(
    MONGO_URL,
    serverSelectionTimeoutMS=5_000,   # fail fast if Atlas is unreachable
    connectTimeoutMS=10_000,
    socketTimeoutMS=30_000,
    maxPoolSize=50,
    minPoolSize=5,
    retryWrites=True,
)
db = client[DB_NAME]

# Rate limiter — shared across all routes
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300/minute"],
    storage_uri=RATE_LIMIT_STORAGE_URI,
)

# ============================================================
# Utilities
# ============================================================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_datetime_utc(value: str) -> datetime:
    """Parse ISO dates or datetimes and always return an aware UTC datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_shift_interval(start: str, end: str) -> None:
    try:
        start_at = parse_datetime_utc(start)
        end_at = parse_datetime_utc(end)
    except (TypeError, ValueError):
        raise HTTPException(422, "Shift start and end must be valid ISO 8601 dates")
    if end_at <= start_at:
        raise HTTPException(422, "Shift end must be after shift start")


def validate_payroll_period(period_start: str, period_end: str, pay_date: Optional[str] = None) -> None:
    try:
        start_on = date.fromisoformat(period_start[:10])
        end_on = date.fromisoformat(period_end[:10])
        if pay_date:
            date.fromisoformat(pay_date[:10])
    except (TypeError, ValueError):
        raise HTTPException(422, "Payroll dates must use ISO 8601 format")
    if end_on < start_on:
        raise HTTPException(422, "Payroll period end must be on or after its start")


def payroll_period_key(user_id: str, period_start: str, period_end: str) -> str:
    source = f"{user_id}|{period_start[:10]}|{period_end[:10]}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def hash_password(pw: str) -> str:
    normalized = hashlib.sha256(pw.encode("utf-8")).hexdigest().encode("ascii")
    return "bcrypt-sha256$" + bcrypt.hashpw(normalized, bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        if hashed.startswith("bcrypt-sha256$"):
            normalized = hashlib.sha256(pw.encode("utf-8")).hexdigest().encode("ascii")
            return bcrypt.checkpw(normalized, hashed.removeprefix("bcrypt-sha256$").encode())
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode())
    except Exception:
        return False


def create_access_token(
    user_id: str,
    email: str,
    role: str,
    expires_minutes: Optional[int] = None,
    session_id: Optional[str] = None,
) -> str:
    ttl = expires_minutes if expires_minutes is not None else ACCESS_TOKEN_MINUTES
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "typ": "access",
        "exp": now_utc() + timedelta(minutes=ttl),
        "iat": now_utc(),
    }
    if session_id:
        payload["jti"] = session_id
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _totp_code(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


def _manager_mfa_setup(email: str) -> tuple[dict, dict]:
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    recovery_codes = [f"{''.join(secrets.choice(alphabet) for _ in range(4))}-{''.join(secrets.choice(alphabet) for _ in range(4))}" for _ in range(10)]
    stored = {
        "mfa_secret_encrypted": encrypt_private_value(secret),
        "mfa_recovery_hashes": [hashlib.sha256(code.encode()).hexdigest() for code in recovery_codes],
        "mfa_last_step": None,
        "mfa_enabled": True,
    }
    uri = f"otpauth://totp/{quote(f'Skyhawk Manager:{email}')}?secret={secret}&issuer={quote('Skyhawk Security')}&algorithm=SHA1&digits=6&period=30"
    return stored, {"secret": secret, "otpauth_uri": uri, "recovery_codes": recovery_codes}


async def verify_manager_mfa(user: dict, submitted: Optional[str]) -> bool:
    if not user.get("mfa_enabled") or not user.get("mfa_secret_encrypted") or not submitted:
        return False
    code = submitted.strip().upper()
    if re.fullmatch(r"\d{6}", code):
        secret = pii_cipher.decrypt(user["mfa_secret_encrypted"].encode()).decode()
        current_step = int(time.time() // 30)
        for step in (current_step - 1, current_step, current_step + 1):
            if hmac.compare_digest(_totp_code(secret, step), code):
                result = await db.users.update_one(
                    {"id": user["id"], "$or": [{"mfa_last_step": {"$lt": step}}, {"mfa_last_step": None}, {"mfa_last_step": {"$exists": False}}]},
                    {"$set": {"mfa_last_step": step}},
                )
                return result.modified_count == 1
        return False
    candidate = hashlib.sha256(code.encode()).hexdigest()
    match = next((value for value in user.get("mfa_recovery_hashes", []) if hmac.compare_digest(value, candidate)), None)
    if not match:
        return False
    result = await db.users.update_one({"id": user["id"], "mfa_recovery_hashes": match}, {"$pull": {"mfa_recovery_hashes": match}})
    return result.modified_count == 1


def refresh_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_refresh_token(user_id: str, family_id: Optional[str] = None) -> str:
    raw = secrets.token_urlsafe(48)
    await db.refresh_tokens.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "family_id": family_id or str(uuid.uuid4()),
        "token_digest": refresh_token_digest(raw),
        "expires_at": now_utc() + timedelta(days=REFRESH_TOKEN_DAYS),
        "created_at": iso(now_utc()),
    })
    return raw


bearer = HTTPBearer(auto_error=False)

MANAGER_PERMISSION_CATALOG = [
    {"key": "dashboard.view", "label": "Dashboard", "description": "View the manager overview and operational totals."},
    {"key": "sos.manage", "label": "SOS Alerts", "description": "Acknowledge and resolve emergency alerts."},
    {"key": "locations.view", "label": "Live Locations", "description": "View on-duty guard locations."},
    {"key": "guards.manage", "label": "Guards", "description": "View and update guard records."},
    {"key": "sites.manage", "label": "Sites", "description": "Create and maintain client sites."},
    {"key": "scheduling.manage", "label": "Scheduling", "description": "Manage shifts, open shifts, and swaps."},
    {"key": "timeclock.manage", "label": "Timeclock", "description": "Review and correct timeclock entries."},
    {"key": "incidents.manage", "label": "Incidents", "description": "Review incidents and update their status."},
    {"key": "payroll.manage", "label": "Payroll", "description": "Prepare, review, and release manager payroll records."},
    {"key": "announcements.manage", "label": "Announcements", "description": "Publish announcements and moderate staff community posts."},
    {"key": "compliance.view", "label": "Compliance", "description": "Review licences and compliance status."},
]
MANAGER_PERMISSION_KEYS = frozenset(item["key"] for item in MANAGER_PERMISSION_CATALOG)


def normalize_manager_permissions(values: Optional[List[str]]) -> list[str]:
    if values is None:
        return []
    return sorted({value for value in values if value in MANAGER_PERMISSION_KEYS})


def enforce_manager_permission(user: dict, permission: str) -> None:
    if user.get("role") != "admin":
        return
    if permission not in normalize_manager_permissions(user.get("manager_permissions")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This manager access level is disabled")


async def active_managers_with_permission(permission: str, projection: dict) -> list[dict]:
    if permission not in MANAGER_PERMISSION_KEYS:
        return []
    return await db.users.find(
        {
            "role": "admin",
            "access_status": "active",
            "manager_permissions": permission,
        },
        projection,
    ).to_list(500)


def required_manager_permission(path: str) -> Optional[str]:
    normalized = path.removeprefix("/api")
    permission_routes = (
        ("/admin/dashboard", "dashboard.view"),
        ("/admin/employee-badge", "guards.manage"),
        ("/admin/guards", "guards.manage"),
        ("/admin/sites", "sites.manage"),
        ("/admin/scheduling", "scheduling.manage"),
        ("/admin/shifts", "scheduling.manage"),
        ("/admin/open-shifts", "scheduling.manage"),
        ("/admin/shift-swaps", "scheduling.manage"),
        ("/admin/timeclock", "timeclock.manage"),
        ("/admin/incidents", "incidents.manage"),
        ("/incidents", "incidents.manage"),
        ("/admin/preferences/payroll", "payroll.manage"),
        ("/admin/payroll", "payroll.manage"),
        ("/payroll", "payroll.manage"),
        ("/admin/announcements", "announcements.manage"),
        ("/admin/community", "announcements.manage"),
        ("/admin/compliance", "compliance.view"),
        ("/ops/live-locations", "locations.view"),
        ("/sos", "sos.manage"),
    )
    for prefix, permission in permission_routes:
        if normalized.startswith(prefix):
            return permission
    return None


async def get_current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    token = creds.credentials if creds else request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return await _user_from_access_token(token)


async def _user_from_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "access":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    user = await db.users.find_one({"id": user_id}, SENSITIVE_USER_PROJECTION)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if user.get("access_status", "active") != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account access is disabled")
    if user.get("role") == "admin":
        session_id = payload.get("jti")
        if not session_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Manager session is invalid")
        session = await db.manager_sessions.find_one({
            "id": session_id,
            "user_id": user["id"],
            "expires_at": {"$gte": now_utc()},
        }, {"_id": 0, "id": 1})
        if not session:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Manager session has expired or was revoked")
    return user


async def send_push(recipients: list[str], data: dict, idempotency_key: Optional[str] = None):
    if not recipients:
        return
    if "title" not in data or "message" not in data:
        return
    payload = {"recipients": recipients, "data": data}
    if idempotency_key:
        payload["$idempotency_key"] = idempotency_key
    await enqueue_job(db, "push", payload, idempotency_key)


async def queue_email(to: str, subject: str, html: str, text: str = "", idempotency_key: Optional[str] = None):
    if to:
        await enqueue_job(db, "email", {"to": to, "subject": subject, "html": html, "text": text}, idempotency_key)


async def queue_sms(to: str, body: str, idempotency_key: Optional[str] = None):
    if to:
        await enqueue_job(db, "sms", {"to": to, "body": body}, idempotency_key)


# ============================================================
# Pydantic Models
# ============================================================
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str
    phone: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = Field(default=None, min_length=6, max_length=32)


class AuthOut(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: dict


class ManagerAuthOut(BaseModel):
    user: dict


class RefreshTokenIn(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=500)


class BadgeVerifyIn(BaseModel):
    token: str = Field(min_length=20, max_length=2000)


class ClockInIn(BaseModel):
    shift_id: str = Field(min_length=1, max_length=100)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    selfie_base64: str = Field(min_length=100, max_length=500_000)


class ClockOutIn(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    selfie_base64: Optional[str] = None


class BreakIn(BaseModel):
    action: str  # "start" | "end"


class AckIn(BaseModel):
    pass


_Photo = Annotated[str, Field(max_length=500_000)]  # ~375 KB per image

class IncidentIn(BaseModel):
    type: str = Field(max_length=50)  # incident|injury|lost_found|property_damage
    site_id: Optional[str] = Field(default=None, max_length=100)
    description: str = Field(min_length=5, max_length=5_000)
    severity: str = Field(default="medium", max_length=20)  # low|medium|high|critical
    witness_name: Optional[str] = Field(default=None, max_length=200)
    witness_contact: Optional[str] = Field(default=None, max_length=200)
    photos: List[_Photo] = Field(default=[], max_length=5)  # max 5 base64 images
    signature_base64: Optional[str] = Field(default=None, max_length=500_000)


class RegisterPushIn(BaseModel):
    user_id: Optional[str] = None
    platform: Literal["ios", "android"]
    device_token: str = Field(min_length=20, max_length=300)


class ClaimShiftIn(BaseModel):
    pass


class SiteAckIn(BaseModel):
    site_id: str


class SOSIn(BaseModel):
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    message: Optional[str] = Field(default=None, max_length=500)


class IncidentStatusIn(BaseModel):
    status: str = Field(max_length=30)
    note: Optional[str] = Field(default=None, max_length=2000)
    assigned_to: Optional[str] = Field(default=None, max_length=100)


class LocationPingIn(BaseModel):
    latitude: float
    longitude: float
    accuracy_m: Optional[float] = None


class SwapRequestIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class SwapActionIn(BaseModel):
    action: str  # approve | reject
    reason: Optional[str] = Field(default=None, max_length=500)


class PayrollCalculateIn(BaseModel):
    user_id: str = Field(min_length=1, max_length=100)
    period_start: str = Field(min_length=10, max_length=50)
    period_end: str = Field(min_length=10, max_length=50)
    pay_date: str = Field(min_length=10, max_length=50)
    hourly_rate: float = Field(gt=0, le=1000)
    overtime_threshold: float = Field(default=40.0, ge=0, le=1000)
    overtime_multiplier: float = Field(default=1.5, ge=1, le=10)
    tax_rate: float = Field(default=0.28, ge=0, le=1)


class WalletDocIn(BaseModel):
    type: str = Field(max_length=50)
    name: str = Field(max_length=200)
    number: str = Field(max_length=100)
    expiry: str = Field(max_length=50)


class CommunityPostIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    type: str = Field(default="post", max_length=20)  # post | announcement | event | recognition
    audience: str = Field(default="All Staff", max_length=50)
    attachments: List[dict] = Field(default_factory=list, max_length=10)


class CommunityCommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


class CommunityEditIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    attachments: List[dict] = Field(default_factory=list, max_length=10)


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=128)


class SettingsIn(BaseModel):
    push_notifications: Optional[bool] = None
    location_sharing: Optional[bool] = None
    shift_reminders: Optional[bool] = None
    community_notifications: Optional[bool] = None


class ManagerPayrollPreferencesIn(BaseModel):
    features: Optional[dict[str, bool]] = None
    columns: Optional[dict[str, bool]] = None
    timesheet_columns: Optional[dict[str, bool]] = None


class OnboardingDocIn(BaseModel):
    type: str = Field(max_length=50)
    name: str = Field(max_length=200)
    number: str = Field(max_length=100)
    expiry: str = Field(max_length=50)
    attachment_url: Optional[str] = Field(default=None, max_length=500)


class OnboardingSINIn(BaseModel):
    sin: str = Field(min_length=9, max_length=11)


class OnboardingDirectDepositIn(BaseModel):
    institution: str = Field(max_length=10)
    transit: str = Field(max_length=10)
    account: str = Field(max_length=20)


class OnboardingEmergencyContactIn(BaseModel):
    name: str = Field(max_length=200)
    phone: str = Field(max_length=50)
    relation: str = Field(max_length=50)


class OnboardingAgreementsIn(BaseModel):
    signed: bool


# ============================================================
# App
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await ensure_indexes()
        logger.info("Database indexes ensured")
    except Exception as exc:
        logger.critical("Failed to create required DB indexes: %s", exc)
        raise
    notif.log_status()
    yield
    client.close()


app = FastAPI(
    title="Skyhawk Ops API",
    lifespan=lifespan,
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None,
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def request_observability(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "")[:100] or str(uuid.uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    route_path = getattr(route, "path", request.url.path)
    HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
    HTTP_LATENCY.labels(request.method, route_path).observe(time.perf_counter() - started)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def enforce_cookie_request_origin(request: Request, call_next):
    """Block cross-site mutations when authentication comes from a browser cookie."""
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.cookies.get(SESSION_COOKIE_NAME)
        and not request.headers.get("authorization")
    ):
        origin = request.headers.get("origin")
        if origin not in CORS_ORIGINS:
            return JSONResponse(status_code=403, content={"detail": "Untrusted request origin"})
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unhandled exceptions — log with context, return a safe 500."""
    if isinstance(exc, HTTPException):
        raise exc
    logger.error(
        "Unhandled exception on %s %s",
        request.method,
        request.url.path,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )


api = APIRouter(prefix="/api")


@app.get("/internal/metrics", include_in_schema=False)
async def metrics(request: Request):
    if not METRICS_TOKEN or not hmac.compare_digest(request.headers.get("x-metrics-token", ""), METRICS_TOKEN):
        raise HTTPException(404, "Not found")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/internal/live", include_in_schema=False)
async def live():
    return {"status": "ok"}


@api.get("/health")
async def health():
    """Readiness probe. Returns 503 if a required dependency is unreachable."""
    try:
        await db.command("ping")
        await storage.healthcheck()
        return {"status": "ok", "dependencies": "connected"}
    except Exception as exc:
        logger.warning("Health check failed: %s", exc)
        raise HTTPException(status_code=503, detail="Required dependency unavailable")


async def ensure_indexes():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.shifts.create_index("id", unique=True)
    await db.shifts.create_index(
        [("claimed_from_open", 1), ("user_id", 1)],
        unique=True,
        partialFilterExpression={"claimed_from_open": {"$type": "string"}},
    )
    await db.open_shifts.create_index("id", unique=True)
    await db.sites.create_index("id", unique=True)
    await db.announcements.create_index("id", unique=True)
    await db.incidents.create_index("id", unique=True)
    await db.timeclock.create_index("id", unique=True)
    await db.payroll.create_index("id", unique=True)
    await db.payroll.create_index("period_key", unique=True, sparse=True)
    await db.push_tokens.create_index([("user_id", 1), ("device_token", 1)], unique=True)
    await db.refresh_tokens.create_index("token_digest", unique=True)
    await db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.refresh_tokens.create_index([("user_id", 1), ("family_id", 1)])
    await db.manager_sessions.create_index("id", unique=True)
    await db.manager_sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.manager_sessions.create_index([("user_id", 1), ("created_at", -1)])
    await db.sos_alerts.create_index("id", unique=True)
    await db.sos_alerts.create_index([("status", 1), ("created_at", -1)])
    await db.shift_swaps.create_index("id", unique=True)
    await db.shift_swaps.create_index([("status", 1), ("start", 1)])
    duplicate_active_swaps = await db.shift_swaps.aggregate([
        {"$match": {"status": {"$in": ["open", "accepted", "processing"]}}},
        {"$group": {"_id": "$shift_id", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gt": 1}}},
        {"$limit": 1},
    ]).to_list(1)
    if duplicate_active_swaps:
        raise RuntimeError(
            f"Multiple active swap requests exist for shift {duplicate_active_swaps[0]['_id']}; "
            "resolve the conflicting records before starting the API"
        )
    await db.shift_swaps.update_many(
        {"status": {"$in": ["open", "accepted", "processing"]}},
        [{"$set": {"active_shift_id": "$shift_id"}}],
    )
    await db.shift_swaps.update_many(
        {"status": {"$nin": ["open", "accepted", "processing"]}, "active_shift_id": {"$exists": True}},
        {"$unset": {"active_shift_id": ""}},
    )
    await db.shift_swaps.create_index("active_shift_id", unique=True, sparse=True)
    await db.location_pings.create_index([("timeclock_id", 1), ("ts", -1)])
    await db.community_posts.create_index("id", unique=True)
    await db.community_posts.create_index([("type", 1), ("created_at", -1)])
    await db.password_resets.create_index("user_id", unique=True)
    await db.password_resets.create_index("token_digest", unique=True, sparse=True)
    await db.password_resets.delete_many({"expires_at": {"$type": "string"}})
    await db.password_resets.create_index("expires_at", expireAfterSeconds=0)
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.access_audit.create_index([("occurred_at", -1)])
    await db.stored_files.create_index([("category", 1), ("stored_name", 1)], unique=True)
    await db.stored_files.create_index([("owner_id", 1), ("created_at", -1)])
    await db.notification_jobs.create_index("id", unique=True)
    await db.notification_jobs.create_index("idempotency_key", unique=True, sparse=True)
    await db.notification_jobs.create_index([("status", 1), ("available_at", 1), ("created_at", 1)])
    await db.notification_jobs.create_index("purge_at", expireAfterSeconds=0, sparse=True)
    await db.notifications.create_index([("user_id", 1), ("read", 1)])
    # One-time compatibility backfill. Once present, missing permission fields
    # are treated as no access rather than silently granting future routes.
    await db.users.update_many(
        {"role": "admin", "access_status": {"$exists": False}},
        {"$set": {"access_status": "active"}},
    )
    await db.users.update_many(
        {"role": "admin", "manager_permissions": {"$exists": False}},
        {"$set": {"manager_permissions": sorted(MANAGER_PERMISSION_KEYS)}},
    )
    await migrate_protected_file_urls()


async def migrate_protected_file_urls():
    """Move legacy public upload paths to the authenticated file endpoint."""
    await db.payroll.update_many(
        {"pay_stub_url": {"$regex": r"^/uploads/paystubs/"}},
        [{"$set": {"pay_stub_url": {"$replaceOne": {
            "input": "$pay_stub_url",
            "find": "/uploads/paystubs/",
            "replacement": "/api/files/paystubs/",
        }}}}],
    )
    await db.wallet_documents.update_many(
        {"attachment_url": {"$regex": r"^/uploads/attachments/"}},
        [{"$set": {"attachment_url": {"$replaceOne": {
            "input": "$attachment_url",
            "find": "/uploads/attachments/",
            "replacement": "/api/files/attachments/",
        }}}}],
    )
    await db.community_posts.update_many(
        {"attachments.url": {"$regex": r"^/uploads/attachments/"}},
        [{"$set": {"attachments": {"$map": {
            "input": {"$ifNull": ["$attachments", []]},
            "as": "attachment",
            "in": {"$mergeObjects": ["$$attachment", {
                "url": {"$replaceOne": {
                    "input": "$$attachment.url",
                    "find": "/uploads/attachments/",
                    "replacement": "/api/files/attachments/",
                }}
            }]},
        }}}}],
    )




# ============================================================
# AUTH
# ============================================================
@api.get("/")
async def root():
    return {"service": "Skyhawk Ops API", "status": "online"}


@api.post("/auth/register", response_model=AuthOut)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterIn):
    if not ALLOW_PUBLIC_REGISTRATION:
        raise HTTPException(403, "Guard accounts must be created by an authorized manager")
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(400, "Email already registered")
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "email": body.email.lower(),
        "hashed_password": hash_password(body.password),
        "full_name": body.full_name,
        "phone": body.phone,
        "role": "employee",
        "access_status": "active",
        "employee_number": f"SH-{str(uuid.uuid4())[:4].upper()}",
        "licence_number": None,
        "licence_expiry": None,
        "certifications": [],
        "employment_status": "Onboarding",
        "photo_url": None,
        "emergency_contact": None,
        "onboarding_complete": False,
        "preferences": {
            "push_notifications": True,
            "location_sharing": True,
            "shift_reminders": True,
            "community_notifications": True,
        },
        "created_at": iso(now_utc()),
    }
    await db.users.insert_one(user)
    token = create_access_token(user_id, user["email"], "employee")
    refresh_token = await create_refresh_token(user_id)
    result = {"access_token": token, "refresh_token": refresh_token, "user": safe_user_document(user)}
    result.update(token_type=OAUTH_SCHEME)
    return result


@api.post("/auth/login", response_model=AuthOut)
@limiter.limit("10/minute")
async def login(request: Request, response: Response, body: LoginIn):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(401, "Invalid email or password")
    if user.get("access_status", "active") != "active":
        raise HTTPException(403, "This account has been disabled by company administration")
    if user.get("role") == "admin":
        raise HTTPException(403, "Manager accounts must sign in through the Manager Portal")
    token = create_access_token(user["id"], user["email"], user["role"])
    refresh_token = await create_refresh_token(user["id"])
    result = {"access_token": token, "refresh_token": refresh_token, "user": safe_user_document(user)}
    result.update(token_type=OAUTH_SCHEME)
    return result


@api.post("/auth/manager-login", response_model=ManagerAuthOut)
@limiter.limit("10/minute")
async def manager_login(request: Request, response: Response, body: LoginIn):
    user = await db.users.find_one({"email": body.email.lower(), "role": "admin"})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(401, "Invalid email, password, or verification code")
    if user.get("access_status", "active") != "active":
        raise HTTPException(403, "This account has been disabled by company administration")
    if not await verify_manager_mfa(user, body.mfa_code):
        raise HTTPException(401, "Invalid email, password, or verification code")
    user["manager_permissions"] = normalize_manager_permissions(user.get("manager_permissions"))
    session_id = str(uuid.uuid4())
    expires_at = now_utc() + timedelta(hours=MANAGER_SESSION_HOURS)
    await db.manager_sessions.insert_one({
        "id": session_id,
        "user_id": user["id"],
        "created_at": now_utc(),
        "expires_at": expires_at,
    })
    token = create_access_token(
        user["id"], user["email"], user["role"],
        expires_minutes=MANAGER_SESSION_HOURS * 60,
        session_id=session_id,
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=MANAGER_SESSION_HOURS * 3600,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return {"user": safe_user_document(user)}


@api.post("/auth/refresh", response_model=AuthOut)
@limiter.limit("20/minute")
async def refresh_access_token(request: Request, body: RefreshTokenIn):
    digest = refresh_token_digest(body.refresh_token)
    current = await db.refresh_tokens.find_one_and_update({
        "token_digest": digest,
        "expires_at": {"$gte": now_utc()},
        "used_at": {"$exists": False},
        "revoked_at": {"$exists": False},
    }, {"$set": {"used_at": now_utc()}}, return_document=ReturnDocument.BEFORE)
    if not current:
        reused = await db.refresh_tokens.find_one({"token_digest": digest})
        if reused and reused.get("family_id"):
            await db.refresh_tokens.delete_many({"family_id": reused["family_id"]})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")
    user = await db.users.find_one({"id": current["user_id"]}, SENSITIVE_USER_PROJECTION)
    if not user or user.get("access_status", "active") != "active" or user.get("role") != "employee":
        await db.refresh_tokens.delete_many({"family_id": current["family_id"]})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account access is unavailable")
    replacement = await create_refresh_token(user["id"], current["family_id"])
    user.pop("_id", None)
    result = {
        "access_token": create_access_token(user["id"], user["email"], user["role"]),
        "refresh_token": replacement,
        "user": user,
    }
    result.update(token_type=OAUTH_SCHEME)
    return result


@api.post("/auth/logout-native", status_code=204)
async def logout_native(body: RefreshTokenIn):
    current = await db.refresh_tokens.find_one({"token_digest": refresh_token_digest(body.refresh_token)})
    if current:
        await db.refresh_tokens.delete_many({"family_id": current["family_id"]})


@api.post("/auth/logout", status_code=204)
async def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
            if payload.get("typ") == "access" and payload.get("jti"):
                await db.manager_sessions.delete_one({"id": payload["jti"], "user_id": payload.get("sub")})
        except jwt.PyJWTError:
            pass
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@api.post("/auth/change-password")
@limiter.limit("5/minute")
async def change_password(request: Request, body: ChangePasswordIn, user=Depends(get_current_user)):
    full_user = await db.users.find_one({"id": user["id"]})
    if not full_user or not verify_password(body.current_password, full_user["hashed_password"]):
        raise HTTPException(401, "Current password is incorrect")
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"hashed_password": hash_password(body.new_password)}},
    )
    # Invalidate any outstanding reset tokens once the password changes.
    await db.password_resets.delete_many({"user_id": user["id"]})
    await db.refresh_tokens.delete_many({"user_id": user["id"]})
    await db.manager_sessions.delete_many({"user_id": user["id"]})
    return {"status": "password_updated"}


@api.post("/auth/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, body: ForgotPasswordIn):
    user = await db.users.find_one({"email": body.email.lower()})
    # Always return a generic response so this endpoint can't be used to
    # enumerate registered emails.
    generic = {"status": "if_registered_email_sent"}
    if not user:
        return generic
    raw_token = secrets.token_urlsafe(32)
    token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    await db.password_resets.update_one(
        {"user_id": user["id"]},
        {"$set": {
            "user_id": user["id"],
            "token_digest": token_digest,
            "expires_at": now_utc() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
            "created_at": iso(now_utc()),
        }},
        upsert=True,
    )
    reset_link = f"disptchr://reset-password?token={raw_token}"
    html = notif.email_template(
        "Reset your Skyhawk password",
        [
            f"Hi {user.get('full_name', 'there')},",
            "We received a request to reset your password. Click the button below — "
            "the link expires in <strong>30 minutes</strong>.",
            "If you didn't request this, you can safely ignore this email.",
        ],
        cta_text="Reset Password",
        cta_link=reset_link,
    )
    await queue_email(
        user["email"],
        "Reset your Skyhawk Security password",
        html,
        f"Password reset link (expires in 30 min): {reset_link}",
        f"password-reset:{user['id']}:{token_digest}",
    )
    return generic


@api.post("/auth/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, body: ResetPasswordIn):
    token_digest = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    match = await db.password_resets.find_one_and_delete({
        "token_digest": token_digest,
        "expires_at": {"$gte": now_utc()},
    })
    if not match:
        raise HTTPException(400, "Invalid or expired reset token")
    await db.users.update_one(
        {"id": match["user_id"]},
        {"$set": {"hashed_password": hash_password(body.new_password)}},
    )
    await db.refresh_tokens.delete_many({"user_id": match["user_id"]})
    await db.manager_sessions.delete_many({"user_id": match["user_id"]})
    return {"status": "password_reset"}


# ============================================================
# SETTINGS / PREFERENCES
# ============================================================
@api.get("/settings")
async def get_settings(user=Depends(get_current_user)):
    defaults = {
        "push_notifications": True,
        "location_sharing": True,
        "shift_reminders": True,
        "community_notifications": True,
    }
    return {**defaults, **(user.get("preferences") or {})}


@api.put("/settings")
async def update_settings(body: SettingsIn, user=Depends(get_current_user)):
    updates = {f"preferences.{k}": v for k, v in body.model_dump(exclude_none=True).items()}
    if updates:
        await db.users.update_one({"id": user["id"]}, {"$set": updates})
    fresh = await db.users.find_one({"id": user["id"]}, SENSITIVE_USER_PROJECTION)
    defaults = {
        "push_notifications": True,
        "location_sharing": True,
        "shift_reminders": True,
        "community_notifications": True,
    }
    return {**defaults, **(fresh.get("preferences") or {})}


# ============================================================
# IN-APP NOTIFICATIONS
# ============================================================
@api.get("/notifications")
async def get_notifications(user=Depends(get_current_user), limit: int = 60):
    items = await db.notifications.find(
        {"user_id": user["id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(min(limit, 100))
    return {"notifications": items}


@api.get("/notifications/unread-count")
async def get_unread_count(user=Depends(get_current_user)):
    count = await db.notifications.count_documents({"user_id": user["id"], "read": False})
    return {"count": count}


@api.post("/notifications/read-all")
async def mark_all_notifications_read(user=Depends(get_current_user)):
    await db.notifications.update_many(
        {"user_id": user["id"], "read": False},
        {"$set": {"read": True}},
    )
    return {"status": "ok"}


@api.post("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str, user=Depends(get_current_user)):
    await db.notifications.update_one(
        {"id": notif_id, "user_id": user["id"]},
        {"$set": {"read": True}},
    )
    return {"status": "ok"}


# ============================================================
# FILE UPLOADS
# ============================================================
@api.post("/uploads", status_code=201)
@limiter.limit("20/minute")
async def upload_file(request: Request, file: UploadFile = File(...), user=Depends(get_current_user)):
    if file.content_type not in ALLOWED_UPLOAD_TYPES:
        raise HTTPException(400, f"Unsupported file type: {file.content_type}")
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (max 10 MB)")
    ext = mimetypes.guess_extension(file.content_type) or ""
    stored_name = f"{uuid.uuid4()}{ext}"
    storage_key = f"attachments/{stored_name}"
    await storage.put(storage_key, contents, file.content_type)
    canonical_url = f"/api/files/attachments/{stored_name}"
    try:
        await db.stored_files.insert_one({
            "id": str(uuid.uuid4()),
            "category": "attachments",
            "stored_name": stored_name,
            "owner_id": user["id"],
            "original_name": file.filename,
            "content_type": file.content_type,
            "byte_size": len(contents),
            "created_at": iso(now_utc()),
        })
    except Exception:
        await storage.delete(storage_key)
        raise
    return {
        "url": canonical_url,
        "name": file.filename,
        "content_type": file.content_type,
        "size": len(contents),
        "kind": "image" if file.content_type.startswith("image/") else "pdf",
    }


def _validated_file_path(category: str, filename: str) -> Path:
    if category not in {"attachments", "paystubs"}:
        raise HTTPException(404, "File not found")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", filename) or filename in {".", ".."}:
        raise HTTPException(404, "File not found")
    path = (UPLOAD_DIR / category / filename).resolve()
    expected_parent = (UPLOAD_DIR / category).resolve()
    if path.parent != expected_parent:
        raise HTTPException(404, "File not found")
    return path


async def _validated_file_key(category: str, filename: str) -> str:
    _validated_file_path(category, filename)
    key = f"{category}/{filename}"
    if not await storage.exists(key):
        raise HTTPException(404, "File not found")
    return key


def _stored_file_reference(url: str) -> Optional[tuple[str, str]]:
    match = re.fullmatch(r"/(?:api/files|uploads)/(attachments|paystubs)/([A-Za-z0-9._-]+)", url or "")
    return (match.group(1), match.group(2)) if match else None


def _attachment_filename(url: str) -> Optional[str]:
    reference = _stored_file_reference(url)
    return reference[1] if reference and reference[0] == "attachments" else None


async def _delete_stored_file(url: str) -> None:
    reference = _stored_file_reference(url)
    if not reference:
        return
    category, filename = reference
    await storage.delete(f"{category}/{filename}")
    await db.stored_files.delete_one({"category": category, "stored_name": filename})


async def _validate_post_attachments(
    attachments: List[dict], user_id: str, existing_urls: Optional[set[str]] = None,
) -> List[dict]:
    existing_urls = existing_urls or set()
    normalized = []
    seen = set()
    for item in attachments:
        url = str(item.get("url") or "")
        filename = _attachment_filename(url)
        if not filename:
            raise HTTPException(422, "Community attachments must be uploaded through Disptchr")
        canonical_url = f"/api/files/attachments/{filename}"
        if canonical_url in seen:
            continue
        stored = await db.stored_files.find_one({
            "category": "attachments", "stored_name": filename,
        }, {"_id": 0})
        if not stored or (stored.get("owner_id") != user_id and canonical_url not in existing_urls):
            raise HTTPException(403, "Attachment is unavailable or belongs to another account")
        seen.add(canonical_url)
        normalized.append({
            "url": canonical_url,
            "name": str(stored.get("original_name") or item.get("name") or "Attachment")[:255],
            "content_type": stored.get("content_type"),
            "size": stored.get("byte_size"),
            "kind": "image" if str(stored.get("content_type") or "").startswith("image/") else "pdf",
        })
    return normalized


async def _delete_attachment_if_unreferenced(url: str) -> None:
    filename = _attachment_filename(url)
    if not filename:
        return
    canonical = f"/api/files/attachments/{filename}"
    legacy = f"/uploads/attachments/{filename}"
    if await db.community_posts.find_one({"attachments.url": {"$in": [canonical, legacy]}}, {"_id": 1}):
        return
    if await db.wallet_documents.find_one({"attachment_url": {"$in": [canonical, legacy]}}, {"_id": 1}):
        return
    await storage.delete(f"attachments/{filename}")
    await db.stored_files.delete_one({"category": "attachments", "stored_name": filename})


async def _can_access_file(user: dict, category: str, filename: str) -> bool:
    if user.get("role") == "admin":
        return True
    stored = await db.stored_files.find_one({
        "category": category,
        "stored_name": filename,
    })
    if stored and stored.get("owner_id") == user["id"]:
        return True
    canonical = f"/api/files/{category}/{filename}"
    legacy = f"/uploads/{category}/{filename}"
    if category == "paystubs":
        return bool(await db.payroll.find_one({
            "user_id": user["id"],
            "pay_stub_url": {"$in": [canonical, legacy]},
        }))
    if await db.wallet_documents.find_one({
        "user_id": user["id"],
        "attachment_url": {"$in": [canonical, legacy]},
    }):
        return True
    # Community attachments are intentionally shared with every signed-in employee.
    return bool(await db.community_posts.find_one({
        "attachments.url": {"$in": [canonical, legacy]},
    }))


def _file_access_token(user_id: str, category: str, filename: str) -> str:
    now = now_utc()
    return jwt.encode({
        "sub": user_id,
        "scope": "file.read",
        "file": f"{category}/{filename}",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)


@api.get("/files/{category}/{filename}/access")
async def create_file_access(category: str, filename: str, user=Depends(get_current_user)):
    await _validated_file_key(category, filename)
    if not await _can_access_file(user, category, filename):
        raise HTTPException(403, "You do not have access to this file")
    file_token = _file_access_token(user["id"], category, filename)
    return {"url": f"/api/files/{category}/{filename}?file_token={file_token}", "expires_in": 300}


@api.get("/files/{category}/{filename}")
async def download_file(
    category: str,
    filename: str,
    request: Request,
    file_token: Optional[str] = Query(default=None),
):
    key = await _validated_file_key(category, filename)
    if file_token:
        try:
            claims = jwt.decode(file_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.PyJWTError as exc:
            raise HTTPException(401, "Invalid or expired file link") from exc
        if claims.get("scope") != "file.read" or claims.get("file") != f"{category}/{filename}":
            raise HTTPException(403, "File link does not match this file")
    else:
        header = request.headers.get("authorization", "")
        access_token = header[7:] if header.lower().startswith("bearer ") else request.cookies.get(SESSION_COOKIE_NAME)
        if not access_token:
            raise HTTPException(401, "Not authenticated")
        user = await _user_from_access_token(access_token)
        if not await _can_access_file(user, category, filename):
            raise HTTPException(403, "You do not have access to this file")
    content, stored_content_type = await storage.get(key)
    metadata = await db.stored_files.find_one({"category": category, "stored_name": filename})
    download_name = (metadata or {}).get("original_name") or filename
    content_type = stored_content_type or (metadata or {}).get("content_type") or "application/octet-stream"
    return StreamingResponse(io.BytesIO(content), media_type=content_type, headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(download_name)}",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
    })


# ============================================================
# DASHBOARD
# ============================================================
@api.get("/dashboard")
@limiter.limit("60/minute")
async def dashboard(request: Request, user=Depends(get_current_user)):
    now = now_utc()
    uid = user["id"]

    # Today's shift
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    today_shift = await db.shifts.find_one(
        {"user_id": uid, "start": {"$gte": iso(today_start), "$lt": iso(today_end)}},
        {"_id": 0},
    )
    if today_shift:
        site = await db.sites.find_one({"id": today_shift["site_id"]}, {"_id": 0})
        today_shift["site"] = site

    # Next shift
    next_shift = await db.shifts.find_one(
        {"user_id": uid, "start": {"$gte": iso(now)}, "status": "scheduled"},
        {"_id": 0},
        sort=[("start", 1)],
    )
    if next_shift:
        site = await db.sites.find_one({"id": next_shift["site_id"]}, {"_id": 0})
        next_shift["site"] = site

    # Active clock-in
    active_clock = await db.timeclock.find_one(
        {"user_id": uid, "clock_out": None}, {"_id": 0, "selfie_in": 0, "selfie_out": 0}
    )

    # Announcements (unread)
    unread_ann = await db.announcements.count_documents({"read_by": {"$ne": uid}})

    # Latest payroll status
    latest_payroll = await db.payroll.find_one(
        {"user_id": uid}, {"_id": 0}, sort=[("period_end", -1)]
    )

    # Licence expiry
    licence_days_remaining = None
    if user.get("licence_expiry"):
        expiry = parse_datetime_utc(user["licence_expiry"])
        licence_days_remaining = (expiry - now).days

    emergency_contacts = []
    if DISPATCH_PHONE:
        emergency_contacts.append({"name": "HQ Dispatch", "phone": DISPATCH_PHONE})
    emergency_contacts.append({"name": "911 Emergency", "phone": "911"})
    supervisor_phone = (today_shift or {}).get("site", {}).get("supervisor_phone")
    if supervisor_phone:
        emergency_contacts.append({"name": "Site Supervisor", "phone": supervisor_phone})

    return {
        "today_shift": today_shift,
        "next_shift": next_shift,
        "active_clock": active_clock,
        "unread_announcements": unread_ann,
        "latest_payroll": latest_payroll,
        "licence_days_remaining": licence_days_remaining,
        "emergency_contacts": emergency_contacts,
    }


# ============================================================
# SCHEDULE
# ============================================================
@api.get("/schedule")
async def schedule(
    user=Depends(get_current_user),
    range: str = Query("week"),  # week|month
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    now = now_utc()
    if start and end:
        start = datetime.fromisoformat(start)
        end = datetime.fromisoformat(end)
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
    elif range == "month":
        start = now - timedelta(days=15)
        end = now + timedelta(days=30)
    else:
        weekday = now.weekday()
        start = (now - timedelta(days=weekday)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=7)
    shifts = await db.shifts.find(
        {"user_id": user["id"], "start": {"$gte": iso(start), "$lt": iso(end)}},
        {"_id": 0},
    ).sort("start", 1).to_list(200)
    site_ids = list({s["site_id"] for s in shifts})
    sites = {s["id"]: s for s in await db.sites.find({"id": {"$in": site_ids}}, {"_id": 0}).to_list(50)}
    for s in shifts:
        s["site"] = sites.get(s["site_id"])
    return {"shifts": shifts, "range_start": iso(start), "range_end": iso(end)}


@api.get("/schedule/stats")
async def schedule_stats(user=Depends(get_current_user)):
    """Quick summary card: week hours, week earnings, upcoming count, pending acks, active clock."""
    now = now_utc()
    # Week boundaries (Monday start)
    weekday = now.weekday()
    week_start = (now - timedelta(days=weekday)).replace(hour=0, minute=0, second=0, microsecond=0)
    week_end = week_start + timedelta(days=7)

    week_shifts = await db.shifts.find(
        {"user_id": user["id"], "start": {"$gte": iso(week_start), "$lt": iso(week_end)}},
        {"_id": 0, "start": 1, "end": 1, "pay_rate": 1, "status": 1, "hours_worked": 1},
    ).to_list(100)

    week_hours = 0.0
    week_earnings = 0.0
    for s in week_shifts:
        if s.get("hours_worked") is not None:
            hrs = s["hours_worked"]
        elif s.get("start") and s.get("end"):
            try:
                hrs = (
                    datetime.fromisoformat(s["end"].replace("Z", "+00:00")) -
                    datetime.fromisoformat(s["start"].replace("Z", "+00:00"))
                ).total_seconds() / 3600
            except Exception:
                hrs = 0.0
        else:
            hrs = 0.0
        week_hours += hrs
        week_earnings += hrs * s.get("pay_rate", 0)

    upcoming = await db.shifts.count_documents({
        "user_id": user["id"], "status": "scheduled", "start": {"$gte": iso(now)},
    })
    needs_ack = await db.shifts.count_documents({
        "user_id": user["id"], "status": "scheduled",
        "instructions_acknowledged": False, "start": {"$gte": iso(now)},
    })
    active_clock = await db.timeclock.find_one(
        {"user_id": user["id"], "clock_out": None},
        {"_id": 0, "selfie_in": 0, "selfie_out": 0},
    )
    return {
        "week_hours": round(week_hours, 1),
        "week_earnings": round(week_earnings, 2),
        "upcoming_shifts": upcoming,
        "needs_ack": needs_ack,
        "active_clock": bool(active_clock),
    }


@api.get("/shifts/{shift_id}")
async def get_shift(shift_id: str, user=Depends(get_current_user)):
    s = await db.shifts.find_one({"id": shift_id, "user_id": user["id"]}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Shift not found")
    s["site"] = await db.sites.find_one({"id": s["site_id"]}, {"_id": 0})
    return s


@api.post("/shifts/{shift_id}/acknowledge-instructions")
async def acknowledge_instructions(shift_id: str, user=Depends(get_current_user)):
    r = await db.shifts.update_one(
        {"id": shift_id, "user_id": user["id"]},
        {"$set": {"instructions_acknowledged": True, "instructions_acknowledged_at": iso(now_utc())}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Shift not found")
    return {"acknowledged": True}


# ============================================================
# OPEN SHIFTS
# ============================================================
@api.get("/open-shifts")
async def list_open_shifts(
    user=Depends(get_current_user),
    site_id: Optional[str] = None,
    from_date: Optional[str] = None,
):
    q = {}
    if site_id:
        q["site_id"] = site_id
    if from_date:
        q["start"] = {"$gte": from_date}
    shifts = await db.open_shifts.find(q, {"_id": 0}).sort("start", 1).to_list(100)
    site_ids = list({s["site_id"] for s in shifts})
    sites = {s["id"]: s for s in await db.sites.find({"id": {"$in": site_ids}}, {"_id": 0}).to_list(50)}
    for s in shifts:
        s["site"] = sites.get(s["site_id"])
        s["already_claimed"] = user["id"] in (s.get("claimed_by") or [])
        s["on_waitlist"] = user["id"] in (s.get("waitlist") or [])
    return {"shifts": shifts}


@api.post("/open-shifts/{shift_id}/claim")
async def claim_shift(shift_id: str, user=Depends(get_current_user)):
    s = await db.open_shifts.find_one({"id": shift_id})
    if not s:
        raise HTTPException(404, "Shift not found")
    if user["id"] in (s.get("claimed_by") or []):
        raise HTTPException(400, "Already claimed")
    overlap = await db.shifts.find_one({
        "user_id": user["id"],
        "status": {"$ne": "cancelled"},
        "start": {"$lt": s["end"]},
        "end": {"$gt": s["start"]},
    })
    if overlap:
        raise HTTPException(409, "This shift overlaps an existing scheduled shift")
    reserved = await db.open_shifts.find_one_and_update(
        {
            "id": shift_id,
            "claimed_by": {"$ne": user["id"]},
            "$expr": {
                "$lt": [
                    {"$size": {"$ifNull": ["$claimed_by", []]}},
                    "$spots_available",
                ]
            },
        },
        {"$addToSet": {"claimed_by": user["id"]}, "$pull": {"waitlist": user["id"]}},
        return_document=ReturnDocument.AFTER,
    )
    if not reserved:
        latest = await db.open_shifts.find_one({"id": shift_id})
        if not latest:
            raise HTTPException(404, "Shift not found")
        if user["id"] in (latest.get("claimed_by") or []):
            raise HTTPException(400, "Already claimed")
        await db.open_shifts.update_one({"id": shift_id}, {"$addToSet": {"waitlist": user["id"]}})
        return {"status": "waitlisted"}
    s = reserved
    # Create a scheduled shift for the user
    new_shift = {
        "id": str(uuid.uuid4()), "user_id": user["id"], "site_id": s["site_id"],
        "start": s["start"], "end": s["end"], "role": s["role"],
        "pay_rate": s["pay_rate"], "status": "scheduled",
        "claimed_from_open": shift_id,
        "instructions_acknowledged": False,
    }
    try:
        await db.shifts.insert_one(new_shift)
    except DuplicateKeyError:
        await db.open_shifts.update_one({"id": shift_id}, {"$pull": {"claimed_by": user["id"]}})
        raise HTTPException(409, "This open shift has already been claimed by this guard")
    except Exception:
        await db.open_shifts.update_one({"id": shift_id}, {"$pull": {"claimed_by": user["id"]}})
        raise
    await send_push([user["id"]], {"title": "Shift Claimed", "message": f"You claimed {s['role']} on {s['start'][:10]}"})
    await notif.save_inapp(db, [user["id"]], "Shift Claimed ✓", f"You claimed {s['role']} on {s['start'][:10]}.", category="shift")
    return {"status": "claimed", "shift_id": new_shift["id"]}


async def promote_open_shift_waitlist(shift_id: str) -> Optional[str]:
    """Atomically promote the next eligible guard when a claimed slot opens."""
    for _ in range(500):
        open_shift = await db.open_shifts.find_one({"id": shift_id})
        if not open_shift:
            return None
        waitlist = open_shift.get("waitlist") or []
        claimed = open_shift.get("claimed_by") or []
        if not waitlist or len(claimed) >= open_shift.get("spots_available", 1):
            return None
        next_uid = waitlist[0]
        guard = await db.users.find_one(
            {"id": next_uid, "role": "employee", "access_status": {"$ne": "disabled"}},
            {"_id": 1},
        )
        overlap = await db.shifts.find_one({
            "user_id": next_uid,
            "status": {"$ne": "cancelled"},
            "start": {"$lt": open_shift["end"]},
            "end": {"$gt": open_shift["start"]},
        })
        if not guard or overlap:
            await db.open_shifts.update_one(
                {"id": shift_id}, {"$pull": {"waitlist": next_uid}}
            )
            continue
        reserved = await db.open_shifts.find_one_and_update(
            {
                "id": shift_id,
                "waitlist": next_uid,
                "claimed_by": {"$ne": next_uid},
                "$expr": {
                    "$lt": [
                        {"$size": {"$ifNull": ["$claimed_by", []]}},
                        "$spots_available",
                    ]
                },
            },
            {"$pull": {"waitlist": next_uid}, "$addToSet": {"claimed_by": next_uid}},
            return_document=ReturnDocument.AFTER,
        )
        if not reserved:
            continue
        promoted = {
            "id": str(uuid.uuid4()), "user_id": next_uid, "site_id": reserved["site_id"],
            "start": reserved["start"], "end": reserved["end"], "role": reserved["role"],
            "pay_rate": reserved["pay_rate"], "status": "scheduled",
            "claimed_from_open": shift_id, "instructions_acknowledged": False,
        }
        try:
            await db.shifts.insert_one(promoted)
        except DuplicateKeyError:
            return next_uid
        except Exception:
            await db.open_shifts.update_one(
                {"id": shift_id},
                {"$pull": {"claimed_by": next_uid}, "$addToSet": {"waitlist": next_uid}},
            )
            raise
        await send_push([next_uid], {
            "title": "Spot Available!",
            "message": f"You've been promoted from the waitlist for a {reserved['role']} shift on {reserved['start'][:10]}",
        })
        await notif.save_inapp(
            db, [next_uid], "Waitlist Promoted 🎉",
            f"You got a spot for {reserved['role']} on {reserved['start'][:10]}.", category="shift",
        )
        return next_uid
    logger.error("Open-shift waitlist promotion did not converge for %s", shift_id)
    return None


async def release_open_shift_claim(shift: dict) -> None:
    open_shift_id = shift.get("claimed_from_open")
    user_id = shift.get("user_id")
    if not open_shift_id or not user_id:
        return
    released = await db.open_shifts.update_one(
        {"id": open_shift_id, "claimed_by": user_id},
        {"$pull": {"claimed_by": user_id}},
    )
    if released.modified_count:
        await promote_open_shift_waitlist(open_shift_id)


@api.post("/open-shifts/{shift_id}/cancel-claim")
async def cancel_claim(shift_id: str, user=Depends(get_current_user)):
    before = await db.open_shifts.find_one_and_update(
        {
            "id": shift_id,
            "$or": [{"claimed_by": user["id"]}, {"waitlist": user["id"]}],
        },
        {"$pull": {"claimed_by": user["id"], "waitlist": user["id"]}},
        return_document=ReturnDocument.BEFORE,
    )
    if not before:
        raise HTTPException(404, "Claim or waitlist entry not found")
    await db.shifts.delete_one({"user_id": user["id"], "claimed_from_open": shift_id})
    if user["id"] in (before.get("claimed_by") or []):
        await promote_open_shift_waitlist(shift_id)
    return {"status": "cancelled"}


@api.get("/my-claims")
async def my_claims(user=Depends(get_current_user)):
    shifts = await db.shifts.find(
        {"user_id": user["id"], "claimed_from_open": {"$exists": True}},
        {"_id": 0},
    ).sort("start", -1).to_list(50)
    return {"claims": shifts}


# ============================================================
# TIME CLOCK
# ============================================================
def haversine_m(lat1, lon1, lat2, lon2):
    import math
    R = 6371000
    p1 = math.radians(lat1); p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1); dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2 * R * math.asin(math.sqrt(a))


def valid_selfie_base64(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return False
    return (
        raw.startswith(b"\xff\xd8\xff")
        or raw.startswith(b"\x89PNG\r\n\x1a\n")
        or (len(raw) > 12 and raw[:4] in {b"II*\x00", b"MM\x00*"})
    )


@api.get("/timeclock/status")
async def timeclock_status(user=Depends(get_current_user)):
    active = await db.timeclock.find_one({"user_id": user["id"], "clock_out": None}, {"_id": 0, "selfie_in": 0, "selfie_out": 0})
    return {"active": active}


@api.post("/timeclock/clock-in")
async def clock_in(body: ClockInIn, user=Depends(get_current_user)):
    existing = await db.timeclock.find_one({"user_id": user["id"], "clock_out": None})
    if existing:
        raise HTTPException(400, "Already clocked in. Clock out first.")

    if not valid_selfie_base64(body.selfie_base64):
        raise HTTPException(400, "A valid JPEG, PNG, or HEIC selfie is required")
    sh = await db.shifts.find_one({"id": body.shift_id, "user_id": user["id"], "status": "scheduled"})
    if not sh:
        raise HTTPException(404, "Assigned scheduled shift not found")
    site = await db.sites.find_one({"id": sh.get("site_id")}, {"_id": 0})
    if not site or not isinstance(site.get("latitude"), (int, float)) or not isinstance(site.get("longitude"), (int, float)):
        raise HTTPException(409, "The assigned site has no verified geofence")
    try:
        shift_start = datetime.fromisoformat(sh["start"].replace("Z", "+00:00"))
        shift_end = datetime.fromisoformat(sh["end"].replace("Z", "+00:00"))
        if shift_start.tzinfo is None: shift_start = shift_start.replace(tzinfo=timezone.utc)
        if shift_end.tzinfo is None: shift_end = shift_end.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(409, "The assigned shift has invalid start or end times") from exc
    current_time = now_utc()
    if current_time < shift_start - timedelta(hours=2) or current_time > shift_end + timedelta(hours=4):
        raise HTTPException(409, "Clock-in is outside the allowed shift window")
    distance_m = haversine_m(body.latitude, body.longitude, site["latitude"], site["longitude"])
    radius_m = max(25, min(float(site.get("geofence_radius_m", 200)), 2000))
    geofence_ok = distance_m <= radius_m
    if not geofence_ok:
        raise HTTPException(403, f"You are outside the assigned site geofence ({round(distance_m)} m away)")

    # Detect late clock-in (> 15 min after shift start)
    mins_late = (current_time - shift_start).total_seconds() / 60
    late_clock_in = mins_late > 15

    entry = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "shift_id": body.shift_id,
        "site_id": site["id"] if site else None,
        "clock_in": iso(now_utc()),
        "clock_in_lat": body.latitude,
        "clock_in_lng": body.longitude,
        "selfie_in": body.selfie_base64,
        "geofence_ok": geofence_ok,
        "geofence_distance_m": distance_m,
        "late_clock_in": late_clock_in,
        "clock_out": None,
        "breaks": [],
        "hours_worked": None,
    }
    await db.timeclock.insert_one(entry)
    entry.pop("selfie_in", None)
    entry.pop("_id", None)
    return {"entry": entry, "geofence_ok": geofence_ok, "distance_m": distance_m, "late_clock_in": late_clock_in}


@api.post("/timeclock/clock-out")
async def clock_out(body: ClockOutIn, user=Depends(get_current_user)):
    active = await db.timeclock.find_one({"user_id": user["id"], "clock_out": None})
    if not active:
        raise HTTPException(400, "Not currently clocked in")
    clock_out_dt = now_utc()
    clock_in_dt = datetime.fromisoformat(active["clock_in"].replace("Z", "+00:00"))
    total_seconds = (clock_out_dt - clock_in_dt).total_seconds()
    # Subtract break minutes
    break_seconds = 0
    for br in active.get("breaks", []):
        if br.get("end"):
            b_start = datetime.fromisoformat(br["start"].replace("Z", "+00:00"))
            b_end = datetime.fromisoformat(br["end"].replace("Z", "+00:00"))
            break_seconds += (b_end - b_start).total_seconds()
    hours = round(max(0, total_seconds - break_seconds) / 3600, 2)
    await db.timeclock.update_one(
        {"id": active["id"]},
        {"$set": {
            "clock_out": iso(clock_out_dt),
            "clock_out_lat": body.latitude,
            "clock_out_lng": body.longitude,
            "selfie_out": body.selfie_base64,
            "hours_worked": hours,
        }},
    )
    # Auto-complete the associated shift
    if active.get("shift_id"):
        await db.shifts.update_one(
            {"id": active["shift_id"], "status": "scheduled"},
            {"$set": {"status": "completed", "hours_worked": hours}},
        )
    return {"hours_worked": hours}


@api.post("/timeclock/break")
async def break_action(body: BreakIn, user=Depends(get_current_user)):
    active = await db.timeclock.find_one({"user_id": user["id"], "clock_out": None})
    if not active:
        raise HTTPException(400, "Not currently clocked in")
    breaks = active.get("breaks", [])
    if body.action == "start":
        if breaks and not breaks[-1].get("end"):
            raise HTTPException(400, "Already on break")
        breaks.append({"start": iso(now_utc()), "end": None})
    elif body.action == "end":
        if not breaks or breaks[-1].get("end"):
            raise HTTPException(400, "Not on break")
        breaks[-1]["end"] = iso(now_utc())
    else:
        raise HTTPException(400, "Invalid action")
    await db.timeclock.update_one({"id": active["id"]}, {"$set": {"breaks": breaks}})
    return {"breaks": breaks}


@api.get("/timeclock/history")
async def timeclock_history(user=Depends(get_current_user), limit: int = 20):
    entries = await db.timeclock.find(
        {"user_id": user["id"]},
        {"_id": 0, "selfie_in": 0, "selfie_out": 0},
    ).sort("clock_in", -1).to_list(limit)
    return {"entries": entries}


# ============================================================
# WALLET
# ============================================================
@api.get("/wallet")
async def wallet(user=Depends(get_current_user)):
    docs = await db.wallet_documents.find({"user_id": user["id"]}, {"_id": 0}).to_list(50)
    qr_payload = jwt.encode({
        "sub": user["id"], "employee_number": user.get("employee_number"),
        "typ": "employee_badge", "aud": "disptchr-manager",
        "iat": now_utc(), "exp": now_utc() + timedelta(minutes=5),
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "documents": docs,
        "employee": {
            "id": user["id"],
            "full_name": user["full_name"],
            "employee_number": user.get("employee_number"),
            "photo_url": user.get("photo_url"),
            "role": user["role"],
            "licence_number": user.get("licence_number"),
            "employment_status": user.get("employment_status"),
        },
        "qr_payload": qr_payload,
        "qr_expires_in_seconds": 300,
    }


# ============================================================
# ANNOUNCEMENTS
# ============================================================
@api.get("/announcements")
async def announcements(user=Depends(get_current_user)):
    site_ids = await db.shifts.distinct("site_id", {"user_id": user["id"]})
    audience = [
        {"recipient_ids": user["id"]},
        {"recipient_ids": {"$exists": False}, "site_id": None},
        {"recipient_ids": {"$exists": False}, "site_id": {"$exists": False}},
    ]
    if site_ids:
        audience.append({"recipient_ids": {"$exists": False}, "site_id": {"$in": site_ids}})
    items = await db.announcements.find({"$or": audience}, {"_id": 0}).sort("posted_at", -1).to_list(50)
    for a in items:
        a["read"] = user["id"] in (a.get("read_by") or [])
        a["read_count"] = len(a.get("read_by") or [])
    return {"announcements": items}


@api.post("/announcements/{ann_id}/acknowledge")
async def ack_announcement(ann_id: str, user=Depends(get_current_user)):
    site_ids = await db.shifts.distinct("site_id", {"user_id": user["id"]})
    audience = [
        {"recipient_ids": user["id"]},
        {"recipient_ids": {"$exists": False}, "site_id": None},
        {"recipient_ids": {"$exists": False}, "site_id": {"$exists": False}},
    ]
    if site_ids:
        audience.append({"recipient_ids": {"$exists": False}, "site_id": {"$in": site_ids}})
    r = await db.announcements.update_one(
        {"id": ann_id, "$or": audience}, {"$addToSet": {"read_by": user["id"]}}
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Announcement not found")
    return {"acknowledged": True}


# ============================================================
# INCIDENTS
# ============================================================
@api.post("/incidents")
async def create_incident(body: IncidentIn, user=Depends(get_current_user)):
    inc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "user_name": user["full_name"],
        "type": body.type,
        "site_id": body.site_id,
        "description": body.description,
        "severity": body.severity,
        "witness_name": body.witness_name,
        "witness_contact": body.witness_contact,
        "photos": body.photos,
        "signature_base64": body.signature_base64,
        "status": "submitted",
        "created_at": iso(now_utc()),
    }
    await db.incidents.insert_one(inc)
    inc.pop("_id", None)
    inc.pop("photos", None)
    inc.pop("signature_base64", None)
    return inc


@api.get("/incidents")
async def list_incidents(user=Depends(get_current_user)):
    items = await db.incidents.find(
        {"user_id": user["id"]},
        {"_id": 0, "photos": 0, "signature_base64": 0},
    ).sort("created_at", -1).to_list(50)
    return {"incidents": items}


# ============================================================
# PAYROLL
# ============================================================
@api.get("/payroll")
async def payroll(user=Depends(get_current_user)):
    periods = await db.payroll.find(
        {"user_id": user["id"], "status": {"$ne": "cancelled"}}, {"_id": 0}
    ).sort("period_end", -1).to_list(20)
    current = periods[0] if periods else None
    total_hours = sum(p.get("hours_regular", 0) + p.get("hours_overtime", 0) for p in periods)
    total_gross = sum(p.get("gross", 0) for p in periods)
    return {"periods": periods, "current": current, "total_hours": total_hours, "total_gross": total_gross}


# ============================================================
# PROFILE
# ============================================================
@api.get("/profile")
async def profile(user=Depends(get_current_user)):
    equipment = await db.equipment.find({"user_id": user["id"]}, {"_id": 0}).to_list(20)
    return {"user": user, "equipment": equipment}


# ============================================================
# ONBOARDING
# ============================================================
ONBOARDING_STEPS = [
    "documents_uploaded",
    "sin_submitted",
    "direct_deposit_submitted",
    "emergency_contact_added",
    "agreements_signed",
]


async def _onboarding_status(user: dict) -> dict:
    ob = await db.onboarding.find_one({"user_id": user["id"]}, {"_id": 0})
    if not ob:
        ob = {"user_id": user["id"]}
    # Emergency contact can also be satisfied by the user profile field.
    if not ob.get("emergency_contact_added") and user.get("emergency_contact"):
        ob["emergency_contact_added"] = True
    status = {step: bool(ob.get(step)) for step in ONBOARDING_STEPS}
    completed = sum(1 for v in status.values() if v)
    total = len(ONBOARDING_STEPS)
    return {"status": status, "completed": completed, "total": total, "percent": int(completed / total * 100)}


@api.get("/onboarding/status")
async def onboarding_status(user=Depends(get_current_user)):
    return await _onboarding_status(user)


@api.post("/onboarding/documents", status_code=201)
async def onboarding_documents(body: OnboardingDocIn, user=Depends(get_current_user)):
    attachment_url = body.attachment_url
    if attachment_url:
        attachment = await _validate_post_attachments([{"url": attachment_url}], user["id"])
        attachment_url = attachment[0]["url"]
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "type": body.type,
        "name": body.name,
        "number": body.number,
        "expiry": body.expiry,
        "status": _compliance_status(body.expiry),
        "attachment_url": attachment_url,
        "created_at": iso(now_utc()),
    }
    await db.wallet_documents.insert_one(doc)
    await db.onboarding.update_one(
        {"user_id": user["id"]},
        {"$set": {"documents_uploaded": True, "updated_at": iso(now_utc())}},
        upsert=True,
    )
    return await _onboarding_status(user)


@api.post("/onboarding/sin", status_code=201)
async def onboarding_sin(body: OnboardingSINIn, user=Depends(get_current_user)):
    normalized = re.sub(r"\D", "", body.sin)
    if len(normalized) != 9:
        raise HTTPException(400, "SIN must contain exactly 9 digits")
    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "sin_encrypted": encrypt_private_value(normalized),
                "sin_last4": normalized[-4:],
            },
            "$unset": {"sin": ""},
        },
    )
    await db.onboarding.update_one(
        {"user_id": user["id"]},
        {"$set": {"sin_submitted": True, "updated_at": iso(now_utc())}},
        upsert=True,
    )
    return await _onboarding_status(user)


@api.post("/onboarding/direct-deposit", status_code=201)
async def onboarding_direct_deposit(body: OnboardingDirectDepositIn, user=Depends(get_current_user)):
    bank_record = body.model_dump()
    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "direct_deposit_encrypted": encrypt_private_value(json.dumps(bank_record, separators=(",", ":"))),
                "direct_deposit_last4": body.account[-4:],
            },
            "$unset": {"direct_deposit": ""},
        },
    )
    await db.onboarding.update_one(
        {"user_id": user["id"]},
        {"$set": {"direct_deposit_submitted": True, "updated_at": iso(now_utc())}},
        upsert=True,
    )
    return await _onboarding_status(user)


@api.post("/onboarding/emergency-contact", status_code=201)
async def onboarding_emergency_contact(body: OnboardingEmergencyContactIn, user=Depends(get_current_user)):
    contact = {"name": body.name, "phone": body.phone, "relation": body.relation}
    await db.users.update_one({"id": user["id"]}, {"$set": {"emergency_contact": contact}})
    await db.onboarding.update_one(
        {"user_id": user["id"]},
        {"$set": {"emergency_contact_added": True, "updated_at": iso(now_utc())}},
        upsert=True,
    )
    return await _onboarding_status(user)


@api.post("/onboarding/agreements", status_code=201)
async def onboarding_agreements(body: OnboardingAgreementsIn, user=Depends(get_current_user)):
    if not body.signed:
        raise HTTPException(400, "Agreements must be signed")
    await db.onboarding.update_one(
        {"user_id": user["id"]},
        {"$set": {"agreements_signed": True, "updated_at": iso(now_utc())}},
        upsert=True,
    )
    # If all steps are complete, flip the master flag.
    status = await _onboarding_status(user)
    if status["percent"] == 100:
        await db.users.update_one({"id": user["id"]}, {"$set": {"onboarding_complete": True}})
    return status


# ============================================================
# PUSH NOTIFICATIONS
# ============================================================
@api.post("/register-push", status_code=201)
async def register_push(body: RegisterPushIn, user=Depends(get_current_user)):
    if not re.fullmatch(r"(?:ExponentPushToken|ExpoPushToken)\[[^\]]+\]", body.device_token):
        raise HTTPException(400, "Invalid Expo push token")
    registration = body.model_dump()
    registration["user_id"] = user["id"]
    await db.push_tokens.update_one(
        {"user_id": user["id"], "device_token": body.device_token},
        {"$set": registration},
        upsert=True,
    )
    return {"status": "registered"}



# ============================================================
# ADMIN — Dependency & Models
# ============================================================

async def require_control_panel(request: Request):
    supplied_key = request.headers.get("x-disptchr-control-key", "")
    if not CONTROL_PANEL_API_KEY:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Control panel integration is not configured")
    if not supplied_key or not hmac.compare_digest(supplied_key, CONTROL_PANEL_API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid control panel credentials")
    return {
        "id": request.headers.get("x-disptchr-actor-id", "control-panel-service").strip()[:120],
        "name": unquote(
            request.headers.get("x-disptchr-actor-name", "Ds Panel").strip()
        )[:120],
    }


@api.get("/control/health")
async def control_health(_control_actor=Depends(require_control_panel)):
    await db.command("ping")
    return {"status": "ok"}


def manager_access_view(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "phone": user.get("phone"),
        "status": user.get("access_status", "active"),
        "permissions": normalize_manager_permissions(user.get("manager_permissions")),
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "created_at": user.get("created_at"),
        "access_updated_at": user.get("access_updated_at"),
    }


def employee_access_view(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "phone": user.get("phone"),
        "status": user.get("access_status", "active"),
        "employee_number": user.get("employee_number"),
        "licence_number": user.get("licence_number"),
        "licence_expiry": user.get("licence_expiry"),
        "employment_status": user.get("employment_status", "Employee"),
        "onboarding_complete": bool(user.get("onboarding_complete")),
        "created_at": user.get("created_at"),
        "access_updated_at": user.get("access_updated_at"),
    }


class ControlManagerCreateIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)
    phone: Optional[str] = Field(default=None, max_length=40)
    status: Literal["active", "disabled"] = "active"
    permissions: List[str] = Field(default_factory=list)


class ControlManagerUpdateIn(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    phone: Optional[str] = Field(default=None, max_length=40)
    status: Optional[Literal["active", "disabled"]] = None
    permissions: Optional[List[str]] = None


class ControlManagerPasswordResetIn(BaseModel):
    new_password: str = Field(min_length=12, max_length=128)


class ControlEmployeeCreateIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)
    phone: Optional[str] = Field(default=None, max_length=40)
    employee_number: Optional[str] = Field(default=None, max_length=40)
    licence_number: Optional[str] = Field(default=None, max_length=80)
    licence_expiry: Optional[str] = Field(default=None, max_length=10)
    employment_status: str = Field(default="Employee", min_length=2, max_length=80)
    status: Literal["active", "disabled"] = "active"


class ControlEmployeeUpdateIn(BaseModel):
    status: Literal["active", "disabled"]


class ControlEmployeePasswordResetIn(BaseModel):
    new_password: str = Field(min_length=12, max_length=128)


@api.get("/control/managers")
async def control_list_managers(_control_actor=Depends(require_control_panel)):
    managers = await db.users.find(
        {"role": "admin"}, SENSITIVE_USER_PROJECTION
    ).sort("full_name", 1).to_list(500)
    return {
        "managers": [manager_access_view(manager) for manager in managers],
        "permission_catalog": MANAGER_PERMISSION_CATALOG,
    }


@api.post("/control/managers", status_code=201)
async def control_create_manager(body: ControlManagerCreateIn, control_actor=Depends(require_control_panel)):
    email = body.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    mfa_fields, mfa_setup = _manager_mfa_setup(email)
    manager = {
        "id": str(uuid.uuid4()),
        "email": email,
        "hashed_password": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "phone": body.phone,
        "role": "admin",
        "access_status": body.status,
        "manager_permissions": normalize_manager_permissions(body.permissions),
        "employee_number": f"SH-M-{str(uuid.uuid4())[:4].upper()}",
        "licence_number": None,
        "licence_expiry": None,
        "certifications": [],
        "employment_status": "Management",
        "photo_url": None,
        "emergency_contact": None,
        "onboarding_complete": True,
        "created_at": iso(now_utc()),
        "access_updated_at": iso(now_utc()),
        **mfa_fields,
    }
    await db.users.insert_one(manager)
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()),
        "action": "manager.created",
        "manager_id": manager["id"],
        "manager_email": email,
        "status": body.status,
        "permissions": manager["manager_permissions"],
        "before": None,
        "after": manager_access_view(manager),
        "actor": control_actor,
        "source": "disptchr-panel",
        "occurred_at": iso(now_utc()),
    })
    return {**manager_access_view(manager), "mfa_setup": mfa_setup}


@api.get("/control/employees")
async def control_list_employees(_control_actor=Depends(require_control_panel)):
    employees = await db.users.find(
        {"role": "employee"}, SENSITIVE_USER_PROJECTION
    ).sort("full_name", 1).to_list(2000)
    return {"employees": [employee_access_view(employee) for employee in employees]}


@api.post("/control/employees", status_code=201)
async def control_create_employee(body: ControlEmployeeCreateIn, control_actor=Depends(require_control_panel)):
    email = body.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    if body.licence_expiry:
        try:
            date.fromisoformat(body.licence_expiry)
        except ValueError:
            raise HTTPException(422, "Licence expiry must use YYYY-MM-DD")
    employee = {
        "id": str(uuid.uuid4()),
        "email": email,
        "hashed_password": hash_password(body.password),
        "full_name": body.full_name.strip(),
        "phone": body.phone,
        "role": "employee",
        "access_status": body.status,
        "employee_number": body.employee_number or f"SH-E-{str(uuid.uuid4())[:6].upper()}",
        "licence_number": body.licence_number,
        "licence_expiry": body.licence_expiry,
        "certifications": [],
        "employment_status": body.employment_status.strip(),
        "photo_url": None,
        "emergency_contact": None,
        "onboarding_complete": False,
        "created_at": iso(now_utc()),
        "access_updated_at": iso(now_utc()),
    }
    try:
        await db.users.insert_one(employee)
    except DuplicateKeyError:
        raise HTTPException(409, "Email already registered")
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()), "action": "employee.created", "employee_id": employee["id"],
        "employee_email": email, "before": None, "after": employee_access_view(employee),
        "actor": control_actor, "source": "ds-panel", "occurred_at": iso(now_utc()),
    })
    return employee_access_view(employee)


@api.patch("/control/employees/{employee_id}")
async def control_update_employee(
    employee_id: str,
    body: ControlEmployeeUpdateIn,
    control_actor=Depends(require_control_panel),
):
    employee = await db.users.find_one({"id": employee_id, "role": "employee"})
    if not employee:
        raise HTTPException(404, "Employee account not found")
    before = employee_access_view(employee)
    changed_at = iso(now_utc())
    result = await db.users.update_one(
        {"id": employee_id, "role": "employee"},
        {"$set": {"access_status": body.status, "access_updated_at": changed_at}},
    )
    if result.matched_count != 1:
        raise HTTPException(404, "Employee account not found")
    if body.status == "disabled":
        await db.refresh_tokens.update_many(
            {"user_id": employee_id, "revoked_at": None},
            {"$set": {"revoked_at": changed_at, "revoke_reason": "account_disabled"}},
        )
    updated = await db.users.find_one({"id": employee_id}, SENSITIVE_USER_PROJECTION)
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()), "action": "employee.access_updated", "employee_id": employee_id,
        "employee_email": employee["email"], "before": before, "after": employee_access_view(updated),
        "actor": control_actor, "source": "ds-panel", "occurred_at": changed_at,
    })
    return employee_access_view(updated)


@api.post("/control/employees/{employee_id}/reset-password")
async def control_reset_employee_password(
    employee_id: str,
    body: ControlEmployeePasswordResetIn,
    control_actor=Depends(require_control_panel),
):
    employee = await db.users.find_one({"id": employee_id, "role": "employee"})
    if not employee:
        raise HTTPException(404, "Employee account not found")
    changed_at = iso(now_utc())
    await db.users.update_one(
        {"id": employee_id, "role": "employee"},
        {"$set": {"hashed_password": hash_password(body.new_password), "access_updated_at": changed_at}},
    )
    await db.refresh_tokens.update_many(
        {"user_id": employee_id, "revoked_at": None},
        {"$set": {"revoked_at": changed_at, "revoke_reason": "password_reset"}},
    )
    await db.password_resets.delete_many({"user_id": employee_id})
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()), "action": "employee.password_reset", "employee_id": employee_id,
        "employee_email": employee["email"], "actor": control_actor,
        "source": "ds-panel", "occurred_at": changed_at,
    })
    return {"status": "password_reset"}


@api.post("/control/managers/{manager_id}/reset-mfa")
async def control_reset_manager_mfa(manager_id: str, control_actor=Depends(require_control_panel)):
    manager = await db.users.find_one({"id": manager_id, "role": "admin"})
    if not manager:
        raise HTTPException(404, "Manager not found")
    mfa_fields, mfa_setup = _manager_mfa_setup(manager["email"])
    result = await db.users.update_one({"id": manager_id, "role": "admin"}, {"$set": mfa_fields})
    if result.matched_count != 1:
        raise HTTPException(404, "Manager not found")
    await db.manager_sessions.delete_many({"user_id": manager_id})
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()), "action": "manager.mfa_reset", "manager_id": manager_id,
        "manager_email": manager["email"], "actor": control_actor, "source": "disptchr-panel",
        "occurred_at": iso(now_utc()),
    })
    return {**manager_access_view({**manager, **mfa_fields}), "mfa_setup": mfa_setup}


@api.post("/control/managers/{manager_id}/reset-password")
async def control_reset_manager_password(
    manager_id: str,
    body: ControlManagerPasswordResetIn,
    control_actor=Depends(require_control_panel),
):
    manager = await db.users.find_one({"id": manager_id, "role": "admin"})
    if not manager:
        raise HTTPException(404, "Manager not found")
    await db.users.update_one(
        {"id": manager_id, "role": "admin"},
        {"$set": {"hashed_password": hash_password(body.new_password), "access_updated_at": iso(now_utc())}},
    )
    await db.manager_sessions.delete_many({"user_id": manager_id})
    await db.password_resets.delete_many({"user_id": manager_id})
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()), "action": "manager.password_reset", "manager_id": manager_id,
        "manager_email": manager["email"], "actor": control_actor, "source": "disptchr-panel",
        "occurred_at": iso(now_utc()),
    })
    return {"status": "password_reset"}


@api.patch("/control/managers/{manager_id}")
async def control_update_manager(
    manager_id: str,
    body: ControlManagerUpdateIn,
    control_actor=Depends(require_control_panel),
):
    manager = await db.users.find_one({"id": manager_id, "role": "admin"})
    if not manager:
        raise HTTPException(404, "Manager account not found")
    before = manager_access_view(manager)

    update = body.model_dump(exclude_none=True)
    if "full_name" in update:
        update["full_name"] = update["full_name"].strip()
    if "status" in update:
        update["access_status"] = update.pop("status")
    if "permissions" in update:
        update["manager_permissions"] = normalize_manager_permissions(update.pop("permissions"))
    update["access_updated_at"] = iso(now_utc())

    await db.users.update_one({"id": manager_id}, {"$set": update})
    if update.get("access_status") == "disabled":
        await db.manager_sessions.delete_many({"user_id": manager_id})
    updated = await db.users.find_one({"id": manager_id}, SENSITIVE_USER_PROJECTION)
    await db.access_audit.insert_one({
        "id": str(uuid.uuid4()),
        "action": "manager.access_updated",
        "manager_id": manager_id,
        "manager_email": manager["email"],
        "changes": {key: value for key, value in update.items() if key != "access_updated_at"},
        "before": before,
        "after": manager_access_view(updated),
        "actor": control_actor,
        "source": "disptchr-panel",
        "occurred_at": iso(now_utc()),
    })
    return manager_access_view(updated)


async def require_admin(request: Request, user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Manager access required")
    required_permission = required_manager_permission(request.url.path)
    if not required_permission:
        logger.error("Manager route has no permission mapping: %s", request.url.path)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Manager route is not assigned to an access level")
    enforce_manager_permission(user, required_permission)
    return user


@api.post("/admin/employee-badge/verify")
async def verify_employee_badge(body: BadgeVerifyIn, _admin=Depends(require_admin)):
    try:
        payload = jwt.decode(body.token, JWT_SECRET, algorithms=[JWT_ALGORITHM], audience="disptchr-manager")
        if payload.get("typ") != "employee_badge" or not payload.get("sub"):
            raise HTTPException(400, "Invalid employee badge")
    except jwt.ExpiredSignatureError:
        raise HTTPException(400, "Employee badge has expired")
    except jwt.PyJWTError as exc:
        raise HTTPException(400, "Invalid employee badge") from exc
    employee = await db.users.find_one({"id": payload["sub"], "role": "employee"}, SENSITIVE_USER_PROJECTION)
    if not employee or employee.get("access_status", "active") != "active":
        raise HTTPException(404, "Active employee not found")
    return {"valid": True, "employee": {
        "id": employee["id"], "full_name": employee.get("full_name"),
        "employee_number": employee.get("employee_number"),
        "licence_number": employee.get("licence_number"),
        "employment_status": employee.get("employment_status"),
    }}


class AdminCreateGuardIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str
    phone: Optional[str] = None
    employee_number: Optional[str] = None
    licence_number: Optional[str] = None
    licence_expiry: Optional[str] = None
    certifications: List[str] = []
    employment_status: str = "Active - Full Time"


class AdminUpdateGuardIn(BaseModel):
    password: Optional[str] = Field(default=None, min_length=12, max_length=128)
    full_name: Optional[str] = None
    phone: Optional[str] = None
    employee_number: Optional[str] = None
    licence_number: Optional[str] = None
    licence_expiry: Optional[str] = None
    certifications: Optional[List[str]] = None
    employment_status: Optional[str] = None
    onboarding_complete: Optional[bool] = None


class AdminCreateSiteIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client_name: Optional[str] = Field(default=None, max_length=200)
    address: str = Field(min_length=1, max_length=500)
    city: Optional[str] = Field(default=None, max_length=120)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    supervisor: str = Field(min_length=1, max_length=200)
    supervisor_phone: str = Field(min_length=3, max_length=50)
    instructions: str = Field(default="", max_length=5000)
    geofence_radius_m: int = Field(default=150, ge=25, le=10_000)


class AdminUpdateSiteIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    client_name: Optional[str] = Field(default=None, max_length=200)
    address: Optional[str] = Field(default=None, min_length=1, max_length=500)
    city: Optional[str] = Field(default=None, max_length=120)
    latitude: Optional[float] = Field(default=None, ge=-90, le=90)
    longitude: Optional[float] = Field(default=None, ge=-180, le=180)
    supervisor: Optional[str] = Field(default=None, min_length=1, max_length=200)
    supervisor_phone: Optional[str] = Field(default=None, min_length=3, max_length=50)
    instructions: Optional[str] = Field(default=None, max_length=5000)
    geofence_radius_m: Optional[int] = Field(default=None, ge=25, le=10_000)


class AdminCreateShiftIn(BaseModel):
    user_id: str = Field(min_length=1, max_length=100)
    site_id: str = Field(min_length=1, max_length=100)
    start: str = Field(min_length=10, max_length=50)
    end: str = Field(min_length=10, max_length=50)
    role: str = Field(default="Patrol", min_length=1, max_length=100)
    pay_rate: float = Field(default=24.50, ge=0, le=1000)
    notes: Optional[str] = Field(default=None, max_length=2000)


class AdminUpdateShiftIn(BaseModel):
    user_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    site_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    start: Optional[str] = Field(default=None, min_length=10, max_length=50)
    end: Optional[str] = Field(default=None, min_length=10, max_length=50)
    role: Optional[str] = Field(default=None, min_length=1, max_length=100)
    pay_rate: Optional[float] = Field(default=None, ge=0, le=1000)
    status: Optional[Literal["scheduled", "active", "completed", "cancelled"]] = None
    hours_worked: Optional[float] = Field(default=None, ge=0, le=24)
    notes: Optional[str] = Field(default=None, max_length=2000)


class AdminCreateOpenShiftIn(BaseModel):
    site_id: str = Field(min_length=1, max_length=100)
    start: str = Field(min_length=10, max_length=50)
    end: str = Field(min_length=10, max_length=50)
    role: str = Field(default="Patrol", min_length=1, max_length=100)
    pay_rate: float = Field(default=24.50, ge=0, le=1000)
    spots_available: int = Field(default=1, ge=1, le=500)
    urgent: bool = False


class AdminCreateAnnouncementIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=5000)
    severity: Literal["info", "warning", "critical"] = "info"
    site_id: Optional[str] = Field(default=None, max_length=100)
    posted_by: Optional[str] = Field(default=None, max_length=120)


class AdminUpdateIncidentIn(BaseModel):
    status: str
    notes: Optional[str] = None


class DeductionItem(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    amount: float = Field(ge=0, le=1_000_000)


class PayrollCommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    at: Optional[str] = Field(default=None, max_length=50)
    author: Optional[str] = Field(default=None, max_length=120)


class AdminCreatePayrollIn(BaseModel):
    user_id: str = Field(min_length=1, max_length=100)
    period_start: str = Field(min_length=10, max_length=50)
    period_end: str = Field(min_length=10, max_length=50)
    pay_date: Optional[str] = Field(default=None, min_length=10, max_length=50)
    hours_regular: Optional[float] = Field(default=None, ge=0, le=1000)
    hours_worked: Optional[float] = Field(default=None, ge=0, le=1000)
    hours_overtime: float = Field(default=0.0, ge=0, le=1000)
    pay_rate: Optional[float] = Field(default=None, gt=0, le=1000)
    hourly_rate: Optional[float] = Field(default=None, gt=0, le=1000)
    status: Literal["submitted", "under_review", "approved", "released", "paid", "cancelled"] = "submitted"
    notes: Optional[str] = Field(default=None, max_length=5000)
    deductions: List[DeductionItem] = Field(default_factory=list, max_length=100)
    paid_via: Optional[Literal["cash", "cheque", "direct_deposit", "interac"]] = None
    comments: List[PayrollCommentIn] = Field(default_factory=list, max_length=500)


class AdminUpdatePayrollIn(BaseModel):
    status: Optional[Literal["submitted", "under_review", "approved", "released", "paid", "cancelled"]] = None
    user_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    period_start: Optional[str] = Field(default=None, min_length=10, max_length=50)
    period_end: Optional[str] = Field(default=None, min_length=10, max_length=50)
    hours_regular: Optional[float] = Field(default=None, ge=0, le=1000)
    hours_worked: Optional[float] = Field(default=None, ge=0, le=1000)
    hours_overtime: Optional[float] = Field(default=None, ge=0, le=1000)
    pay_rate: Optional[float] = Field(default=None, gt=0, le=1000)
    hourly_rate: Optional[float] = Field(default=None, gt=0, le=1000)
    pay_date: Optional[str] = Field(default=None, min_length=10, max_length=50)
    notes: Optional[str] = Field(default=None, max_length=5000)
    deductions: Optional[List[DeductionItem]] = Field(default=None, max_length=100)
    paid_via: Optional[Literal["cash", "cheque", "direct_deposit", "interac"]] = None
    comments: Optional[List[PayrollCommentIn]] = Field(default=None, max_length=500)


class AdminUpdateTimeclockIn(BaseModel):
    clock_in: Optional[str] = Field(default=None, max_length=50)
    clock_out: Optional[str] = Field(default=None, max_length=50)
    hours_worked: Optional[float] = Field(default=None, ge=0, le=24)
    notes: Optional[str] = Field(default=None, max_length=2000)


# ============================================================
# ADMIN ROUTES — Dashboard
# ============================================================

@api.get("/admin/dashboard")
async def admin_dashboard(admin=Depends(require_admin)):
    now = now_utc()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    total_guards = await db.users.count_documents({"role": "employee"})
    shifts_today = await db.shifts.count_documents({"start": {"$gte": iso(today_start), "$lt": iso(today_end)}})
    active_clocked = await db.timeclock.count_documents({"clock_out": None})
    open_incidents = await db.incidents.count_documents({"status": "submitted"})
    pending_payroll = await db.payroll.count_documents({"status": {"$in": ["submitted", "under_review"]}})
    recent_incidents = await db.incidents.find(
        {}, {"_id": 0, "photos": 0, "signature_base64": 0}
    ).sort("created_at", -1).to_list(5)
    active_entries = await db.timeclock.find({"clock_out": None}, {"_id": 0, "selfie_in": 0}).to_list(20)
    if active_entries:
        uids = [e["user_id"] for e in active_entries]
        sids = [e["site_id"] for e in active_entries if e.get("site_id")]
        um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(20)}
        sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(20)} if sids else {}
        for e in active_entries:
            e["user"] = um.get(e["user_id"])
            e["site"] = sm.get(e.get("site_id"))
    return {
        "total_guards": total_guards, "shifts_today": shifts_today,
        "active_clocked": active_clocked, "open_incidents": open_incidents,
        "pending_payroll": pending_payroll, "recent_incidents": recent_incidents,
        "active_entries": active_entries,
    }


# ============================================================
# ADMIN ROUTES — Guards
# ============================================================

@api.get("/admin/guards")
async def admin_list_guards(admin=Depends(require_admin)):
    guards = await db.users.find(
        {"role": "employee"}, SENSITIVE_USER_PROJECTION
    ).sort("full_name", 1).to_list(500)
    return {"guards": guards}


@api.post("/admin/guards", status_code=201)
async def admin_create_guard(body: AdminCreateGuardIn, admin=Depends(require_admin)):
    if await db.users.find_one({"email": body.email.lower()}):
        raise HTTPException(400, "Email already registered")
    user_id = str(uuid.uuid4())
    guard = {
        "id": user_id, "email": body.email.lower(),
        "hashed_password": hash_password(body.password),
        "full_name": body.full_name, "phone": body.phone, "role": "employee",
        "access_status": "active",
        "employee_number": body.employee_number or f"SH-{str(uuid.uuid4())[:4].upper()}",
        "licence_number": body.licence_number, "licence_expiry": body.licence_expiry,
        "certifications": body.certifications, "employment_status": body.employment_status,
        "photo_url": None, "emergency_contact": None, "onboarding_complete": False,
        "created_at": iso(now_utc()),
    }
    await db.users.insert_one(guard)
    guard.pop("hashed_password", None); guard.pop("_id", None)
    return guard


@api.get("/admin/guards/{guard_id}")
async def admin_get_guard(guard_id: str, admin=Depends(require_admin)):
    guard = await db.users.find_one(
        {"id": guard_id, "role": "employee"}, SENSITIVE_USER_PROJECTION
    )
    if not guard:
        raise HTTPException(404, "Guard not found")
    recent_shifts = await db.shifts.find({"user_id": guard_id}, {"_id": 0}).sort("start", -1).to_list(10)
    for s in recent_shifts:
        s["site"] = await db.sites.find_one({"id": s["site_id"]}, {"_id": 0})
    recent_clock = await db.timeclock.find(
        {"user_id": guard_id}, {"_id": 0, "selfie_in": 0, "selfie_out": 0}
    ).sort("clock_in", -1).to_list(10)
    equipment = await db.equipment.find({"user_id": guard_id}, {"_id": 0}).to_list(20)
    documents = await db.wallet_documents.find({"user_id": guard_id}, {"_id": 0}).sort("uploaded_at", -1).to_list(50)
    onboarding = await db.onboarding.find_one({"user_id": guard_id}, {"_id": 0})
    return {
        "guard": guard,
        "recent_shifts": recent_shifts,
        "recent_clock": recent_clock,
        "equipment": equipment,
        "documents": documents,
        "onboarding": onboarding,
    }


@api.put("/admin/guards/{guard_id}")
async def admin_update_guard(guard_id: str, body: AdminUpdateGuardIn, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    new_password = update.pop("password", None)
    if new_password:
        update["hashed_password"] = hash_password(new_password)
    if not update:
        raise HTTPException(400, "No fields to update")
    r = await db.users.update_one({"id": guard_id, "role": "employee"}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(404, "Guard not found")
    if new_password:
        await db.refresh_tokens.delete_many({"user_id": guard_id})
        await db.access_audit.insert_one({
            "id": str(uuid.uuid4()), "action": "guard.password_reset", "guard_id": guard_id,
            "actor": {"id": admin["id"], "name": admin.get("full_name")},
            "occurred_at": iso(now_utc()),
        })
    return await db.users.find_one(
        {"id": guard_id, "role": "employee"}, SENSITIVE_USER_PROJECTION
    )


# ============================================================
# ADMIN ROUTES — Sites
# ============================================================

@api.get("/admin/sites")
async def admin_list_sites(admin=Depends(require_admin)):
    sites = await db.sites.find({}, {"_id": 0}).sort("name", 1).to_list(200)
    return {"sites": sites}


@api.post("/admin/sites", status_code=201)
async def admin_create_site(body: AdminCreateSiteIn, admin=Depends(require_admin)):
    site = {"id": str(uuid.uuid4()), **body.model_dump()}
    await db.sites.insert_one(site)
    site.pop("_id", None)
    return site


@api.put("/admin/sites/{site_id}")
async def admin_update_site(site_id: str, body: AdminUpdateSiteIn, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    r = await db.sites.update_one({"id": site_id}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(404, "Site not found")
    return await db.sites.find_one({"id": site_id}, {"_id": 0})


@api.delete("/admin/sites/{site_id}", status_code=204)
async def admin_delete_site(site_id: str, admin=Depends(require_admin)):
    if await db.shifts.find_one({"site_id": site_id}, {"_id": 1}) or await db.open_shifts.find_one({"site_id": site_id}, {"_id": 1}):
        raise HTTPException(409, "Site is used by scheduled or open shifts and cannot be deleted")
    r = await db.sites.delete_one({"id": site_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Site not found")


# ============================================================
# ADMIN ROUTES — Shifts
# ============================================================

@api.get("/admin/scheduling/options")
async def admin_scheduling_options(admin=Depends(require_admin)):
    """Supply limited scheduling choices without granting broad record access."""
    guards = await db.users.find(
        {"role": "employee", "access_status": {"$ne": "disabled"}},
        {"_id": 0, "id": 1, "full_name": 1, "email": 1, "employee_number": 1},
    ).sort("full_name", 1).to_list(500)
    sites = await db.sites.find(
        {"active": {"$ne": False}},
        {"_id": 0, "id": 1, "name": 1, "address": 1},
    ).sort("name", 1).to_list(200)
    return {"guards": guards, "sites": sites}

@api.get("/admin/shifts")
async def admin_list_shifts(
    admin=Depends(require_admin),
    user_id: Optional[str] = None,
    site_id: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    shift_status: Optional[str] = Query(None, alias="status"),
):
    q: dict = {}
    if user_id: q["user_id"] = user_id
    if site_id: q["site_id"] = site_id
    if shift_status: q["status"] = shift_status
    if from_date or to_date:
        q["start"] = {}
        if from_date: q["start"]["$gte"] = from_date
        if to_date: q["start"]["$lte"] = to_date
    shifts = await db.shifts.find(q, {"_id": 0}).sort("start", -1).to_list(500)
    if shifts:
        sids = list({s["site_id"] for s in shifts})
        uids = list({s["user_id"] for s in shifts})
        sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(200)}
        um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(500)}
        for s in shifts:
            s["site"] = sm.get(s["site_id"]); s["user"] = um.get(s["user_id"])
    return {"shifts": shifts}


@api.post("/admin/shifts", status_code=201)
async def admin_create_shift(body: AdminCreateShiftIn, admin=Depends(require_admin)):
    validate_shift_interval(body.start, body.end)
    if not await db.users.find_one({"id": body.user_id, "role": "employee"}):
        raise HTTPException(404, "Guard not found")
    if not await db.sites.find_one({"id": body.site_id}):
        raise HTTPException(404, "Site not found")
    # Conflict detection: guard must not have an overlapping scheduled shift
    overlap = await db.shifts.find_one({
        "user_id": body.user_id,
        "status": {"$ne": "cancelled"},
        "start": {"$lt": body.end},
        "end": {"$gt": body.start},
    })
    if overlap:
        raise HTTPException(409, f"Scheduling conflict: guard already has a shift from {overlap['start'][:16]} to {overlap['end'][:16]}.")
    shift = {
        "id": str(uuid.uuid4()), "user_id": body.user_id, "site_id": body.site_id,
        "start": body.start, "end": body.end, "role": body.role, "pay_rate": body.pay_rate,
        "notes": body.notes,
        "status": "scheduled", "instructions_acknowledged": False,
        "created_by": admin["id"], "created_at": iso(now_utc()),
    }
    await db.shifts.insert_one(shift); shift.pop("_id", None)
    await send_push([body.user_id], {"title": "New Shift Assigned", "message": f"{body.role} shift on {body.start[:10]}"})
    return shift


@api.put("/admin/shifts/{shift_id}")
async def admin_update_shift(shift_id: str, body: AdminUpdateShiftIn, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    current = await db.shifts.find_one({"id": shift_id})
    if not current:
        raise HTTPException(404, "Shift not found")
    merged = {**current, **update}
    if current.get("status") == "cancelled" and merged.get("status") != "cancelled":
        raise HTTPException(409, "A cancelled shift cannot be reactivated; create a new shift")
    validate_shift_interval(merged["start"], merged["end"])
    if "user_id" in update and not await db.users.find_one({"id": merged["user_id"], "role": "employee"}, {"_id": 1}):
        raise HTTPException(404, "Guard not found")
    if "site_id" in update and not await db.sites.find_one({"id": merged["site_id"]}, {"_id": 1}):
        raise HTTPException(404, "Site not found")
    if merged.get("status") != "cancelled":
        overlap = await db.shifts.find_one({
            "id": {"$ne": shift_id},
            "user_id": merged["user_id"],
            "status": {"$ne": "cancelled"},
            "start": {"$lt": merged["end"]},
            "end": {"$gt": merged["start"]},
        })
        if overlap:
            raise HTTPException(409, f"Scheduling conflict: guard already has a shift from {overlap['start'][:16]} to {overlap['end'][:16]}.")
    await db.shifts.update_one({"id": shift_id}, {"$set": update})
    if current.get("status") != "cancelled" and merged.get("status") == "cancelled":
        await db.shift_swaps.update_many(
            {"shift_id": shift_id, "status": {"$in": ["open", "accepted", "processing"]}},
            {"$set": {
                "status": "cancelled", "resolved_at": iso(now_utc()),
                "manager_note": "The assigned shift was cancelled by management.",
            }, "$unset": {"active_shift_id": "", "decision_started_at": "", "decision_started_by": ""}},
        )
        await release_open_shift_claim(current)
        await send_push([current["user_id"]], {
            "title": "Shift Cancelled",
            "message": f"Your shift on {current['start'][:10]} was cancelled by management.",
        })
        await notif.save_inapp(
            db, [current["user_id"]], "Shift Cancelled",
            f"Your shift on {current['start'][:10]} was cancelled by management.", category="shift",
        )
    return await db.shifts.find_one({"id": shift_id}, {"_id": 0})


@api.delete("/admin/shifts/{shift_id}", status_code=204)
async def admin_delete_shift(shift_id: str, admin=Depends(require_admin)):
    shift = await db.shifts.find_one({"id": shift_id})
    if not shift:
        raise HTTPException(404, "Shift not found")
    await db.shifts.delete_one({"id": shift_id})
    await db.shift_swaps.update_many(
        {"shift_id": shift_id, "status": {"$in": ["open", "accepted", "processing"]}},
        {"$set": {
            "status": "cancelled", "resolved_at": iso(now_utc()),
            "manager_note": "The assigned shift was deleted by management.",
        }, "$unset": {"active_shift_id": "", "decision_started_at": "", "decision_started_by": ""}},
    )
    await release_open_shift_claim(shift)
    await send_push([shift["user_id"]], {
        "title": "Shift Removed",
        "message": f"Your shift on {shift['start'][:10]} was removed by management.",
    })
    await notif.save_inapp(
        db, [shift["user_id"]], "Shift Removed",
        f"Your shift on {shift['start'][:10]} was removed by management.", category="shift",
    )


# ============================================================
# ADMIN ROUTES — Open Shifts
# ============================================================

@api.get("/admin/open-shifts")
async def admin_list_open_shifts(admin=Depends(require_admin)):
    shifts = await db.open_shifts.find({}, {"_id": 0}).sort("start", 1).to_list(200)
    if shifts:
        sids = list({s["site_id"] for s in shifts})
        sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(50)}
        for s in shifts:
            s["site"] = sm.get(s["site_id"]); s["claimed_count"] = len(s.get("claimed_by") or [])
    return {"shifts": shifts}


@api.post("/admin/open-shifts", status_code=201)
async def admin_create_open_shift(body: AdminCreateOpenShiftIn, admin=Depends(require_admin)):
    validate_shift_interval(body.start, body.end)
    if not await db.sites.find_one({"id": body.site_id}):
        raise HTTPException(404, "Site not found")
    shift = {"id": str(uuid.uuid4()), **body.model_dump(), "posted_at": iso(now_utc()), "claimed_by": [], "waitlist": [], "posted_by": admin["id"]}
    await db.open_shifts.insert_one(shift); shift.pop("_id", None)
    return shift


@api.delete("/admin/open-shifts/{shift_id}", status_code=204)
async def admin_delete_open_shift(shift_id: str, admin=Depends(require_admin)):
    r = await db.open_shifts.delete_one({"id": shift_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Open shift not found")


# ============================================================
# ADMIN ROUTES — Announcements
# ============================================================

@api.get("/admin/announcements")
async def admin_list_announcements(admin=Depends(require_admin)):
    items = await db.announcements.find({}, {"_id": 0}).sort("posted_at", -1).to_list(200)
    total_guards = await db.users.count_documents({"role": "employee"})
    for a in items:
        a["read_count"] = len(a.get("read_by") or [])
        if "recipient_ids" in a:
            a["total_guards"] = len(a.get("recipient_ids") or [])
        elif a.get("site_id"):
            a["total_guards"] = len(await db.shifts.distinct("user_id", {"site_id": a["site_id"]}))
        else:
            a["total_guards"] = total_guards
    return {"announcements": items}


@api.get("/admin/announcements/sites")
async def admin_announcement_sites(admin=Depends(require_admin)):
    sites = await db.sites.find(
        {"active": {"$ne": False}},
        {"_id": 0, "id": 1, "name": 1},
    ).sort("name", 1).to_list(200)
    return {"sites": sites}


@api.post("/admin/announcements", status_code=201)
async def admin_create_announcement(body: AdminCreateAnnouncementIn, admin=Depends(require_admin)):
    if body.site_id and not await db.sites.find_one({"id": body.site_id}, {"_id": 1}):
        raise HTTPException(404, "Site not found")
    if body.site_id:
        scheduled_ids = await db.shifts.distinct("user_id", {"site_id": body.site_id})
        guard_filter = {"role": "employee", "id": {"$in": scheduled_ids}}
    else:
        guard_filter = {"role": "employee"}
    guards = await db.users.find(guard_filter, {"id": 1, "email": 1, "_id": 0}).to_list(500)
    guard_ids = [g["id"] for g in guards]
    ann = {
        "id": str(uuid.uuid4()), "title": body.title, "body": body.body,
        "severity": body.severity, "site_id": body.site_id,
        "posted_by": body.posted_by or admin.get("full_name", "Admin"),
        "posted_at": iso(now_utc()), "read_by": [], "recipient_ids": guard_ids,
    }
    await db.announcements.insert_one(ann); ann.pop("_id", None)
    await send_push(guard_ids, {"title": body.title, "message": body.body[:120]})
    ann_html = notif.email_template(
        body.title,
        [body.body],
        cta_text="View in App",
        cta_link="disptchr://notifications",
    )
    await asyncio.gather(
        *[queue_email(g["email"], f"[Skyhawk] {body.title}", ann_html, body.body,
            f"announcement:{ann['id']}:email:{g['id']}") for g in guards if g.get("email")],
        notif.save_inapp(db, guard_ids, body.title, body.body[:300], category="announcement"),
        return_exceptions=True,
    )
    return ann


@api.delete("/admin/announcements/{ann_id}", status_code=204)
async def admin_delete_announcement(ann_id: str, admin=Depends(require_admin)):
    r = await db.announcements.delete_one({"id": ann_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Announcement not found")


# ============================================================
# ADMIN ROUTES — Incidents
# ============================================================

@api.get("/admin/incidents")
async def admin_list_incidents(
    admin=Depends(require_admin),
    inc_status: Optional[str] = Query(None, alias="status"),
):
    q: dict = {}
    if inc_status: q["status"] = inc_status
    items = await db.incidents.find(q, {"_id": 0, "photos": 0, "signature_base64": 0}).sort("created_at", -1).to_list(200)
    if items:
        sids = list({i["site_id"] for i in items if i.get("site_id")})
        if sids:
            sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(50)}
            for inc in items:
                inc["site"] = sm.get(inc.get("site_id"))
    return {"incidents": items}


@api.put("/admin/incidents/{inc_id}")
async def admin_update_incident(inc_id: str, body: AdminUpdateIncidentIn, admin=Depends(require_admin)):
    update: dict = {"status": body.status, "reviewed_by": admin["id"], "reviewed_at": iso(now_utc())}
    if body.notes: update["review_notes"] = body.notes
    r = await db.incidents.update_one({"id": inc_id}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(404, "Incident not found")
    return await db.incidents.find_one({"id": inc_id}, {"_id": 0, "photos": 0, "signature_base64": 0})


# ============================================================
# ADMIN ROUTES — Payroll
# ============================================================

PAYROLL_FEATURE_KEYS = {"paystub", "bulk", "dashboard", "anomaly", "overlap", "comments"}
PAYROLL_COLUMN_KEYS = {"guard", "period", "hours", "rate", "gross", "deductions", "net", "paid_via", "status", "lic", "projects"}
TIMESHEET_COLUMN_KEYS = {"guard_name", "lic", "status", "shifts", "hours", "period", "projects", "rate", "gross"}


@api.get("/admin/preferences/payroll")
async def get_manager_payroll_preferences(admin=Depends(require_admin)):
    return admin.get("manager_preferences", {}).get("payroll", {})


@api.patch("/admin/preferences/payroll")
async def update_manager_payroll_preferences(body: ManagerPayrollPreferencesIn, admin=Depends(require_admin)):
    updates: dict = {}
    if body.features is not None:
        updates["manager_preferences.payroll.features"] = {
            key: bool(value) for key, value in body.features.items() if key in PAYROLL_FEATURE_KEYS
        }
    if body.columns is not None:
        updates["manager_preferences.payroll.columns"] = {
            key: bool(value) for key, value in body.columns.items() if key in PAYROLL_COLUMN_KEYS
        }
    if body.timesheet_columns is not None:
        updates["manager_preferences.payroll.timesheet_columns"] = {
            key: bool(value) for key, value in body.timesheet_columns.items() if key in TIMESHEET_COLUMN_KEYS
        }
    if updates:
        await db.users.update_one({"id": admin["id"]}, {"$set": updates})
    fresh = await db.users.find_one({"id": admin["id"]}, {"_id": 0, "manager_preferences": 1})
    return (fresh or {}).get("manager_preferences", {}).get("payroll", {})

@api.get("/admin/payroll")
async def admin_list_payroll(
    admin=Depends(require_admin),
    user_id: Optional[str] = None,
    payroll_status: Optional[str] = Query(None, alias="status"),
):
    q: dict = {}
    if user_id: q["user_id"] = user_id
    if payroll_status: q["status"] = payroll_status
    periods = await db.payroll.find(q, {"_id": 0}).sort("period_end", -1).to_list(500)
    if periods:
        uids = list({p["user_id"] for p in periods})
        um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(500)}
        for p in periods: p["user"] = um.get(p["user_id"])
    return {"periods": periods}


@api.get("/admin/payroll/guards")
async def admin_payroll_guards(admin=Depends(require_admin)):
    guards = await db.users.find(
        {"role": "employee"},
        {"_id": 0, "id": 1, "full_name": 1, "email": 1, "employee_number": 1,
         "licence_number": 1, "licence_expiry": 1, "hourly_rate": 1},
    ).sort("full_name", 1).to_list(500)
    return {"guards": guards}


@api.post("/admin/payroll", status_code=201)
async def admin_create_payroll(body: AdminCreatePayrollIn, admin=Depends(require_admin)):
    if not await db.users.find_one({"id": body.user_id, "role": "employee"}, {"_id": 1}):
        raise HTTPException(404, "Guard not found")
    validate_payroll_period(body.period_start, body.period_end, body.pay_date)
    hours_reg = body.hours_regular if body.hours_regular is not None else (body.hours_worked or 0.0)
    rate = body.pay_rate if body.pay_rate is not None else body.hourly_rate
    if rate is None:
        raise HTTPException(422, "Pay rate is required")
    period_key = payroll_period_key(body.user_id, body.period_start, body.period_end)
    existing = await db.payroll.find_one({
        "user_id": body.user_id,
        "period_start": {"$regex": f"^{re.escape(body.period_start[:10])}"},
        "period_end": {"$regex": f"^{re.escape(body.period_end[:10])}"},
    }, {"_id": 1})
    if existing:
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    gross = round(hours_reg * rate + body.hours_overtime * rate * 1.5, 2)
    total_deductions = round(sum(d.amount for d in body.deductions), 2)
    net = round(gross - total_deductions, 2)
    if net < 0:
        raise HTTPException(422, "Payroll deductions cannot exceed gross pay")
    record = {
        "id": str(uuid.uuid4()), "user_id": body.user_id, "period_key": period_key,
        "period_start": body.period_start, "period_end": body.period_end,
        "pay_date": body.pay_date or body.period_end,
        "hours_regular": hours_reg, "hours_overtime": body.hours_overtime,
        "pay_rate": rate, "gross": gross,
        "deductions": [d.model_dump() for d in body.deductions],
        "total_deductions": total_deductions,
        "net": net,
        "status": body.status, "notes": body.notes or "",
        "paid_via": body.paid_via,
        "comments": [
            {
                "text": comment.text.strip(), "at": iso(now_utc()),
                "author": admin.get("full_name") or "Manager", "author_id": admin["id"],
            }
            for comment in body.comments
        ],
        "pay_stub_url": None,
        "created_by": admin["id"], "created_at": iso(now_utc()),
    }
    try:
        await db.payroll.insert_one(record)
    except DuplicateKeyError:
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    record.pop("_id", None)
    return record


# ── Timesheet Import ────────────────────────────────────────────────────────

def _parse_timesheet_xlsx(data: bytes, from_date=None, to_date=None):
    """Parse a client timesheet xlsx and return per-guard shift summaries."""
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(500, "openpyxl not available on server. Contact admin.")

    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True)
    ws = wb["Sheet1"] if "Sheet1" in wb.sheetnames else wb.active

    guards: dict = {}
    for r in range(2, ws.max_row + 1):
        row = [ws.cell(r, c).value for c in range(1, 10)]
        if not any(row):
            continue
        name_raw, lic_raw, date_val, project = row[0], row[1], row[2], row[3]
        hours = float(row[7]) if row[7] is not None else 0.0

        if not name_raw:
            continue
        name_str = str(name_raw).strip()
        if name_str.lower().startswith("skyhawk"):
            continue

        # Parse shift date
        shift_date = None
        if isinstance(date_val, datetime):
            shift_date = date_val.date()
        elif isinstance(date_val, date):
            shift_date = date_val

        # Optional date-range filter
        if shift_date and from_date and shift_date < from_date:
            continue
        if shift_date and to_date and shift_date > to_date:
            continue

        # Parse licence number (stored as float in some cells)
        if lic_raw is not None:
            try:
                lic_str = str(int(float(lic_raw)))
            except Exception:
                lic_str = str(lic_raw).strip()
        else:
            m = re.search(r"(\d{7,10})$", name_str)
            lic_str = m.group(1) if m else None
        if not lic_str:
            continue

        # Clean name – strip {N} repeat-markers and embedded lic number at tail
        clean = re.sub(r"\s*\{[^}]*\}", "", name_str).strip()
        clean = re.sub(r"\s+\d{6,10}$", "", clean).strip()

        if lic_str not in guards:
            guards[lic_str] = {
                "lic_number": lic_str, "guard_name": clean,
                "total_hours": 0.0, "shift_count": 0,
                "dates": [], "projects": [],
            }
        g = guards[lic_str]
        g["total_hours"] += hours
        g["shift_count"] += 1
        if shift_date:
            g["dates"].append(shift_date.isoformat())
        proj = str(project).strip() if project else None
        if proj and proj not in g["projects"]:
            g["projects"].append(proj)

    result = []
    for g in guards.values():
        ds = sorted(g["dates"])
        result.append({
            "lic_number":   g["lic_number"],
            "guard_name":   g["guard_name"],
            "total_hours":  round(g["total_hours"], 2),
            "shift_count":  g["shift_count"],
            "shift_dates":  ds,
            "period_start": ds[0]  if ds else None,
            "period_end":   ds[-1] if ds else None,
            "projects":     g["projects"][:5],
        })
    result.sort(key=lambda x: x["guard_name"].upper())
    return result


@api.post("/admin/payroll/parse-timesheet")
async def parse_timesheet_upload(
    file: UploadFile = File(...),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    admin=Depends(require_admin),
):
    data = await file.read()
    from_d = date.fromisoformat(from_date) if from_date else None
    to_d   = date.fromisoformat(to_date)   if to_date   else None
    try:
        guards = _parse_timesheet_xlsx(data, from_d, to_d)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"Could not parse file: {exc}")

    if not guards:
        raise HTTPException(400, "No valid shift rows found. Check the date range or file format.")

    # Match guards in DB by licence_number field
    lic_numbers = [g["lic_number"] for g in guards]
    db_users = await db.users.find(
        {"licence_number": {"$in": lic_numbers}},
        {"_id": 0, "id": 1, "full_name": 1, "licence_number": 1},
    ).to_list(5000)
    lic_to_user = {u["licence_number"]: u for u in db_users}

    matched = 0
    for g in guards:
        u = lic_to_user.get(g["lic_number"])
        g["user_id"]      = u["id"]        if u else None
        g["matched_name"] = u["full_name"] if u else None
        g["matched"]      = bool(u)
        if u:
            matched += 1

    return {
        "guards":         guards,
        "total_guards":   len(guards),
        "total_shifts":   sum(g["shift_count"] for g in guards),
        "total_hours":    round(sum(g["total_hours"] for g in guards), 2),
        "matched_guards": matched,
    }


class BulkPayrollEntryIn(BaseModel):
    lic_number: str = Field(min_length=1, max_length=100)
    guard_name: str = Field(min_length=1, max_length=200)
    user_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    period_start: str = Field(min_length=10, max_length=50)
    period_end: str = Field(min_length=10, max_length=50)
    pay_date: Optional[str] = Field(default=None, min_length=10, max_length=50)
    hours_regular: float = Field(ge=0, le=1000)
    pay_rate: float = Field(gt=0, le=1000)
    notes: Optional[str] = Field(default="", max_length=5000)
    shift_count: Optional[int] = Field(default=None, ge=0, le=10_000)
    shift_dates: Optional[List[str]] = Field(default=None, max_length=1000)


@api.post("/admin/payroll/bulk-create", status_code=201)
async def bulk_create_payroll(entries: List[BulkPayrollEntryIn], admin=Depends(require_admin)):
    if not entries:
        raise HTTPException(422, "At least one payroll entry is required")
    if len(entries) > 500:
        raise HTTPException(413, "A maximum of 500 payroll entries can be imported at once")
    linked_ids = {entry.user_id for entry in entries if entry.user_id}
    if linked_ids:
        valid_ids = set(await db.users.distinct("id", {"id": {"$in": list(linked_ids)}, "role": "employee"}))
        missing_ids = linked_ids - valid_ids
        if missing_ids:
            raise HTTPException(404, "One or more linked guards no longer exist")
    records = []
    batch_keys: set[str] = set()
    legacy_queries = []
    for e in entries:
        validate_payroll_period(e.period_start, e.period_end, e.pay_date)
        payroll_user_id = e.user_id or f"ext:{e.lic_number}"
        period_key = payroll_period_key(payroll_user_id, e.period_start, e.period_end)
        if period_key in batch_keys:
            raise HTTPException(409, "The import contains duplicate guard payroll periods")
        batch_keys.add(period_key)
        legacy_queries.append({
            "user_id": payroll_user_id,
            "period_start": {"$regex": f"^{re.escape(e.period_start[:10])}"},
            "period_end": {"$regex": f"^{re.escape(e.period_end[:10])}"},
        })
        gross = round(e.hours_regular * e.pay_rate, 2)
        records.append({
            "id":               str(uuid.uuid4()),
            "user_id":          payroll_user_id,
            "period_key":       period_key,
            "lic_number":       e.lic_number,
            "guard_name_import": e.guard_name,
            "period_start":     e.period_start,
            "period_end":       e.period_end,
            "pay_date":         e.pay_date or e.period_end,
            "hours_regular":    e.hours_regular,
            "hours_overtime":   0.0,
            "pay_rate":         e.pay_rate,
            "gross":            gross,
            "deductions":       [],
            "total_deductions": 0.0,
            "net":              gross,
            "status":           "submitted",
            "notes":            e.notes or "",
            "paid_via":         None,
            "pay_stub_url":     None,
            "imported":         True,
            "shift_count":      e.shift_count,
            "shift_dates":      e.shift_dates or [],
            "created_by":       admin["id"],
            "created_at":       iso(now_utc()),
        })
    if await db.payroll.find_one({"$or": legacy_queries}, {"_id": 1}):
        raise HTTPException(409, "A payroll record already exists for one or more imported periods")
    try:
        await db.payroll.insert_many(records)
    except DuplicateKeyError:
        await db.payroll.delete_many({"id": {"$in": [record["id"] for record in records]}})
        raise HTTPException(409, "A payroll record already exists for one or more imported periods")
    for record in records:
        record.pop("_id", None)
    return {"created": len(records)}


@api.put("/admin/payroll/{payroll_id}")
async def admin_update_payroll(payroll_id: str, body: AdminUpdatePayrollIn, admin=Depends(require_admin)):
    current = await db.payroll.find_one({"id": payroll_id})
    if not current:
        raise HTTPException(404, "Payroll record not found")
    raw = body.model_dump()
    if raw.get("hours_worked") is not None and raw.get("hours_regular") is None:
        raw["hours_regular"] = raw["hours_worked"]
    if raw.get("hourly_rate") is not None and raw.get("pay_rate") is None:
        raw["pay_rate"] = raw["hourly_rate"]
    raw.pop("hours_worked", None); raw.pop("hourly_rate", None)
    if raw.get("deductions") is not None:
        raw["deductions"] = [d if isinstance(d, dict) else d.model_dump() for d in raw["deductions"]]
    if raw.get("comments") is not None:
        incoming = [comment if isinstance(comment, dict) else comment.model_dump() for comment in raw["comments"]]
        existing_comments = current.get("comments") or []
        if len(incoming) < len(existing_comments):
            raise HTTPException(409, "Payroll approval comments are append-only")
        for index, existing in enumerate(existing_comments):
            candidate = incoming[index]
            if any(candidate.get(key) != existing.get(key) for key in ("text", "at", "author")):
                raise HTTPException(409, "Payroll approval comments are append-only")
        raw["comments"] = existing_comments + [
            {
                "text": comment["text"].strip(),
                "at": iso(now_utc()),
                "author": admin.get("full_name") or "Manager",
                "author_id": admin["id"],
            }
            for comment in incoming[len(existing_comments):]
        ]
    update = {k: v for k, v in raw.items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    merged = {**current, **update}
    validate_payroll_period(merged["period_start"], merged["period_end"], merged.get("pay_date"))
    if not str(merged["user_id"]).startswith("ext:") and not await db.users.find_one(
        {"id": merged["user_id"], "role": "employee"}, {"_id": 1}
    ):
        raise HTTPException(404, "Guard not found")
    new_period_key = payroll_period_key(merged["user_id"], merged["period_start"], merged["period_end"])
    duplicate = await db.payroll.find_one({
        "id": {"$ne": payroll_id},
        "$or": [
            {"period_key": new_period_key},
            {
                "user_id": merged["user_id"],
                "period_start": {"$regex": f"^{re.escape(merged['period_start'][:10])}"},
                "period_end": {"$regex": f"^{re.escape(merged['period_end'][:10])}"},
            },
        ],
    }, {"_id": 1})
    if duplicate:
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    hours_regular = float(merged.get("hours_regular") or 0)
    hours_overtime = float(merged.get("hours_overtime") or 0)
    rate = merged.get("pay_rate", merged.get("hourly_rate"))
    if rate is None or float(rate) <= 0:
        raise HTTPException(422, "Pay rate is required")
    deductions = merged.get("deductions") or []
    total_deductions = round(sum(float(item.get("amount") or 0) for item in deductions), 2)
    gross = round(hours_regular * float(rate) + hours_overtime * float(rate) * float(merged.get("overtime_multiplier") or 1.5), 2)
    tax_rate = float(merged.get("tax_rate") or 0)
    net = round(gross * (1 - tax_rate) - total_deductions, 2)
    if net < 0:
        raise HTTPException(422, "Payroll deductions cannot exceed available net pay")
    update.update({
        "period_key": new_period_key,
        "pay_rate": float(rate),
        "gross": gross,
        "total_deductions": total_deductions,
        "net": net,
        "updated_by": admin["id"],
        "updated_at": iso(now_utc()),
    })
    try:
        await db.payroll.update_one({"id": payroll_id}, {"$set": update})
    except DuplicateKeyError:
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    updated = await db.payroll.find_one({"id": payroll_id}, {"_id": 0})
    status_changed = current.get("status") != updated.get("status")
    if status_changed and updated.get("status") in {"released", "paid"} and not str(updated["user_id"]).startswith("ext:"):
        status_label = "Paid" if updated["status"] == "paid" else "Released"
        await send_push([updated["user_id"]], {"title": f"Payroll {status_label}", "message": f"Pay for {updated.get('period_end','')[:10]} is {status_label.lower()}."})
        guard = await db.users.find_one({"id": updated["user_id"]}, {"_id": 0, "email": 1, "full_name": 1})
        pay_html = notif.email_template(
            f"Your pay is {status_label.lower()}",
            [
                f"Hi {guard.get('full_name', 'there') if guard else 'there'},",
                f"Your pay for the period ending <strong>{updated.get('period_end','')[:10]}</strong> is {status_label.lower()}.",
                f"Net pay: <strong>${updated.get('net', 0):.2f}</strong> (Gross: ${updated.get('gross', 0):.2f})",
            ],
            cta_text="View Pay Stub",
            cta_link="disptchr://payroll",
        )
        await asyncio.gather(
            queue_email(guard["email"], f"Your Skyhawk pay is {status_label.lower()}", pay_html, "",
                f"payroll:{updated['id']}:{updated['status']}:email") if guard and guard.get("email") else asyncio.sleep(0),
            notif.save_inapp(db, [updated["user_id"]], f"Payroll {status_label} 💰", f"Pay for {updated.get('period_end','')[:10]} is {status_label.lower()}. Net: ${updated.get('net', 0):.2f}", category="payroll"),
            return_exceptions=True,
        )
    return updated


@api.delete("/admin/payroll/{payroll_id}", status_code=204)
async def admin_delete_payroll(payroll_id: str, admin=Depends(require_admin)):
    record = await db.payroll.find_one_and_delete({"id": payroll_id})
    if not record:
        raise HTTPException(404, "Payroll record not found")
    if record.get("pay_stub_url"):
        await _delete_stored_file(record["pay_stub_url"])


# ============================================================
# ADMIN ROUTES — Timeclock
# ============================================================

@api.get("/admin/timeclock")
async def admin_list_timeclock(
    admin=Depends(require_admin),
    user_id: Optional[str] = None,
    active_only: bool = False,
):
    q: dict = {}
    if user_id: q["user_id"] = user_id
    if active_only: q["clock_out"] = None
    entries = await db.timeclock.find(q, {"_id": 0, "selfie_in": 0, "selfie_out": 0}).sort("clock_in", -1).to_list(200)
    if entries:
        uids = list({e["user_id"] for e in entries})
        sids = list({e["site_id"] for e in entries if e.get("site_id")})
        um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(200)}
        sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(50)} if sids else {}
        for e in entries:
            e["user"] = um.get(e["user_id"]); e["site"] = sm.get(e.get("site_id"))
    return {"entries": entries}


@api.put("/admin/timeclock/{entry_id}")
async def admin_update_timeclock(entry_id: str, body: AdminUpdateTimeclockIn, admin=Depends(require_admin)):
    update = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    current = await db.timeclock.find_one({"id": entry_id})
    if not current:
        raise HTTPException(404, "Timeclock entry not found")
    merged = {**current, **update}
    if "clock_in" in update or "clock_out" in update:
        try:
            clock_in_at = parse_datetime_utc(merged["clock_in"])
            clock_out_at = parse_datetime_utc(merged["clock_out"]) if merged.get("clock_out") else None
        except (TypeError, ValueError):
            raise HTTPException(422, "Clock-in and clock-out must be valid ISO 8601 dates")
        if clock_out_at:
            if clock_out_at <= clock_in_at:
                raise HTTPException(422, "Clock-out must be after clock-in")
            break_seconds = 0.0
            for item in merged.get("breaks") or []:
                if not item.get("start") or not item.get("end"):
                    continue
                try:
                    break_start = parse_datetime_utc(item["start"])
                    break_end = parse_datetime_utc(item["end"])
                except (TypeError, ValueError):
                    continue
                if break_end > break_start:
                    break_seconds += (break_end - break_start).total_seconds()
            elapsed_seconds = max(0.0, (clock_out_at - clock_in_at).total_seconds() - break_seconds)
            update["hours_worked"] = round(elapsed_seconds / 3600, 2)
    update.update({"manually_adjusted": True, "adjusted_by": admin["id"], "adjusted_at": iso(now_utc())})
    await db.timeclock.update_one({"id": entry_id}, {"$set": update})
    if current.get("shift_id") and "hours_worked" in update:
        await db.shifts.update_one({"id": current["shift_id"]}, {"$set": {"hours_worked": update["hours_worked"]}})
    return await db.timeclock.find_one({"id": entry_id}, {"_id": 0, "selfie_in": 0, "selfie_out": 0})


# ============================================================
# SOS / PANIC
# ============================================================

@api.post("/sos", status_code=201)
async def trigger_sos(body: SOSIn, user=Depends(get_current_user)):
    if (body.latitude is None) != (body.longitude is None):
        raise HTTPException(422, "latitude and longitude must be supplied together")
    alert_id = str(uuid.uuid4())
    now = now_utc()
    location_available = body.latitude is not None and body.longitude is not None
    location_text = (
        f"{body.latitude:.5f},{body.longitude:.5f}"
        if location_available else "unavailable"
    )
    alert = {
        "id": alert_id,
        "user_id": user["id"],
        "user_name": user["full_name"],
        "employee_number": user.get("employee_number"),
        "latitude": body.latitude,
        "longitude": body.longitude,
        "location_available": location_available,
        "message": body.message,
        "status": "active",
        "created_at": iso(now),
        "acknowledged_by": None,
        "acknowledged_at": None,
    }
    await db.sos_alerts.insert_one(alert)
    alert.pop("_id", None)
    incident = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "user_name": user["full_name"],
        "type": "incident",
        "site_id": None,
        "description": f"SOS ALERT triggered by {user['full_name']}. GPS: {location_text}. {body.message or ''}".strip(),
        "severity": "critical",
        "witness_name": None,
        "witness_contact": None,
        "photos": [],
        "signature_base64": None,
        "status": "open",
        "sos_alert_id": alert_id,
        "created_at": iso(now),
        "audit_trail": [],
    }
    await db.incidents.insert_one(incident)
    admins = await active_managers_with_permission(
        "sos.manage", {"id": 1, "email": 1, "phone": 1, "_id": 0}
    )
    admin_ids = [a["id"] for a in admins]
    push_location = f" · {body.latitude:.4f},{body.longitude:.4f}" if location_available else " · GPS unavailable"
    await send_push(
        admin_ids,
        {"title": f"🆘 SOS — {user['full_name']}", "message": f"{body.message or 'Guard needs immediate assistance'}{push_location}"},
        idempotency_key=f"sos-{alert_id}",
    )
    # SOS is critical, but only active managers explicitly assigned SOS access
    # may receive precise guard location or contact details.
    sos_html = notif.email_template(
        f"🆘 SOS ALERT — {user['full_name']}",
        [
            f"<strong style='color:#EF4444'>EMERGENCY — Guard needs immediate assistance.</strong>",
            f"<strong>Guard:</strong> {user['full_name']} (#{user.get('employee_number', 'N/A')})",
            f"<strong>GPS:</strong> {location_text}",
            f"<strong>Message:</strong> {body.message or 'No message provided'}",
            f"<strong>Time:</strong> {iso(now)}",
        ],
    )
    sms_body = (
        f"🆘 SOS ALERT: {user['full_name']} needs help. "
        f"GPS: {location_text}. "
        f"{body.message or 'Immediate assistance required.'}"
    )
    await asyncio.gather(
        *[queue_email(a["email"], f"🆘 SOS ALERT — {user['full_name']}", sos_html, "",
            f"sos:{alert['id']}:email:{a['id']}") for a in admins if a.get("email")],
        *[queue_sms(a["phone"], sms_body, f"sos:{alert['id']}:sms:{a['id']}") for a in admins if a.get("phone")],
        notif.save_inapp(db, admin_ids, f"🆘 SOS — {user['full_name']}", body.message or "Guard needs immediate assistance", category="sos"),
        notif.save_inapp(db, [user["id"]], "SOS Alert Sent", "Your emergency alert has been sent to authorized response managers.", category="sos"),
        return_exceptions=True,
    )
    logger.warning("SOS triggered by user %s; GPS %s", user["id"], location_text)
    return alert


@api.get("/sos/active")
async def list_sos_active(admin=Depends(require_admin)):
    alerts = await db.sos_alerts.find(
        {"status": {"$in": ["active", "acknowledged"]}}, {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    uids = list({a["user_id"] for a in alerts})
    if uids:
        um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(50)}
        for a in alerts:
            a["user"] = um.get(a["user_id"])
    return {"alerts": alerts}


@api.get("/sos/history")
async def sos_history(admin=Depends(require_admin)):
    alerts = await db.sos_alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"alerts": alerts}


@api.post("/sos/{alert_id}/acknowledge")
async def acknowledge_sos(alert_id: str, admin=Depends(require_admin)):
    r = await db.sos_alerts.update_one(
        {"id": alert_id, "status": "active"},
        {"$set": {"status": "acknowledged", "acknowledged_by": admin["id"], "acknowledged_at": iso(now_utc())}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Alert not found or already acknowledged")
    alert = await db.sos_alerts.find_one({"id": alert_id}, {"_id": 0})
    if alert:
        await send_push(
            [alert["user_id"]],
            {"title": "SOS Acknowledged", "message": f"Help is on the way. Acknowledged by {admin['full_name']}."},
        )
    return {"acknowledged": True}


@api.post("/sos/{alert_id}/resolve")
async def resolve_sos(alert_id: str, admin=Depends(require_admin)):
    r = await db.sos_alerts.update_one(
        {"id": alert_id, "status": {"$in": ["active", "acknowledged"]}},
        {"$set": {"status": "resolved", "resolved_at": iso(now_utc()), "resolved_by": admin["id"]}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Alert not found or already resolved")
    return {"resolved": True}


# ============================================================
# INCIDENT LIFECYCLE
# ============================================================

_INCIDENT_STATUSES = {"submitted", "open", "under_review", "escalated", "resolved"}


@api.patch("/incidents/{inc_id}/status")
async def update_incident_status(inc_id: str, body: IncidentStatusIn, admin=Depends(require_admin)):
    if body.status not in _INCIDENT_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(_INCIDENT_STATUSES)}")
    inc = await db.incidents.find_one({"id": inc_id}, {"_id": 0, "photos": 0, "signature_base64": 0})
    if not inc:
        raise HTTPException(404, "Incident not found")
    now = now_utc()
    update: dict = {"status": body.status, "updated_at": iso(now), "last_updated_by": admin["id"]}
    if body.assigned_to:
        update["assigned_to"] = body.assigned_to
    note_entry = {"ts": iso(now), "by": admin["full_name"], "status": body.status, "note": body.note}
    await db.incidents.update_one({"id": inc_id}, {"$set": update, "$push": {"audit_trail": note_entry}})
    if body.status == "resolved":
        msg = f"Your {inc['type'].replace('_', ' ')} report has been resolved. {body.note or ''}".strip()
        await send_push([inc["user_id"]], {"title": "Incident Resolved", "message": msg})
        await notif.save_inapp(db, [inc["user_id"]], "Incident Resolved ✓", msg, category="incident")
    elif body.status in ("escalated", "under_review"):
        label = "Escalated" if body.status == "escalated" else "Under Review"
        await notif.save_inapp(db, [inc["user_id"]], f"Incident {label}", f"Your report is now {body.status.replace('_',' ')}. {body.note or ''}".strip(), category="incident")
    return await db.incidents.find_one({"id": inc_id}, {"_id": 0, "photos": 0, "signature_base64": 0})


@api.get("/incidents/{inc_id}")
async def get_incident(inc_id: str, user=Depends(get_current_user)):
    q: dict = {"id": inc_id}
    if user["role"] == "admin":
        enforce_manager_permission(user, "incidents.manage")
    else:
        q["user_id"] = user["id"]
    inc = await db.incidents.find_one(q, {"_id": 0, "photos": 0, "signature_base64": 0})
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


# ============================================================
# LIVE GPS TRACKING
# ============================================================

@api.post("/timeclock/location-ping")
async def location_ping(body: LocationPingIn, user=Depends(get_current_user)):
    active = await db.timeclock.find_one({"user_id": user["id"], "clock_out": None})
    if not active:
        raise HTTPException(400, "Not currently clocked in")
    ping = {
        "timeclock_id": active["id"],
        "user_id": user["id"],
        "latitude": body.latitude,
        "longitude": body.longitude,
        "accuracy_m": body.accuracy_m,
        "ts": iso(now_utc()),
    }
    await db.location_pings.insert_one(ping)
    await db.timeclock.update_one(
        {"id": active["id"]},
        {"$set": {"last_ping_lat": body.latitude, "last_ping_lng": body.longitude, "last_ping_ts": iso(now_utc())}},
    )
    return {"ok": True}


@api.get("/ops/live-locations")
async def live_locations(admin=Depends(require_admin)):
    """All guards currently clocked in with their last GPS ping."""
    active_entries = await db.timeclock.find(
        {"clock_out": None}, {"_id": 0, "selfie_in": 0, "selfie_out": 0}
    ).to_list(200)
    if not active_entries:
        return {"guards": []}
    uids = list({e["user_id"] for e in active_entries})
    sids = list({e["site_id"] for e in active_entries if e.get("site_id")})
    um = {u["id"]: u for u in await db.users.find({"id": {"$in": uids}}, SENSITIVE_USER_PROJECTION).to_list(100)}
    sm = {s["id"]: s for s in await db.sites.find({"id": {"$in": sids}}, {"_id": 0}).to_list(50)} if sids else {}
    guards = []
    for entry in active_entries:
        ud = um.get(entry["user_id"])
        if not ud:
            continue
        last_ts = entry.get("last_ping_ts") or entry["clock_in"]
        try:
            stale = (now_utc() - datetime.fromisoformat(last_ts.replace("Z", "+00:00"))).total_seconds() > 900
        except Exception:
            stale = True
        guards.append({
            "user_id": entry["user_id"],
            "full_name": ud.get("full_name"),
            "employee_number": ud.get("employee_number"),
            "photo_url": ud.get("photo_url"),
            "site": sm.get(entry.get("site_id")),
            "clock_in": entry["clock_in"],
            "last_lat": entry.get("last_ping_lat") or entry.get("clock_in_lat"),
            "last_lng": entry.get("last_ping_lng") or entry.get("clock_in_lng"),
            "last_ping_ts": entry.get("last_ping_ts"),
            "stale": stale,
        })
    return {"guards": guards}


# ============================================================
# SHIFT SWAP MARKETPLACE
# ============================================================

@api.post("/shifts/{shift_id}/request-swap", status_code=201)
async def request_swap(shift_id: str, body: SwapRequestIn, user=Depends(get_current_user)):
    shift = await db.shifts.find_one({"id": shift_id, "user_id": user["id"]})
    if not shift:
        raise HTTPException(404, "Shift not found or not yours")
    if shift.get("status") not in ("scheduled",):
        raise HTTPException(400, "Only scheduled shifts can be swapped")
    existing = await db.shift_swaps.find_one({"shift_id": shift_id, "status": {"$in": ["open", "accepted", "processing"]}})
    if existing:
        raise HTTPException(400, "A swap request for this shift already exists")
    site = None
    if shift.get("site_id"):
        site = await db.sites.find_one({"id": shift["site_id"]}, {"_id": 0, "name": 1, "id": 1})
    swap = {
        "id": str(uuid.uuid4()),
        "shift_id": shift_id,
        "requester_id": user["id"],
        "requester_name": user["full_name"],
        "site_id": shift.get("site_id"),
        "site_name": site["name"] if site else None,
        "start": shift["start"],
        "end": shift["end"],
        "role": shift.get("role"),
        "pay_rate": shift.get("pay_rate"),
        "reason": body.reason,
        "status": "open",
        "active_shift_id": shift_id,
        "volunteer_id": None,
        "volunteer_name": None,
        "created_at": iso(now_utc()),
        "resolved_at": None,
    }
    try:
        await db.shift_swaps.insert_one(swap)
    except DuplicateKeyError as exc:
        raise HTTPException(400, "An active swap request for this shift already exists") from exc
    swap.pop("_id", None)
    swap.pop("active_shift_id", None)
    managers = await active_managers_with_permission("scheduling.manage", {"id": 1, "_id": 0})
    admin_ids = [manager["id"] for manager in managers]
    await send_push(admin_ids, {"title": "Shift Swap Requested", "message": f"{user['full_name']} wants to swap their {shift['start'][:10]} shift."})
    return swap


@api.get("/shift-swaps")
async def list_shift_swaps(user=Depends(get_current_user)):
    own = await db.shift_swaps.find({"requester_id": user["id"]}, {"_id": 0, "active_shift_id": 0}).sort("created_at", -1).to_list(50)
    marketplace = await db.shift_swaps.find(
        {"status": "open", "requester_id": {"$ne": user["id"]}}, {"_id": 0, "active_shift_id": 0}
    ).sort("start", 1).to_list(50)
    return {"own": own, "marketplace": marketplace}


@api.post("/shift-swaps/{swap_id}/volunteer")
async def volunteer_swap(swap_id: str, user=Depends(get_current_user)):
    swap = await db.shift_swaps.find_one({"id": swap_id, "status": "open"})
    if not swap:
        raise HTTPException(404, "Swap not found or no longer open")
    if swap["requester_id"] == user["id"]:
        raise HTTPException(400, "Cannot volunteer for your own swap")
    swap = await db.shift_swaps.find_one_and_update(
        {"id": swap_id, "status": "open"},
        {"$set": {"status": "accepted", "volunteer_id": user["id"], "volunteer_name": user["full_name"]}},
        return_document=ReturnDocument.AFTER,
    )
    if not swap:
        raise HTTPException(409, "Another guard already volunteered for this swap")
    managers = await active_managers_with_permission("scheduling.manage", {"id": 1, "_id": 0})
    admin_ids = [manager["id"] for manager in managers]
    await send_push(
        admin_ids + [swap["requester_id"]],
        {"title": "Swap Volunteer", "message": f"{user['full_name']} wants to cover {swap['requester_name']}'s shift on {swap['start'][:10]}."},
    )
    return {"volunteered": True}


@api.post("/shift-swaps/{swap_id}/cancel")
async def cancel_swap(swap_id: str, user=Depends(get_current_user)):
    r = await db.shift_swaps.update_one(
        {"id": swap_id, "requester_id": user["id"], "status": {"$in": ["open", "accepted"]}},
        {"$set": {"status": "cancelled", "resolved_at": iso(now_utc())}, "$unset": {"active_shift_id": ""}},
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Swap not found or cannot be cancelled")
    return {"cancelled": True}


@api.post("/admin/shift-swaps/{swap_id}/decision")
async def admin_swap_decision(swap_id: str, body: SwapActionIn, admin=Depends(require_admin)):
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be 'approve' or 'reject'")
    swap = await db.shift_swaps.find_one_and_update(
        {"id": swap_id, "status": "accepted"},
        {"$set": {"status": "processing", "decision_started_at": iso(now_utc()), "decision_started_by": admin["id"]}},
        return_document=ReturnDocument.BEFORE,
    )
    if not swap:
        raise HTTPException(404, "Swap not found or not in 'accepted' state")
    both_ids = [swap["requester_id"], swap["volunteer_id"]]
    if body.action == "approve":
        transfer = await db.shifts.update_one(
            {"id": swap["shift_id"], "user_id": swap["requester_id"], "status": "scheduled"},
            {"$set": {"user_id": swap["volunteer_id"], "swapped_from": swap["requester_id"]}},
        )
        if transfer.matched_count == 0:
            await db.shift_swaps.update_one(
                {"id": swap_id, "status": "processing"},
                {"$set": {"status": "accepted"}, "$unset": {"decision_started_at": "", "decision_started_by": ""}},
            )
            raise HTTPException(409, "The assigned shift changed before this decision could be applied")
        await db.shift_swaps.update_one(
            {"id": swap_id, "status": "processing"},
            {"$set": {
                "status": "approved", "resolved_at": iso(now_utc()), "approved_by": admin["id"],
                "manager_note": body.reason,
            }, "$unset": {"active_shift_id": "", "decision_started_at": "", "decision_started_by": ""}},
        )
        await send_push(
            both_ids,
            {"title": "Shift Swap Approved ✓", "message": f"The {swap['start'][:10]} shift has been transferred to {swap['volunteer_name']}."},
        )
        # SMS both parties + in-app
        req_user = await db.users.find_one({"id": swap["requester_id"]},  {"phone": 1, "_id": 0})
        vol_user = await db.users.find_one({"id": swap["volunteer_id"]},  {"phone": 1, "_id": 0})
        await asyncio.gather(
            queue_sms(req_user["phone"], f"Skyhawk: Your swap request for {swap['start'][:10]} was APPROVED. You're now off this shift.",
                f"swap:{swap_id}:approved:sms:{swap['requester_id']}") if req_user and req_user.get("phone") else asyncio.sleep(0),
            queue_sms(vol_user["phone"], f"Skyhawk: Shift swap APPROVED — you're now working {swap['start'][:10]}.",
                f"swap:{swap_id}:approved:sms:{swap['volunteer_id']}") if vol_user and vol_user.get("phone") else asyncio.sleep(0),
            notif.save_inapp(db, both_ids, "Shift Swap Approved ✓", f"The {swap['start'][:10]} shift has been transferred to {swap['volunteer_name']}.", category="swap"),
            return_exceptions=True,
        )
    else:
        await db.shift_swaps.update_one(
            {"id": swap_id, "status": "processing"},
            {"$set": {
                "status": "rejected", "resolved_at": iso(now_utc()), "rejected_by": admin["id"],
                "manager_note": body.reason,
            }, "$unset": {"active_shift_id": "", "decision_started_at": "", "decision_started_by": ""}},
        )
        await send_push(
            both_ids,
            {"title": "Shift Swap Rejected", "message": f"The swap request for {swap['start'][:10]} was not approved."},
        )
        await notif.save_inapp(db, both_ids, "Shift Swap Rejected", f"The swap request for {swap['start'][:10]} was not approved.", category="swap")
    return {"action": body.action}


@api.get("/admin/shift-swaps")
async def admin_list_swaps(admin=Depends(require_admin), status: Optional[str] = None):
    q: dict = {}
    if status:
        q["status"] = status
    swaps = await db.shift_swaps.find(q, {"_id": 0, "active_shift_id": 0}).sort("created_at", -1).to_list(100)
    return {"swaps": swaps}


# ============================================================
# PAYROLL ENGINE
# ============================================================

async def _generate_pay_stub_pdf(record: dict) -> str:
    """Render a simple one-page pay stub PDF and return its served URL."""
    filename = f"{record['id']}.pdf"
    buffer = io.BytesIO()
    c = pdf_canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 72

    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, y, "Skyhawk Security Operations")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(72, y, "Pay Stub")
    y -= 30

    c.setFont("Helvetica-Bold", 11)
    c.drawString(72, y, record["user_name"])
    c.drawString(320, y, f"Employee #: {record.get('employee_number', '-')}")
    y -= 16
    c.setFont("Helvetica", 10)
    c.drawString(72, y, f"Pay period: {record['period_start'][:10]} - {record['period_end'][:10]}")
    y -= 14
    c.drawString(72, y, f"Pay date: {record['pay_date'][:10]}")
    y -= 30

    rows = [
        ("Regular hours", f"{record['hours_regular']:.2f}"),
        ("Overtime hours", f"{record['hours_overtime']:.2f}"),
        ("Hourly rate", f"${record['hourly_rate']:.2f}"),
        ("Overtime multiplier", f"{record['overtime_multiplier']:.2f}x"),
        ("Gross pay", f"${record['gross']:.2f}"),
        ("Tax withheld", f"${record['gross'] - record['net']:.2f}"),
        ("Net pay", f"${record['net']:.2f}"),
    ]
    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, y, "Summary")
    y -= 16
    c.setFont("Helvetica", 10)
    for label, value in rows:
        c.drawString(80, y, label)
        c.drawRightString(300, y, value)
        y -= 14

    y -= 16
    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, y, "Shift detail")
    y -= 16
    c.setFont("Helvetica", 9)
    for item in record.get("line_items", [])[:25]:
        if y < 72:
            c.showPage()
            y = height - 72
        c.drawString(80, y, item.get("date", ""))
        c.drawRightString(300, y, f"{item.get('hours', 0):.2f} h")
        y -= 12

    c.showPage()
    c.save()
    content = buffer.getvalue()
    storage_key = f"paystubs/{filename}"
    await storage.put(storage_key, content, "application/pdf")
    try:
        await db.stored_files.insert_one({
            "id": str(uuid.uuid4()), "category": "paystubs", "stored_name": filename,
            "owner_id": record["user_id"], "original_name": f"paystub-{record['pay_date'][:10]}.pdf",
            "content_type": "application/pdf", "byte_size": len(content), "created_at": iso(now_utc()),
        })
    except Exception:
        await storage.delete(storage_key)
        raise
    return f"/api/files/paystubs/{filename}"


@api.post("/admin/payroll/calculate", status_code=201)
async def calculate_payroll(body: PayrollCalculateIn, admin=Depends(require_admin)):
    user = await db.users.find_one({"id": body.user_id}, SENSITIVE_USER_PROJECTION)
    if not user:
        raise HTTPException(404, "User not found")
    validate_payroll_period(body.period_start, body.period_end, body.pay_date)
    period_key = payroll_period_key(body.user_id, body.period_start, body.period_end)
    if await db.payroll.find_one({
        "user_id": body.user_id,
        "period_start": {"$regex": f"^{re.escape(body.period_start[:10])}"},
        "period_end": {"$regex": f"^{re.escape(body.period_end[:10])}"},
    }, {"_id": 1}):
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    try:
        ps = parse_datetime_utc(body.period_start)
        pe = parse_datetime_utc(body.period_end)
        pd_dt = parse_datetime_utc(body.pay_date)
    except (TypeError, ValueError):
        raise HTTPException(400, "Invalid date format. Use ISO 8601 (YYYY-MM-DD)")
    entries = await db.timeclock.find(
        {"user_id": body.user_id, "clock_out": {"$ne": None},
         "clock_in": {"$gte": iso(ps), "$lte": iso(pe + timedelta(days=1))}},
        {"_id": 0, "selfie_in": 0, "selfie_out": 0},
    ).to_list(200)
    total_hours = sum(e.get("hours_worked") or 0 for e in entries)
    regular_hours = min(total_hours, body.overtime_threshold)
    overtime_hours = max(0.0, total_hours - body.overtime_threshold)
    gross = round(regular_hours * body.hourly_rate + overtime_hours * body.hourly_rate * body.overtime_multiplier, 2)
    net = round(gross * (1 - body.tax_rate), 2)
    line_items = [{"date": e["clock_in"][:10], "hours": round(e.get("hours_worked") or 0, 2), "shift_id": e.get("shift_id")} for e in entries]
    record = {
        "id": str(uuid.uuid4()),
        "user_id": body.user_id,
        "period_key": period_key,
        "user_name": user["full_name"],
        "employee_number": user.get("employee_number"),
        "period_start": iso(ps),
        "period_end": iso(pe),
        "pay_date": iso(pd_dt),
        "hours_regular": round(regular_hours, 2),
        "hours_overtime": round(overtime_hours, 2),
        "hourly_rate": body.hourly_rate,
        "overtime_multiplier": body.overtime_multiplier,
        "tax_rate": body.tax_rate,
        "gross": gross,
        "net": net,
        "status": "submitted",
        "line_items": line_items,
        "shifts_count": len(entries),
        "pay_stub_url": None,
        "created_at": iso(now_utc()),
        "created_by": admin["id"],
    }
    try:
        await db.payroll.insert_one(record)
    except DuplicateKeyError:
        raise HTTPException(409, "A payroll record already exists for this guard and period")
    record.pop("_id", None)
    generated_stub_url = None
    try:
        generated_stub_url = await _generate_pay_stub_pdf(record)
        record["pay_stub_url"] = generated_stub_url
        await db.payroll.update_one({"id": record["id"]}, {"$set": {"pay_stub_url": record["pay_stub_url"]}})
    except Exception:
        await db.payroll.delete_one({"id": record["id"]})
        if generated_stub_url:
            await _delete_stored_file(generated_stub_url)
        raise
    return record


@api.get("/payroll/{period_id}/stub")
async def payroll_stub(period_id: str, user=Depends(get_current_user)):
    q: dict = {"id": period_id}
    if user["role"] == "admin":
        enforce_manager_permission(user, "payroll.manage")
    else:
        q["user_id"] = user["id"]
    period = await db.payroll.find_one(q, {"_id": 0})
    if not period:
        raise HTTPException(404, "Payroll period not found")
    return period


# ============================================================
# COMPLIANCE / CREDENTIAL MANAGEMENT
# ============================================================

def _compliance_status(expiry_iso: str) -> str:
    try:
        expiry_dt = parse_datetime_utc(expiry_iso)
        days_left = (expiry_dt - now_utc()).days
        if days_left < 0:
            return "expired"
        if days_left <= 30:
            return "expiring_soon"
        if days_left <= 60:
            return "expiring"
        return "valid"
    except Exception:
        return "unknown"


@api.get("/compliance/status")
async def my_compliance(user=Depends(get_current_user)):
    docs = await db.wallet_documents.find({"user_id": user["id"]}, {"_id": 0}).to_list(50)
    for doc in docs:
        if doc.get("expiry"):
            doc["compliance_status"] = _compliance_status(doc["expiry"])
            try:
                doc["days_until_expiry"] = (parse_datetime_utc(doc["expiry"]) - now_utc()).days
            except Exception:
                doc["days_until_expiry"] = None
    expired = [d for d in docs if d.get("compliance_status") == "expired"]
    expiring_soon = [d for d in docs if d.get("compliance_status") == "expiring_soon"]
    expiring = [d for d in docs if d.get("compliance_status") == "expiring"]
    overall = "expired" if expired else ("expiring_soon" if expiring_soon else ("expiring" if expiring else "compliant"))
    return {"overall_status": overall, "documents": docs, "expired_count": len(expired), "expiring_soon_count": len(expiring_soon)}


@api.get("/admin/compliance")
async def admin_compliance(admin=Depends(require_admin)):
    guards = await db.users.find({"role": "employee"}, SENSITIVE_USER_PROJECTION).to_list(200)
    results = []
    for g in guards:
        docs = await db.wallet_documents.find({"user_id": g["id"]}, {"_id": 0}).to_list(50)
        expired = sum(1 for d in docs if d.get("expiry") and _compliance_status(d["expiry"]) == "expired")
        expiring_soon = sum(1 for d in docs if d.get("expiry") and _compliance_status(d["expiry"]) == "expiring_soon")
        lic_status = _compliance_status(g["licence_expiry"]) if g.get("licence_expiry") else "unknown"
        results.append({
            "id": g["id"],
            "user_id": g["id"],
            "full_name": g["full_name"],
            "email": g.get("email"),
            "employee_number": g.get("employee_number"),
            "licence_number": g.get("licence_number"),
            "licence_expiry": g.get("licence_expiry"),
            "certifications": g.get("certifications") or [],
            "licence_status": lic_status,
            "expired_docs": expired,
            "expiring_soon_docs": expiring_soon,
            "total_docs": len(docs),
        })
    results.sort(key=lambda x: (x["licence_status"] not in ("expired",), x["licence_status"] not in ("expiring_soon",)))
    return {"guards": results}


@api.post("/wallet/documents", status_code=201)
async def add_wallet_doc(body: WalletDocIn, user=Depends(get_current_user)):
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "type": body.type,
        "name": body.name,
        "number": body.number,
        "expiry": body.expiry,
        "status": _compliance_status(body.expiry),
        "created_at": iso(now_utc()),
    }
    await db.wallet_documents.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api.patch("/wallet/documents/{doc_id}")
async def update_wallet_doc(doc_id: str, body: WalletDocIn, user=Depends(get_current_user)):
    existing = await db.wallet_documents.find_one({"id": doc_id, "user_id": user["id"]})
    if not existing:
        raise HTTPException(404, "Document not found")
    update = {"name": body.name, "number": body.number, "expiry": body.expiry, "type": body.type, "status": _compliance_status(body.expiry), "updated_at": iso(now_utc())}
    await db.wallet_documents.update_one({"id": doc_id}, {"$set": update})
    return await db.wallet_documents.find_one({"id": doc_id}, {"_id": 0})


# ============================================================
# COMMUNITY
# ============================================================
def _serialize_post(p: dict, user_id: str) -> dict:
    likes = p.get("likes") or []
    return {
        "id": p["id"],
        "author_id": p.get("author_id"),
        "author_name": p.get("author_name"),
        "author_handle": p.get("author_handle"),
        "author_photo": p.get("author_photo"),
        "audience": p.get("audience", "All Staff"),
        "type": p.get("type", "post"),
        "title": p.get("title"),
        "body": p.get("body", ""),
        "attachments": p.get("attachments") or [],
        "created_at": p.get("created_at"),
        "like_count": len(likes),
        "liked_by_me": user_id in likes,
        "comments": p.get("comments") or [],
        "comment_count": len(p.get("comments") or []),
        "seen_count": len(p.get("seen_by") or []),
    }


@api.get("/community/posts")
async def list_community_posts(type: Optional[str] = Query(default=None), user=Depends(get_current_user)):
    query = {}
    if type and type != "all":
        query["type"] = type
    items = await db.community_posts.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    if items:
        await db.community_posts.update_many(
            {"id": {"$in": [p["id"] for p in items]}},
            {"$addToSet": {"seen_by": user["id"]}},
        )
    return {"posts": [_serialize_post(p, user["id"]) for p in items]}


@api.post("/community/posts", status_code=201)
async def create_community_post(body: CommunityPostIn, user=Depends(get_current_user)):
    if body.type not in ("post", "announcement", "event", "recognition"):
        raise HTTPException(400, "Invalid post type")
    attachments = await _validate_post_attachments(body.attachments, user["id"])
    post = {
        "id": str(uuid.uuid4()),
        "author_id": user["id"],
        "author_name": user["full_name"],
        "author_handle": (user["full_name"] or "").lower().replace(" ", ""),
        "author_photo": user.get("photo_url"),
        "audience": body.audience,
        "type": body.type,
        "title": None,
        "body": body.body,
        "attachments": attachments,
        "created_at": iso(now_utc()),
        "likes": [],
        "comments": [],
        "seen_by": [user["id"]],
    }
    await db.community_posts.insert_one(post)
    return _serialize_post(post, user["id"])


@api.post("/community/posts/{post_id}/like")
async def toggle_like_community_post(post_id: str, user=Depends(get_current_user)):
    post = await db.community_posts.find_one({"id": post_id}, {"_id": 0})
    if not post:
        raise HTTPException(404, "Post not found")
    likes = post.get("likes") or []
    if user["id"] in likes:
        await db.community_posts.update_one({"id": post_id}, {"$pull": {"likes": user["id"]}})
        liked = False
    else:
        await db.community_posts.update_one({"id": post_id}, {"$addToSet": {"likes": user["id"]}})
        liked = True
    post = await db.community_posts.find_one({"id": post_id}, {"_id": 0})
    return _serialize_post(post, user["id"])


@api.post("/community/posts/{post_id}/comments", status_code=201)
async def add_community_comment(post_id: str, body: CommunityCommentIn, user=Depends(get_current_user)):
    comment = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "user_name": user["full_name"],
        "body": body.body,
        "created_at": iso(now_utc()),
    }
    r = await db.community_posts.update_one({"id": post_id}, {"$push": {"comments": comment}})
    if r.matched_count == 0:
        raise HTTPException(404, "Post not found")
    post = await db.community_posts.find_one({"id": post_id}, {"_id": 0})
    return _serialize_post(post, user["id"])


@api.delete("/admin/community/posts/{post_id}")
async def admin_delete_community_post(post_id: str, admin=Depends(require_admin)):
    post = await db.community_posts.find_one_and_delete({"id": post_id})
    if not post:
        raise HTTPException(404, "Post not found")
    await asyncio.gather(*[
        _delete_attachment_if_unreferenced(item.get("url", ""))
        for item in post.get("attachments") or []
    ])
    return {"deleted": True}


@api.delete("/community/posts/{post_id}")
async def delete_own_community_post(post_id: str, user=Depends(get_current_user)):
    q = {"id": post_id}
    if user["role"] == "admin":
        enforce_manager_permission(user, "announcements.manage")
    else:
        q["author_id"] = user["id"]
    post = await db.community_posts.find_one_and_delete(q)
    if not post:
        raise HTTPException(404, "Post not found or not authorized")
    await asyncio.gather(*[
        _delete_attachment_if_unreferenced(item.get("url", ""))
        for item in post.get("attachments") or []
    ])
    return {"deleted": True}


@api.put("/community/posts/{post_id}")
async def edit_own_community_post(post_id: str, body: CommunityEditIn, user=Depends(get_current_user)):
    q = {"id": post_id}
    if user["role"] == "admin":
        enforce_manager_permission(user, "announcements.manage")
    else:
        q["author_id"] = user["id"]
    existing = await db.community_posts.find_one(q)
    if not existing:
        raise HTTPException(404, "Post not found or not authorized")
    existing_urls = {item.get("url") for item in existing.get("attachments") or [] if item.get("url")}
    attachments = await _validate_post_attachments(body.attachments, user["id"], existing_urls)
    await db.community_posts.update_one(
        {"id": post_id},
        {"$set": {"body": body.body, "attachments": attachments, "updated_at": iso(now_utc())}}
    )
    retained_urls = {item.get("url") for item in attachments}
    await asyncio.gather(*[
        _delete_attachment_if_unreferenced(url) for url in existing_urls - retained_urls
    ])
    post = await db.community_posts.find_one({"id": post_id}, {"_id": 0})
    return _serialize_post(post, user["id"])


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Control-Panel-Key", "Idempotency-Key"],
)
