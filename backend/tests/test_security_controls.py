import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest
from fastapi import HTTPException
from fastapi import Response
from starlette.requests import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server


def request(path="/api/auth/register"):
    return Request({"type": "http", "method": "POST", "path": path, "headers": [], "client": ("127.0.0.1", 1234)})


def test_public_guard_registration_is_closed_by_default(monkeypatch):
    monkeypatch.setattr(server, "ALLOW_PUBLIC_REGISTRATION", False)
    body = server.RegisterIn(email="guard@example.com", password="long-enough-password", full_name="Test Guard")
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.register(request(), body))
    assert error.value.status_code == 403


def test_private_values_are_encrypted_with_randomized_ciphertext():
    first = server.encrypt_private_value("123456789")
    second = server.encrypt_private_value("123456789")
    assert first != second
    assert "123456789" not in first


def test_password_hashing_supports_long_unicode_and_legacy_bcrypt_hashes():
    password = "Correct horse battery staple — sécurité — " * 4
    hashed = server.hash_password(password)
    assert hashed.startswith("bcrypt-sha256$")
    assert server.verify_password(password, hashed) is True
    assert server.verify_password(password + "x", hashed) is False
    legacy = server.bcrypt.hashpw(b"legacy-password", server.bcrypt.gensalt()).decode()
    assert server.verify_password("legacy-password", legacy) is True


def test_date_only_credential_expiry_is_normalized_to_utc():
    future = (datetime.now(timezone.utc) + timedelta(days=90)).date().isoformat()
    parsed = server.parse_datetime_utc(future)
    assert parsed.tzinfo == timezone.utc
    assert server._compliance_status(future) == "valid"


def test_manager_totp_matches_rfc_vector_and_sensitive_fields_are_removed():
    assert server._totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1) == "287082"
    safe = server.safe_user_document({
        "id": "manager-1", "email": "manager@example.com", "hashed_password": "hash",
        "mfa_secret_encrypted": "ciphertext", "mfa_recovery_hashes": ["digest"],
        "sin_encrypted": "ciphertext", "full_name": "Manager",
    })
    assert safe == {"id": "manager-1", "email": "manager@example.com", "full_name": "Manager"}


class UpdateResult:
    modified_count = 1


class MfaUsers:
    async def update_one(self, query, update):
        self.query = query
        self.update = update
        return UpdateResult()


class MfaDatabase:
    def __init__(self):
        self.users = MfaUsers()


def test_manager_mfa_setup_is_encrypted_and_code_is_verified(monkeypatch):
    stored, setup = server._manager_mfa_setup("manager@example.com")
    assert setup["secret"] not in stored["mfa_secret_encrypted"]
    fixed_time = 1_700_000_000
    code = server._totp_code(setup["secret"], fixed_time // 30)
    database = MfaDatabase()
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server.time, "time", lambda: fixed_time)
    user = {"id": "manager-1", **stored}
    assert asyncio.run(server.verify_manager_mfa(user, code)) is True
    assert database.users.update["$set"]["mfa_last_step"] == fixed_time // 30


def test_timeclock_selfie_must_be_a_real_supported_image():
    assert server.valid_selfie_base64("/9j/" + "AA" * 60) is True
    assert server.valid_selfie_base64("aVZCT1J3MEs=" ) is False
    assert server.valid_selfie_base64("not-base64") is False


@pytest.mark.parametrize("category,filename", [
    ("../attachments", "file.pdf"),
    ("attachments", "../file.pdf"),
    ("unknown", "file.pdf"),
])
def test_file_path_validation_rejects_traversal(category, filename):
    with pytest.raises(HTTPException) as error:
        server._validated_file_path(category, filename)
    assert error.value.status_code == 404


def test_payroll_preferences_are_permission_protected():
    assert server.required_manager_permission("/api/admin/preferences/payroll") == "payroll.manage"


def test_sensitive_fields_are_excluded_from_user_queries():
    assert server.SENSITIVE_USER_PROJECTION["sin"] == 0
    assert server.SENSITIVE_USER_PROJECTION["sin_encrypted"] == 0
    assert server.SENSITIVE_USER_PROJECTION["direct_deposit"] == 0
    assert server.SENSITIVE_USER_PROJECTION["direct_deposit_encrypted"] == 0


class RefreshTokenCollection:
    def __init__(self, current=None):
        self.current = current
        self.inserted = []
        self.deleted_families = []

    async def find_one_and_update(self, query, update, return_document=None):
        if self.current and query.get("token_digest") == self.current.get("token_digest") and not self.current.get("used_at"):
            value = dict(self.current)
            self.current.update(update["$set"])
            return value
        return None

    async def find_one(self, query):
        return dict(self.current) if self.current and query.get("token_digest") == self.current.get("token_digest") else None

    async def insert_one(self, document):
        self.inserted.append(document)

    async def delete_many(self, query):
        self.deleted_families.append(query)


class UserCollection:
    def __init__(self, user):
        self.user = user

    async def find_one(self, query, projection=None):
        return dict(self.user) if self.user and query.get("id") == self.user.get("id") else None


class RefreshDatabase:
    def __init__(self, token, user):
        self.refresh_tokens = RefreshTokenCollection(token)
        self.users = UserCollection(user)


def test_refresh_token_is_rotated_and_returns_short_lived_access_token(monkeypatch):
    raw = "r" * 48
    current = {
        "user_id": "guard-1", "family_id": "family-1",
        "token_digest": server.refresh_token_digest(raw),
        "expires_at": server.now_utc() + timedelta(days=1),
    }
    database = RefreshDatabase(current, {
        "id": "guard-1", "email": "guard@example.com", "role": "employee",
        "access_status": "active", "full_name": "Guard One",
    })
    monkeypatch.setattr(server, "db", database)
    result = asyncio.run(server.refresh_access_token(
        request("/api/auth/refresh"), server.RefreshTokenIn(refresh_token=raw),
    ))
    assert result["refresh_token"] != raw
    assert len(database.refresh_tokens.inserted) == 1
    payload = server.jwt.decode(result["access_token"], server.JWT_SECRET, algorithms=[server.JWT_ALGORITHM])
    assert payload["sub"] == "guard-1"
    assert payload["typ"] == "access"


def test_refresh_token_reuse_is_rejected(monkeypatch):
    raw = "x" * 48
    current = {
        "user_id": "guard-1", "family_id": "family-compromised",
        "token_digest": server.refresh_token_digest(raw), "used_at": server.now_utc(),
        "expires_at": server.now_utc() + timedelta(days=1),
    }
    database = RefreshDatabase(current, None)
    monkeypatch.setattr(server, "db", database)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.refresh_access_token(
            request("/api/auth/refresh"), server.RefreshTokenIn(refresh_token=raw),
        ))
    assert error.value.status_code == 401
    assert {"family_id": "family-compromised"} in database.refresh_tokens.deleted_families


class ManagerSessionUsers:
    async def find_one(self, query, projection=None):
        return {
            "id": "manager-1", "email": "manager@example.com", "role": "admin",
            "access_status": "active", "manager_permissions": ["dashboard.view"],
        }


class ManagerSessions:
    def __init__(self, active=True):
        self.active = active

    async def find_one(self, query, projection=None):
        return {"id": query["id"]} if self.active else None


class ManagerSessionDatabase:
    def __init__(self, active=True):
        self.users = ManagerSessionUsers()
        self.manager_sessions = ManagerSessions(active)


def test_manager_access_token_requires_active_database_session(monkeypatch):
    monkeypatch.setattr(server, "db", ManagerSessionDatabase())
    legacy_token = server.create_access_token("manager-1", "manager@example.com", "admin")
    with pytest.raises(HTTPException, match="session is invalid"):
        asyncio.run(server._user_from_access_token(legacy_token))

    token = server.create_access_token(
        "manager-1", "manager@example.com", "admin", session_id="session-1",
    )
    user = asyncio.run(server._user_from_access_token(token))
    assert user["id"] == "manager-1"

    monkeypatch.setattr(server, "db", ManagerSessionDatabase(active=False))
    with pytest.raises(HTTPException, match="expired or was revoked"):
        asyncio.run(server._user_from_access_token(token))


class ManagerLoginUsers:
    async def find_one(self, query, projection=None):
        return {
            "id": "manager-1", "email": "manager@example.com", "role": "admin",
            "access_status": "active", "hashed_password": "stored",
            "manager_permissions": ["dashboard.view"], "full_name": "Manager One",
        }


class InsertedCollection:
    def __init__(self):
        self.documents = []

    async def insert_one(self, document):
        self.documents.append(document)


class ManagerLoginDatabase:
    def __init__(self):
        self.users = ManagerLoginUsers()
        self.manager_sessions = InsertedCollection()


def test_manager_login_returns_only_user_and_sets_revocable_http_only_cookie(monkeypatch):
    database = ManagerLoginDatabase()
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server, "verify_password", lambda supplied, stored: True)

    async def accept_mfa(user, code):
        return True

    monkeypatch.setattr(server, "verify_manager_mfa", accept_mfa)
    response = Response()
    result = asyncio.run(server.manager_login(
        request("/api/auth/manager-login"),
        response,
        server.LoginIn(email="manager@example.com", password="a" * 12, mfa_code="123456"),
    ))
    assert set(result) == {"user"}
    assert "access_token" not in result
    assert len(database.manager_sessions.documents) == 1
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "disptchr_session=" in response.headers["set-cookie"]


def test_native_login_never_returns_manager_bearer_token(monkeypatch):
    monkeypatch.setattr(server, "db", ManagerLoginDatabase())
    monkeypatch.setattr(server, "verify_password", lambda supplied, stored: True)
    with pytest.raises(HTTPException, match="Manager Portal") as error:
        asyncio.run(server.login(
            request("/api/auth/login"),
            Response(),
            server.LoginIn(email="manager@example.com", password="a" * 12),
        ))
    assert error.value.status_code == 403
