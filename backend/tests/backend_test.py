"""Skyhawk Ops backend API tests"""
import os
import uuid
import base64
import hashlib
import hmac
import struct
import time
from datetime import datetime, timedelta, timezone
import pytest
import httpx

pytestmark = pytest.mark.skipif(
    os.environ.get("DISPTCHR_E2E_ENABLED") != "1",
    reason="External end-to-end suite requires an explicitly configured disposable environment",
)
BASE_URL = os.environ.get("DISPTCHR_E2E_BASE_URL", "")
GUARD_EMAIL = os.environ.get("DISPTCHR_E2E_GUARD_EMAIL", "")
GUARD_PASSWORD = os.environ.get("DISPTCHR_E2E_GUARD_PASSWORD", "")
ADMIN_EMAIL = os.environ.get("DISPTCHR_E2E_MANAGER_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("DISPTCHR_E2E_MANAGER_PASSWORD", "")
ADMIN_MFA_CODE = os.environ.get("DISPTCHR_E2E_MANAGER_MFA_CODE", "")
ADMIN_MFA_SECRET = os.environ.get("DISPTCHR_E2E_MANAGER_MFA_SECRET", "")


def current_mfa_code():
    if ADMIN_MFA_CODE:
        return ADMIN_MFA_CODE
    if not ADMIN_MFA_SECRET:
        return ""
    normalized = ADMIN_MFA_SECRET.replace(" ", "").upper()
    key = base64.b32decode(normalized + "=" * ((8 - len(normalized) % 8) % 8))
    step = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


@pytest.fixture(scope="session")
def session():
    s = httpx.Client(timeout=20.0, follow_redirects=False)
    s.headers.update({"Content-Type": "application/json"})
    yield s
    s.close()


@pytest.fixture(scope="session")
def guard_token(session):
    r = session.post(f"{BASE_URL}/api/auth/login", json={"email": GUARD_EMAIL, "password": GUARD_PASSWORD})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data and "user" in data
    return data["access_token"]


@pytest.fixture(scope="session")
def guard_headers(guard_token):
    return {"Authorization": f"Bearer {guard_token}", "Content-Type": "application/json"}


# ---- health ----
def test_root(session):
    r = session.get(f"{BASE_URL}/api/")
    assert r.status_code == 200
    assert r.json().get("status") == "online"


# ---- auth ----
class TestAuth:
    def test_login_guard(self, session):
        r = session.post(f"{BASE_URL}/api/auth/login", json={"email": GUARD_EMAIL, "password": GUARD_PASSWORD})
        assert r.status_code == 200
        d = r.json()
        assert d["token_type"] == "bearer"
        assert d["user"]["email"] == GUARD_EMAIL
        assert d["user"]["role"] == "employee"
        assert "hashed_password" not in d["user"]

    def test_login_admin(self, session):
        r = session.post(f"{BASE_URL}/api/auth/manager-login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "mfa_code": current_mfa_code()})
        assert r.status_code == 200
        assert r.json()["user"]["role"] == "admin"
        assert "access_token" not in r.json()

    def test_login_wrong_password(self, session):
        r = session.post(f"{BASE_URL}/api/auth/login", json={"email": GUARD_EMAIL, "password": "wrong"})
        assert r.status_code == 401

    def test_public_registration_is_closed(self, session):
        email = f"TEST_{uuid.uuid4().hex[:8]}@skyhawk.com"
        payload = {"email": email, "password": "A-long-test-password-123", "full_name": "TEST User", "phone": "+1 000"}
        r = session.post(f"{BASE_URL}/api/auth/register", json=payload)
        assert r.status_code == 403, r.text

    def test_me_requires_auth(self, session):
        r = session.get(f"{BASE_URL}/api/auth/me")
        assert r.status_code in (401, 403)

    def test_me_ok(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/auth/me", headers=guard_headers)
        assert r.status_code == 200
        assert r.json()["email"] == GUARD_EMAIL

    def test_dashboard_requires_auth(self, session):
        r = session.get(f"{BASE_URL}/api/dashboard")
        assert r.status_code in (401, 403)


# ---- dashboard ----
class TestDashboard:
    def test_dashboard(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/dashboard", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        for k in ("today_shift", "next_shift", "unread_announcements", "latest_payroll", "emergency_contacts"):
            assert k in d
        assert isinstance(d["unread_announcements"], int)


# ---- schedule ----
class TestSchedule:
    def test_schedule_week(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/schedule?range=week", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert "shifts" in d and isinstance(d["shifts"], list)
        if d["shifts"]:
            s = d["shifts"][0]
            assert "site" in s and s["site"] is not None
            assert "name" in s["site"]

    def test_shift_detail_and_ack(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/schedule?range=week", headers=guard_headers)
        shifts = r.json()["shifts"]
        if not shifts:
            pytest.skip("no shifts to test")
        sid = shifts[0]["id"]
        r = session.get(f"{BASE_URL}/api/shifts/{sid}", headers=guard_headers)
        assert r.status_code == 200
        assert r.json()["id"] == sid
        r2 = session.post(f"{BASE_URL}/api/shifts/{sid}/acknowledge-instructions", headers=guard_headers)
        assert r2.status_code == 200
        assert r2.json()["acknowledged"] is True
        r3 = session.get(f"{BASE_URL}/api/shifts/{sid}", headers=guard_headers)
        assert r3.json()["instructions_acknowledged"] is True

    def test_shift_not_found(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/shifts/does-not-exist", headers=guard_headers)
        assert r.status_code == 404


# ---- open shifts ----
class TestOpenShifts:
    def test_list_and_claim_cycle(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/open-shifts", headers=guard_headers)
        assert r.status_code == 200
        shifts = r.json()["shifts"]
        assert isinstance(shifts, list) and len(shifts) > 0
        assert "already_claimed" in shifts[0] and "on_waitlist" in shifts[0]
        assert "site" in shifts[0]

        # find unclaimed
        target = next((s for s in shifts if not s["already_claimed"] and s["spots_available"] > len(s.get("claimed_by") or [])), None)
        assert target, "no available open shift"
        sid = target["id"]
        r2 = session.post(f"{BASE_URL}/api/open-shifts/{sid}/claim", headers=guard_headers)
        assert r2.status_code == 200
        body = r2.json()
        assert body["status"] in ("claimed", "waitlisted")
        # verify appears in schedule as claimed_from_open
        r3 = session.get(f"{BASE_URL}/api/my-claims", headers=guard_headers)
        assert r3.status_code == 200
        # duplicate claim should fail
        r4 = session.post(f"{BASE_URL}/api/open-shifts/{sid}/claim", headers=guard_headers)
        assert r4.status_code == 400 or r4.json().get("status") == "waitlisted"
        # cancel claim
        r5 = session.post(f"{BASE_URL}/api/open-shifts/{sid}/cancel-claim", headers=guard_headers)
        assert r5.status_code == 200
        assert r5.json()["status"] == "cancelled"


# ---- time clock ----
class TestTimeClock:
    def test_full_clock_cycle(self, session, guard_headers):
        # Ensure clean state
        r = session.get(f"{BASE_URL}/api/timeclock/status", headers=guard_headers)
        assert r.status_code == 200
        if r.json().get("active"):
            session.post(f"{BASE_URL}/api/timeclock/clock-out",
                         headers=guard_headers,
                         json={"latitude": 43.6467, "longitude": -79.3785})

        schedule = session.get(f"{BASE_URL}/api/schedule?range=week", headers=guard_headers)
        assert schedule.status_code == 200
        now = datetime.now(timezone.utc)
        eligible = next((shift for shift in schedule.json()["shifts"]
                         if shift.get("status") == "scheduled" and shift.get("site")
                         and datetime.fromisoformat(shift["start"].replace("Z", "+00:00")) - timedelta(hours=2) <= now
                         <= datetime.fromisoformat(shift["end"].replace("Z", "+00:00")) + timedelta(hours=4)), None)
        if not eligible:
            pytest.skip("disposable environment has no currently clockable assigned shift")
        latitude = eligible["site"]["latitude"]
        longitude = eligible["site"]["longitude"]
        selfie = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100).decode()

        # Clock in at the assigned site's configured geofence.
        r1 = session.post(f"{BASE_URL}/api/timeclock/clock-in",
                          headers=guard_headers,
                          json={"shift_id": eligible["id"], "latitude": latitude, "longitude": longitude,
                                "selfie_base64": selfie})
        assert r1.status_code == 200, r1.text
        d = r1.json()
        assert d["entry"]["clock_in"] is not None
        # duplicate clock-in
        r_dup = session.post(f"{BASE_URL}/api/timeclock/clock-in",
                             headers=guard_headers,
                             json={"shift_id": eligible["id"], "latitude": latitude, "longitude": longitude,
                                   "selfie_base64": selfie})
        assert r_dup.status_code == 400

        # Break start/end
        rb = session.post(f"{BASE_URL}/api/timeclock/break", headers=guard_headers, json={"action": "start"})
        assert rb.status_code == 200
        assert len(rb.json()["breaks"]) >= 1
        rb2 = session.post(f"{BASE_URL}/api/timeclock/break", headers=guard_headers, json={"action": "end"})
        assert rb2.status_code == 200
        assert rb2.json()["breaks"][-1]["end"] is not None

        # Status shows active
        rs = session.get(f"{BASE_URL}/api/timeclock/status", headers=guard_headers)
        assert rs.json()["active"] is not None

        # Clock out
        ro = session.post(f"{BASE_URL}/api/timeclock/clock-out",
                          headers=guard_headers,
                          json={"latitude": latitude, "longitude": longitude, "selfie_base64": selfie})
        assert ro.status_code == 200
        assert "hours_worked" in ro.json()

        # Not clocked in error
        r_err = session.post(f"{BASE_URL}/api/timeclock/clock-out",
                             headers=guard_headers,
                             json={"latitude": 43.6, "longitude": -79.3})
        assert r_err.status_code == 400


# ---- wallet ----
class TestWallet:
    def test_wallet(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/wallet", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert "documents" in d and isinstance(d["documents"], list) and len(d["documents"]) > 0
        assert d["employee"]["employee_number"]
        assert d["qr_payload"].count(".") == 2
        assert d["qr_expires_in_seconds"] == 300


# ---- announcements ----
class TestAnnouncements:
    def test_list_and_ack(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/announcements", headers=guard_headers)
        assert r.status_code == 200
        items = r.json()["announcements"]
        assert isinstance(items, list) and len(items) > 0
        assert "read" in items[0] and "read_count" in items[0]

        unread = next((a for a in items if not a["read"]), None)
        if unread:
            aid = unread["id"]
            r2 = session.post(f"{BASE_URL}/api/announcements/{aid}/acknowledge", headers=guard_headers)
            assert r2.status_code == 200
            r3 = session.get(f"{BASE_URL}/api/announcements", headers=guard_headers)
            match = next(a for a in r3.json()["announcements"] if a["id"] == aid)
            assert match["read"] is True

    def test_ack_missing(self, session, guard_headers):
        r = session.post(f"{BASE_URL}/api/announcements/does-not-exist/acknowledge", headers=guard_headers)
        assert r.status_code == 404


# ---- incidents ----
class TestIncidents:
    def test_create_and_list(self, session, guard_headers):
        payload = {
            "type": "incident",
            "description": "TEST_incident description",
            "severity": "low",
            "photos": ["iVBORw0K"],
            "signature_base64": "abc",
        }
        r = session.post(f"{BASE_URL}/api/incidents", headers=guard_headers, json=payload)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "submitted"
        # photos + signature must not be in response
        assert "photos" not in d
        assert "signature_base64" not in d

        r2 = session.get(f"{BASE_URL}/api/incidents", headers=guard_headers)
        assert r2.status_code == 200
        items = r2.json()["incidents"]
        found = next((i for i in items if i["id"] == d["id"]), None)
        assert found is not None
        assert "photos" not in found and "signature_base64" not in found


# ---- payroll ----
class TestPayroll:
    def test_payroll(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/payroll", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert isinstance(d["periods"], list) and len(d["periods"]) > 0
        assert d["current"] is not None
        stages = {p["status"] for p in d["periods"]}
        assert stages.issubset({"submitted", "under_review", "released", "paid"})
        assert isinstance(d["total_hours"], (int, float))
        assert isinstance(d["total_gross"], (int, float))


# ---- profile ----
class TestProfile:
    def test_profile(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/profile", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert d["user"]["email"] == GUARD_EMAIL
        assert isinstance(d["equipment"], list) and len(d["equipment"]) > 0


# ---- onboarding ----
class TestOnboarding:
    def test_onboarding(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/onboarding/status", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert "percent" in d and 0 <= d["percent"] <= 100
        assert d["total"] == 6
