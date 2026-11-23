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
from pymongo import MongoClient

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
ADMIN_RECOVERY_CODE = ""
ADMIN_SOS_RECOVERY_CODE = ""
SECOND_GUARD_EMAIL = ""
SECOND_GUARD_PASSWORD = ""
SWAP_SHIFT_ID = ""
BOOTSTRAP_DISPOSABLE = os.environ.get("DISPTCHR_E2E_BOOTSTRAP") == "1"
CONTROL_KEY = os.environ.get("CONTROL_PANEL_API_KEY", "")
E2E_ORIGIN = os.environ.get("DISPTCHR_E2E_ORIGIN", "http://127.0.0.1:5050")


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
    if BOOTSTRAP_DISPOSABLE:
        s.headers.update({"Origin": E2E_ORIGIN})
    yield s
    s.close()


def expect(response, status_code):
    assert response.status_code == status_code, f"{response.request.method} {response.request.url}: {response.status_code} {response.text}"
    return response.json() if response.content else None


@pytest.fixture(scope="session", autouse=True)
def bootstrap_disposable_environment(session):
    """Create a complete disposable company dataset through public application APIs only."""
    if not BOOTSTRAP_DISPOSABLE:
        yield
        return

    database_name = os.environ.get("DB_NAME", "")
    mongo_url = os.environ.get("MONGO_URL", "")
    assert database_name.startswith("disptchr_e2e_"), "Disposable E2E database must use the disptchr_e2e_ prefix"
    assert mongo_url, "Disposable E2E bootstrap requires MONGO_URL"
    cleanup_client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
    database = cleanup_client[database_name]
    non_empty_collections = [
        name for name in database.list_collection_names()
        if database[name].count_documents({}, limit=1)
    ]
    assert not non_empty_collections, (
        f"Disposable E2E database must start empty; data exists in {', '.join(non_empty_collections)}"
    )

    global GUARD_EMAIL, GUARD_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_MFA_SECRET
    global ADMIN_RECOVERY_CODE, ADMIN_SOS_RECOVERY_CODE, SECOND_GUARD_EMAIL, SECOND_GUARD_PASSWORD, SWAP_SHIFT_ID
    assert BASE_URL and CONTROL_KEY, "Disposable E2E bootstrap requires its API URL and control key"
    GUARD_EMAIL = "guard.e2e@skyhawksecurity.ca"
    GUARD_PASSWORD = "Guard-E2E-password-2026"
    ADMIN_EMAIL = "manager.e2e@skyhawksecurity.ca"
    ADMIN_PASSWORD = "Manager-E2E-password-2026"
    SECOND_GUARD_EMAIL = "guard.cover.e2e@skyhawksecurity.ca"
    SECOND_GUARD_PASSWORD = "Guard-Cover-E2E-password-2026"

    control_headers = {
        "x-disptchr-control-key": CONTROL_KEY,
        "x-disptchr-actor-id": "github-e2e",
        "x-disptchr-actor-name": "Disposable E2E Bootstrap",
    }
    permission_catalog = expect(session.get(f"{BASE_URL}/api/control/managers", headers=control_headers), 200)["permission_catalog"]
    manager = expect(session.post(
        f"{BASE_URL}/api/control/managers",
        headers=control_headers,
        json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
            "full_name": "E2E Manager",
            "status": "active",
            "permissions": [item["key"] for item in permission_catalog],
        },
    ), 201)
    ADMIN_MFA_SECRET = manager["mfa_setup"]["secret"]
    ADMIN_RECOVERY_CODE = manager["mfa_setup"]["recovery_codes"][1]
    ADMIN_SOS_RECOVERY_CODE = manager["mfa_setup"]["recovery_codes"][2]

    # Use a one-time recovery code for setup so the TOTP remains unused for the login test.
    expect(session.post(
        f"{BASE_URL}/api/auth/manager-login",
        json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
            "mfa_code": manager["mfa_setup"]["recovery_codes"][0],
        },
    ), 200)

    expiry = (datetime.now(timezone.utc) + timedelta(days=365)).date().isoformat()
    guard = expect(session.post(
        f"{BASE_URL}/api/admin/guards",
        json={
            "email": GUARD_EMAIL,
            "password": GUARD_PASSWORD,
            "full_name": "E2E Guard",
            "phone": "+14165550100",
            "employee_number": "E2E-GUARD-001",
            "licence_number": "E2E-LIC-001",
            "licence_expiry": expiry,
            "certifications": ["First Aid"],
        },
    ), 201)

    expect(session.post(
        f"{BASE_URL}/api/admin/guards",
        json={
            "email": SECOND_GUARD_EMAIL,
            "password": SECOND_GUARD_PASSWORD,
            "full_name": "E2E Cover Guard",
            "phone": "+14165550102",
            "employee_number": "E2E-GUARD-002",
            "licence_number": "E2E-LIC-002",
            "licence_expiry": expiry,
            "certifications": ["First Aid"],
        },
    ), 201)
    site = expect(session.post(
        f"{BASE_URL}/api/admin/sites",
        json={
            "name": "E2E Test Site",
            "address": "100 Test Street, Toronto, ON",
            "latitude": 43.6467,
            "longitude": -79.3785,
            "supervisor": "E2E Supervisor",
            "supervisor_phone": "+14165550101",
            "instructions": "Disposable automated test assignment.",
            "geofence_radius_m": 200,
        },
    ), 201)

    now = datetime.now(timezone.utc)
    expect(session.post(
        f"{BASE_URL}/api/admin/shifts",
        json={
            "user_id": guard["id"],
            "site_id": site["id"],
            "start": (now - timedelta(minutes=30)).isoformat(),
            "end": (now + timedelta(hours=7, minutes=30)).isoformat(),
            "role": "Security Guard",
            "pay_rate": 25.0,
        },
    ), 201)
    swap_shift = expect(session.post(
        f"{BASE_URL}/api/admin/shifts",
        json={
            "user_id": guard["id"],
            "site_id": site["id"],
            "start": (now + timedelta(days=2)).isoformat(),
            "end": (now + timedelta(days=2, hours=8)).isoformat(),
            "role": "Swap Coverage",
            "pay_rate": 25.0,
        },
    ), 201)
    SWAP_SHIFT_ID = swap_shift["id"]
    expect(session.post(
        f"{BASE_URL}/api/admin/open-shifts",
        json={
            "site_id": site["id"],
            "start": (now + timedelta(days=1)).isoformat(),
            "end": (now + timedelta(days=1, hours=8)).isoformat(),
            "role": "Patrol",
            "pay_rate": 26.0,
            "spots_available": 1,
        },
    ), 201)
    expect(session.post(
        f"{BASE_URL}/api/admin/announcements",
        json={"title": "E2E Announcement", "body": "Disposable automated announcement.", "severity": "info"},
    ), 201)
    expect(session.post(
        f"{BASE_URL}/api/admin/payroll",
        json={
            "user_id": guard["id"],
            "period_start": (now - timedelta(days=14)).date().isoformat(),
            "period_end": now.date().isoformat(),
            "pay_date": (now + timedelta(days=2)).date().isoformat(),
            "hours_worked": 40,
            "hourly_rate": 25,
            "status": "submitted",
        },
    ), 201)

    # Do not leak the manager's secure session cookie into guard or anonymous tests.
    session.cookies.clear()
    guard_login = expect(session.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": GUARD_EMAIL, "password": GUARD_PASSWORD},
    ), 200)
    expect(session.post(
        f"{BASE_URL}/api/wallet/documents",
        headers={"Authorization": f"Bearer {guard_login['access_token']}"},
        json={"type": "security_licence", "name": "Ontario Security Licence", "number": "E2E-LIC-001", "expiry": expiry},
    ), 201)

    yield
    cleanup_client.drop_database(database_name)
    cleanup_client.close()


@pytest.fixture(scope="session")
def guard_token(session, bootstrap_disposable_environment):
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
        try:
            r = session.post(f"{BASE_URL}/api/auth/manager-login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "mfa_code": current_mfa_code()})
            assert r.status_code == 200
            assert r.json()["user"]["role"] == "admin"
            assert "access_token" not in r.json()
        finally:
            session.cookies.clear()

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


# ---- shift swaps ----
class TestShiftSwaps:
    def test_request_volunteer_and_manager_approval(self, session, guard_headers):
        created = expect(session.post(
            f"{BASE_URL}/api/shifts/{SWAP_SHIFT_ID}/request-swap",
            headers=guard_headers,
            json={"reason": "Disposable end-to-end coverage request."},
        ), 201)
        assert created["status"] == "open"
        assert created["reason"] == "Disposable end-to-end coverage request."

        duplicate = session.post(
            f"{BASE_URL}/api/shifts/{SWAP_SHIFT_ID}/request-swap",
            headers=guard_headers,
            json={"reason": "Duplicate request must be rejected."},
        )
        assert duplicate.status_code == 400

        own = expect(session.get(f"{BASE_URL}/api/shift-swaps", headers=guard_headers), 200)
        assert any(item["id"] == created["id"] and item["status"] == "open" for item in own["own"])

        covering_guard = expect(session.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": SECOND_GUARD_EMAIL, "password": SECOND_GUARD_PASSWORD},
        ), 200)
        covering_headers = {"Authorization": f"Bearer {covering_guard['access_token']}"}
        marketplace = expect(session.get(f"{BASE_URL}/api/shift-swaps", headers=covering_headers), 200)
        assert any(item["id"] == created["id"] for item in marketplace["marketplace"])
        expect(session.post(
            f"{BASE_URL}/api/shift-swaps/{created['id']}/volunteer",
            headers=covering_headers,
        ), 200)

        manager_headers = {"Content-Type": "application/json", "Origin": E2E_ORIGIN}
        with httpx.Client(timeout=20.0, headers=manager_headers) as manager_session:
            expect(manager_session.post(
                f"{BASE_URL}/api/auth/manager-login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "mfa_code": ADMIN_RECOVERY_CODE},
            ), 200)
            awaiting = expect(manager_session.get(f"{BASE_URL}/api/admin/shift-swaps?status=accepted"), 200)
            assert any(item["id"] == created["id"] for item in awaiting["swaps"])
            expect(manager_session.post(
                f"{BASE_URL}/api/admin/shift-swaps/{created['id']}/decision",
                json={"action": "approve", "reason": "Coverage verified by the E2E manager."},
            ), 200)
            approved = expect(manager_session.get(f"{BASE_URL}/api/admin/shift-swaps?status=approved"), 200)
            completed = next(item for item in approved["swaps"] if item["id"] == created["id"])
            assert completed["manager_note"] == "Coverage verified by the E2E manager."

        expect(session.get(f"{BASE_URL}/api/shifts/{SWAP_SHIFT_ID}", headers=covering_headers), 200)
        assert session.get(f"{BASE_URL}/api/shifts/{SWAP_SHIFT_ID}", headers=guard_headers).status_code == 404


# ---- emergency SOS ----
class TestSos:
    def test_location_optional_manager_acknowledgement_and_resolution(self, session, guard_headers):
        partial_location = session.post(
            f"{BASE_URL}/api/sos",
            headers=guard_headers,
            json={"latitude": 43.65, "message": "This incomplete location must be rejected."},
        )
        assert partial_location.status_code == 422

        created = expect(session.post(
            f"{BASE_URL}/api/sos",
            headers=guard_headers,
            json={"message": "Disposable end-to-end emergency alert."},
        ), 201)
        assert created["status"] == "active"
        assert created["location_available"] is False
        assert created["latitude"] is None
        assert created["longitude"] is None

        manager_headers = {"Content-Type": "application/json", "Origin": E2E_ORIGIN}
        with httpx.Client(timeout=20.0, headers=manager_headers) as manager_session:
            expect(manager_session.post(
                f"{BASE_URL}/api/auth/manager-login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "mfa_code": ADMIN_SOS_RECOVERY_CODE},
            ), 200)
            active = expect(manager_session.get(f"{BASE_URL}/api/sos/active"), 200)
            current = next(item for item in active["alerts"] if item["id"] == created["id"])
            assert current["created_at"]
            assert current["status"] == "active"

            expect(manager_session.post(f"{BASE_URL}/api/sos/{created['id']}/acknowledge"), 200)
            acknowledged = expect(manager_session.get(f"{BASE_URL}/api/sos/active"), 200)
            current = next(item for item in acknowledged["alerts"] if item["id"] == created["id"])
            assert current["status"] == "acknowledged"
            assert current["acknowledged_at"]

            expect(manager_session.post(f"{BASE_URL}/api/sos/{created['id']}/resolve"), 200)
            active_after_resolution = expect(manager_session.get(f"{BASE_URL}/api/sos/active"), 200)
            assert all(item["id"] != created["id"] for item in active_after_resolution["alerts"])
            history = expect(manager_session.get(f"{BASE_URL}/api/sos/history"), 200)
            resolved = next(item for item in history["alerts"] if item["id"] == created["id"])
            assert resolved["status"] == "resolved"
            assert resolved["resolved_at"]


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
        assert isinstance(d["equipment"], list)


# ---- compliance ----
class TestCompliance:
    def test_date_only_credential_expiry(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/compliance/status", headers=guard_headers)
        assert r.status_code == 200
        documents = r.json()["documents"]
        assert documents
        assert documents[0]["compliance_status"] in {"valid", "expiring", "expiring_soon", "expired"}
        assert isinstance(documents[0]["days_until_expiry"], int)


# ---- onboarding ----
class TestOnboarding:
    def test_onboarding(self, session, guard_headers):
        r = session.get(f"{BASE_URL}/api/onboarding/status", headers=guard_headers)
        assert r.status_code == 200
        d = r.json()
        assert "percent" in d and 0 <= d["percent"] <= 100
        assert d["total"] == 5
