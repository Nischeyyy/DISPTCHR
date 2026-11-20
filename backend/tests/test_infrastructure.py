import asyncio
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import job_worker
import notifications
from jobs import enqueue
from object_storage import ObjectStorage


class InsertCollection:
    def __init__(self):
        self.documents = []

    async def insert_one(self, document):
        self.documents.append(document)


class FakeDatabase:
    def __init__(self):
        self.notification_jobs = InsertCollection()


def test_local_object_storage_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    storage = ObjectStorage(tmp_path, production=False)
    asyncio.run(storage.put("attachments/record.pdf", b"%PDF-test", "application/pdf"))
    assert asyncio.run(storage.exists("attachments/record.pdf")) is True
    content, content_type = asyncio.run(storage.get("attachments/record.pdf"))
    assert content == b"%PDF-test"
    assert content_type is None
    with pytest.raises(ValueError):
        asyncio.run(storage.get("../outside.txt"))


def test_production_rejects_local_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    with pytest.raises(RuntimeError, match="required in production"):
        ObjectStorage(tmp_path, production=True)


def test_notification_job_is_persisted_without_logging_payload():
    database = FakeDatabase()
    job_id = asyncio.run(enqueue(database, "email", {"to": "guard@example.com", "subject": "Notice"}, "notice:1"))
    document = database.notification_jobs.documents[0]
    assert document["id"] == job_id
    assert document["status"] == "queued"
    assert document["idempotency_key"] == "notice:1"
    assert document["payload"]["to"] == "guard@example.com"


def test_worker_delivers_email(monkeypatch):
    delivered = []

    async def send_email(to, subject, html, text):
        delivered.append((to, subject, html, text))
        return True

    monkeypatch.setattr(job_worker.notif, "send_email", send_email)
    job = {"kind": "email", "payload": {"to": "guard@example.com", "subject": "Notice", "html": "<p>Hi</p>", "text": "Hi"}}
    asyncio.run(job_worker.deliver(job, object()))
    assert delivered == [("guard@example.com", "Notice", "<p>Hi</p>", "Hi")]


def test_worker_rejects_unknown_job_kind():
    with pytest.raises(RuntimeError, match="Unsupported job kind"):
        asyncio.run(job_worker.deliver({"kind": "unknown", "payload": {}}, object()))


class ProviderResponse:
    def __init__(self, status_code=202):
        self.status_code = status_code


class ProviderClient:
    requests = []
    status_code = 202

    def __init__(self, **kwargs):
        self.options = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, **kwargs):
        self.requests.append((url, kwargs, self.options))
        return ProviderResponse(self.status_code)


def test_sendgrid_http_delivery_uses_authenticated_provider_request(monkeypatch):
    ProviderClient.requests = []
    ProviderClient.status_code = 202
    monkeypatch.setattr(notifications, "EMAIL_ENABLED", True)
    monkeypatch.setattr(notifications, "SENDGRID_API_KEY", "test-key")
    monkeypatch.setattr(notifications, "SENDGRID_FROM", "verified@example.invalid")
    monkeypatch.setattr(notifications.httpx, "AsyncClient", ProviderClient)
    delivered = asyncio.run(notifications.send_email(
        "guard@example.invalid", "Shift notice", "<p>Assigned</p>", "Assigned",
    ))
    assert delivered is True
    url, request, options = ProviderClient.requests[0]
    assert url == "https://api.sendgrid.com/v3/mail/send"
    assert request["headers"] == {"Authorization": "Bearer test-key"}
    assert request["json"]["personalizations"][0]["to"][0]["email"] == "guard@example.invalid"
    assert request["json"]["from"]["email"] == "verified@example.invalid"
    assert options["timeout"] == 15.0


def test_twilio_http_delivery_uses_basic_auth_and_form_payload(monkeypatch):
    ProviderClient.requests = []
    ProviderClient.status_code = 201
    monkeypatch.setattr(notifications, "SMS_ENABLED", True)
    monkeypatch.setattr(notifications, "TWILIO_SID", "AC-test")
    monkeypatch.setattr(notifications, "TWILIO_TOKEN", "auth-test")
    monkeypatch.setattr(notifications, "TWILIO_FROM", "+14165550100")
    monkeypatch.setattr(notifications.httpx, "AsyncClient", ProviderClient)
    delivered = asyncio.run(notifications.send_sms("+14165550101", "Shift changed"))
    assert delivered is True
    url, request, _options = ProviderClient.requests[0]
    assert url.endswith("/Accounts/AC-test/Messages.json")
    assert request["auth"] == ("AC-test", "auth-test")
    assert request["data"] == {"Body": "Shift changed", "From": "+14165550100", "To": "+14165550101"}


def test_notification_provider_rejection_is_reported(monkeypatch):
    ProviderClient.requests = []
    ProviderClient.status_code = 429
    monkeypatch.setattr(notifications, "EMAIL_ENABLED", True)
    monkeypatch.setattr(notifications.httpx, "AsyncClient", ProviderClient)
    assert asyncio.run(notifications.send_email("guard@example.invalid", "Notice", "<p>Notice</p>")) is False


class PushCursor:
    async def to_list(self, _limit):
        return [
            {"device_token": "ExponentPushToken[active]"},
            {"device_token": "ExponentPushToken[expired]"},
        ]


class PushTokens:
    def __init__(self):
        self.deleted = []

    def find(self, query, projection):
        assert query == {"user_id": {"$in": ["guard-1"]}}
        return PushCursor()

    async def delete_many(self, query):
        self.deleted.append(query)


class PushDatabase:
    def __init__(self):
        self.push_tokens = PushTokens()


class PushResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"data": [
            {"status": "ok", "id": "ticket-1"},
            {"status": "error", "message": "Device not registered", "details": {"error": "DeviceNotRegistered"}},
        ]}


class PushClient:
    def __init__(self):
        self.requests = []

    async def post(self, path, json):
        self.requests.append((path, json))
        return PushResponse()


def test_worker_sends_expo_push_and_removes_expired_device_token():
    database = PushDatabase()
    client = PushClient()
    job = {"kind": "push", "payload": {
        "recipients": ["guard-1"],
        "data": {"title": "Shift changed", "message": "Your shift moved", "screen": "schedule"},
    }}
    asyncio.run(job_worker.deliver(job, client, database))
    assert client.requests[0][0] == "/--/api/v2/push/send"
    assert client.requests[0][1][0]["to"] == "ExponentPushToken[active]"
    assert client.requests[0][1][0]["data"] == {"screen": "schedule"}
    assert database.push_tokens.deleted == [{"device_token": "ExponentPushToken[expired]"}]
