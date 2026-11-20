"""Durable MongoDB-backed job outbox used by API workers and the background worker."""
import uuid
from datetime import datetime, timezone
from typing import Optional

from pymongo.errors import DuplicateKeyError


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def enqueue(db, kind: str, payload: dict, idempotency_key: Optional[str] = None) -> str:
    job_id = str(uuid.uuid4())
    document = {
        "id": job_id,
        "kind": kind,
        "payload": payload,
        "status": "queued",
        "attempts": 0,
        "available_at": utc_iso(),
        "created_at": utc_iso(),
        "updated_at": utc_iso(),
    }
    if idempotency_key:
        document["idempotency_key"] = idempotency_key
    try:
        await db.notification_jobs.insert_one(document)
    except DuplicateKeyError:
        existing = await db.notification_jobs.find_one({"idempotency_key": idempotency_key}, {"id": 1})
        return existing["id"] if existing else job_id
    return job_id
