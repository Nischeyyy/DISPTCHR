"""DISPTCHR durable notification worker with retries and dead-letter state."""
import asyncio
import logging
import os
import signal
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument

import notifications as notif

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("disptchr.worker")
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
EXPO_ACCESS_TOKEN = os.environ.get("EXPO_ACCESS_TOKEN", "")
MAX_ATTEMPTS = 8


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


async def deliver(job: dict, push_client: httpx.AsyncClient, db=None) -> None:
    payload = job["payload"]
    if job["kind"] == "email":
        if not await notif.send_email(payload["to"], payload["subject"], payload["html"], payload.get("text")):
            raise RuntimeError("Email provider unavailable or rejected message")
    elif job["kind"] == "sms":
        if not await notif.send_sms(payload["to"], payload["body"]):
            raise RuntimeError("SMS provider unavailable or rejected message")
    elif job["kind"] == "push":
        if db is None:
            raise RuntimeError("Push delivery requires the database")
        registrations = await db.push_tokens.find(
            {"user_id": {"$in": payload.get("recipients", [])}},
            {"_id": 0, "device_token": 1},
        ).to_list(1000)
        tokens = list(dict.fromkeys(item["device_token"] for item in registrations if item.get("device_token")))
        if not tokens:
            return
        data = payload["data"]
        messages = [{
            "to": token,
            "sound": "default",
            "title": data["title"],
            "body": data["message"],
            "data": {key: value for key, value in data.items() if key not in {"title", "message"}},
        } for token in tokens]
        failures = []
        for offset in range(0, len(messages), 100):
            batch = messages[offset:offset + 100]
            batch_tokens = tokens[offset:offset + 100]
            response = await push_client.post("/--/api/v2/push/send", json=batch)
            response.raise_for_status()
            tickets = response.json().get("data", [])
            if len(tickets) != len(batch):
                raise RuntimeError("Expo returned an incomplete push ticket response")
            for token, ticket in zip(batch_tokens, tickets):
                if ticket.get("status") != "error":
                    continue
                if ticket.get("details", {}).get("error") == "DeviceNotRegistered":
                    await db.push_tokens.delete_many({"device_token": token})
                else:
                    failures.append(ticket.get("message", "Expo rejected push notification"))
        if failures:
            raise RuntimeError("; ".join(failures[:5]))
    else:
        raise RuntimeError(f"Unsupported job kind: {job['kind']}")


async def run() -> None:
    client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5_000, retryWrites=True)
    db = client[DB_NAME]
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    headers = {"Authorization": f"Bearer {EXPO_ACCESS_TOKEN}"} if EXPO_ACCESS_TOKEN else {}
    async with httpx.AsyncClient(base_url="https://exp.host", headers=headers, timeout=15.0) as push_client:
        logger.info("Notification worker started")
        next_heartbeat = datetime.min.replace(tzinfo=timezone.utc)
        while not stop.is_set():
            now = datetime.now(timezone.utc)
            if now >= next_heartbeat:
                await db.worker_health.update_one({"worker": "notifications"}, {"$set": {
                    "worker": "notifications", "heartbeat_at": iso(now), "process_id": os.getpid()
                }}, upsert=True)
                next_heartbeat = now + timedelta(seconds=20)
            job = await db.notification_jobs.find_one_and_update(
                {"$or": [
                    {"status": "queued", "available_at": {"$lte": iso(now)}},
                    {"status": "processing", "leased_until": {"$lte": iso(now)}},
                ]},
                {"$set": {"status": "processing", "leased_until": iso(now + timedelta(minutes=5)), "updated_at": iso(now)}},
                sort=[("available_at", 1), ("created_at", 1)],
                return_document=ReturnDocument.AFTER,
            )
            if not job:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
                continue
            try:
                await deliver(job, push_client, db)
                await db.notification_jobs.update_one({"_id": job["_id"]}, {"$set": {
                    "status": "completed", "completed_at": iso(datetime.now(timezone.utc)),
                    "updated_at": iso(datetime.now(timezone.utc)),
                    "purge_at": datetime.now(timezone.utc) + timedelta(days=30),
                }, "$unset": {"payload": "", "leased_until": ""}})
            except Exception as exc:
                attempts = int(job.get("attempts", 0)) + 1
                dead = attempts >= MAX_ATTEMPTS
                delay = min(3600, 2 ** attempts * 15)
                await db.notification_jobs.update_one({"_id": job["_id"]}, {"$set": {
                    "status": "dead" if dead else "queued", "attempts": attempts,
                    "available_at": iso(datetime.now(timezone.utc) + timedelta(seconds=delay)),
                    "last_error": str(exc)[:500], "updated_at": iso(datetime.now(timezone.utc)),
                    **({"purge_at": datetime.now(timezone.utc) + timedelta(days=90)} if dead else {}),
                }, "$unset": {"leased_until": ""}})
                logger.warning("Job %s failed on attempt %s", job.get("id"), attempts)
    client.close()


if __name__ == "__main__":
    asyncio.run(run())
