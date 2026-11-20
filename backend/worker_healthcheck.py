import asyncio
import os
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorClient


async def main() -> None:
    client = AsyncIOMotorClient(os.environ["MONGO_URL"], serverSelectionTimeoutMS=3000)
    row = await client[os.environ["DB_NAME"]].worker_health.find_one({"worker": "notifications"})
    client.close()
    if not row or datetime.fromisoformat(row["heartbeat_at"]) < datetime.now(timezone.utc) - timedelta(seconds=60):
        raise SystemExit(1)


asyncio.run(main())
