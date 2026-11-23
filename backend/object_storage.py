"""Private attachment storage with local development and S3-compatible production backends."""
import asyncio
import io
import os
from pathlib import Path
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class ObjectStorage:
    def __init__(self, root: Path, production: bool):
        self.backend = os.environ.get("STORAGE_BACKEND", "local").strip().lower()
        self.root = root
        self.bucket = os.environ.get("S3_BUCKET", "").strip()
        self.region = os.environ.get("S3_REGION", "ca-central-1").strip()
        self.endpoint = os.environ.get("S3_ENDPOINT_URL", "").strip() or None
        if self.backend not in {"local", "s3"}:
            raise RuntimeError("STORAGE_BACKEND must be 'local' or 's3'")
        if production and self.backend != "s3":
            raise RuntimeError("STORAGE_BACKEND=s3 is required in production")
        if self.backend == "s3" and not self.bucket:
            raise RuntimeError("S3_BUCKET is required when STORAGE_BACKEND=s3")
        self.root.mkdir(parents=True, exist_ok=True)
        self._client = None

    def _s3(self):
        if self._client is None:
            self._client = boto3.client(
                "s3",
                region_name=self.region,
                endpoint_url=self.endpoint,
                config=Config(retries={"max_attempts": 5, "mode": "adaptive"}, signature_version="s3v4"),
            )
        return self._client

    def _local_path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("Invalid storage key")
        return path

    async def put(self, key: str, content: bytes, content_type: str) -> None:
        if self.backend == "local":
            path = self._local_path(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(path.write_bytes, content)
            return
        await asyncio.to_thread(
            self._s3().put_object,
            Bucket=self.bucket,
            Key=key,
            Body=io.BytesIO(content),
            ContentType=content_type,
            ServerSideEncryption="AES256",
        )

    async def exists(self, key: str) -> bool:
        if self.backend == "local":
            return self._local_path(key).is_file()
        try:
            await asyncio.to_thread(self._s3().head_object, Bucket=self.bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise

    async def get(self, key: str) -> tuple[bytes, Optional[str]]:
        if self.backend == "local":
            return await asyncio.to_thread(self._local_path(key).read_bytes), None
        response = await asyncio.to_thread(self._s3().get_object, Bucket=self.bucket, Key=key)
        body = await asyncio.to_thread(response["Body"].read)
        return body, response.get("ContentType")

    async def delete(self, key: str) -> None:
        if self.backend == "local":
            path = self._local_path(key)
            await asyncio.to_thread(path.unlink, missing_ok=True)
            return
        await asyncio.to_thread(self._s3().delete_object, Bucket=self.bucket, Key=key)

    async def healthcheck(self) -> None:
        if self.backend == "local":
            self.root.mkdir(parents=True, exist_ok=True)
            return
        await asyncio.to_thread(self._s3().head_bucket, Bucket=self.bucket)
