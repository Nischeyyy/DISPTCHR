#!/usr/bin/env python3

"""Create persistent local-only DISPTCHR backend settings without exposing values."""

from pathlib import Path
import argparse
import secrets
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / "backend" / ".env"


def read_existing() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_PATH.exists():
        return values

    for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


parser = argparse.ArgumentParser()
parser.add_argument(
    "--mongo-url-stdin",
    action="store_true",
    help="Read a MongoDB connection string from standard input without displaying it.",
)
parser.add_argument(
    "--use-local-mongo",
    action="store_true",
    help="Use the private local MongoDB development service.",
)
args = parser.parse_args()

values = read_existing()
if args.mongo_url_stdin and args.use_local_mongo:
    raise SystemExit("Choose either --mongo-url-stdin or --use-local-mongo, not both.")
if args.mongo_url_stdin:
    mongo_url = sys.stdin.readline().strip()
    if not mongo_url.startswith(("mongodb://", "mongodb+srv://")):
        raise SystemExit("The supplied MongoDB connection string is not valid.")
    values["MONGO_URL"] = mongo_url
if args.use_local_mongo:
    values["MONGO_URL"] = "mongodb://127.0.0.1:27017"
values.setdefault("MONGO_URL", "mongodb://127.0.0.1:27017")
values.setdefault("DB_NAME", "skyhawk_ops_dev")
if not values.get("JWT_SECRET"):
    values["JWT_SECRET"] = secrets.token_hex(32)
values.setdefault("JWT_ALGORITHM", "HS256")
values.setdefault("JWT_EXPIRE_HOURS", "168")
values.setdefault("SENDGRID_API_KEY", "")
values.setdefault("SENDGRID_FROM_EMAIL", "")
values.setdefault("TWILIO_ACCOUNT_SID", "")
values.setdefault("TWILIO_AUTH_TOKEN", "")
values.setdefault("TWILIO_FROM_NUMBER", "")
values.setdefault("EMERGENT_PUSH_KEY", "")

ordered_keys = [
    "MONGO_URL",
    "DB_NAME",
    "JWT_SECRET",
    "JWT_ALGORITHM",
    "JWT_EXPIRE_HOURS",
    "SENDGRID_API_KEY",
    "SENDGRID_FROM_EMAIL",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_FROM_NUMBER",
    "EMERGENT_PUSH_KEY",
]

contents = [
    "# Local DISPTCHR development settings. This file is ignored by Git.",
    "# Production secrets must be configured separately in the deployment platform.",
    "",
]
contents.extend(f"{key}={values.get(key, '')}" for key in ordered_keys)
contents.append("")

ENV_PATH.write_text("\n".join(contents), encoding="utf-8")
ENV_PATH.chmod(0o600)
print("Local backend environment is configured; secret values were not displayed.")
