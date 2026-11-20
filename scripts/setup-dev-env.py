#!/usr/bin/env python3

"""Create persistent local-only DISPTCHR backend settings without exposing values."""

from pathlib import Path
import argparse
import base64
import secrets
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / "backend" / ".env"
PANEL_ENV_PATH = REPO_ROOT.parent / "disptchr-panel" / ".env.local"


def read_existing(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
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

values = read_existing(ENV_PATH)
panel_values = read_existing(PANEL_ENV_PATH)
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
control_panel_key = (
    values.get("CONTROL_PANEL_API_KEY")
    or panel_values.get("DISPTCHR_CONTROL_API_KEY")
    or secrets.token_hex(32)
)
values["CONTROL_PANEL_API_KEY"] = control_panel_key
values.setdefault("JWT_ALGORITHM", "HS256")
values.setdefault("ACCESS_TOKEN_MINUTES", "15")
values.setdefault("MANAGER_SESSION_HOURS", "8")
values.setdefault("REFRESH_TOKEN_DAYS", "30")
values.setdefault("APP_ENV", "development")
values.setdefault("ALLOW_PUBLIC_REGISTRATION", "false")
values.setdefault("SESSION_COOKIE_SECURE", "false")
values.setdefault("CORS_ORIGINS", "http://127.0.0.1:5050,http://localhost:5050,http://127.0.0.1:3000,http://localhost:3000")
if not values.get("PII_ENCRYPTION_KEY"):
    values["PII_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
values.setdefault("SENDGRID_API_KEY", "")
values.setdefault("SENDGRID_FROM_EMAIL", "")
values.setdefault("TWILIO_ACCOUNT_SID", "")
values.setdefault("TWILIO_AUTH_TOKEN", "")
values.setdefault("TWILIO_FROM_NUMBER", "")
values.setdefault("EXPO_ACCESS_TOKEN", "")

ordered_keys = [
    "MONGO_URL",
    "DB_NAME",
    "JWT_SECRET",
    "CONTROL_PANEL_API_KEY",
    "JWT_ALGORITHM",
    "ACCESS_TOKEN_MINUTES",
    "MANAGER_SESSION_HOURS",
    "REFRESH_TOKEN_DAYS",
    "APP_ENV",
    "ALLOW_PUBLIC_REGISTRATION",
    "SESSION_COOKIE_SECURE",
    "CORS_ORIGINS",
    "PII_ENCRYPTION_KEY",
    "SENDGRID_API_KEY",
    "SENDGRID_FROM_EMAIL",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_FROM_NUMBER",
    "EXPO_ACCESS_TOKEN",
]

contents = [
    "# Local DISPTCHR development settings. This file is ignored by Git.",
    "# Production secrets must be configured separately in the deployment platform.",
    "",
]
contents.extend(f"{key}={values.get(key, '')}" for key in ordered_keys)
contents.extend(
    f"{key}={values[key]}" for key in sorted(set(values).difference(ordered_keys))
)
contents.append("")

ENV_PATH.write_text("\n".join(contents), encoding="utf-8")
ENV_PATH.chmod(0o600)

if PANEL_ENV_PATH.parent.is_dir():
    panel_values.setdefault("DISPTCHR_DEV_ACCESS", "1")
    if not panel_values.get("PANEL_ENCRYPTION_KEY"):
        panel_values["PANEL_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    panel_values.setdefault("DISPTCHR_CONTROL_API_URL", "http://127.0.0.1:8000/api")
    panel_values["DISPTCHR_CONTROL_API_KEY"] = control_panel_key
    panel_values.setdefault("DISPTCHR_MANAGER_PORTAL_URL", "http://127.0.0.1:5050/manager/")
    panel_ordered_keys = [
        "DISPTCHR_DEV_ACCESS",
        "PANEL_ENCRYPTION_KEY",
        "DISPTCHR_CONTROL_API_URL",
        "DISPTCHR_CONTROL_API_KEY",
        "DISPTCHR_MANAGER_PORTAL_URL",
    ]
    panel_contents = [
        "# Local Disptchr Panel settings. This file is ignored by Git.",
        "# The control key is server-only and shared with the local workforce API.",
        "",
    ]
    panel_contents.extend(f"{key}={panel_values.get(key, '')}" for key in panel_ordered_keys)
    panel_contents.extend(
        f"{key}={panel_values[key]}"
        for key in sorted(set(panel_values).difference(panel_ordered_keys))
    )
    panel_contents.append("")
    PANEL_ENV_PATH.write_text("\n".join(panel_contents), encoding="utf-8")
    PANEL_ENV_PATH.chmod(0o600)
    print("Local backend and control-panel environments are configured; secret values were not displayed.")
else:
    print("Local backend environment is configured; no sibling Disptchr Panel checkout was found.")
