import os
from pathlib import Path
import subprocess
import sys


BACKEND = Path(__file__).resolve().parents[1]


def production_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "APP_ENV": "production",
        "MONGO_URL": "mongodb://database.invalid:27017",
        "DB_NAME": "disptchr_test",
        "JWT_SECRET": "production-test-secret-with-more-than-32-characters",
        "PII_ENCRYPTION_KEY": "XsEh4JQ9QnQ6PqZDCf2fEvWguzVhKqM5-3xYpKz0OHU=",
        "CONTROL_PANEL_API_KEY": "control-test-secret-with-more-than-32-characters",
        "METRICS_TOKEN": "metrics-test-secret-with-more-than-32-characters",
        "CORS_ORIGINS": "https://app.example.invalid,https://panel.example.invalid",
        "RATE_LIMIT_STORAGE_URI": "redis://cache.example.invalid:6379/0",
        "STORAGE_BACKEND": "s3",
        "S3_BUCKET": "disptchr-production-test",
        "AWS_EC2_METADATA_DISABLED": "true",
        "SENDGRID_API_KEY": "sendgrid-test-value",
        "SENDGRID_FROM_EMAIL": "notifications@example.invalid",
        "TWILIO_ACCOUNT_SID": "twilio-test-value",
        "TWILIO_AUTH_TOKEN": "twilio-test-token",
        "TWILIO_FROM_NUMBER": "+14165550123",
        "DISPATCH_PHONE": "+14165550124",
    })
    return environment


def import_server(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=BACKEND,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )


def test_complete_production_configuration_imports_without_network_access():
    result = import_server(production_environment())
    assert result.returncode == 0, result.stderr


def test_production_configuration_rejects_localhost_cors_origin():
    environment = production_environment()
    environment["CORS_ORIGINS"] = "http://localhost:5050"
    result = import_server(environment)
    assert result.returncode != 0
    assert "production HTTPS origins" in result.stderr


def test_production_configuration_rejects_invalid_dispatch_number():
    environment = production_environment()
    environment["DISPATCH_PHONE"] = "416-555-0124"
    result = import_server(environment)
    assert result.returncode != 0
    assert "E.164" in result.stderr
