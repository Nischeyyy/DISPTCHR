# DISPTCHR API — FastAPI backend
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# curl is used by the container healthcheck; build tools cover any wheel that must compile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Local development storage uses this path. Production files use private S3,
# but the directory remains writable for safe startup and temporary work.
RUN addgroup --system --gid 10001 disptchr \
    && adduser --system --uid 10001 --ingroup disptchr disptchr \
    && mkdir -p /app/uploads \
    && chown -R disptchr:disptchr /app

USER disptchr

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8001/api/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
