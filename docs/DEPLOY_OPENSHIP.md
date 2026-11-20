# Production deployment

DISPTCHR deploys from `docker-compose.yml`. Openship may orchestrate the Compose project, but the topology does not depend on an Openship-specific database or filesystem.

```text
Public HTTPS hostname
        |
        v
edge (only public service)
  |-- /api/*      -> FastAPI API
  `-- /manager/*  -> Manager Portal

FastAPI API + notification worker
  |-- managed MongoDB with backups and point-in-time recovery
  |-- managed Redis for shared rate limits
  `-- private S3-compatible object storage

Guard application -> same public /api endpoint from native iOS/Android builds
Disptchr Panel -> /api/control/* over its server-only control connection
```

The guard application is native. There is no production `guard-web` service and no public uploads directory. Files are private and retrieved only through authenticated, short-lived access tokens.

## Services

| Service | Public | Responsibility |
| --- | --- | --- |
| `edge` | yes | single ingress and path routing |
| `api` | no | authentication, authorization, workforce operations, health and metrics |
| `manager-portal` | no | static manager website served under `/manager/` |
| `notification-worker` | no | durable email, SMS, and Expo push delivery |

Disptchr Panel is deployed from the separate `Nischeyyy/disptchr-panel` repository and connects to the API with a server-only key.

## Required production configuration

The API deliberately refuses to start when a required control is missing.

- `APP_ENV=production`
- `MONGO_URL` and `DB_NAME`
- `JWT_SECRET` with at least 32 random characters
- valid `PII_ENCRYPTION_KEY` (Fernet key)
- `CONTROL_PANEL_API_KEY` shared only with Disptchr Panel
- `METRICS_TOKEN`
- `CORS_ORIGINS` containing only the exact HTTPS application origins
- non-memory `RATE_LIMIT_STORAGE_URI` pointing to managed Redis
- `STORAGE_BACKEND=s3`, `S3_BUCKET`, region/endpoint as applicable, and workload identity or S3 credentials
- SendGrid key and verified sender
- Twilio account, token, and sender number
- optional `SENTRY_DSN` and `EXPO_ACCESS_TOKEN`

Use the deployment platform's secret store. Never place real values in Git, build arguments, screenshots, or support messages. Rotate any credential that has ever been pasted into a chat or terminal transcript before production use.

## Release procedure

1. Complete every local gate in `docs/PRODUCTION_READINESS.md` on the exact commit to deploy.
2. Rotate exposed credentials and create separate staging and production values.
3. Provision managed MongoDB, Redis, private object storage, notification providers, monitoring, and backups.
4. Set all variables for both `api` and `notification-worker`. Keep only `edge` public.
5. Deploy to staging and verify `/internal/live`, `/api/health`, authenticated manager login/MFA, control-panel health, file upload/download, one notification per channel, and worker heartbeat.
6. Restore a backup into an isolated environment and record the result.
7. Run the smoke/load/security test plan, then promote the same image digests to production.
8. Configure DNS/TLS, CDN/WAF/rate policies, uptime checks, log retention, and alert escalation.

## Native guard releases

Bind `frontend/` to the company EAS project and set `EXPO_PUBLIC_BACKEND_URL` to the public HTTPS origin. Build signed iOS and Android artifacts with company-owned Apple/Google credentials. Validate push entitlement, deep links, camera/location permissions, background location behavior, and store privacy declarations on physical devices before submission.

## Health and observability

- `/internal/live` proves the API process is alive.
- `/api/health` proves MongoDB and private object storage are reachable.
- the notification worker health check fails when its heartbeat is more than 60 seconds old.
- `/internal/metrics` is hidden unless the correct metrics token is supplied.
- request logs are structured and include an `X-Request-ID`; Sentry is supported when configured.

## Rollback and recovery

Deploy immutable image tags and retain the previous known-good tag. Application rollback must never roll back data blindly. Schema/data changes require a tested forward repair or an explicitly tested restore. MongoDB backups, object versions, and PostgreSQL backups for Disptchr Panel must have documented retention, encryption, restore ownership, RPO, and RTO.
