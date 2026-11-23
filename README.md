# DISPTCHR workforce platform

This repository contains the existing Skyhawk workforce applications and their shared API. It is intentionally separate from the directors' `disptchr-panel` repository.

## Product hierarchy

1. **Disptchr Panel** (sibling repository) — directors and board members control company records and manager access.
2. **Manager Portal** (`manager-portal/`) — managers operate the guard workforce within permissions assigned by directors.
3. **Guard application** (`frontend/`) — guards use the native Expo application for shifts, timeclock, incidents, payroll, credentials, announcements, and related operations.

The FastAPI service in `backend/` is the enforcement boundary. Manager account status and permissions are checked on every protected request; disabling an account revokes its active sessions.

## Local development

From the parent workspace, run `npm run dev`. This starts the existing repositories together:

- combined workforce API and Manager Portal: `http://127.0.0.1:5050`
- directors' Disptchr Panel: `http://127.0.0.1:3000`

The guard product is a native iOS/Android application, not a production web application. Use Expo Go or a development build from `frontend/`.

The backend requires Python 3.11 or newer; production and CI use Python 3.12. Local secrets are generated into ignored files by `python3 scripts/setup-dev-env.py`. Public registration is disabled by default; the runtime contains no demo-data seeder.

## Security model

- guards use short-lived access tokens and rotating, revocable refresh tokens stored in native secure storage;
- managers use secure, HttpOnly server sessions and mandatory TOTP MFA;
- director actions arrive through a separate server-to-server control key and are enforced by this API;
- SIN and direct-deposit data are encrypted at rest and only masked values are returned to ordinary clients;
- uploaded evidence and pay stubs use private object storage in production and short-lived scoped download tokens;
- rate limits use shared Redis in production;
- notification delivery uses a durable MongoDB outbox with a separate worker, retry/backoff, leases, and dead-letter state;
- readiness checks cover MongoDB and object storage; metrics require a bearer token.

## Verification

Run the same gates as CI before release:

```bash
cd backend && ../.venv/bin/pytest tests -q
cd ../manager-portal && npm test -- --run && npm run build && npm audit --omit=dev
cd ../frontend && corepack yarn lint && npx tsc --noEmit && npx expo-doctor && corepack yarn audit --groups dependencies --level moderate
npx expo export --platform ios
npx expo export --platform android
```

CI also starts the real FastAPI service with a fresh disposable MongoDB database and runs the complete API workflow in `backend/tests/backend_test.py`. The workflow creates its manager, MFA enrollment, guard, site, shifts, payroll, credential, and announcement through application APIs, exercises the guard operations, and discards the database after the run.

See `docs/PRODUCTION_READINESS.md` for the release checklist and `docs/DEPLOY_OPENSHIP.md` for deployment topology and required external services.

## Production dependencies

Production fails closed unless real managed MongoDB, Redis, private S3-compatible storage, notification providers, strong signing/encryption keys, and HTTPS origins are configured. Apple/Google signing, EAS project binding, DNS/TLS, backups, and provider credentials are deployment-owner responsibilities; no real secret or imported employee dataset belongs in Git.
