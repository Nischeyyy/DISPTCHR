# Production readiness report

**Assessment date:** 2026-11-23
**Scope:** `Nischeyyy/DISPTCHR` workforce API, Manager Portal, guard application, and the integrated `Nischeyyy/disptchr-panel` directors' website.

## Release decision

The application code and local integrated runtime are green. Production release is **not yet authorized** because the external production environment, credentials, company accounts, real provider delivery, backup restoration, and store signing have not been supplied or exercised. Those are release blockers, not application placeholders.

No fake business records, demo accounts, default passwords, or development authentication bypasses are permitted in production. The local workforce database is intentionally empty. The locally imported Master Timesheet is held only in the ignored Panel development database; its source workbook is not part of the current Git tree.

## Verified application gates

| Area | Result | Evidence |
| --- | --- | --- |
| Workforce backend syntax | Green | all production Python modules compile |
| Backend security scan | Green | Bandit reports no findings; the production Python dependency audit reports 0 known vulnerabilities |
| Backend automated tests | Green | 46 core tests passed; 24 API E2E workflows passed against a fresh disposable MongoDB database created by CI |
| Manager Portal | Green | 9 tests passed; production build passed; dependency audit reports 0 vulnerabilities |
| Disptchr Panel database | Green | schema v6 migration and connectivity check passed against persistent local PostgreSQL/PGlite |
| Disptchr Panel | Green | TypeScript passed; 5 full-stack/unit tests passed; production build passed; dependency audit reports 0 vulnerabilities |
| Guard application | Green | lint and TypeScript passed; Expo Doctor 20/20; dependency audit reports 0 vulnerabilities |
| Native bundles | Green | production-style Expo exports completed for iOS and Android |
| Integrated local runtime | Green | API, gateway, Manager Portal, Disptchr Panel, control connection, MongoDB, and notification worker health verified |
| Unfinished-code scan | Green | no TODO, FIXME, coming-soon, not-implemented, fake-data, or placeholder-feature markers in application code; HTML input placeholder text and test mocks are legitimate |

## Completed full-stack capabilities

### Identity, access, and security

- Guard access tokens are short-lived; rotating refresh tokens are stored in native secure storage. Refresh-token replay revokes the complete token family.
- Manager sessions are HttpOnly and revocable, with mandatory TOTP MFA. Manager status and every permission are enforced by FastAPI, not only by website navigation.
- Disptchr Panel creates, enables, disables, scopes, and resets MFA for Manager accounts through a server-only control API.
- Director accounts use bcrypt-SHA256 password hashing, mandatory TOTP/recovery codes, throttling, revocable sessions, and encrypted MFA secrets.
- SIN and direct-deposit fields are encrypted at rest and masked outside authorized operations.
- Production configuration fails closed for weak or missing signing, encryption, database, cache, storage, and origin settings.

### Workforce operations

- Guard onboarding, assigned schedules, shift details and acknowledgement, open-shift claiming, shift swaps, timeclock, breaks, geofencing, location heartbeat, selfie verification, incidents, SOS, announcements, community, payroll views, credentials, notifications, and password recovery are connected to the API and database.
- Guard data screens expose API failures with an accessible error state and an explicit retry path; create, update, acknowledgement, attachment, comment, reaction, and pay-stub failures are surfaced to the user instead of being silently discarded.
- Shift swaps now cover the complete guarded lifecycle: a guard posts a specific assigned shift with an optional reason, another guard volunteers, a scheduling manager reviews the accepted request under a single-winner decision lock, the assignment transfers, both guards receive the recorded decision, and duplicate active requests are blocked by a database invariant.
- Emergency SOS uses one shared API contract across the guard app and Manager Portal: alerts remain sendable when GPS is unavailable without inventing coordinates, managers can acknowledge and resolve the actual backend states, real coordinates open the correct map, and the resulting critical incident remains linked to the alert.
- The guard dashboard no longer contains a sample dispatch number. It uses the validated `DISPATCH_PHONE` production setting and disables the call action when local development has no approved company number.
- Time Clock resolves a real assigned shift even when opened directly, displays the assignment, blocks capture outside the allowed window, and is independently revalidated by the API.
- Manager Portal provides permission-controlled guards, sites, shifts, open shifts, timeclock, live locations, incidents, SOS, announcements, compliance, shift swaps, and payroll workflows.
- Durable email, SMS, and Expo notification jobs use leases, retry/backoff, retention, dead-letter state, and a separately monitored worker.

### Directors' Disptchr Panel

- Master Timesheet import preserves immutable source rows, provenance, row numbers, modified time, SHA-256 fingerprint, and searchable normalized records.
- Client and subcontractor invoices include line items, integrity validation, lifecycle state, audit history, and generated PDF output.
- Reconciliation covers selected periods, trailing biweekly totals, YTD totals, client and subcontractor comparisons, duplicates, missing or extreme hours, unmatched accounts, and invoice line/total integrity.
- Documents support folders, uploads, versions, private downloads, and controlled deletion.
- Spreadsheet Studio, saved workbooks, `.xlsx` exports, report builder, complete PDF reports, audit cases, findings, evidence, activity export, letterhead generation, licensing records, and record import are database-backed and audited.
- Employment Package creates and stores six separate PDFs: employment summary/acceptance, employee information, direct-deposit authorization, emergency contact, policy/confidentiality, and licence/work eligibility.

## External release blockers

These items cannot truthfully be marked green from source code or a local machine:

1. **Credential rotation:** rotate every MongoDB password and signing/control secret ever pasted into a chat before using production.
2. **Production infrastructure:** provision managed MongoDB, PostgreSQL, Redis, private S3-compatible storage, backups, point-in-time recovery, monitoring, log retention, and alert escalation.
3. **Delivery providers and dispatch line:** configure verified SendGrid, Twilio, Expo Push, and Sentry accounts, provide the real company `DISPATCH_PHONE`, and prove real email, SMS, push, call-link, and error delivery in staging.
4. **Initial identity:** provision the first real director account and enroll its MFA. No default director exists.
5. **Business data:** approve and import real manager, guard, site, rate, invoice, and operational data. The workforce development database contains no invented records.
6. **Native ownership:** bind the Expo project, add company-owned Apple and Google signing credentials, validate on physical devices, complete privacy declarations, and submit through company store accounts.
7. **Network edge:** configure production DNS, TLS, CDN/WAF, exact HTTPS origins, uptime probes, and the public API hostname.
8. **Operational validation:** run the automated API workflow against the deployed staging environment, plus concurrency/load tests, penetration testing, accessibility review, physical-device checks, notification delivery tests, and a documented disaster-restore exercise.
9. **Licence verification:** Ontario provides a public browser verification workflow but no approved automation API has been established; licence checks therefore require an authorized human verification record unless an official integration becomes available.
10. **Git history privacy:** the Master Timesheet workbook and three historical upload artifacts are removed from the current tree, but remain in older Git commits. Purging them requires an approved history rewrite and force-push, followed by fresh clones for all collaborators.

## Production release sequence

1. Approve and perform the Git history rewrite, then verify the remote no longer contains the workbook.
2. Rotate exposed credentials and create separate staging and production secrets in the deployment platform.
3. Provision and verify the managed services, backups, alerting, DNS, TLS, and WAF.
4. Deploy immutable images to staging and run the API E2E workflow against that deployment plus provider, load, security, accessibility, device, and restore tests.
5. Provision the director, manager, and guard identities through the real controlled flows and import approved business data.
6. Record sign-off, promote the same image digests to production, and retain the known-good rollback images.

Production must remain closed until every external blocker above has named evidence and an accountable owner. Passing source-code tests alone is not a production launch approval.
