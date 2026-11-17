# DISPTCHR repository guide

This is the existing `Nischeyyy/DISPTCHR` workforce application. Preserve its established Expo/React Native, FastAPI, and MongoDB architecture.

## Ownership

- `frontend/` — employee/guard mobile app for shifts, payroll, credentials, time clock, incidents, announcements, and related workforce operations.
- `manager-portal/` — existing Skyhawk manager website, subordinate to director controls in the separate Disptchr Panel.
- `backend/` — shared FastAPI API and MongoDB data layer.
- `proxy.js` — local/Replit routing between the employee app, manager portal, and API.

## Multi-repository workspace

- This repository is not the cPanel-style company control panel.
- The separate company control panel is `../disptchr-panel` / `Nischeyyy/disptchr-panel`.
- Never recreate or replace that control panel in this repository.
- Cross-application work must preserve both repositories and integrate through explicit URLs, authentication, or APIs.
- Manager account status and permissions originate in `../disptchr-panel` Access & Roles and are enforced server-side by this repository's backend.
- In the combined Codex workspace, run both projects from the parent directory with `npm run dev`.
- The combined functional DISPTCHR URL is `http://127.0.0.1:5050`; its proxy joins the employee app, manager portal, and API. Production keeps the original default proxy port unless overridden.

## Data and security

- Never commit real `.env` files, MongoDB credentials, JWT secrets, imported employee data, generated pay stubs, or runtime logs.
- Local development secrets live only in ignored `backend/.env`; `scripts/setup-dev-env.py` creates them without displaying their values.
- Keep production authentication and authorization server-enforced.
- Do not migrate this application to another framework or database unless the user explicitly requests that architectural change.
