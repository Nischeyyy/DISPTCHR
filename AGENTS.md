# DISPTCHR repository guide

This is the existing `Nischeyyy/DISPTCHR` workforce application. Preserve its established Expo/React Native, FastAPI, and MongoDB architecture.

## Ownership

- `frontend/` — employee/guard app for shifts, payroll, credentials, time clock, incidents, announcements, and related workforce operations.
- `manager-portal/` — existing Skyhawk manager portal.
- `backend/` — shared FastAPI API and MongoDB data layer.
- `proxy.js` — local/Replit routing between the employee app, manager portal, and API.

## Multi-repository workspace

- This repository is not the cPanel-style company control panel.
- The separate company control panel is `../disptchr-panel` / `Nischeyyy/disptchr-panel`.
- Never recreate or replace that control panel in this repository.
- Cross-application work must preserve both repositories and integrate through explicit URLs, authentication, or APIs.
- In the combined Codex workspace, run both projects from the parent directory with `npm run dev`.

## Data and security

- Never commit real `.env` files, MongoDB credentials, JWT secrets, imported employee data, generated pay stubs, or runtime logs.
- Keep production authentication and authorization server-enforced.
- Do not migrate this application to another framework or database unless the user explicitly requests that architectural change.
