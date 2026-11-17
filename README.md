# Here are your Instructions

## Product hierarchy

- `frontend/` is the guard mobile application.
- `manager-portal/` is the manager website.
- The separate `Nischeyyy/disptchr-panel` repository is the directors/board website and sits above the Manager Portal.

Manager accounts are created, enabled, disabled, and permissioned in Disptchr Panel under **Access & Roles**. This repository's API is the enforcement boundary: manager permissions are checked on every protected manager request, and disabled accounts lose both existing sessions and new sign-in access.

## Deployment

DISPTCHR deploys with [Openship](https://openship.io) from `docker-compose.yml` / `openship.json`. See [docs/DEPLOY_OPENSHIP.md](docs/DEPLOY_OPENSHIP.md).
