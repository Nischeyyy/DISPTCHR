# Deploying DISPTCHR with Openship

Openship is the deployment/hosting layer for DISPTCHR. It reads `docker-compose.yml` at the
repo root (declared in `openship.json`) and runs the whole stack — API, both web frontends,
the edge router and MongoDB — as one project with one public hostname.

```
                 https://your-domain            (TLS terminated by Openship)
                          │
                       ┌──▼──┐
                       │edge │  nginx router — the ONLY public service
                       └──┬──┘
      ┌───────────────────┼─────────────────────┐
  /api /uploads       /manager/*                 /*
      ▼                   ▼                      ▼
   ┌─────┐         ┌───────────────┐       ┌───────────┐
   │ api │         │manager-portal │       │ guard-web │
   │:8001│         │  (Vite dist)  │       │(Expo web) │
   └──┬──┘         └───────────────┘       └───────────┘
      ▼
   ┌─────┐
   │mongo│  (or MongoDB Atlas — see below)
   └─────┘
```

Because every request enters through `edge` on one hostname, both frontends call the API at
the relative path `/api` — no CORS, no hard-coded backend URLs in the web builds.

## Services

| Service          | Source                          | Port | Visibility | Notes |
|------------------|---------------------------------|------|------------|-------|
| `edge`           | `deploy/edge/`                  | 80   | **Public** | Routes by path prefix; `/healthz` for uptime checks |
| `api`            | `backend/Dockerfile`            | 8001 | Internal   | FastAPI; `/api/health`; `uploads` volume |
| `manager-portal` | `manager-portal/Dockerfile`     | 80   | Internal   | Served under `/manager/` (matches `vite.config.js` base) |
| `guard-web`      | `frontend/Dockerfile.web`       | 80   | Internal   | `expo export --platform web`, SPA fallback |
| `mongo`          | `mongo:7`                       | 27017| Internal   | `mongo-data` volume; disable if using Atlas |

## First deployment

1. **Connect GitHub** — Openship → Settings → Git → connect, granting access to `Nischeyyy/DISPTCHR`.
2. **New project** → Library → Repositories → pick `DISPTCHR`. Openship detects `docker-compose.yml`
   via `openship.json` and lists the five services above.
3. **Choose where it runs** — *Your server* (VPS over SSH, Docker) is the recommended target for
   production because it supports persistent volumes. See *Openship Cloud* note below.
4. **Set environment variables** on the **`api`** service (Services → api → Environment):

   | Key | Required | Value |
   |-----|----------|-------|
   | `JWT_SECRET` | **Yes** | `openssl rand -hex 32` — mark as secret |
   | `MONGO_URL` | No | Defaults to `mongodb://mongo:27017`. For Atlas set `mongodb+srv://…` (secret) |
   | `DB_NAME` | No | Defaults to `disptchr` |
   | `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL` | No | Enables email (password-reset delivery, alerts) |
   | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` | No | Enables SMS |
   | `EMERGENT_PUSH_KEY` | No | Push notifications provider key |

   The API refuses to start with a clear error if `JWT_SECRET` is missing — it never falls back to a default.
5. **Routing** — make sure only `edge` is **Publicly exposed**; leave the other four **Internal**.
6. Press **Deploy**. When the build finishes:
   - Guard web app → `https://<domain>/`
   - Manager portal → `https://<domain>/manager/`
   - API docs → `https://<domain>/docs`
   - Health → `https://<domain>/healthz` and `https://<domain>/api/health`
7. **Custom domain** — Project → Domains → add `app.yourcompany.com`; Openship verifies DNS and issues TLS.
8. **Auto-deploy** — Project → Source → enable *Auto-deploy* so every push to the deploy branch redeploys.

CLI equivalent:

```bash
openship project create --name disptchr --git-owner Nischeyyy --git-repo DISPTCHR
openship service env set --project disptchr api JWT_SECRET=$(openssl rand -hex 32) --secret
openship deploy
openship project git auto-deploy disptchr --enable
```

## MongoDB: bundled vs Atlas

- **Bundled (`mongo` service)** — zero config, data in the `mongo-data` volume. Turn on the service's
  **Backup** tab. Good for staging and small single-tenant deployments.
- **MongoDB Atlas** — set `MONGO_URL` on `api` to your `mongodb+srv://` string, then open the
  `mongo` service → Settings → **Disable Service**. Allow the server's IP in Atlas Network Access.

## Persistent data

Two named volumes must survive redeploys:

- `uploads` → `/app/uploads` on `api` (incident photos, documents, generated pay stubs — payroll retention)
- `mongo-data` → `/data/db` on `mongo`

On a self-hosted server these are real Docker volumes. **Openship Cloud has no volume primitive** — if you
deploy there, use Atlas for the database and plan to move uploads to object storage (S3/R2) before
production use.

## Mobile builds

`guard-web` is the browser build of the Expo app. Native iOS/Android binaries are built separately; point
them at the deployed API by setting `EXPO_PUBLIC_BACKEND_URL=https://<domain>` at build time (the API
client appends `/api`).

## Running the same stack locally

```bash
cp .env.example .env         # set JWT_SECRET
docker compose up --build    # http://localhost:<edge port>  (docker compose port edge 80)
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `api` exits: `Required environment variable 'JWT_SECRET' is not set` | Set it on the api service → Environment, redeploy |
| `api` unhealthy, logs show `ServerSelectionTimeoutError` | `MONGO_URL` wrong, `mongo` disabled without Atlas configured, or Atlas IP allow-list |
| `/manager/` returns the guard app | `edge` couldn't reach `manager-portal`; check that service is Running |
| Uploads vanish after redeploy | `uploads` volume missing (Openship Cloud) — use object storage |
| `guard-web` build fails at `yarn install` | Ensure `frontend/yarn.lock` has no `package-firewall.replit.local` URLs |
