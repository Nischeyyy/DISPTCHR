# DISPTCHR development notes

This repository retains its React Native/Expo guard application, React Manager Portal, and FastAPI/MongoDB backend. The separate sibling `disptchr-panel` repository is the directors' website.

The supported combined local command is run from the parent workspace:

```bash
npm run dev
```

It exposes the workforce API and Manager Portal at `http://127.0.0.1:5050` and Disptchr Panel at `http://127.0.0.1:3000`. The guard product should be run through Expo Go or a native development build, not treated as a production browser application.

Local secrets belong only in ignored `.env` files. Run `python3 scripts/setup-dev-env.py` to create them without printing values. Public registration is disabled by default and the runtime has no demo-data seeder or shared demo account.

Production requirements and topology are documented in `docs/DEPLOY_OPENSHIP.md`; verification status and external launch dependencies are documented in `docs/PRODUCTION_READINESS.md`.
