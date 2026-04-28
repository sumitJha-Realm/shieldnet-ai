# Vercel Deployment

Deploy this repo as two separate Vercel projects:

1. `frontend` project
2. `backend` project

## Frontend Project

- Root Directory: `frontend`
- Framework Preset: `Next.js`
- Build Command: `npm run build`
- Install Command: `npm install`

Environment variables:

- `NEXT_PUBLIC_API_URL=https://<your-backend-vercel-domain>`

## Backend Project

- Root Directory: `backend`
- Framework Preset: `Other`
- Install Command: `pip install -r requirements.txt`

Environment variables:

- `MONGODB_URI=<your-mongodb-connection-string>`
- `DB_NAME=shieldnet-ai`
- `VOYAGE_AI_API_KEY=<your-voyage-api-key>`
- `FRONTEND_URL=https://<your-frontend-vercel-domain>`
- `SKIP_STARTUP_INDEXES=true`

Optional if you use Microsoft Foundry endpoints:

- `GROVE_FOUNDRY_CHAT_URL=<your-foundry-chat-url>`
- `GROVE_API_KEY=<your-foundry-api-key>`
- `GROVE_FOUNDRY_MODEL=gpt-5.4`
- `GROVE_FOUNDRY_TIMEOUT_SECS=20`
- `AGENTIC_AGENT_CHAIN=classifier`

## Notes

- Vercel runs the backend as a serverless function through `backend/api/index.py`.
- Startup index creation is disabled for the Vercel backend to reduce cold-start overhead.
- Create Atlas Search / Vector Search indexes and seed data outside Vercel using your existing scripts.
- The frontend proxies `/api/*` requests to the backend using Next.js rewrites.