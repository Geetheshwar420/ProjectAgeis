# Deployment Guide

This repo contains a Flask + Flask-SocketIO backend and a React frontend.
Below are tested steps for local development and production deployment.

## Prerequisites

- Python 3.10+
- Node.js 18+
- For production Socket.IO: eventlet (already in backend/requirements.txt)
- Database: SQLite by default, or PostgreSQL/CockroachDB via DATABASE_URL

## Environment variables (Backend)

- FLASK_ENV: development or production
- APP_DEBUG: true|false (only used when FLASK_ENV != production)
- TRUSTED_ORIGINS: comma-separated list of allowed HTTP origins for CORS
  - Example (local): `http://localhost:3000,http://127.0.0.1:3000`
- ALLOW_VERCEL_PREVIEWS: true|false (adds regex allowance for *.vercel.app)
- DATABASE_URL (optional): postgres URL (postgresql://user:pass@host:port/db)
  - If omitted, SQLite is used at backend/messaging_app.db

## Local development

1) Backend (PowerShell on Windows)

   - Create venv and install deps:
     - `python -m venv .venv`
     - `.\.venv\Scripts\Activate.ps1`
     - `pip install -r backend/requirements.txt`

   - Initialize database (one time):
     - `python - << 'PY'
from backend.db_init import init_database
init_database()
print('DB initialized ✅')
PY`

   - Run backend server (uses eventlet):
     - `python -c "import os; os.chdir('backend'); import app"`
       - Or run: `python backend/app.py`

2) Frontend

   - `cd frontend`
   - `npm install`
   - `npm start`
   - The app will open at http://localhost:3000 and talk to backend at http://localhost:5000

## Production deployment (Render)

- Create a new Web Service for the backend:
  - Root: repo root
  - Build command: `pip install -r backend/requirements.txt`
  - Start command: `python backend/app.py`
  - Environment: set
    - `FLASK_ENV=production`
    - `TRUSTED_ORIGINS=https://<your-frontend-domain>`
    - `ALLOW_VERCEL_PREVIEWS=false` (or true if needed)
    - Optional: `DATABASE_URL=postgresql://...`

- Create a Static Site for the frontend:
  - Root: `frontend`
  - Build command: `npm install && npm run build`
  - Publish directory: `frontend/build`
  - Set environment: `REACT_APP_API_URL=https://<your-backend-domain>`

## Production deployment (Vercel + Render)

- Frontend on Vercel:
  - Import the repo, set `REACT_APP_API_URL` to your backend public URL
  - Build & deploy (vercel.json already present)

- Backend on Render as above

## Socket.IO, sessions, and CORS

- This backend enables CORS for the provided origin list and allows credentials.
- Flask-SocketIO is initialized with basic CORS settings (string origins only). Regex origins are supported for HTTP CORS, not Socket.IO. If you need dynamic origins for Socket.IO in production, prefer setting a fixed explicit domain in TRUSTED_ORIGINS.

## Database notes

- SQLite in development; single-file DB stored at `backend/messaging_app.db`.
- For PostgreSQL/CockroachDB, set `DATABASE_URL` accordingly. The adapter enforces native placeholders: `?` for SQLite, `%s` for PostgreSQL.

## Health checklist

- [ ] Backend boots without errors (Render logs show Socket.IO up)
- [ ] /register and /login work; session cookie is set
- [ ] Socket.IO connects from the frontend (you see "Connected to server" toast)
- [ ] Selecting a user initiates a secure session (/initiate_qke returns ready)
- [ ] Sending a message succeeds, both sides see decrypted content

## Troubleshooting

- CORS or cookies failing locally: ensure browser allows third-party cookies or run both on localhost.
- Socket.IO connect issues on https: make sure your backend supports https or use a platform that terminates TLS.
- Database permission errors on Render: check DATABASE_URL and ensure the instance is reachable and initialized.
