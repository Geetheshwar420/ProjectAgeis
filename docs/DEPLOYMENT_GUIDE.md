# 🚀 Complete Deployment Guide - ProjectAgeis

**Last Updated**: October 22, 2025  
**Status**: Ready for Production Deployment

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Production Deployment](#production-deployment)
4. [Testing Checklist](#testing-checklist)
5. [Troubleshooting](#troubleshooting)
6. [Environment Variables Reference](#environment-variables-reference)

---

## 🔧 Prerequisites

### Required Accounts
- ✅ **GitHub** account (for code repository)
- ✅ **Render** account (for backend hosting)
- ✅ **Vercel** account (for frontend hosting)
- ✅ **CockroachDB** account (for production database)

### Required Software (Local Development)
- Python 3.12+
- Node.js 18+
- Git

---

## 💻 Local Development Setup

### 1. Clone Repository
```bash
git clone https://github.com/Geetheshwar420/ProjectAgeis.git
cd ProjectAgeis
```

### 2. Backend Setup

#### Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

#### Configure Environment
Create `backend/.env` file:
```env
# Flask Configuration
FLASK_ENV=development
APP_DEBUG=True
SECRET_KEY=your-local-secret-key-here

# Database (SQLite for localhost)
# DATABASE_URL is NOT set for local development (uses SQLite by default)
SQLITE_DATABASE_PATH=messaging_app.db

# CORS Configuration
TRUSTED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:5000

# Socket.IO (optional - set to 'true' for debugging)
SOCKETIO_CORS_ALL=false
```

#### Initialize Database
```bash
python init_db_standalone.py
```

#### Start Backend Server
```bash
python run.py
```

**Expected Output**:
```
✅ App created successfully
🔓 Development mode: Relaxed session cookies
🔐 Quantum Cryptography Service initialized
🚀 Starting server...
(XXXXX) wsgi starting up on http://0.0.0.0:5000
```

### 3. Frontend Setup

#### Install Dependencies
```bash
cd frontend
npm install
```

#### Configure Environment
Create `frontend/.env` file:
```env
# API Configuration
REACT_APP_API_URL=http://localhost:5000

# Optional: For LAN testing
# REACT_APP_API_URL=http://YOUR_LAN_IP:5000
```

#### Start Frontend
```bash
npm start
```

**Expected Output**:
```
Compiled successfully!
Local:   http://localhost:3000
On Your Network:  http://YOUR_LAN_IP:3000
```

### 4. Test Locally

1. **Open Browser**: Navigate to `http://localhost:3000`
2. **Register Users**: Create two test accounts (e.g., `alice`, `bob`)
3. **Add Friends**: Send and accept friend requests
4. **Test Messaging**: Send encrypted messages between users
5. **Verify Real-Time**: Open two browser windows and test live messaging

---

## 🌐 Production Deployment

### Step 1: Configure CockroachDB (Production Database)

#### 1.1 Create Database Cluster
1. Login to [CockroachDB Cloud](https://cockroachlabs.cloud/)
2. Click "Create Cluster"
3. Choose **Serverless** plan (free tier available)
4. Select region: **ap-south-1** (Mumbai) or closest to your users
5. Name your cluster: `messaging-app-prod`
6. Click "Create Cluster"

#### 1.2 Get Connection String
1. After cluster creation, click "Connect"
2. Select "General connection string"
3. Copy the connection string (format):
   ```
   postgresql://USERNAME:PASSWORD@CLUSTER_HOST:26257/defaultdb?sslmode=verify-full
   ```
4. **IMPORTANT**: Save this securely - you'll need it for Render

#### 1.3 Initialize Production Database
1. Update `backend/.env` temporarily:
   ```env
   DATABASE_URL=postgresql://USERNAME:PASSWORD@CLUSTER_HOST:26257/defaultdb?sslmode=verify-full
   ```

2. Run initialization script:
   ```bash
   cd backend
   python init_db_standalone.py
   ```

3. **Expected Output**:
   ```
   🗄️  Database: POSTGRESQL
   🔧 Initializing POSTGRESQL database schema...
   ✅ Database initialized successfully!
   ```

4. Verify tables in CockroachDB dashboard:
   - `users` (with keypair columns)
   - `messages`
   - `friend_requests`

5. **Comment out DATABASE_URL** in local `.env` after initialization

---

### Step 2: Deploy Backend to Render

#### 2.1 Connect Repository
1. Login to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository: `Geetheshwar420/ProjectAgeis`
4. Select repository and click "Connect"

#### 2.2 Configure Service
- **Name**: `projectageis-backend`
- **Region**: Choose closest to your CockroachDB region
- **Branch**: `main`
- **Root Directory**: Leave empty (render.yaml handles this)
- **Environment**: `Python 3`
- **Build Command**: `cd backend && pip install -r requirements.txt`
- **Start Command**: `cd backend && python run.py`
- **Plan**: Free (or Starter for better performance)

#### 2.3 Set Environment Variables

Click "Environment" tab and add:

| Key | Value | Notes |
|-----|-------|-------|
| `FLASK_ENV` | `production` | Required |
| `APP_DEBUG` | `False` | Required |
| `SECRET_KEY` | (Auto-generated) | Click "Generate Value" |
| `DATABASE_URL` | `postgresql://...` | Your CockroachDB connection string |
| `TRUSTED_ORIGINS` | `https://project-ageis.vercel.app,https://projectageis.onrender.com` | Update with your actual domains |
| `ALLOW_VERCEL_PREVIEWS` | `true` | Optional |
| `SOCKETIO_CORS_ALL` | `false` | Keep false for security |
| `PYTHON_VERSION` | `3.12.0` | Optional |

#### 2.4 Deploy
1. Click "Create Web Service"
2. Wait for build to complete (~5-10 minutes)
3. Check logs for successful startup
4. Note your backend URL: `https://projectageis.onrender.com`

#### 2.5 Verify Backend
Open in browser: `https://projectageis.onrender.com/healthz`

**Expected Response**:
```json
{
  "status": "healthy",
  "database": "connected",
  "quantum_service": "active"
}
```

---

### Step 3: Deploy Frontend to Vercel

#### 3.1 Connect Repository
1. Login to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "Add New..." → "Project"
3. Import repository: `Geetheshwar420/ProjectAgeis`
4. Select repository and click "Import"

#### 3.2 Configure Project
- **Framework Preset**: Create React App
- **Root Directory**: `frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `build`

#### 3.3 Set Environment Variables

Click "Environment Variables" and add:

| Key | Value | Environment |
|-----|-------|-------------|
| `REACT_APP_API_URL` | `https://projectageis.onrender.com` | Production |

#### 3.4 Deploy
1. Click "Deploy"
2. Wait for deployment (~2-5 minutes)
3. Note your frontend URL: `https://project-ageis.vercel.app`

#### 3.5 Update Backend CORS
Go back to Render → Environment Variables → Update `TRUSTED_ORIGINS`:
```
https://YOUR-ACTUAL-VERCEL-URL.vercel.app,https://projectageis.onrender.com
```

Redeploy backend after updating.

---

## ✅ Testing Checklist

### Local Testing

- [ ] Backend starts without errors
- [ ] Frontend connects to backend
- [ ] User registration works
- [ ] User login/logout works
- [ ] Friend requests send/accept
- [ ] Messages encrypt and send
- [ ] Real-time messaging works (two browser windows)
- [ ] Socket.IO connects from LAN IP
- [ ] Session persists after page refresh

### Production Testing

- [ ] Backend health check passes (`/healthz`)
- [ ] Frontend loads from Vercel URL
- [ ] CORS allows requests from Vercel to Render
- [ ] User registration works in production
- [ ] User login works with session cookies
- [ ] Friend requests work
- [ ] Messages encrypt and send
- [ ] Real-time messaging works (two devices)
- [ ] Socket.IO connects over HTTPS
- [ ] Database persists data (CockroachDB)

### Multi-User Testing

- [ ] Register User A on Device 1
- [ ] Register User B on Device 2
- [ ] Users can find and add each other as friends
- [ ] Messages send bidirectionally
- [ ] Real-time updates work without refresh
- [ ] Sessions persist across page reloads
- [ ] No CORS errors in browser console
- [ ] No 500 errors in backend logs

### Security Testing

- [ ] Session cookies are HttpOnly
- [ ] Session cookies are Secure (HTTPS only in production)
- [ ] SameSite=None for cross-domain cookies
- [ ] CSRF protection enabled
- [ ] Keypairs stored securely in database
- [ ] Messages encrypted with BB84 + Kyber + Dilithium
- [ ] No sensitive data in browser console
- [ ] No API keys exposed in frontend code

---

## 🐛 Troubleshooting

### Backend Issues

#### "Database connection failed"
**Solution**: Verify `DATABASE_URL` in Render environment variables. Test connection string in local `.env` first.

#### "Port 5000 already in use"
**Solution**: 
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Mac/Linux
lsof -ti:5000 | xargs kill -9
```

#### "Module not found"
**Solution**: Reinstall dependencies
```bash
pip install -r requirements.txt --force-reinstall
```

### Frontend Issues

#### "Network Error" / "Failed to fetch"
**Solution**: 
1. Check `REACT_APP_API_URL` in `.env`
2. Verify backend is running
3. Check CORS configuration in backend
4. Clear browser cache

#### "Socket.IO connection failed"
**Solution**:
1. Check browser console for exact error
2. Verify `socketio_origins` in `backend/app.py`
3. Ensure `cors_credentials=True` in Socket.IO config
4. Check if backend firewall blocks WebSocket connections

#### "Session not persisted"
**Solution**:
1. Check session cookie settings (HttpOnly, SameSite, Secure)
2. Verify `withCredentials: true` in Axios config
3. Ensure frontend and backend domains are in TRUSTED_ORIGINS
4. Clear browser cookies and retry

### Database Issues

#### "KeyError: 'kyber_public_key'"
**Solution**: Database needs reinitialization
```bash
cd backend
python init_db_standalone.py
```

#### "Table does not exist"
**Solution**: Run database initialization script
```bash
python init_db_standalone.py
```

#### "CockroachDB connection timeout"
**Solution**:
1. Verify connection string format
2. **⚠️ TEMPORARY DEBUGGING ONLY**: Check IP whitelist in CockroachDB (allow all `0.0.0.0/0` for Render)
3. Ensure SSL mode is `verify-full`

**🔒 SECURITY HARDENING - CRITICAL**:

> **WARNING**: Allowing `0.0.0.0/0` (all IPs) is **INSECURE** and should **ONLY** be used temporarily for debugging connection issues.

After confirming connectivity, **immediately implement one of these secure alternatives**:

1. **✅ Whitelist Render's Static IP Ranges** (Recommended):
   - Check [Render's documentation](https://render.com/docs/static-outbound-ip-addresses) for current static outbound IPs
   - Add only these specific IP addresses/ranges to CockroachDB allowlist
   - Example: `35.190.247.0/24`, `104.155.0.0/16` (verify current ranges from Render docs)

2. **✅ Use Private Networking** (Most Secure):
   - Enable [Render Private Services](https://render.com/docs/private-services) if available on your plan
   - Use CockroachDB's [VPC peering or PrivateLink](https://www.cockroachlabs.com/docs/cockroachcloud/network-authorization.html#vpc-peering) (requires paid plans)
   - This keeps all traffic internal, never exposed to public internet

3. **✅ Cloud-Specific Private Connectivity**:
   - If both services are on same cloud provider (e.g., AWS, GCP), use provider's private networking
   - AWS: VPC peering, PrivateLink
   - GCP: VPC Service Controls, Private Service Connect

**Required Action After Debugging**:
```bash
# 1. Verify your app connects successfully
# 2. Go to CockroachDB Console > Networking > IP Allowlist
# 3. DELETE the 0.0.0.0/0 rule immediately
# 4. ADD only Render's static IPs or enable private networking
# 5. Test again to confirm connectivity still works
```

**Why This Matters**:
- `0.0.0.0/0` exposes your database to the entire internet
- Increases risk of unauthorized access, brute force attacks, and data breaches
- CockroachDB still requires authentication, but defense-in-depth is critical
- Production databases should **never** be publicly accessible without IP restrictions

---

## 📚 Environment Variables Reference

### Backend Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FLASK_ENV` | Yes | `development` | Flask environment (production/development) |
| `APP_DEBUG` | No | `True` | Enable debug mode |
| `SECRET_KEY` | Yes | None | Flask secret key for sessions |
| `DATABASE_URL` | No | None | PostgreSQL/CockroachDB connection string (if not set, uses SQLite) |
| `SQLITE_DATABASE_PATH` | No | `messaging_app.db` | SQLite database file path |
| `TRUSTED_ORIGINS` | Yes | `http://localhost:3000` | Comma-separated list of allowed CORS origins |
| `ALLOW_VERCEL_PREVIEWS` | No | `false` | Allow Vercel preview deployments |
| `SOCKETIO_CORS_ALL` | No | `false` | Allow all Socket.IO origins (debugging only) |

### Frontend Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REACT_APP_API_URL` | No | Auto-detected | Backend API base URL |

**Note**: `REACT_APP_API_URL` auto-detects:
- If on localhost/LAN: Uses same host with port 5000
- If on Vercel/production: Uses `https://projectageis.onrender.com`
- Can be manually overridden by setting the env var

---

## 🔒 Security Best Practices

### Production Checklist

- ✅ Use strong `SECRET_KEY` (auto-generated by Render)
- ✅ Set `APP_DEBUG=False` in production
- ✅ Never commit `.env` file to Git
- ✅ Use HTTPS for all production URLs
- ✅ Set `SameSite=None; Secure` for cross-domain cookies
- ✅ Enable CORS only for trusted domains
- ✅ Store CockroachDB credentials securely (Render env vars)
- ✅ Use SSL for database connections (`sslmode=verify-full`)
- ✅ Keep dependencies updated (`pip list --outdated`)
- ✅ Monitor Render logs for suspicious activity

---

## 📊 Architecture Overview

### Development (Localhost)
```
Frontend (React)          Backend (Flask)
http://localhost:3000  →  http://0.0.0.0:5000
                              ↓
                        SQLite Database
                       (messaging_app.db)
```

### Production
```
Frontend (React)          Backend (Flask)          Database
Vercel                 →  Render              →   CockroachDB
project-ageis             projectageis             Serverless
.vercel.app               .onrender.com            (PostgreSQL)
```

---

## 🎯 Quick Reference

### Start Development
```bash
# Terminal 1 - Backend
cd backend
python run.py

# Terminal 2 - Frontend
cd frontend
npm start
```

### Deploy to Production
```bash
# Push to GitHub
git add .
git commit -m "Deploy to production"
git push origin main

# Automatic deployments:
# - Render rebuilds backend
# - Vercel rebuilds frontend
```

### Check Deployment Status
- **Backend**: https://projectageis.onrender.com/healthz
- **Frontend**: https://project-ageis.vercel.app
- **Database**: CockroachDB Dashboard

---

## 📞 Support & Resources

- **Repository**: https://github.com/Geetheshwar420/ProjectAgeis
- **Render Docs**: https://render.com/docs
- **Vercel Docs**: https://vercel.com/docs
- **CockroachDB Docs**: https://www.cockroachlabs.com/docs/

---

**Deployment Status**: ✅ Ready for Production  
**Last Tested**: October 22, 2025  
**Version**: 2.0.0 (Session Auth + Dual Database)
