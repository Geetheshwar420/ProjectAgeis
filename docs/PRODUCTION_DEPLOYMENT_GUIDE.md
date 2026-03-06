# 🚀 Production Deployment Guide - Project Ageis

**Last Updated**: October 22, 2025  
**Status**: Ready for Production Deployment

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Database Setup (CockroachDB)](#database-setup-cockroachdb)
3. [Backend Deployment (Render)](#backend-deployment-render)
4. [Frontend Deployment (Vercel)](#frontend-deployment-vercel)
5. [Post-Deployment Testing](#post-deployment-testing)
6. [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

### Required Accounts
- ✅ GitHub account (for code repository)
- ✅ CockroachDB Cloud account (for database)
- ✅ Render account (for backend hosting)
- ✅ Vercel account (for frontend hosting)

### Local Setup Verification
Before deploying, ensure your local setup works:

```powershell
# 1. Backend is running without errors
cd backend
python run.py

# 2. Frontend builds successfully
cd frontend
npm run build

# 3. Database is initialized
cd backend
python init_db_standalone.py
```

---

## 🗄️ Database Setup (CockroachDB)

### Step 1: Create CockroachDB Serverless Cluster

1. **Login to CockroachDB Cloud**
   - Go to: https://cockroachlabs.cloud/
   - Sign in with your account

2. **Create a New Cluster**
   - Click "Create Cluster"
   - Select **Serverless** plan (Free tier available)
   - Choose region: **AWS ap-south-1** (Mumbai) or closest to your users
   - Cluster name: `messaging-app` or your preferred name

3. **Create SQL User**
   - Username: Choose a secure username (e.g., `admin`)
   - Password: Generate a strong password (save it securely!)
   - Click "Create"

4. **Get Connection String**
   - Click "Connect"
   - Select "General connection string"
   - Copy the connection string (format below):
   ```
   postgresql://username:password@cluster-name.xxx.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full
   ```

5. **Create Application Database**
   - Open SQL Console in CockroachDB dashboard
   - Run: `CREATE DATABASE messaging_app;`
   - Update connection string to use `messaging_app` database:
   ```
   postgresql://username:password@cluster-name.xxx.cockroachlabs.cloud:26257/messaging_app?sslmode=verify-full
   ```

### Step 2: Initialize Database Schema

**Option A: Using Local Script (Recommended)**

1. Update your local `.env` file:
   ```bash
   DATABASE_URL=postgresql://username:password@cluster-name.xxx.cockroachlabs.cloud:26257/messaging_app?sslmode=verify-full
   ```

2. Run initialization script:
   ```powershell
   cd backend
   python init_db_standalone.py
   ```

3. Verify tables were created:
   - Open CockroachDB SQL Console
   - Run: `SHOW TABLES FROM messaging_app;`
   - Should see: `users`, `messages`, `friend_requests`

**Option B: Using SQL Console**

If the script doesn't work, you can manually create tables in CockroachDB SQL Console using the schema from `backend/db_init.py`.

---

## 🔙 Backend Deployment (Render)

### Step 1: Prepare Repository

1. **Commit and Push Changes**
   ```bash
   git add .
   git commit -m "Production deployment ready with CockroachDB support"
   git push origin main
   ```

2. **Verify render.yaml Configuration**
   - File should be at project root
   - Should include `DATABASE_URL` environment variable

### Step 2: Deploy to Render

1. **Login to Render**
   - Go to: https://render.com/
   - Sign in with your GitHub account

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository: `Geetheshwar420/ProjectAgeis`
   - Render will auto-detect `render.yaml`

3. **Configure Environment Variables**
   - Render will use `render.yaml` settings automatically
   - **IMPORTANT**: Manually add `DATABASE_URL` in Render Dashboard:
     - Go to: Environment → Environment Variables
     - Add new variable:
       - Key: `DATABASE_URL`
       - Value: `postgresql://username:password@cluster-name.xxx.cockroachlabs.cloud:26257/messaging_app?sslmode=verify-full`
     - Click "Save Changes"

4. **Deploy**
   - Click "Create Web Service"
   - Render will automatically:
     - Install dependencies
     - Run health checks
     - Deploy your backend
   - Wait for "Live" status (green)

5. **Verify Deployment**
   - Copy your Render URL: `https://projectageis.onrender.com`
   - Test health endpoint: `https://projectageis.onrender.com/healthz`
   - Should return: `{"status": "healthy"}`

### Step 3: Verify Database Connection

Check Render logs for:
```
🗄️  Database: POSTGRESQL
   Host: cluster-name.xxx.cockroachlabs.cloud
✅ Database connected successfully!
```

If you see connection errors:
- Verify DATABASE_URL is correctly set in Render dashboard
- Check CockroachDB cluster is running
- Verify IP allowlist in CockroachDB (should allow all IPs for serverless)

---

## 🎨 Frontend Deployment (Vercel)

### Step 1: Prepare Frontend Configuration

1. **Update Environment Variables**
   Create `frontend/.env.production`:
   ```bash
   REACT_APP_API_URL=https://projectageis.onrender.com
   ```

2. **Verify Build**
   ```powershell
   cd frontend
   npm run build
   ```
   - Should complete without errors
   - Creates optimized `build/` directory

### Step 2: Deploy to Vercel

1. **Login to Vercel**
   - Go to: https://vercel.com/
   - Sign in with your GitHub account

2. **Import Project**
   - Click "Add New..." → "Project"
   - Import: `Geetheshwar420/ProjectAgeis`
   - Select repository

3. **Configure Project**
   - Framework Preset: **Create React App** (auto-detected)
   - Root Directory: `frontend`
   - Build Command: `npm run build`
   - Output Directory: `build`

4. **Add Environment Variables**
   - Go to: Project Settings → Environment Variables
   - Add:
     - Key: `REACT_APP_API_URL`
     - Value: `https://projectageis.onrender.com`
     - Environment: Production
   - Click "Save"

5. **Deploy**
   - Click "Deploy"
   - Vercel will automatically build and deploy
   - Wait for "Ready" status

6. **Get Production URL**
   - Copy your Vercel URL: `https://project-ageis.vercel.app`

### Step 3: Update Backend CORS

1. **Update Render Environment Variables**
   - Go to Render Dashboard → Your Service → Environment
   - Update `TRUSTED_ORIGINS`:
     ```
     https://project-ageis.vercel.app,https://projectageis.onrender.com
     ```
   - Save changes (will auto-redeploy)

---

## ✅ Post-Deployment Testing

### Test 1: Health Check
```bash
# Backend health
curl https://projectageis.onrender.com/healthz

# Expected: {"status": "healthy"}
```

### Test 2: Registration & Login

1. **Open Frontend**
   - Go to: `https://project-ageis.vercel.app`

2. **Register User A**
   - Click "Register"
   - Username: `testuser1`
   - Email: `test1@example.com`
   - Password: Strong password
   - Click "Register"
   - Should redirect to login

3. **Login User A**
   - Enter credentials
   - Click "Login"
   - Should redirect to `/chat`
   - Check browser console: No errors

4. **Register User B**
   - Logout
   - Register another user: `testuser2`
   - Login as `testuser2`

### Test 3: Friend Requests

1. **Send Friend Request**
   - Login as `testuser1`
   - Go to "Add Friends" or search
   - Send friend request to `testuser2`
   - Should see "Friend request sent"

2. **Accept Friend Request**
   - Logout, login as `testuser2`
   - Check friend requests section
   - Accept request from `testuser1`
   - Should see `testuser1` in friends list

### Test 4: Messaging

1. **Send Message**
   - Login as `testuser1`
   - Select `testuser2` from friends list
   - Type message: "Hello from production!"
   - Click Send
   - Should see message appear in chat

2. **Verify Encryption**
   - Check backend logs in Render:
     ```
     🔐 Initiating quantum key exchange
     ✅ BB84 Protocol complete
     ✅ Kyber encapsulation complete
     ✅ Session key derived
     ```

3. **Receive Message**
   - Open another browser/incognito window
   - Login as `testuser2`
   - Should see message from `testuser1` without refresh

### Test 5: Real-Time Updates (Socket.IO)

1. **Two Windows Test**
   - Window 1: Login as `testuser1`
   - Window 2: Login as `testuser2`
   - Send message from `testuser1`
   - **Expected**: Message appears in `testuser2`'s window immediately

2. **Check Socket Connection**
   - Open browser DevTools → Console
   - Should see: "Socket.IO connected"
   - No CORS errors

### Test 6: Multi-Device Test

1. **Desktop + Mobile**
   - Desktop: Login as `testuser1`
   - Mobile: Login as `testuser2`
   - Send messages both ways
   - Verify real-time updates work

2. **Network Test**
   - Different WiFi networks
   - Mobile data + WiFi
   - Should work across all networks

---

## 🐛 Troubleshooting

### Issue 1: CORS Errors in Browser Console

**Symptoms**:
```
Access to XMLHttpRequest at 'https://projectageis.onrender.com' from origin 'https://project-ageis.vercel.app' has been blocked by CORS policy
```

**Solution**:
1. Check `TRUSTED_ORIGINS` in Render environment variables
2. Should include both frontend and backend URLs
3. No trailing slashes
4. Use exact URLs (not wildcards)

---

### Issue 2: Socket.IO Connection Failed

**Symptoms**:
```
WebSocket connection to 'wss://projectageis.onrender.com/socket.io/' failed
```

**Solution**:
1. Check Render logs for Socket.IO initialization
2. Verify `cors_credentials=True` in `app.py`
3. Check `SOCKETIO_CORS_ALL` is `false` in production
4. Verify frontend Socket.IO client has `withCredentials: true`

---

### Issue 3: Database Connection Timeout

**Symptoms**:
```
psycopg2.OperationalError: could not connect to server
```

**Solution**:
1. Verify CockroachDB cluster is running
2. Check DATABASE_URL format:
   - Should end with `?sslmode=verify-full`
   - No spaces in connection string
3. Check CockroachDB IP allowlist (serverless should allow all)
4. Verify database name exists: `messaging_app`

---

### Issue 4: Session Cookies Not Working

**Symptoms**:
- Login succeeds but redirects back to login
- `/me` endpoint returns 401

**Solution**:
1. Check `SESSION_COOKIE_SECURE=True` in production
2. Verify `SESSION_COOKIE_SAMESITE='None'` for cross-origin
3. Check `SESSION_COOKIE_HTTPONLY=True`
4. Ensure frontend Axios has `withCredentials: true`

---

### Issue 5: Keypair KeyError on Message Send

**Symptoms**:
```
KeyError: 'kyber_public'
```

**Solution**:
1. Drop and recreate database tables
2. Re-register users (old users won't have secret keys)
3. Verify `generate_user_keypairs()` returns all 4 keys
4. Check database has columns: `kyber_secret_key`, `dilithium_secret_key`

---

### Issue 6: Build Fails on Render

**Symptoms**:
```
ERROR: Could not install packages due to an OSError
```

**Solution**:
1. Check `requirements.txt` has correct versions
2. Verify Python version in `render.yaml` matches local: `3.12.0`
3. Check for conflicting dependencies
4. Try deploying with `pip install --upgrade pip` in buildCommand

---

## 📊 Production Monitoring

### Key Metrics to Monitor

1. **Backend (Render)**
   - Response times (should be < 500ms)
   - Error rate (should be < 1%)
   - Memory usage (should be stable)
   - Database connections (should not leak)

2. **Frontend (Vercel)**
   - Page load time (should be < 3s)
   - Build success rate (should be 100%)
   - Bundle size (should be < 1MB)

3. **Database (CockroachDB)**
   - Connection count (monitor for leaks)
   - Query performance (slow queries)
   - Storage usage (serverless limits)

### Logging

**Backend Logs (Render)**:
```bash
# View live logs
render logs --tail

# Search for errors
render logs | grep ERROR
```

**Frontend Logs (Vercel)**:
- Go to: Project → Deployments → Click deployment → Logs

**Database Logs (CockroachDB)**:
- Dashboard → Cluster → Monitoring → Slow Queries

---

## 🔒 Security Checklist

- ✅ `SECRET_KEY` is randomly generated (not hardcoded)
- ✅ `DATABASE_URL` is stored securely (not in git)
- ✅ Session cookies use `HttpOnly` + `Secure` + `SameSite`
- ✅ CORS restricted to specific origins (no wildcards)
- ✅ Database credentials are strong passwords
- ✅ SSL/TLS enabled for all connections
- ✅ API rate limiting enabled (if needed)
- ✅ Input validation on all endpoints
- ✅ SQL injection prevented (using parameterized queries)
- ✅ XSS protection (React escapes by default)

---

## 🎉 Success Criteria

Your deployment is successful when:

- ✅ Frontend loads at `https://project-ageis.vercel.app`
- ✅ Backend health check returns 200
- ✅ Users can register and login
- ✅ Friend requests work end-to-end
- ✅ Messages send with encryption (no 500 errors)
- ✅ Real-time updates work (Socket.IO connected)
- ✅ Multi-device messaging works
- ✅ No CORS errors in browser console
- ✅ No database connection errors in Render logs
- ✅ Session persistence works (refresh doesn't logout)

---

## 📞 Support Resources

- **Render Docs**: https://render.com/docs
- **Vercel Docs**: https://vercel.com/docs
- **CockroachDB Docs**: https://www.cockroachlabs.com/docs/
- **Flask-SocketIO**: https://flask-socketio.readthedocs.io/
- **React Deployment**: https://create-react-app.dev/docs/deployment/

---

## 🔄 Continuous Deployment

### Auto-Deploy on Git Push

**Render**:
- Automatically deploys on push to `main` branch
- Can configure branch in Render dashboard

**Vercel**:
- Automatically deploys on push to `main` branch
- Creates preview deployments for PRs

### Manual Deploy

**Render**:
```bash
# From Render dashboard
Dashboard → Service → Manual Deploy → Deploy latest commit
```

**Vercel**:
```bash
# Using Vercel CLI
npm install -g vercel
cd frontend
vercel --prod
```

---

## 📝 Environment Variables Reference

### Backend (Render)

| Variable | Value | Required |
|----------|-------|----------|
| `FLASK_ENV` | `production` | ✅ |
| `APP_DEBUG` | `false` | ✅ |
| `SECRET_KEY` | Auto-generated | ✅ |
| `DATABASE_URL` | CockroachDB connection string | ✅ |
| `TRUSTED_ORIGINS` | `https://project-ageis.vercel.app,https://projectageis.onrender.com` | ✅ |
| `ALLOW_VERCEL_PREVIEWS` | `true` | ⚠️ |
| `SOCKETIO_CORS_ALL` | `false` | ✅ |
| `PYTHON_VERSION` | `3.12.0` | ✅ |

### Frontend (Vercel)

| Variable | Value | Required |
|----------|-------|----------|
| `REACT_APP_API_URL` | `https://projectageis.onrender.com` | ✅ |

---

**Deployment Status**: ✅ Ready for production deployment!
