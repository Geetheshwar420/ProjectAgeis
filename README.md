# Quantum-Secure Messaging App

A full-stack secure messaging application with post-quantum cryptography features:
- **Backend**: Flask + Flask-SocketIO + SQLite with session-based authentication
- **Frontend**: React 18 with real-time Socket.IO communication
- **Security**: Post-quantum crypto (BB84, Kyber, Dilithium) + session-based auth

## 🚀 Quick Start (Development)

### Backend Setup (Windows PowerShell):

```powershell
cd backend

# Create and activate virtual environment (recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Copy environment template and configure
if (!(Test-Path .env)) { Copy-Item .env.sample .env }

# Initialize database
python db_init.py

# Start the server
python run.py
```

### Frontend Setup (separate terminal):

```powershell
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

**Access the app:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- Health check: http://localhost:5000/healthz

## ⚙️ Environment Variables

### Backend (`backend/.env`):

```env
# Required
SECRET_KEY=your-secret-key-here

# Optional - defaults shown
SQLITE_DATABASE_PATH=messaging_app.db
TRUSTED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
APP_DEBUG=true
FLASK_ENV=development
```

### Frontend (`frontend/.env`):

```env
# For production builds only (dev uses proxy)
REACT_APP_API_URL=http://localhost:5000
```

## 🔒 Authentication

The app uses **session-based authentication** with HttpOnly cookies:
- No JWT tokens stored in localStorage
- Secure session cookies with CSRF protection
- Sessions persist server-side with 1-hour timeout
- Socket.IO connections authenticated via session cookies

## 📦 Production Deployment

### Backend:

1. **Update environment variables:**
   ```env
   APP_DEBUG=false
   FLASK_ENV=production
   TRUSTED_ORIGINS=https://your-frontend-domain.com
   SECRET_KEY=strong-random-secret-key
   ```

2. **Set session security:**
   - Enable HTTPS
   - Set `SESSION_COOKIE_SECURE=True` in production
   - Configure `SESSION_COOKIE_DOMAIN` for your domain

3. **Deploy:**
   ```powershell
   python run.py
   ```
   - Runs with eventlet (production-ready WSGI server)
   - Use nginx/Apache reverse proxy for HTTPS termination
   - Recommended: Use gunicorn or similar for production

### Frontend:

1. **Build production bundle:**
   ```powershell
   cd frontend
   npm run build
   ```

2. **Deploy:**
   - Upload `build/` folder to hosting platform
   - Platforms: Vercel, Netlify, AWS S3 + CloudFront, etc.
   - Set `REACT_APP_API_URL` to your backend URL before building

## 🧪 Testing

### Health Check:
```powershell
curl http://localhost:5000/healthz
```

### Manual Testing:
1. Register a new account at http://localhost:3000/register
2. Login with credentials
3. Select a user to chat with
4. Send encrypted messages

## 🛠️ Troubleshooting

### Port 5000 already in use:
```powershell
netstat -ano | Select-String ":5000"
Stop-Process -Id <PID> -Force
```

### CORS errors:
- Check `TRUSTED_ORIGINS` includes your frontend origin
- Ensure `withCredentials: true` in frontend API calls
- Verify CORS headers in backend response

### Session not persisting:
- Check browser allows cookies
- Verify `SESSION_COOKIE_SAMESITE` setting
- Ensure frontend uses `withCredentials: true`

### Socket.IO connection fails:
- Verify backend is running and accessible
- Check Socket.IO CORS configuration
- Ensure session cookie is being sent with connection

## 📁 Project Structure

```
messaging_app_capstone/
├── backend/
│   ├── app.py              # Main Flask application
│   ├── run.py              # Server entry point
│   ├── config.py           # Configuration
│   ├── db_models.py        # Database models
│   ├── db_init.py          # Database initialization
│   ├── utils.py            # Helper functions
│   ├── requirements.txt    # Python dependencies
│   ├── .env.sample         # Environment template
│   └── crypto/             # Quantum crypto modules
│       ├── bb84.py         # BB84 quantum key distribution
│       ├── kyber.py        # Kyber KEM
│       ├── dilithium.py    # Dilithium signatures
│       └── quantum_service.py
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API services
│   │   ├── utils/          # Utilities
│   │   └── App.js          # Root component
│   ├── package.json
│   └── .env
└── README.md
```

## 🔐 Security Features

1. **Post-Quantum Cryptography:**
   - BB84: Quantum key exchange simulation
   - Kyber: Post-quantum key encapsulation
   - Dilithium: Post-quantum digital signatures

2. **Session Security:**
   - HttpOnly cookies (prevents XSS)
   - SameSite protection (prevents CSRF)
   - Secure flag for HTTPS
   - Server-side session storage

3. **Transport Security:**
   - CORS with credential support
   - Socket.IO with session authentication
   - Encrypted message payloads

## ⚠️ Notes

- Quantum crypto modules are **educational demonstrations** only
- Not audited for production cryptographic use
- For real deployments:
  - Use production database (PostgreSQL, MySQL)
  - Implement proper key management system
  - Enable HTTPS/TLS everywhere
  - Add rate limiting and input validation
  - Use Redis for session storage at scale

## 📝 License

Educational/Research project - check with your institution for licensing
