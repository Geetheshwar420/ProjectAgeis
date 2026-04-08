import os
import sys
import logging

# Force Firestore HTTP transport (idempotent — also set in wsgi.py for Gunicorn)
os.environ.setdefault("GOOGLE_CLOUD_FIRESTORE_FORCE_HTTP", "true")

from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config
from routes import api
from socket_events import register_socket_events
import time

def log_ts(msg):
    # Standard log format for Gunicorn to relay to Render
    print(f"[{time.strftime('%H:%M:%S')}] [INIT] {msg}", flush=True)

log_ts("Starting Flask application init...")
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS — use exact origins for credentials support
log_ts("Configuring CORS...")
cors_origins = app.config['TRUSTED_ORIGINS']
CORS(app, supports_credentials=True, resources={r"/*": {"origins": cors_origins}})
log_ts(f"CORS configured for: {cors_origins}")

# SocketIO async mode: set to 'gevent' by wsgi.py in production, defaults to 'threading' locally
log_ts("Configuring SocketIO...")
async_mode = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
socketio = SocketIO(app, cors_allowed_origins=cors_origins, async_mode=async_mode, manage_session=False)
log_ts(f"SocketIO initialized with async_mode={async_mode}")

# Register Blueprints
log_ts("Registering blueprints/routes...")
app.register_blueprint(api)
log_ts("Blueprints registered.")

# Register Socket Events
log_ts("Registering socket events...")
register_socket_events(socketio)
log_ts("Socket events registered. Init complete.")

# cross-origin session cookie settings for Vercel -> Ngrok auth
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True
)

@app.after_request
def add_security_headers(response):
    # Production Profiling: Log every response to identify "NETWORK ERROR" source
    if request.endpoint != 'api.healthz':
        log_ts(f"Response: {response.status} for {request.method} {request.path} from {request.remote_addr}")

    # Support Chrome's Private Network Access and explicit CORS preflight
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Private-Network'] = 'true'
        return response
    
    # Simple headers for development
    if os.getenv('FLASK_ENV') != 'production':
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    else:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Relaxed CSP for production: allow ourselves, Render backend, and Google Fonts
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "connect-src 'self' https://projectageis.onrender.com wss://projectageis.onrender.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: blob:;"
        )
    return response


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    log_ts(f"Starting server on port {port}")
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=port)
