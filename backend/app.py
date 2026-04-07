import os
import sys

# Force Firestore to use HTTP instead of gRPC to prevent Eventlet conflicts
os.environ["GOOGLE_CLOUD_FIRESTORE_FORCE_HTTP"] = "true"

# Gevent monkey patching — only when running under Gunicorn (production)
# When running locally via `python app.py`, skip patching to avoid Firestore SSL conflicts
_async_available = False
_running_under_gunicorn = 'gunicorn' in os.environ.get('SERVER_SOFTWARE', '') or 'gunicorn' in sys.modules
try:
    import gevent
    from gevent import monkey
    if _running_under_gunicorn:
        if not monkey.is_module_patched('os'):
            monkey.patch_all()
            print("[SERVER] Gevent monkey patching applied (Gunicorn detected).")
        else:
            print("[SERVER] Gevent already patched by Gunicorn.")
        _async_available = True
    else:
        print("[SERVER] Running locally — skipping gevent monkey patch for Firestore compatibility.")
except ImportError:
    print("[SERVER] Gevent not found, skipping monkey patch.")

from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config
from routes import api
from socket_events import register_socket_events
import logging

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS — strip trailing slashes from origins for exact match compliance
cors_origins = [o.rstrip('/') for o in app.config['TRUSTED_ORIGINS']]
CORS(app, supports_credentials=True, resources={r"/*": {"origins": cors_origins}})

# Configure SocketIO with appropriate async mode
# Use gevent ONLY if it was successfully loaded and patched
async_mode = 'gevent' if _async_available else 'threading'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)

# Register Blueprints
app.register_blueprint(api)

# Register Socket Events
register_socket_events(socketio)

# session cookie settings for HTTP/LAN development
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True
)

@app.after_request
def add_security_headers(response):
    # Support Chrome's Private Network Access
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Private-Network'] = 'true'
    
    # Simple headers for development
    if os.getenv('FLASK_ENV') != 'production':
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # No CSP or strict HSTS in development to avoid LAN IP blocks
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
    logging.info("Starting server on port %s", port)
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=port)
