import os
import sys

# Eventlet monkey patching MUST happen before any other imports
# Only patch if not already patched by Gunicorn and not on Windows (unless in production)
_eventlet_available = False
if os.name != 'nt' or os.getenv('FLASK_ENV') == 'production':
    try:
        import eventlet
        from eventlet import patcher
        if not patcher.is_monkey_patched('os'):
            eventlet.monkey_patch()
            print("[SERVER] Eventlet monkey patching applied successfully.")
        else:
            print("[SERVER] Eventlet already patched by Gunicorn/Supervisor.")
        _eventlet_available = True
    except ImportError:
        print("[SERVER] Eventlet not found, skipping monkey patch.")

from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config
from routes import api
from socket_events import register_socket_events
import logging

app = Flask(__name__)
app.config.from_object(Config)

# Configure SocketIO with appropriate async mode
# Use eventlet ONLY if it was successfully loaded and patched
async_mode = 'eventlet' if _eventlet_available else 'threading'
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

# Standard Flask-CORS setup
trusted_origins = [
    "https://project-ageis.vercel.app",
    "https://project-ageis-fmhxrlnr4-geetheshwar-linuxs-projects.vercel.app"
]

if os.getenv('FLASK_ENV') != 'production':
    CORS(app, supports_credentials=True, origins=["*"])
else:
    CORS(app, supports_credentials=True, origins=trusted_origins)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logging.info("Starting server on port %s", port)
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=port)
