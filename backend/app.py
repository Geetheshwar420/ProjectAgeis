import os
import sys

# Force Firestore HTTP transport (idempotent — also set in wsgi.py for Gunicorn)
os.environ.setdefault("GOOGLE_CLOUD_FIRESTORE_FORCE_HTTP", "true")

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

# SocketIO async mode: set to 'gevent' by wsgi.py in production, defaults to 'threading' locally
async_mode = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=async_mode)
print(f"[SERVER] SocketIO async_mode={async_mode}")

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
