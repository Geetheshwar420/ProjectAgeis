# Note: Do not use eventlet monkey patch with async_mode='threading' on Windows to avoid deadlocks
from flask import Flask, request
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config
from routes import api
from socket_events import register_socket_events
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize SocketIO
# async_mode='threading' is crucial for Windows/local dev compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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
        response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Standard Flask-CORS setup (using * for origins in dev handles dynamic IPs better)
if os.getenv('FLASK_ENV') != 'production':
    CORS(app, supports_credentials=True, origins=["*"])
else:
    CORS(app, supports_credentials=True, origins=["https://project-ageis.vercel.app/"])

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f"Starting server on port {port}")
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=port)
