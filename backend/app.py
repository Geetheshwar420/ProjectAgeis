# Monkey-patch eventlet FIRST to avoid runtime warnings with gunicorn --worker-class eventlet
import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify, session
import os
import re
import logging
import sqlite3
import base64
from concurrent.futures import ThreadPoolExecutor
from flask_cors import CORS
from functools import wraps

from flask_socketio import SocketIO, emit, join_room, leave_room
from utils import create_app, get_db
from db_models import User, Message
from crypto.quantum_service import QuantumCryptoService
from datetime import datetime, timezone

from dotenv import load_dotenv

# Provide a portable background execution helper that prefers eventlet.tpool when available,
# and falls back to a standard ThreadPoolExecutor otherwise.
try:
    # Some environments may not expose eventlet.tpool; guard access here
    from eventlet import tpool as _eventlet_tpool  # type: ignore

    def run_in_bg(func, *args, **kwargs):
        return _eventlet_tpool.execute(func, *args, **kwargs)
except Exception:
    _bg_executor = ThreadPoolExecutor(max_workers=4)

    def run_in_bg(func, *args, **kwargs):
        future = _bg_executor.submit(func, *args, **kwargs)
        return future.result()

# Load environment variables from .env files when running locally
print("Attempting to load .env file...")
# Explicitly check for the .env file and print the result
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    print(f".env file found at: {dotenv_path}")
    load_dotenv(dotenv_path=dotenv_path, verbose=True)
else:
    print(f"Warning: .env file not found at {dotenv_path}")

def init_app_database():
    """Initialize database tables if they don't exist and ensure required columns.

    This function is safe to run multiple times. In addition to creating base
    tables the first time, it will backfill newer columns used by the app:
    formatted_timestamp, iso_timestamp, session_id, status, delivered_at, read_at.
    """
    from db_adapter import DatabaseAdapter
    
    try:
        with DatabaseAdapter() as db:
            cursor = db.cursor()
            
            # Check if users table exists
            if db.db_type == "postgresql":
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = 'users'
                    );
                """)
            else:
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='users'
                """)
            
            result = cursor.fetchone()
            # Handle different result formats
            if db.db_type == "postgresql":
                # PostgreSQL with RealDictCursor returns dict-like rows
                # Query returns {'exists': True/False}
                if result and isinstance(result, dict):
                    table_exists = result.get('exists', False)
                elif result:
                    # Fallback for tuple/list format
                    table_exists = result[0] if len(result) > 0 else False
                else:
                    table_exists = False
            else:
                # SQLite returns Row object or None
                table_exists = bool(result)
            
            if not table_exists:
                print("📊 Initializing database tables...")
                
                # Create users table
                if db.db_type == "postgresql":
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            username VARCHAR(80) UNIQUE NOT NULL,
                            email VARCHAR(120) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            public_key TEXT,
                            kyber_public_key TEXT,
                            dilithium_public_key TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            public_key TEXT,
                            kyber_public_key TEXT,
                            dilithium_public_key TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                
                # Create messages table
                if db.db_type == "postgresql":
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS messages (
                            id SERIAL PRIMARY KEY,
                            sender_id INTEGER NOT NULL,
                            receiver_id INTEGER NOT NULL,
                            encrypted_content TEXT NOT NULL,
                            signature TEXT,
                            session_key_encrypted TEXT,
                            nonce TEXT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            is_read BOOLEAN DEFAULT FALSE,
                            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            sender_id INTEGER NOT NULL,
                            receiver_id INTEGER NOT NULL,
                            encrypted_content TEXT NOT NULL,
                            signature TEXT,
                            session_key_encrypted TEXT,
                            nonce TEXT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            is_read BOOLEAN DEFAULT 0,
                            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
                        )
                    """)
                
                # Create friend_requests table
                if db.db_type == "postgresql":
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS friend_requests (
                            id SERIAL PRIMARY KEY,
                            requester_id INTEGER NOT NULL,
                            recipient_id INTEGER NOT NULL,
                            status VARCHAR(20) DEFAULT 'pending',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
                            UNIQUE(requester_id, recipient_id)
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS friend_requests (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            requester_id INTEGER NOT NULL,
                            recipient_id INTEGER NOT NULL,
                            status TEXT DEFAULT 'pending',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
                            UNIQUE(requester_id, recipient_id)
                        )
                    """)
                
                # Create friendships table
                if db.db_type == "postgresql":
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS friendships (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            friend_id INTEGER NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
                            UNIQUE(user_id, friend_id)
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS friendships (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            friend_id INTEGER NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
                            UNIQUE(user_id, friend_id)
                        )
                    """)
                
                # Create indexes for better performance
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_messages_sender 
                    ON messages(sender_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_messages_receiver 
                    ON messages(receiver_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_messages_timestamp 
                    ON messages(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_friend_requests_recipient 
                    ON friend_requests(recipient_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_friend_requests_status 
                    ON friend_requests(status)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_friendships_user 
                    ON friendships(user_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_friendships_friend 
                    ON friendships(friend_id)
                """)
                
                db.commit()
                print("✅ Database tables created successfully!")
            else:
                print("✅ Database tables already exist")

            # Ensure required message columns exist (schema backfill)
            try:
                def column_exists(table, column):
                    if db.db_type == "postgresql":
                        cursor.execute(
                            """
                            SELECT 1 FROM information_schema.columns
                             WHERE table_schema = 'public' AND table_name = %s AND column_name = %s
                            """,
                            (table, column)
                        )
                        return cursor.fetchone() is not None
                    else:
                        cursor.execute(f"PRAGMA table_info({table})")
                        rows = cursor.fetchall()
                        # rows: cid, name, type, notnull, dflt_value, pk
                        return any((r[1] if isinstance(r, tuple) else r['name']).lower() == column for r in rows)

                def ensure_column(table, column, col_type):
                    try:
                        if not column_exists(table, column):
                            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                            if not is_production:
                                print(f"   ➕ Added missing column {table}.{column}")
                    except Exception as e:
                        # SQLite older versions may not support certain ALTER variants; ignore non-fatal
                        print(f"⚠️  Could not add column {table}.{column}: {e}")

                # Backfill modern columns used by the app
                ensure_column('messages', 'formatted_timestamp', 'TEXT')
                ensure_column('messages', 'iso_timestamp', 'TEXT')
                ensure_column('messages', 'session_id', 'TEXT')
                ensure_column('messages', 'status', "TEXT DEFAULT 'sent'")
                ensure_column('messages', 'delivered_at', 'TIMESTAMP NULL')
                ensure_column('messages', 'read_at', 'TIMESTAMP NULL')
                db.commit()
            except Exception as schema_err:
                print(f"⚠️  Schema backfill skipped: {schema_err}")
                
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        raise

print("\n" + "="*60)
print("🚀 Starting Quantum Secure Messaging Backend")
print("="*60 + "\n")

# Configure session security based on environment
# Check multiple indicators to determine if we're in production
is_production = (
    os.getenv('FLASK_ENV') == 'production' or 
    os.getenv('RENDER') == 'true' or  # Render sets this automatically
    os.getenv('APP_ENV') == 'production' or
    'onrender.com' in os.getenv('RENDER_EXTERNAL_URL', '')
)

# Initialize database on startup
init_app_database()
    
app = create_app()

print(f"🔍 Environment detection:")
print(f"   FLASK_ENV: {os.getenv('FLASK_ENV', 'not set')}")
print(f"   RENDER: {os.getenv('RENDER', 'not set')}")
print(f"   RENDER_EXTERNAL_URL: {os.getenv('RENDER_EXTERNAL_URL', 'not set')}")
print(f"   → Detected as: {'PRODUCTION' if is_production else 'DEVELOPMENT'}")

app.config['SESSION_COOKIE_SECURE'] = is_production  # True for HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'None' if is_production else 'Lax'  # None for cross-origin in production
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_NAME'] = 'session'  # Explicit cookie name
# Don't set SESSION_COOKIE_DOMAIN - let Flask use the request's host automatically
# This allows cookies to work on localhost, LAN IPs, and production domains

if is_production:
    print("🔒 Production mode: Secure session cookies enabled (SameSite=None, Secure=True)")
else:
    print("🔓 Development mode: Relaxed session cookies (SameSite=Lax, Secure=False)")

# Parse trusted origins from environment variable
# Format: comma-separated list of origins (e.g., "http://localhost:3000,https://example.com")
trusted_origins_env = os.getenv('TRUSTED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000')
trusted_origins = [origin.strip() for origin in trusted_origins_env.split(',') if origin.strip()]

print(f"🌐 CORS Configuration:")
print(f"   TRUSTED_ORIGINS env: {trusted_origins_env}")
print(f"   Parsed origins: {trusted_origins}")

# In development, also allow common private LAN origins on port 3000
private_lan_regex = None
if not is_production:
    private_lan_regex = re.compile(r'^http://((localhost)|(127\.0\.0\.1)|(10\..*)|(192\.168\..*)|(172\.(1[6-9]|2\d|3[0-1])\..*)):3000$')
    trusted_origins.append(private_lan_regex)
    print(f"   Added LAN regex pattern for development")

# Add regex pattern for Vercel preview deployments if ALLOW_VERCEL_PREVIEWS is set
if os.getenv('ALLOW_VERCEL_PREVIEWS', 'false').lower() == 'true':
    vercel_preview_regex = re.compile(r'^https://[a-zA-Z0-9-]+-vercel\.app$')
    trusted_origins.append(vercel_preview_regex)
    print(f"   Added Vercel preview regex pattern")

print(f"   Total origins configured: {len(trusted_origins)}")

# Enable CORS for HTTP routes with explicit configuration
CORS(app, 
     resources={r"/*": {
         "origins": trusted_origins,
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],
         "expose_headers": ["Content-Type"],
         "max_age": 3600
     }}, 
     supports_credentials=True)

print("✅ CORS enabled with credential support")

# Initialize Socket.IO with CORS; filter out regex for this parameter
socketio_allowed_origins = [o for o in trusted_origins if isinstance(o, str)] or "*"
socketio = SocketIO(app, cors_allowed_origins=socketio_allowed_origins, logger=False, engineio_logger=False)

# Instantiate crypto service
crypto_service = QuantumCryptoService()

# Track online users - maps username to socket session ID
online_users = {}  # {username: sid}

def emit_user_status(username, is_online):
    """Notify friends when a user goes online/offline"""
    print(f"👤 User status change: {username} -> {'online' if is_online else 'offline'}")
    
    # Get user's friends to notify them
    db = get_db()
    try:
        # Production schema: requester and recipient columns store user IDs as TEXT
        friends = []
        # Resolve current user's id
        me_row = db.fetchone('SELECT id FROM users WHERE username = %s' if db.db_type == 'postgresql' else 'SELECT id FROM users WHERE username = ?', (username,))
        if me_row:
            me_id = str(me_row['id'] if isinstance(me_row, dict) else me_row[0])
            if db.db_type == 'postgresql':
                rows = db.fetchall(
                    """
                    SELECT u.username AS friend_username
                      FROM friend_requests fr
                      JOIN users u ON (CASE WHEN fr.requester = %s THEN CAST(fr.recipient AS BIGINT) ELSE CAST(fr.requester AS BIGINT) END) = u.id
                     WHERE fr.status = 'accepted'
                       AND (%s = fr.requester OR %s = fr.recipient)
                    """,
                    (me_id, me_id, me_id)
                )
            else:
                rows = db.fetchall(
                    """
                    SELECT CASE WHEN fr.requester = ? THEN u2.username ELSE u1.username END AS friend_username
                      FROM friend_requests fr
                      JOIN users u1 ON CAST(fr.requester AS INTEGER) = u1.id
                      JOIN users u2 ON CAST(fr.recipient AS INTEGER) = u2.id
                     WHERE fr.status = 'accepted'
                       AND (? = fr.requester OR ? = fr.recipient)
                    """,
                    (me_id, me_id, me_id)
                )
            friends = [r['friend_username'] if isinstance(r, dict) else r[0] for r in rows]

        notified = False
        for friend_username in friends:
            if friend_username in online_users:
                socketio.emit('user_status_changed', {
                    'username': username,
                    'is_online': is_online
                }, room=friend_username)
                notified = True
                print(f"   → Notified {friend_username}")

        # Fallback: if no friends detected, broadcast to all online users to ensure UI updates
        if not notified:
            for room_user in list(online_users.keys()):
                if room_user == username:
                    continue
                socketio.emit('user_status_changed', {
                    'username': username,
                    'is_online': is_online
                }, room=room_user)
    except Exception as e:
        print(f"❌ Error emitting user status: {e}")
        import traceback
        traceback.print_exc()

# Add explicit CORS headers to all responses as a fallback
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    
    # Debug logging in development
    if not is_production:
        print(f"📤 After request for {request.method} {request.path}")
        print(f"   Origin: {origin}")
        print(f"   Status: {response.status_code}")
    
    if origin:
        # Check if origin is allowed
        allowed = False
        for trusted_origin in trusted_origins:
            if isinstance(trusted_origin, str):
                if origin == trusted_origin:
                    allowed = True
                    break
            elif hasattr(trusted_origin, 'match'):  # Regex pattern
                if trusted_origin.match(origin):
                    allowed = True
                    break
        
        if allowed:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Max-Age'] = '3600'
            
            if not is_production:
                print(f"   ✅ CORS headers added for allowed origin")
        else:
            print(f"   ❌ Origin '{origin}' not in trusted list")
            print(f"   📋 Trusted origins: {[o for o in trusted_origins if isinstance(o, str)]}")
    
    return response

# Simple health check for Render/infra
@app.route('/healthz', methods=['GET'])
def health_check():
    """Health check endpoint for Render and debugging"""
    from datetime import datetime, timezone
    
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'database': 'unknown',
        'crypto': 'initialized' if crypto_service else 'not initialized',
        'env': {
            'flask_env': os.getenv('FLASK_ENV', 'not set'),
            'has_database_url': bool(os.getenv('DATABASE_URL')),
            'has_secret_key': bool(os.getenv('SECRET_KEY'))
        }
    }
    
    # Test database connection and table existence
    try:
        db = get_db()
        cursor = db.cursor()
        try:
            # Test basic connectivity
            cursor.execute("SELECT 1")
            cursor.fetchone()
            
            # Check if users table exists
            if db.db_type == "postgresql":
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = 'users'
                """)
            else:
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='users'
                """)
            
            users_table_exists = cursor.fetchone() is not None
            
            health_status['database'] = {
                'connected': True,
                'type': db.db_type,
                'users_table_exists': users_table_exists
            }
            if not users_table_exists:
                health_status['status'] = 'degraded'
                health_status['warning'] = 'Database connected but tables not initialized. Run init_db_standalone.py'
        finally:
            cursor.close()
    except Exception as e:
        health_status['database'] = {
            'connected': False,
            'error': str(e),
            'error_type': type(e).__name__
        }
        health_status['status'] = 'unhealthy'
        return jsonify(health_status), 503
    
    status_code = 200 if health_status['status'] == 'healthy' else 500
    return jsonify(health_status), status_code

# Simple session-based auth decorator
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/register', methods=['POST'])
def register():
    print(f"📝 Registration request received from {request.remote_addr}")
    print(f"   Content-Type: {request.content_type}")
    print(f"   Origin: {request.headers.get('Origin', 'not set')}")
    
    data = request.get_json(silent=True) or {}
    print(f"   Data received: {list(data.keys()) if data else 'empty'}")
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not isinstance(username, str) or not username.strip():
        print(f"   ❌ Validation failed: Invalid username")
        return jsonify({'error': 'Valid username is required'}), 400
    if not isinstance(password, str) or len(password) < 6:
        print(f"   ❌ Validation failed: Password too short")
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if not isinstance(email, str) or '@' not in email:
        print(f"   ❌ Validation failed: Invalid email")
        return jsonify({'error': 'Valid email is required'}), 400

    db = get_db()
    # Check uniqueness
    if User.find_by_username(db, username):
        print(f"   ❌ Username '{username}' already exists")
        return jsonify({'error': 'Username already exists'}), 400
    if User.find_by_email(db, email):
        print(f"   ❌ Email '{email}' already in use")
        return jsonify({'error': 'Email already in use'}), 400

    try:
        print(f"   💾 Creating user: {username}")
        user = User(username=username, password=password, email=email)
        user_id = user.save(db)
        # Set session
        session['username'] = username
        session['email'] = email
        session.permanent = True
        
        # Store user's password as seed for deterministic key generation
        crypto_service.set_user_seed(username, password)
        
        print(f"   ✅ User registered successfully: {username} (ID: {user_id})")
        return jsonify({'message': 'Registration successful', 'user': {'username': username, 'email': email}}), 201
    except Exception as e:
        logging.error(f"Registration failed: {e}", exc_info=True)
        print(f"   ❌ Registration exception: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'Username and password must be strings'}), 400

    db = get_db()
    try:
        user = User.find_by_username(db, username)
    except Exception as e:
        print(f'Login DB error: {e}')
        return jsonify({'error': 'Service unavailable (database).'}), 503

    if user and User.check_password(user, password):
        # Store user info in session
        session['username'] = user['username']
        session['email'] = user['email']
        session.permanent = True
        
        # Store user's password as seed for deterministic key generation
        # This ensures both users in a conversation can derive the same session key
        crypto_service.set_user_seed(username, password)

        response = jsonify({
            'message': 'Login successful',
            'user': {
                'username': user['username'],
                'email': user['email']
            }
        })
        return response, 200

    return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/me', methods=['GET'])
@login_required
def get_current_user():
    # Reduce sensitive logging; only log minimal info in development
    if not is_production:
        try:
            print(f"[DEBUG /me] Session keys: {list(session.keys())}")
            print(f"[DEBUG /me] Request host: {request.host}")
        except Exception:
            pass
    return jsonify({
        'username': session.get('username'),
        'email': session.get('email')
    }), 200


@app.route('/users', methods=['GET'])
@login_required
def get_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT username, kyber_public_key, dilithium_public_key
        FROM users
    ''')
    rows = cursor.fetchall()
    users = []
    for row in rows:
        users.append({
            'username': row['username'],
            'keys': {
                'kyber_public_key': row['kyber_public_key'],
                'dilithium_public_key': row['dilithium_public_key']
            }
        })
    return jsonify(users), 200


@app.route('/user/status/<username>', methods=['GET'])
@login_required
def get_user_status(username):
    """Check if a specific user is currently online"""
    is_online = username in online_users
    return jsonify({
        'username': username,
        'is_online': is_online
    }), 200


@socketio.on('connect')
def handle_connect(auth=None):
    """
    Handle SocketIO connection with session-based validation.
    Expects the client to send session cookie.
    """
    try:
        print(f'🔌 Socket.IO connection attempt')
        print(f'   Session data: {dict(session)}')
        print(f'   Has username: {"username" in session}')
        
        # Check if user is authenticated via session
        if 'username' not in session:
            print('❌ Connection rejected: User not authenticated')
            return False  # Reject connection
        
        user_id = session['username']
        
        # Join room with the authenticated user's ID
        join_room(user_id)
        
        # Track user as online
        online_users[user_id] = request.sid
        
        print(f'✅ Client {user_id} connected and joined room.')
        print(f'   Online users: {list(online_users.keys())}')
        
        # Notify friends that this user is now online
        emit_user_status(user_id, is_online=True)
        
        # Send current online status of friends to this user
        emit('online_users_list', {'users': list(online_users.keys())})

        # Deliver any stored (undelivered) messages to this user and then delete them
        try:
            db = get_db()
            if db.db_type == 'postgresql':
                rows = db.fetchall(
                    """
                    SELECT id, sender_id, recipient_id, encrypted_message, signature,
                           nonce, tag, formatted_timestamp, iso_timestamp
                      FROM messages
                     WHERE recipient_id = %s AND (status = 'sent' OR status IS NULL)
                  ORDER BY timestamp ASC
                    """,
                    (user_id,)
                )
            else:
                rows = db.fetchall(
                    """
                    SELECT id, sender_id, recipient_id, encrypted_message, signature,
                           nonce, tag, formatted_timestamp, iso_timestamp
                      FROM messages
                     WHERE recipient_id = ? AND (status = 'sent' OR status IS NULL)
                  ORDER BY timestamp ASC
                    """,
                    (user_id,)
                )

            for row in rows:
                payload = {
                    '_id': str(row['id']),
                    'sender_id': row['sender_id'],
                    'recipient_id': row['recipient_id'],
                    'encrypted_message': row['encrypted_message'],
                    'signature': row['signature'],
                    'nonce': row['nonce'],
                    'tag': row['tag'],
                    'formatted_timestamp': row.get('formatted_timestamp') or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'timestamp': row.get('iso_timestamp') or datetime.now(timezone.utc).isoformat()
                }
                # Deliver to recipient
                emit('new_message', payload, room=user_id)
                # Notify sender that delivery occurred
                socketio.emit('message_delivered', {
                    'message_id': payload['_id'],
                    'delivered_at': datetime.now(timezone.utc).isoformat()
                }, room=payload['sender_id'])

            if rows:
                ids = [r['id'] for r in rows]
                if db.db_type == 'postgresql':
                    placeholders = ','.join(['%s'] * len(ids))
                    db.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids, add_returning_id=False)
                else:
                    placeholders = ','.join(['?'] * len(ids))
                    db.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids, add_returning_id=False)
                db.commit()
                print(f"🗑️  Deleted {len(ids)} delivered offline messages for {user_id}")
        except Exception as deliver_err:
            print(f"⚠️  Failed to deliver offline messages: {deliver_err}")
        
    except Exception as e:
        print(f'❌ Connection error: {str(e)}')
        import traceback
        traceback.print_exc()
        return False  # Reject connection


@socketio.on('disconnect')
def handle_disconnect(*args):
    """Handle user disconnection and update online status"""
    try:
        if 'username' in session:
            user_id = session['username']
            
            # Remove from online users
            if user_id in online_users:
                del online_users[user_id]
                print(f'👋 Client {user_id} disconnected')
                print(f'   Online users: {list(online_users.keys())}')
                
                # Notify friends that this user is now offline
                emit_user_status(user_id, is_online=False)
        else:
            print('Client disconnected (not authenticated)')
    except Exception as e:
        print(f'❌ Disconnect error: {str(e)}')


@socketio.on('send_message')
def handle_send_message(data):
    """Handle incoming messages with comprehensive error handling and validation."""
    try:
        print(f'\n📨 Received send_message event')
        print(f'   Session username: {session.get("username", "NOT SET")}')
        print(f'   Data keys: {list(data.keys())}')

        # Check authentication
        if 'username' not in session:
            print(f'❌ Authentication failed: No username in session')
            emit('message_error', {
                'error': 'Unauthorized',
                'message': 'You must be logged in to send messages'
            })
            return

        # Accept either inner fields (legacy) or Kyber-packaged envelope
        sender_id = data.get('sender_id')
        recipient_id = data.get('recipient_id')
        client_msg_id = data.get('client_msg_id')
        encrypted_message = data.get('encrypted_message')
        signature = data.get('signature')
        nonce = data.get('nonce')
        tag = data.get('tag')
        kyber_ct = data.get('kyber_ct')
        outer_ciphertext = data.get('outer_ciphertext')
        outer_nonce = data.get('outer_nonce')
        outer_tag = data.get('outer_tag')

        print(f'   Sender: {sender_id}')
        print(f'   Recipient: {recipient_id}')
        print(f'   Has encrypted_message: {bool(encrypted_message)}')
        print(f'   Has signature: {bool(signature)}')
        print(f'   Has nonce: {bool(nonce)}')
        print(f'   Has tag: {bool(tag)}')

        # If Kyber envelope present, try to unpack to get inner fields
        if all([kyber_ct, outer_ciphertext, outer_nonce, outer_tag, sender_id, recipient_id]):
            try:
                inner = crypto_service.unpack_with_kyber(recipient_id, kyber_ct, outer_ciphertext, outer_nonce, outer_tag)
                encrypted_message = inner.get('ciphertext')
                signature = inner.get('signature')
                nonce = inner.get('nonce')
                tag = inner.get('tag')
                print('🔓 Unpacked Kyber envelope successfully')
            except Exception as e:
                print(f'❌ Failed to unpack Kyber envelope: {e}')
                emit('message_error', {
                    'error': 'Invalid encrypted envelope',
                    'message': 'Message could not be unpacked'
                })
                return

        # Validate that inner required fields are present
        if not all([sender_id, recipient_id, encrypted_message, signature, nonce, tag]):
            missing_fields = []
            if not sender_id: missing_fields.append('sender_id')
            if not recipient_id: missing_fields.append('recipient_id')
            if not encrypted_message: missing_fields.append('encrypted_message')
            if not signature: missing_fields.append('signature')
            if not nonce: missing_fields.append('nonce')
            if not tag: missing_fields.append('tag')

            print(f'❌ Missing required fields: {missing_fields}')
            emit('message_error', {
                'error': 'Missing required fields',
                'message': f'Missing: {", ".join(missing_fields)}'
            })
            return

        # Verify sender is the authenticated user
        if sender_id != session['username']:
            print(f'❌ Authorization failed: {sender_id} != {session["username"]}')
            emit('message_error', {
                'error': 'Unauthorized',
                'message': 'You can only send messages as yourself'
            })
            return

        print(f'✅ Validation passed')

        # Get database connection with error handling
        try:
            print(f'📊 Getting database connection...')
            db = get_db()
            print(f'✅ Database connection successful')
        except Exception as db_error:
            logging.error(f'Database connection failed in send_message: {db_error}')
            print(f'❌ Database connection failed: {db_error}')
            emit('message_error', {
                'error': 'Database unavailable',
                'message': 'Unable to save message. Please check your connection and try again.'
            })
            return

        # Decide delivery path based on recipient online status
        recipient_online = recipient_id in online_users
        print(f"📶 Recipient online? {recipient_online}")

        # Generate server-side timestamp
        now_dt = datetime.now(timezone.utc)
        formatted_timestamp = now_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        iso_timestamp = now_dt.isoformat()

        message_id = None
        if not recipient_online:
            # Store-and-forward for offline recipient
            try:
                print('💾 Storing offline message for later delivery...')
                if db.db_type == 'postgresql':
                    insert_sql = (
                        """
                        INSERT INTO messages (sender_id, recipient_id, encrypted_message, signature,
                                              nonce, tag, timestamp, formatted_timestamp, iso_timestamp, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'sent')
                        RETURNING id
                        """
                    )
                    cur = db.execute(insert_sql, (
                        sender_id, recipient_id, encrypted_message, signature, nonce, tag,
                        now_dt, formatted_timestamp, iso_timestamp
                    ))
                    message_id = db.get_last_insert_id(cur)
                else:
                    insert_sql = (
                        """
                        INSERT INTO messages (sender_id, recipient_id, encrypted_message, signature,
                                              nonce, tag, timestamp, formatted_timestamp, iso_timestamp, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent')
                        """
                    )
                    cur = db.execute(insert_sql, (
                        sender_id, recipient_id, encrypted_message, signature, nonce, tag,
                        now_dt, formatted_timestamp, iso_timestamp
                    ), add_returning_id=False)
                    message_id = db.get_last_insert_id(cur)
                db.commit()
                print(f"✅ Stored offline message id={message_id}")
            except Exception as save_err:
                db.rollback()
                logging.error(f'Failed to store offline message: {save_err}', exc_info=True)
                emit('message_error', {
                    'error': 'Failed to save message',
                    'message': 'Your message could not be saved for offline delivery.'
                })
                return

        # Build common message payload
        message_data = {
            '_id': str(message_id) if message_id is not None else None,
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'client_msg_id': client_msg_id,
            'encrypted_message': encrypted_message,
            'signature': signature,
            'nonce': nonce,
            'tag': tag,
            'formatted_timestamp': formatted_timestamp,
            'timestamp': iso_timestamp
        }

        # Emit to appropriate rooms
        if recipient_online:
            emit('new_message', message_data, room=recipient_id)
            emit('new_message', message_data, room=sender_id)
            # Inform sender the message reached the recipient
            emit('message_delivered', {
                'client_msg_id': client_msg_id,
                'message_id': message_data['_id'],
                'delivered_at': iso_timestamp
            }, room=sender_id)
        else:
            # Only echo to sender when recipient is offline
            emit('new_message', message_data, room=sender_id)

        # Acknowledge send handling to sender
        emit('message_sent', {
            'message_id': str(message_id) if message_id is not None else None,
            'client_msg_id': client_msg_id,
            'timestamp': formatted_timestamp
        }, room=sender_id)
        print('✅ Message processing complete')

    except Exception as e:
        # Catch-all for any unexpected errors
        logging.error(f'Unexpected error in send_message handler: {e}', exc_info=True)
        print(f'❌ Unexpected error in send_message: {e}')
        import traceback
        traceback.print_exc()
        emit('message_error', {
            'error': 'Internal server error',
            'message': 'An unexpected error occurred. Please try again or contact support.'
        })


@socketio.on('message_read')
def handle_message_read(data):
    """Handle read receipt from recipient and forward to sender."""
    try:
        msg_id = data.get('message_id')
        client_msg_id = data.get('client_msg_id')
        sender_id = data.get('sender_id')
        recipient_id = data.get('recipient_id')

        if not sender_id or not recipient_id:
            return

        # Best-effort DB update (if message exists)
        try:
            db = get_db()
            if msg_id:
                if db.db_type == 'postgresql':
                    db.execute("UPDATE messages SET status = 'read', read_at = NOW() WHERE id = %s", (int(msg_id),))
                else:
                    db.execute("UPDATE messages SET status = 'read', read_at = CURRENT_TIMESTAMP WHERE id = ?", (int(msg_id),), add_returning_id=False)
                db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            print(f"⚠️  Failed to update read status: {e}")

        # Forward to sender room
        socketio.emit('message_read', {
            'message_id': str(msg_id) if msg_id else None,
            'client_msg_id': client_msg_id,
            'reader_id': recipient_id,
            'read_at': datetime.now(timezone.utc).isoformat()
        }, room=sender_id)
    except Exception as e:
        print(f"❌ Error in message_read handler: {e}")


@app.route('/initiate_qke', methods=['POST'])
@login_required
def initiate_qke():
    data = request.get_json()
    user_a = data.get('user_a')
    user_b = data.get('user_b')
    
    db = get_db()
    try:
        # Ensure both users have keypairs
        # ⚠️ SECURITY FIX: Secret keys are never stored in database
        # If keypairs don't exist in memory, regenerate them (user will need to re-establish sessions)
        if user_a not in crypto_service.user_keypairs:
            user_a_data = User.find_by_username(db, user_a)
            # Explicitly validate existence to avoid silent skips leading to later failures
            if not user_a_data:
                return jsonify({'error': f"User '{user_a}' not found"}), 404
            # Regenerate keypairs (secret keys are ephemeral, not persisted)
            print(f"⚠️ Regenerating keypairs for {user_a} (secret keys are not persisted)")
            crypto_service.generate_user_keypairs(user_a)
        
        if user_b not in crypto_service.user_keypairs:
            user_b_data = User.find_by_username(db, user_b)
            # Explicitly validate existence to avoid silent skips leading to later failures
            if not user_b_data:
                return jsonify({'error': f"User '{user_b}' not found"}), 404
            # Regenerate keypairs (secret keys are ephemeral, not persisted)
            print(f"⚠️ Regenerating keypairs for {user_b} (secret keys are not persisted)")
            crypto_service.generate_user_keypairs(user_b)
        
        # Initiate quantum key exchange (may reuse an existing ready session)
        session_info = crypto_service.initiate_quantum_key_exchange(user_a, user_b)
        session_id = session_info['session_id']

        # If we are reusing an existing ready session, do not alter keys; just return ready
        if session_info.get('reused'):
            info = crypto_service.get_session_info(session_id)
            return jsonify({
                'session_id': session_id,
                'status': 'ready',
                'bb84_complete': info.get('has_bb84_key', False),
                'kyber_complete': info.get('has_kyber_secret', False),
                'key_derived': info.get('has_session_key', False)
            })

        # Otherwise, complete the key exchange for this new session
        kyber_result = crypto_service.perform_kyber_encapsulation(session_id, user_b)
        key_result = crypto_service.derive_session_key(session_id)

        return jsonify({
            'session_id': session_id,
            'status': 'ready',
            'bb84_complete': session_info['status'] == 'bb84_complete',
            'kyber_complete': kyber_result['status'] == 'success',
            'key_derived': key_result['status'] == 'ready'
        })
    except Exception as e:
        logging.error(f"/initiate_qke failed: {e}", exc_info=True)
        return jsonify({'error': 'Failed to initiate secure session'}), 500


@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400

    session_id = data.get('session_id')
    message = data.get('message')

    # Validate inputs before processing
    if session_id is None or not isinstance(session_id, str) or not session_id.strip():
        return jsonify({'error': 'Valid session_id is required'}), 400

    if message is None or not isinstance(message, str):
        return jsonify({'error': 'Message must be a string'}), 400

    message_bytes = message.encode('utf-8')

    try:
        encrypted_data = crypto_service.encrypt_message(session_id, message_bytes)
        return jsonify(encrypted_data)
    except Exception as e:
        logging.error(f"/encrypt failed: {e}", exc_info=True)
        return jsonify({'error': 'Encryption failed'}), 400

@app.route('/prepare_message', methods=['POST'])
@login_required
def prepare_message():
    """
    End-to-end preparation of a message according to pipeline:
    1) Encrypt plaintext with session (BB84-derived) key (AES-GCM)
    2) Sign the ciphertext with Dilithium (sender's key)
    3) Package the (ciphertext, nonce, tag, signature) using Kyber envelope to recipient

    Request JSON:
      { session_id: str, sender_id: str, recipient_id: str, message: str }

    Response JSON:
      { sender_id, recipient_id, kyber_ct, outer_ciphertext, outer_nonce, outer_tag, formatted_timestamp }
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400

    session_id = data.get('session_id')
    sender_id = data.get('sender_id')
    recipient_id = data.get('recipient_id')
    message = data.get('message')

    # AuthN: ensure the sender matches the logged-in user
    if sender_id is None or sender_id != session.get('username'):
        return jsonify({'error': 'Unauthorized: sender mismatch'}), 401

    # Validate inputs
    for name, value in [('session_id', session_id), ('sender_id', sender_id), ('recipient_id', recipient_id)]:
        if value is None or not isinstance(value, str) or not value.strip():
            return jsonify({'error': f'Valid {name} is required'}), 400
    if message is None or not isinstance(message, str):
        return jsonify({'error': 'Message must be a string'}), 400

    try:
        # Ensure keypairs exist for sender and recipient (secrets are in-memory and may be lost after worker restarts)
        try:
            db = get_db()
            from_username_list = [sender_id, recipient_id]
            for uid in from_username_list:
                if uid not in crypto_service.user_keypairs:
                    user_row = User.find_by_username(db, uid)
                    if not user_row:
                        return jsonify({'error': f"User '{uid}' not found"}), 404
                    print(f"⚠️ Regenerating keypairs for {uid} (secret keys are not persisted)")
                    crypto_service.generate_user_keypairs(uid)
        except Exception as ensure_keys_err:
            logging.error(f"Failed ensuring user keypairs: {ensure_keys_err}", exc_info=True)
            return jsonify({'error': 'Key setup failed'}), 400

        # 1) Encrypt with session key
        enc = crypto_service.encrypt_message(session_id, message.encode('utf-8'))
        if enc.get('status') == 'failed':
            return jsonify({'error': enc.get('error', 'Encryption failed')}), 400

        # 2) Sign ciphertext with sender's Dilithium key (offloaded to eventlet thread pool to avoid worker timeouts)
        ciphertext_bytes = base64.b64decode(enc['ciphertext'])
        try:
            sig = run_in_bg(crypto_service.sign_message, sender_id, ciphertext_bytes)
        except Exception as tpool_err:
            logging.error(f"Signing (tpool) failed: {tpool_err}", exc_info=True)
            return jsonify({'error': f'Signing failed: {str(tpool_err)}'}), 400
        if sig.get('status') == 'failed' or 'signature' not in sig:
            return jsonify({'error': sig.get('error', 'Signing failed')}), 400

        # 3) Package using Kyber envelope to recipient
        inner_payload = {
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'signature': sig['signature']
        }
        try:
            packaged = run_in_bg(crypto_service.package_with_kyber, recipient_id, inner_payload)
        except Exception as tpool_err:
            logging.error(f"Kyber packaging (tpool) failed: {tpool_err}", exc_info=True)
            return jsonify({'error': 'Packaging failed'}), 400

        return jsonify({
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            **packaged,
            'formatted_timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        })
    except Exception as e:
        logging.error(f"/prepare_message failed: {e}", exc_info=True)
        return jsonify({'error': 'Failed to prepare message'}), 400


@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400

    session_id = data.get('session_id')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    tag = data.get('tag')

    # Validate inputs
    if session_id is None or not isinstance(session_id, str) or not session_id.strip():
        return jsonify({'error': 'Valid session_id is required'}), 400
    for name, value in [('ciphertext', ciphertext), ('nonce', nonce), ('tag', tag)]:
        if value is None or not isinstance(value, str) or not value.strip():
            return jsonify({'error': f'{name} is required'}), 400

    try:
        decrypted_data = crypto_service.decrypt_message(session_id, ciphertext, nonce, tag)
        return jsonify(decrypted_data)
    except Exception as e:
        logging.error(f"/decrypt failed: {e}", exc_info=True)
        return jsonify({'error': 'Decryption failed'}), 400


@app.route('/sign', methods=['POST'])
@login_required
def sign():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400

    user_id = data.get('user_id')
    message = data.get('message')

    # Validate user_id before processing
    if user_id is None or not isinstance(user_id, str) or not user_id.strip():
        return jsonify({'error': 'user_id must be a non-empty string'}), 400

    if message is None or not isinstance(message, str):
        return jsonify({'error': 'Message must be a string'}), 400

    message_bytes = message.encode('utf-8')

    try:
        signature_data = crypto_service.sign_message(user_id, message_bytes)
        return jsonify(signature_data)
    except Exception as e:
        logging.error(f"/sign failed: {e}", exc_info=True)
        return jsonify({'error': 'Signing failed'}), 400


@app.route('/verify', methods=['POST'])
@login_required
def verify():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON body'}), 400

    user_id = data.get('user_id')
    message = data.get('message')
    signature = data.get('signature')

    # Validate inputs similar to /encrypt and /sign
    if user_id is None or not isinstance(user_id, str) or not user_id.strip():
        return jsonify({'error': 'Valid user_id is required'}), 400
    if message is None or not isinstance(message, str):
        return jsonify({'error': 'Message must be a string'}), 400
    if signature is None or not isinstance(signature, str) or not signature.strip():
        return jsonify({'error': 'Valid signature is required'}), 400

    message_bytes = message.encode('utf-8')

    try:
        verification_result = crypto_service.verify_signature(user_id, message_bytes, signature)
        return jsonify(verification_result)
    except Exception as e:
        logging.error(f"/verify failed: {e}", exc_info=True)
        return jsonify({'error': 'Verification failed'}), 400


@app.route('/messages', methods=['GET'])
@login_required
def get_messages():
    user_a = request.args.get('user_a')
    user_b = request.args.get('user_b')
    db = get_db()
    # Use correct placeholder style per database
    if db.db_type == 'postgresql':
        rows = db.fetchall('''
            SELECT id, sender_id, recipient_id, encrypted_message, signature,
                   nonce, tag, timestamp, formatted_timestamp, iso_timestamp
              FROM messages
             WHERE (sender_id = %s AND recipient_id = %s)
                OR (sender_id = %s AND recipient_id = %s)
          ORDER BY timestamp ASC
        ''', (user_a, user_b, user_b, user_a))
    else:
        rows = db.fetchall('''
            SELECT id, sender_id, recipient_id, encrypted_message, signature,
                   nonce, tag, timestamp, formatted_timestamp, iso_timestamp
              FROM messages
             WHERE (sender_id = ? AND recipient_id = ?)
                OR (sender_id = ? AND recipient_id = ?)
          ORDER BY timestamp ASC
        ''', (user_a, user_b, user_b, user_a))
    messages = []
    for row in rows:
        messages.append({
            '_id': str(row['id']),
            'sender_id': row['sender_id'],
            'recipient_id': row['recipient_id'],
            'encrypted_message': row['encrypted_message'],
            'signature': row['signature'],
            'nonce': row['nonce'],
            'tag': row['tag'],
            'timestamp': row['iso_timestamp'],
            'formatted_timestamp': row['formatted_timestamp']
        })
    
    # Return messages as-is (encrypted) - client will decrypt them
    return jsonify(messages)


@app.route('/user/<username>', methods=['GET'])
@login_required
def get_user(username):
    db = get_db()
    user = User.find_by_username(db, username)
    if user:
        return jsonify({
            'username': user['username'],
            'email': user['email']
        }), 200
    return jsonify({'error': 'User not found'}), 404


@app.route('/user/<username>', methods=['PUT'])
@login_required
def update_user(username):
    if session.get('username') != username:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    requested_username = data.get('username') if data else None
    new_email = data.get('email') if data else None

    # Disallow username changes to preserve referential integrity across
    # messages, friend_requests, and Socket.IO room keys.
    if requested_username is not None and requested_username != username:
        return jsonify({'error': 'Username cannot be changed'}), 400

    if not new_email or not isinstance(new_email, str):
        return jsonify({'error': 'Valid email is required'}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        if db.db_type == 'postgresql':
            cursor.execute('''
                UPDATE users
                SET email = %s
                WHERE username = %s
            ''', (new_email, username))
        else:
            cursor.execute('''
                UPDATE users
                SET email = ?
                WHERE username = ?
            ''', (new_email, username))
        db.commit()

        # Update session email only
        session['email'] = new_email

        return jsonify({'message': 'Email updated successfully'}), 200
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({'error': 'Email already exists'}), 400


@app.route('/user/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    if session.get('username') != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Delete user and related records in a transaction to prevent orphaned data
        # First, get user ID for foreign key cascades
        if db.db_type == 'postgresql':
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
        else:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return jsonify({'error': 'User not found'}), 404
        user_id = str(user_row['id'] if isinstance(user_row, dict) else user_row[0])
        
        # Delete related records first to maintain referential integrity
        # Messages use username (TEXT) in sender_id/recipient_id columns
        if db.db_type == 'postgresql':
            cursor.execute('DELETE FROM messages WHERE sender_id = %s OR recipient_id = %s', (username, username))
        else:
            cursor.execute('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?', (username, username))
        
        # Friend requests: production schema uses TEXT columns (requester/recipient) storing user IDs
        if db.db_type == 'postgresql':
            cursor.execute('DELETE FROM friend_requests WHERE requester = %s OR recipient = %s', (user_id, user_id))
        else:
            cursor.execute('DELETE FROM friend_requests WHERE requester = ? OR recipient = ?', (user_id, user_id))
        
        # Finally, delete the user
        if db.db_type == 'postgresql':
            cursor.execute('DELETE FROM users WHERE username = %s', (username,))
        else:
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        
        db.commit()
        
        # Clear session after successful deletion
        session.clear()
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        db.rollback()
        logging.error(f"Failed to delete user {username}: {e}", exc_info=True)
        return jsonify({'error': 'Failed to delete user'}), 500
    finally:
        cursor.close()


@app.route('/user/<username>/password', methods=['PUT'])
@login_required
def update_password(username):
    if session.get('username') != username:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    db = get_db()
    user = User.find_by_username(db, username)

    if not User.check_password(user, old_password):
        return jsonify({'error': 'Invalid old password'}), 400

    if new_password != confirm_new_password:
        return jsonify({'error': 'New passwords do not match'}), 400

    hashed_password = User.hash_password(new_password)
    cursor = db.cursor()
    if db.db_type == 'postgresql':
        cursor.execute('''
            UPDATE users
            SET password_hash = %s
            WHERE username = %s
        ''', (hashed_password, username))
    else:
        cursor.execute('''
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
        ''', (hashed_password, username))
    db.commit()

    return jsonify({'message': 'Password updated successfully'}), 200


@app.route('/friend-request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.get_json()
    requester_username = session.get('username')
    recipient_username = data.get('recipient')

    db = get_db()
    cursor = db.cursor()
    try:
        # Get user IDs from usernames for proper foreign key references
        if db.db_type == 'postgresql':
            cursor.execute('SELECT id FROM users WHERE username = %s', (requester_username,))
        else:
            cursor.execute('SELECT id FROM users WHERE username = ?', (requester_username,))
        requester_row = cursor.fetchone()
        if not requester_row:
            return jsonify({'error': 'Requester not found'}), 404
        requester_id = str(requester_row['id'] if isinstance(requester_row, dict) else requester_row[0])
        
        if db.db_type == 'postgresql':
            cursor.execute('SELECT id FROM users WHERE username = %s', (recipient_username,))
        else:
            cursor.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
        recipient_row = cursor.fetchone()
        if not recipient_row:
            return jsonify({'error': 'Recipient not found'}), 404
        recipient_id = str(recipient_row['id'] if isinstance(recipient_row, dict) else recipient_row[0])
        
        # Insert with TEXT columns storing user IDs as strings (production schema)
        if db.db_type == 'postgresql':
            cursor.execute('''
                INSERT INTO friend_requests (requester, recipient, status)
                VALUES (%s, %s, 'pending')
            ''', (requester_id, recipient_id))
        else:
            cursor.execute('''
                INSERT INTO friend_requests (requester, recipient, status)
                VALUES (?, ?, 'pending')
            ''', (requester_id, recipient_id))
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error(f"Friend request creation failed: {e}", exc_info=True)
        return jsonify({'error': 'Friend request already exists'}), 400

    # Use the SocketIO server instance to emit events from HTTP context
    socketio.emit('new_friend_request', {'requester': requester_username}, room=recipient_username, namespace='/')

    return jsonify({'message': 'Friend request sent'}), 201


@app.route('/friend-requests/<username>', methods=['GET'])
@login_required
def get_friend_requests(username):
    if session.get('username') != username:
        return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()
    
        # Production schema: requester and recipient columns store user IDs as TEXT
    # Join with users table to get requester username from user ID
    if db.db_type == 'postgresql':
        rows = db.fetchall('''
                SELECT fr.id, u.username as requester, fr.recipient, fr.status, fr.created_at
              FROM friend_requests fr
                  JOIN users u ON CAST(fr.requester AS BIGINT) = u.id
                 WHERE fr.recipient = (SELECT CAST(id AS TEXT) FROM users WHERE username = %s) 
               AND fr.status = 'pending'
        ''', (username,))
    else:
        rows = db.fetchall('''
                SELECT fr.id, u.username as requester, fr.recipient, fr.status, fr.created_at
              FROM friend_requests fr
                  JOIN users u ON CAST(fr.requester AS INTEGER) = u.id
                 WHERE fr.recipient = (SELECT CAST(id AS TEXT) FROM users WHERE username = ?) 
               AND fr.status = 'pending'
        ''', (username,))

    requests = []
    for row in rows:
        requests.append({
            '_id': str(row['id']),
            'requester': row['requester'],
            'recipient': username,  # We know the recipient is the current user
            'status': row['status']
        })
    return jsonify(requests), 200


@app.route('/friend-request/<request_id>', methods=['PUT'])
@login_required
def update_friend_request(request_id):
    data = request.get_json()
    new_status = data.get('status')
    db = get_db()
    cursor = db.cursor()
    if db.db_type == 'postgresql':
        cursor.execute('''
            UPDATE friend_requests
               SET status = %s
             WHERE id = %s
        ''', (new_status, request_id))
    else:
        cursor.execute('''
            UPDATE friend_requests
               SET status = ?
             WHERE id = ?
        ''', (new_status, request_id))
    db.commit()
    return jsonify({'message': 'Friend request updated'}), 200


@app.route('/friends/<username>', methods=['GET'])
@login_required
def get_friends(username):
    if session.get('username') != username:
        return jsonify({'error': 'Unauthorized'}), 401
    db = get_db()

    # Production schema: requester and recipient columns store user IDs as TEXT
    friends = []
    # Resolve user ID
    me_row = db.fetchone('SELECT id FROM users WHERE username = %s' if db.db_type == 'postgresql' else 'SELECT id FROM users WHERE username = ?', (username,))
    if not me_row:
        return jsonify({'error': 'User not found'}), 404
    me_id = str(me_row['id'] if isinstance(me_row, dict) else me_row[0])

    # Fetch friend usernames via join
    if db.db_type == 'postgresql':
        rows = db.fetchall('''
            SELECT u.username AS friend_username
              FROM friend_requests fr
              JOIN users u ON (CASE WHEN fr.requester = %s THEN CAST(fr.recipient AS BIGINT) ELSE CAST(fr.requester AS BIGINT) END) = u.id
             WHERE fr.status = 'accepted' AND (%s = fr.requester OR %s = fr.recipient)
        ''', (me_id, me_id, me_id))
    else:
        rows = db.fetchall('''
            SELECT CASE WHEN fr.requester = ? THEN u2.username ELSE u1.username END AS friend_username
              FROM friend_requests fr
              JOIN users u1 ON CAST(fr.requester AS INTEGER) = u1.id
              JOIN users u2 ON CAST(fr.recipient AS INTEGER) = u2.id
             WHERE fr.status = 'accepted' AND (? = fr.requester OR ? = fr.recipient)
        ''', (me_id, me_id, me_id))
    friends = [r['friend_username'] if isinstance(r, dict) else r[0] for r in rows]

    return jsonify(friends), 200


if __name__ == '__main__':
    # Parse debug mode from environment variable
    # NEVER enable debug mode in production (security risk: exposes code and enables reloader)
    flask_env = os.getenv('FLASK_ENV', 'production').lower()
    app_debug_env = os.getenv('APP_DEBUG', 'false').lower()
    
    # Debug is enabled only if explicitly set and not in production
    debug_mode = False
    if flask_env != 'production' and app_debug_env in ('true', '1', 'yes'):
        debug_mode = True
    
    # Use PORT provided by hosting (e.g., Render) or default to 5000 locally
    port = int(os.getenv('PORT', '5000'))
    socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode)
