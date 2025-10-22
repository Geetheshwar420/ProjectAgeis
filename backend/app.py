# Monkey-patch eventlet FIRST to avoid runtime warnings with gunicorn --worker-class eventlet
import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify, session
import os
import re
import logging
import sqlite3
import base64
from flask_cors import CORS
from functools import wraps

from flask_socketio import SocketIO, emit, join_room, leave_room
from utils import create_app, get_db
from db_models import User, Message
from crypto.quantum_service import QuantumCryptoService
from datetime import datetime, timezone

from dotenv import load_dotenv

# Load environment variables from .env files when running locally
print("Attempting to load .env file...")
# Explicitly check for the .env file and print the result
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    print(f".env file found at: {dotenv_path}")
    load_dotenv(dotenv_path=dotenv_path, verbose=True)
else:
    print(f"Warning: .env file not found at {dotenv_path}")
    
app = create_app()

# Configure session security based on environment
is_production = os.getenv('FLASK_ENV') == 'production'

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

# In development, also allow common private LAN origins on port 3000
private_lan_regex = None
if not is_production:
    private_lan_regex = re.compile(r'^http://((localhost)|(127\.0\.0\.1)|(10\..*)|(192\.168\..*)|(172\.(1[6-9]|2\d|3[0-1])\..*)):3000$')
    trusted_origins.append(private_lan_regex)

# Add regex pattern for Vercel preview deployments if ALLOW_VERCEL_PREVIEWS is set
if os.getenv('ALLOW_VERCEL_PREVIEWS', 'false').lower() == 'true':
    vercel_preview_regex = re.compile(r'^https://[a-zA-Z0-9-]+-vercel\.app$')
    trusted_origins.append(vercel_preview_regex)

# Enable CORS for HTTP routes
CORS(app, resources={r"/*": {"origins": trusted_origins}}, supports_credentials=True)

# Initialize Socket.IO with CORS; filter out regex for this parameter
socketio_allowed_origins = [o for o in trusted_origins if isinstance(o, str)] or "*"
socketio = SocketIO(app, cors_allowed_origins=socketio_allowed_origins, logger=False, engineio_logger=False)

# Instantiate crypto service
crypto_service = QuantumCryptoService()

# Simple health check for Render/infra
@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({
        'status': 'ok',
        'time': datetime.now(timezone.utc).isoformat()
    }), 200

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
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not isinstance(username, str) or not username.strip():
        return jsonify({'error': 'Valid username is required'}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if not isinstance(email, str) or '@' not in email:
        return jsonify({'error': 'Valid email is required'}), 400

    db = get_db()
    # Check uniqueness
    if User.find_by_username(db, username):
        return jsonify({'error': 'Username already exists'}), 400
    if User.find_by_email(db, email):
        return jsonify({'error': 'Email already in use'}), 400

    try:
        user = User(username=username, password=password, email=email)
        user_id = user.save(db)
        # Set session
        session['username'] = username
        session['email'] = email
        session.permanent = True
        
        # Store user's password as seed for deterministic key generation
        crypto_service.set_user_seed(username, password)
        
        return jsonify({'message': 'Registration successful', 'user': {'username': username, 'email': email}}), 201
    except Exception as e:
        logging.error(f"Registration failed: {e}", exc_info=True)
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
    print(f"[DEBUG /me] Session data: {dict(session)}")
    print(f"[DEBUG /me] Session cookie received: {request.cookies.get('session')}")
    print(f"[DEBUG /me] All cookies: {dict(request.cookies)}")
    print(f"[DEBUG /me] Request host: {request.host}")
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


@socketio.on('connect')
def handle_connect():
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
        print(f'✅ Client {user_id} connected and joined room.')
        
    except Exception as e:
        print(f'❌ Connection error: {str(e)}')
        import traceback
        traceback.print_exc()
        return False  # Reject connection


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


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

        # Create message with server-generated timestamp
        # The Message class generates a single timestamp used for DB and client
        print(f'💾 Creating message object...')
        message = Message(sender_id, recipient_id, encrypted_message, signature, nonce, tag)

        # Save to database with error handling
        try:
            print(f'💾 Saving message to database...')
            message_id = message.save(db)
            print(f'✅ Message saved successfully with ID: {message_id}')
        except Exception as save_error:
            logging.error(f'Failed to save message: {save_error}', exc_info=True)
            print(f'❌ Failed to save message: {save_error}')
            emit('message_error', {
                'error': 'Failed to save message',
                'message': 'Your message could not be saved. Please try again.'
            })
            return

        # Use the same timestamp from the Message object for consistency
        # This ensures DB and client receive identical timestamps
        formatted_timestamp = message.formatted_timestamp  # Human-readable format
        iso_timestamp = message.iso_timestamp  # ISO 8601 for ordering/auditing

        message_data = {
            '_id': str(message_id),
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'client_msg_id': client_msg_id,
            'encrypted_message': encrypted_message,
            'signature': signature,
            'nonce': nonce,
            'tag': tag,
            'formatted_timestamp': formatted_timestamp,
            'timestamp': iso_timestamp  # ISO 8601 with timezone for ordering/auditing
        }

        print(f'📤 Emitting message to rooms...')
        print(f'   Recipient room: {recipient_id}')
        print(f'   Sender room: {sender_id}')

        # Emit to both participants
        emit('new_message', message_data, room=recipient_id)
        emit('new_message', message_data, room=sender_id)

        # Send success confirmation to sender
        emit('message_sent', {'message_id': str(message_id), 'timestamp': formatted_timestamp})
        print(f'✅ Message successfully broadcasted')

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
        # 1) Encrypt with session key
        enc = crypto_service.encrypt_message(session_id, message.encode('utf-8'))
        if enc.get('status') == 'failed':
            return jsonify({'error': enc.get('error', 'Encryption failed')}), 400

        # 2) Sign ciphertext with sender's Dilithium key
        sig = crypto_service.sign_message(sender_id, base64.b64decode(enc['ciphertext']))
        if sig.get('status') == 'failed' or 'signature' not in sig:
            return jsonify({'error': sig.get('error', 'Signing failed')}), 400

        # 3) Package using Kyber envelope to recipient
        inner_payload = {
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'tag': enc['tag'],
            'signature': sig['signature']
        }
        packaged = crypto_service.package_with_kyber(recipient_id, inner_payload)

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
    # Use adapter helpers to be portable across SQLite and PostgreSQL
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
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return jsonify({'error': 'User not found'}), 404
        user_id = user_row['id']
        
        # Delete related records first to maintain referential integrity
        # Messages use username (TEXT) in sender_id/recipient_id columns
        cursor.execute('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?', (username, username))
        
        # Friend requests use INTEGER foreign keys (requester/recipient)
        cursor.execute('DELETE FROM friend_requests WHERE requester = ? OR recipient = ?', (user_id, user_id))
        
        # Finally, delete the user
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
        cursor.execute('SELECT id FROM users WHERE username = ?', (requester_username,))
        requester_row = cursor.fetchone()
        if not requester_row:
            return jsonify({'error': 'Requester not found'}), 404
        requester_id = requester_row['id']
        
        cursor.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
        recipient_row = cursor.fetchone()
        if not recipient_row:
            return jsonify({'error': 'Recipient not found'}), 404
        recipient_id = recipient_row['id']
        
        # Insert with INTEGER foreign keys
        cursor.execute('''
            INSERT INTO friend_requests (requester, recipient, status)
            VALUES (?, ?, 'pending')
        ''', (requester_id, recipient_id))
        db.commit()
    except sqlite3.IntegrityError:
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
    cursor = db.cursor()
    
    # JOIN with users table to get requester username from user ID
    cursor.execute('''
        SELECT fr.id, u.username as requester, fr.recipient, fr.status, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.requester = u.id
        WHERE fr.recipient = (SELECT id FROM users WHERE username = ?) 
        AND fr.status = 'pending'
    ''', (username,))
    rows = cursor.fetchall()
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
    cursor = db.cursor()
    
    # Get current user's ID
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_row = cursor.fetchone()
    if not user_row:
        return jsonify({'error': 'User not found'}), 404
    user_id = user_row['id']
    
    # Get friends with JOIN to retrieve usernames
    cursor.execute('''
        SELECT 
            CASE 
                WHEN fr.requester = ? THEN u2.username 
                ELSE u1.username 
            END as friend_username
        FROM friend_requests fr
        JOIN users u1 ON fr.requester = u1.id
        JOIN users u2 ON fr.recipient = u2.id
        WHERE fr.status = 'accepted'
          AND (fr.requester = ? OR fr.recipient = ?)
    ''', (user_id, user_id, user_id))
    rows = cursor.fetchall()
    friends = []
    for row in rows:
        friends.append(row['friend_username'])
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
