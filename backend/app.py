from flask import Flask, request, jsonify
import os
import re
from bson.objectid import ObjectId
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from utils import create_app, get_db
from db_models import User, Message
from crypto.quantum_service import QuantumCryptoService
from datetime import datetime, timezone

from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token

app = create_app()
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in your production app
jwt = JWTManager(app)

# Configure CORS to allow Vercel frontend and local development
# Use regex for *.vercel.app and allow an explicit FRONTEND_ORIGIN override
frontend_origin = os.getenv('FRONTEND_ORIGIN')
vercel_regex = re.compile(r'^https://.*\.vercel\.app$')
allowed_cors_origins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    vercel_regex,
]
if frontend_origin:
    allowed_cors_origins.append(frontend_origin.rstrip('/'))

CORS(app, resources={
    r"/*": {
        "origins": allowed_cors_origins,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
    }
})

# Configure Socket.IO to allow Vercel frontend
socketio = SocketIO(app, cors_allowed_origins=[
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://*.vercel.app",
    "https://project-ageis.vercel.app/"  # Update with your actual domain
])
db = get_db(app)
crypto_service = QuantumCryptoService()

@app.route('/healthz', methods=['GET'])
def healthz():
    """Basic health check with MongoDB ping and CORS origin echo."""
    details = {
        'status': 'ok',
        'mongo': {'ok': False},
        'cors': {
            'allowed': [str(o) for o in allowed_cors_origins],
        },
        'env': {
            'frontend_origin_set': bool(frontend_origin),
            'mongo_uri_set': bool(os.getenv('MONGO_URI')),
        }
    }
    try:
        # Attempt a ping to confirm DB connectivity
        db.command('ping')
        details['mongo']['ok'] = True
    except Exception as e:
        details['status'] = 'degraded'
        details['mongo']['error'] = str(e)
    return jsonify(details), 200 if details['mongo']['ok'] else 500

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    try:
        if User.find_by_username(db, username):
            return jsonify({'error': 'Username already exists'}), 400

        if User.find_by_email(db, email):
            return jsonify({'error': 'Email already exists'}), 400

        user = User(username, password, email)
        user.save(db)

        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        print(f'Register error: {e}')
        return jsonify({'error': 'Database unavailable. Please try again later.'}), 503

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        user = User.find_by_username(db, username)
    except Exception as e:
        print(f'Login DB error: {e}')
        return jsonify({'error': 'Service unavailable (database).'}), 503

    if user and User.check_password(user, password):
        access_token = create_access_token(identity=user['username'])
        return jsonify({'message': 'Login successful', 'access_token': access_token, 'user': {'username': user['username'], 'email': user['email']}}), 200

    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = list(db.users.find({}, {'_id': 0, 'username': 1, 'keys.kyber_public_key': 1, 'keys.dilithium_public_key': 1}))
    return jsonify(users), 200

@socketio.on('connect')
def handle_connect(auth):
    """
    Handle SocketIO connection with manual JWT validation.
    Expects the client to send JWT token in auth dict (e.g., auth={'token': 'jwt_token_here'}).
    """
    try:
        # Extract token from auth parameters
        if not auth or 'token' not in auth:
            print('Connection rejected: Missing token in auth')
            emit('error', {'message': 'Authentication required'})
            return False  # Reject connection
        
        token = auth['token']
        
        # Manually decode and validate the JWT token
        try:
            decoded = decode_token(token)
            user_id = decoded['sub']  # 'sub' is the standard JWT claim for identity
        except Exception as e:
            print(f'Connection rejected: Invalid token - {str(e)}')
            emit('error', {'message': 'Invalid or expired token'})
            return False  # Reject connection
        
        # Join room with the authenticated user's ID
        join_room(user_id)
        print(f'Client {user_id} connected and joined room.')
        
    except Exception as e:
        print(f'Connection error: {str(e)}')
        emit('error', {'message': 'Connection failed'})
        return False  # Reject connection

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data.get('sender_id')
    recipient_id = data.get('recipient_id')
    encrypted_message = data.get('encrypted_message')
    signature = data.get('signature')
    nonce = data.get('nonce')
    tag = data.get('tag')
    # DO NOT trust client-provided timestamp - generate server-side
    
    # Create message with server-generated timestamp
    # The Message class generates a single timestamp used for DB and client
    message = Message(sender_id, recipient_id, encrypted_message, signature, nonce, tag)
    message_id = message.save(db)
    
    # Use the same timestamp from the Message object for consistency
    # This ensures DB and client receive identical timestamps
    formatted_timestamp = message.formatted_timestamp  # Human-readable format
    iso_timestamp = message.iso_timestamp  # ISO 8601 for ordering/auditing

    message_data = {
        '_id': str(message_id),
        'sender_id': sender_id,
        'recipient_id': recipient_id,
        'encrypted_message': encrypted_message,
        'signature': signature,
        'nonce': nonce,
        'tag': tag,
        'formatted_timestamp': formatted_timestamp,
        'timestamp': iso_timestamp  # ISO 8601 with timezone for ordering/auditing
    }

    emit('new_message', message_data, room=recipient_id)
    emit('new_message', message_data, room=sender_id)

@app.route('/initiate_qke', methods=['POST'])
@jwt_required()
def initiate_qke():
    data = request.get_json()
    user_a = data.get('user_a')
    user_b = data.get('user_b')
    
    try:
        # Ensure both users have keypairs
        if user_a not in crypto_service.user_keypairs:
            user_a_data = User.find_by_username(db, user_a)
            if user_a_data and 'keys' in user_a_data:
                # Restore keypairs from database
                crypto_service.user_keypairs[user_a] = user_a_data['keys']
        
        if user_b not in crypto_service.user_keypairs:
            user_b_data = User.find_by_username(db, user_b)
            if user_b_data and 'keys' in user_b_data:
                # Restore keypairs from database
                crypto_service.user_keypairs[user_b] = user_b_data['keys']
        
        # Initiate quantum key exchange
        session_info = crypto_service.initiate_quantum_key_exchange(user_a, user_b)
        
        # Automatically complete the key exchange
        session_id = session_info['session_id']
        
        # Perform Kyber encapsulation (user_a encapsulates to user_b)
        kyber_result = crypto_service.perform_kyber_encapsulation(session_id, user_b)
        
        # Derive session key
        key_result = crypto_service.derive_session_key(session_id)
        
        return jsonify({
            'session_id': session_id,
            'status': 'ready',
            'bb84_complete': session_info['status'] == 'bb84_complete',
            'kyber_complete': kyber_result['status'] == 'success',
            'key_derived': key_result['status'] == 'ready'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt():
    data = request.get_json()
    session_id = data.get('session_id')
    message = data.get('message').encode('utf-8')
    encrypted_data = crypto_service.encrypt_message(session_id, message)
    return jsonify(encrypted_data)

@app.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt():
    data = request.get_json()
    session_id = data.get('session_id')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    tag = data.get('tag')
    decrypted_data = crypto_service.decrypt_message(session_id, ciphertext, nonce, tag)
    return jsonify(decrypted_data)

@app.route('/sign', methods=['POST'])
@jwt_required()
def sign():
    data = request.get_json()
    user_id = data.get('user_id')
    message = data.get('message').encode('utf-8')
    signature_data = crypto_service.sign_message(user_id, message)
    return jsonify(signature_data)

@app.route('/verify', methods=['POST'])
@jwt_required()
def verify():
    data = request.get_json()
    user_id = data.get('user_id')
    message = data.get('message').encode('utf-8')
    signature = data.get('signature')
    verification_result = crypto_service.verify_signature(user_id, message, signature)
    return jsonify(verification_result)

@app.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    user_a = request.args.get('user_a')
    user_b = request.args.get('user_b')
    messages = list(db.messages.find(
        {
            '$or': [
                {'sender_id': user_a, 'recipient_id': user_b},
                {'sender_id': user_b, 'recipient_id': user_a}
            ]
        }
    ).sort('timestamp', 1))
    
    # Convert ObjectId to string for JSON serialization
    for msg in messages:
        msg['_id'] = str(msg['_id'])
    
    # Return messages as-is (encrypted) - client will decrypt them
    return jsonify(messages)

@app.route('/user/<username>', methods=['GET'])
@jwt_required()
def get_user(username):
    user = User.find_by_username(db, username)
    if user:
        return jsonify({
            'username': user['username'],
            'email': user['email']
        }), 200
    return jsonify({'error': 'User not found'}), 404

@app.route('/user/<username>', methods=['PUT'])
@jwt_required()
def update_user(username):
    if get_jwt_identity() != username:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    new_username = data.get('username')
    new_email = data.get('email')

    # In a real app, you would add more validation here
    db.users.update_one({'username': username}, {'$set': {'username': new_username, 'email': new_email}})

    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/user/<username>', methods=['DELETE'])
@jwt_required()
def delete_user(username):
    if get_jwt_identity() != username:
        return jsonify({'error': 'Unauthorized'}), 401
    db.users.delete_one({'username': username})
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/user/<username>/password', methods=['PUT'])
@jwt_required()
def update_password(username):
    if get_jwt_identity() != username:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    user = User.find_by_username(db, username)

    if not User.check_password(user, old_password):
        return jsonify({'error': 'Invalid old password'}), 400

    if new_password != confirm_new_password:
        return jsonify({'error': 'New passwords do not match'}), 400

    hashed_password = User.hash_password(new_password)
    db.users.update_one({'username': username}, {'$set': {'password': hashed_password}})

    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/friend-request', methods=['POST'])
@jwt_required()
def send_friend_request():
    data = request.get_json()
    requester = get_jwt_identity()
    recipient = data.get('recipient')

    # In a real app, you would add more validation here
    db.friend_requests.insert_one({
        'requester': requester,
        'recipient': recipient,
        'status': 'pending'
    })

    emit('new_friend_request', {'requester': requester}, room=recipient)

    return jsonify({'message': 'Friend request sent'}), 201

@app.route('/friend-requests/<username>', methods=['GET'])
@jwt_required()
def get_friend_requests(username):
    if get_jwt_identity() != username:
        return jsonify({'error': 'Unauthorized'}), 401
    requests = list(db.friend_requests.find({'recipient': username, 'status': 'pending'}))
    for req in requests:
        req['_id'] = str(req['_id'])
    return jsonify(requests), 200

@app.route('/friend-request/<request_id>', methods=['PUT'])
@jwt_required()
def update_friend_request(request_id):
    data = request.get_json()
    new_status = data.get('status')
    # In a real app, you would add more validation here
    db.friend_requests.update_one({'_id': ObjectId(request_id)}, {'$set': {'status': new_status}})
    return jsonify({'message': 'Friend request updated'}), 200

@app.route('/friends/<username>', methods=['GET'])
@jwt_required()
def get_friends(username):
    if get_jwt_identity() != username:
        return jsonify({'error': 'Unauthorized'}), 401
    friends = []
    requests = list(db.friend_requests.find({
        'status': 'accepted',
        '$or': [
            {'requester': username},
            {'recipient': username}
        ]
    }))
    for req in requests:
        if req['requester'] == username:
            friends.append(req['recipient'])
        else:
            friends.append(req['requester'])
    return jsonify(friends), 200

if __name__ == '__main__':
    socketio.run(app, debug=True)
