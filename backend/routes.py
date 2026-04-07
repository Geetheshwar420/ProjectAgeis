from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from db import (
    create_user, get_user_by_username, get_user_by_id, get_all_users,
    upload_file_content, get_pending_friend_requests, create_friend_request,
    update_friend_request, get_messages_between_users, get_user_messages,
    get_db_client, get_friend_request_by_id
)

import uuid
import logging

logger = logging.getLogger(__name__)

api = Blueprint('api', __name__)

@api.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_keys = data.get('public_keys')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if get_user_by_username(username):
        return jsonify({"error": "Username already exists"}), 400

    password_hash = generate_password_hash(password)
    user = create_user(username, password_hash, public_keys)

    if user:
        return jsonify({"message": "User created successfully", "user": user}), 201
    return jsonify({"error": "Failed to create user"}), 500

@api.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "is_online": user['is_online']
            }
        }), 200

    return jsonify({"error": "Invalid credentials"}), 401

@api.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200

@api.route('/me', methods=['GET'])
def me():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user = get_user_by_username(session['username'])
    if user:
        return jsonify({
            "id": user['id'],
            "username": user['username'],
            "is_online": user['is_online']
        }), 200
    return jsonify({"error": "User not found"}), 404

@api.route('/users', methods=['GET'])
def list_users():
    users = get_all_users()
    return jsonify(users), 200

@api.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"

    try:
        file_content = file.read()
        public_url = upload_file_content(
            file_content,
            unique_filename,
            folder='attachments'
        )

        if not public_url:
            return jsonify({"error": "Failed to upload file"}), 500

        return jsonify({
            "message": "File uploaded successfully",
            "url": public_url,
            "filename": filename,
            "size": len(file_content)
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Removed redundant prepare_message route. Crypto is now handled on the frontend.


# ============================================================================
# Friend & Social Routes (required by frontend)
# ============================================================================

@api.route('/friends', methods=['GET'])
def get_friends():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({"error": "User not found"}), 404
    all_users = get_all_users()
    friends = [u for u in all_users if u['id'] != user['id']]
    return jsonify(friends), 200

@api.route('/friend-request', methods=['POST'])
def send_friend_request():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json
    to_username = data.get('to_username')
    if not to_username:
        return jsonify({"error": "to_username required"}), 400
    from_user = get_user_by_username(session['username'])
    to_user = get_user_by_username(to_username)
    if not from_user:
        return jsonify({"error": "User not found"}), 404
    if not to_user:
        return jsonify({"error": "User not found"}), 404
    if from_user['id'] == to_user['id']:
        return jsonify({"error": "Cannot send friend request to yourself"}), 400
    result = create_friend_request(from_user['id'], to_user['id'])
    if result:
        return jsonify({"message": "Friend request sent", "request": result}), 201
    return jsonify({"error": "Request already exists or failed"}), 400
@api.route('/friend-requests', methods=['GET'])
def get_friend_requests():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({"error": "User not found"}), 404
    requests_list = get_pending_friend_requests(user['id'])
    enriched = []
    for req in requests_list:
        from_user = get_user_by_id(req['from_user_id'])
        enriched.append({
            'id': req['id'],
            'from_user_id': req['from_user_id'],
            'from_username': from_user['username'] if from_user else 'Unknown',
            'status': req['status'],
            'created_at': str(req.get('created_at', '')),
        })
    return jsonify(enriched), 200

@api.route('/friend-request/respond', methods=['POST'])
def respond_friend_request():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    data = request.json
    request_id = data.get('request_id')
    status = data.get('status')
    if not request_id or status not in ('accepted', 'rejected'):
        return jsonify({"error": "request_id and valid status required"}), 400
        
    # Fetch the friend request and verify the current user is the recipient
    friend_request = get_friend_request_by_id(request_id)
    if not friend_request:
        return jsonify({"error": "Friend request not found"}), 404
        
    if friend_request['to_user_id'] != user['id']:
        return jsonify({"error": "Not authorized to respond to this request"}), 403
        
    update_friend_request(request_id, status)
    return jsonify({"message": f"Request {status}"}), 200

@api.route('/messages', methods=['GET'])
def get_messages():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    peer_id = request.args.get('peer_id')
    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({"error": "User not found"}), 404
    if peer_id:
        messages = get_messages_between_users(user['id'], peer_id)
    else:
        messages = get_user_messages(user['id'])
    return jsonify(messages), 200

@api.route('/update_keys', methods=['POST'])
def update_keys():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json
    public_keys = data.get('public_keys')
    if not public_keys:
        return jsonify({"error": "public_keys required"}), 400
    try:
        from google.cloud.firestore_v1.base_query import FieldFilter
        db_client = get_db_client()
        users_ref = db_client.collection('users')
        query = users_ref.where(filter=FieldFilter('username', '==', session['username']))
        for doc in query.stream():
            doc.reference.update({'public_keys': public_keys})
        return jsonify({"message": "Keys updated"}), 200
    except Exception as e:
        logger.error("Error updating keys: %s", e)
        return jsonify({"error": str(e)}), 500

@api.route('/user/<username>', methods=['GET'])
def get_user_profile(username):
    user = get_user_by_username(username)
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'public_keys': user.get('public_keys', {}),
            'is_online': user.get('is_online', False),
        }), 200
    return jsonify({"error": "User not found"}), 404

@api.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({"status": "ok"}), 200

