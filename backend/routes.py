from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from db import create_user, get_user_by_username, get_all_users, upload_file_content
import uuid

api = Blueprint('api', __name__)

@api.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_keys = data.get('public_keys') # Expecting keys from frontend if generated there, or we generate on backend?
    # Based on existing crypto code, keys are generated on backend usually, but let's see.
    # The existing crypto service generates keys in memory. 
    # For persistence, we should probably generate them here or accept them.
    # Let's assume for now we just register the user and keys are handled by the crypto service later/separately.
    
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
    # Unique filename
    unique_filename = f"{uuid.uuid4()}_{filename}"
    
    try:
        file_content = file.read()
        # Upload to Firebase Storage
        # Note: Cloud Storage bucket must be configured in Firebase Console
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

from services import quantum_service

@api.route('/prepare_message', methods=['POST'])
def prepare_message():
    if 'username' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.json
    sender_id = session['username']
    recipient_id = data.get('recipient_id')
    message = data.get('message')
    
    if not recipient_id or not message:
        return jsonify({"error": "Recipient ID and message required"}), 400
        
    try:
        # 1. Ensure keys exist for both users (in case of restart)
        if sender_id not in quantum_service.user_keypairs:
            quantum_service.generate_user_keypairs(sender_id)
        if recipient_id not in quantum_service.user_keypairs:
            quantum_service.generate_user_keypairs(recipient_id)
            
        # 2. Initiate/Get Session (BB84)
        exchange_result = quantum_service.initiate_quantum_key_exchange(sender_id, recipient_id)
        session_id = exchange_result['session_id']
        
        # 3. Ensure Session is Ready (Kyber + Derivation)
        # Check if we need to perform Kyber to get shared secret
        sess_info = quantum_service.get_session_info(session_id)
        if not sess_info.get('has_session_key'):
            if not sess_info.get('has_kyber_secret'):
                # Perform Kyber encapsulation to establish shared secret
                quantum_service.perform_kyber_encapsulation(session_id, recipient_id)
            
            # Derive final session key
            quantum_service.derive_session_key(session_id)
            
        # 4. Encrypt Message
        # Message needs to be bytes
        msg_bytes = message.encode('utf-8')
        encrypted_data = quantum_service.encrypt_message(session_id, msg_bytes)
        
        if encrypted_data.get('status') == 'failed':
             return jsonify({"error": "Encryption failed", "details": encrypted_data.get('error')}), 500

        # 5. Sign Message (Sign the ciphertext or the original? 
        # Usually sign the ciphertext to prevent malleability, or sign-then-encrypt.
        # ChatWindow.tsx expects 'signature' as a separate field.
        # Let's sign the ciphertext (encrypted_message) as that's what's sent over the wire usually.
        # Or sign the original message to prove authenticity of content.
        # Let's sign the ciphertext to match the likely expectation of "authenticated encryption" verification on receipt.
        # Wait, ChatWindow sends: encrypted_message, signature, nonce, tag.
        # If I sign the ciphertext, the receiver verifies signature of ciphertext, then decrypts.
        # Let's sign the ciphertext.
        ciphertext = encrypted_data['ciphertext']
        sign_result = quantum_service.sign_message(sender_id, ciphertext.encode('utf-8'))
        
        if sign_result.get('status') == 'failed':
            return jsonify({"error": "Signing failed", "details": sign_result.get('error')}), 500

        return jsonify({
            "encrypted_message": ciphertext,
            "signature": sign_result['signature'],
            "nonce": encrypted_data['nonce'],
            "tag": encrypted_data['tag'],
            "session_id": session_id,
            "timestamp": encrypted_data['timestamp']
        }), 200

    except Exception as e:
        print(f"Error in prepare_message: {e}")
        return jsonify({"error": str(e)}), 500

@api.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({"status": "ok"}), 200
