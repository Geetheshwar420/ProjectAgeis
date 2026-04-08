"""
Firebase Realtime Database and Firestore implementation for the messaging app.
Replaces the Supabase database module.
"""

from config import Config
import datetime
import os
import json

# Lazy imports — these are heavy and trigger SSL/gRPC loading.
# Deferring them prevents Gunicorn worker timeout during cold start.
firebase_admin = None
credentials = None
firestore = None
storage = None
FieldFilter = None

def _ensure_imports():
    """Lazy-load firebase and google cloud modules on first use."""
    global firebase_admin, credentials, firestore, storage, FieldFilter
    if firebase_admin is None:
        import firebase_admin as _fa
        from firebase_admin import credentials as _cred, firestore as _fs, storage as _st
        from google.cloud.firestore_v1.base_query import FieldFilter as _ff
        firebase_admin = _fa
        credentials = _cred
        firestore = _fs
        storage = _st
        FieldFilter = _ff

# Initialize Firebase Admin SDK
def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    _ensure_imports()
    if not firebase_admin._apps:
        cred = None
        
        # 1. Try to load from environment variable (for Render/Vercel)
        creds_json = os.getenv('FIREBASE_CREDENTIALS')
        if creds_json:
            try:
                # If it's a JSON string, parse it
                cred_dict = json.loads(creds_json)
                print(f"[{time.strftime('%H:%M:%S')}] [PROF] Parsing credentials dict...", flush=True)
                cred = credentials.Certificate(cred_dict)
                print(f"[{time.strftime('%H:%M:%S')}] [PROF] Firebase initialized using FIREBASE_CREDENTIALS environment variable.", flush=True)
            except Exception as e:
                print(f"Error parsing FIREBASE_CREDENTIALS env var: {e}")
        
        # 2. Fall back to credential file (local development)
        if cred is None:
            creds_path = Config.FIREBASE_CREDENTIALS_PATH
            
            if not os.path.exists(creds_path):
                # Check for a generic fallback path too
                if os.path.exists('firebase-credentials.json'):
                    creds_path = 'firebase-credentials.json'
                else:
                    raise FileNotFoundError(
                        f"Firebase credentials not found. Set FIREBASE_CREDENTIALS env var or "
                        f"place service account JSON at {creds_path}."
                    )
            
            cred = credentials.Certificate(creds_path)
            print(f"Firebase initialized using file: {creds_path}")

        print(f"[{time.strftime('%H:%M:%S')}] [PROF] Calling firebase_admin.initialize_app...", flush=True)
        firebase_admin.initialize_app(cred, {
            'projectId': Config.FIREBASE_PROJECT_ID,
            'storageBucket': Config.FIREBASE_STORAGE_BUCKET,
        })
        print(f"[{time.strftime('%H:%M:%S')}] [PROF] initialize_app complete.", flush=True)
    
    print(f"[{time.strftime('%H:%M:%S')}] [PROF] Fetching firestore client...", flush=True)
    client = firestore.client()
    print(f"[{time.strftime('%H:%M:%S')}] [PROF] Firestore client ready.", flush=True)
    return client

# Initialize Firestore client
_db_client = None

def get_db_client():
    """Get Firestore client instance"""
    global _db_client
    if _db_client is None:
        _db_client = initialize_firebase()
    return _db_client

# ============================================================================
# User Operations
# ============================================================================

def create_user(username, password_hash, public_keys=None, **kwargs):
    """Create a new user in Firestore"""
    try:
        db_client = get_db_client()
        
        # Check if username already exists
        users_ref = db_client.collection('users')
        query = users_ref.where(filter=FieldFilter('username', '==', username))
        existing = list(query.stream())
        
        if existing:
            print(f"User {username} already exists")
            return None
        
        user_data = {
            'username': username,
            'password_hash': password_hash,
            'public_keys': public_keys or {},
            'is_online': False,
            'last_seen': datetime.datetime.now(datetime.timezone.utc),
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'updated_at': datetime.datetime.now(datetime.timezone.utc),
        }
        
        # Add any extra metadata (e.g., google_email)
        user_data.update(kwargs)
        
        # Add user and get the document ID
        doc_ref = users_ref.add(user_data)
        doc_id = doc_ref[1].id
        
        # Get and return the created user
        created_user = users_ref.document(doc_id).get().to_dict()
        created_user['id'] = doc_id
        return created_user
        
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def get_user_by_username(username):
    """Get user by username"""
    try:
        print(f"[{time.strftime('%H:%M:%S')}] [PROF] Database query: finding user '{username}'", flush=True)
        db_client = get_db_client()
        users_ref = db_client.collection('users')
        
        query = users_ref.where(filter=FieldFilter('username', '==', username))
        
        print(f"[{time.strftime('%H:%M:%S')}] [PROF] Executing firestore stream() for user lookup...", flush=True)
        docs = list(query.stream())
        print(f"[{time.strftime('%H:%M:%S')}] [PROF] firestore stream() returned {len(docs)} docs.", flush=True)
        
        if docs:
            user_data = docs[0].to_dict()
            user_data['id'] = docs[0].id
            return user_data
        return None
        
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def get_user_by_google_email(email):
    """Get user by linked Google email"""
    try:
        db_client = get_db_client()
        users_ref = db_client.collection('users')
        
        query = users_ref.where(filter=FieldFilter('google_email', '==', email))
        docs = list(query.stream())
        
        if docs:
            user_data = docs[0].to_dict()
            user_data['id'] = docs[0].id
            return user_data
        return None
        
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def get_user_by_id(user_id):
    """Get user by document ID"""
    try:
        db_client = get_db_client()
        doc = db_client.collection('users').document(user_id).get()
        
        if doc.exists:
            user_data = doc.to_dict()
            user_data['id'] = doc.id
            return user_data
        return None
        
    except Exception as e:
        print(f"Error getting user by ID: {e}")
        return None

def update_user_status(username, is_online):
    """Update user online status"""
    try:
        db_client = get_db_client()
        users_ref = db_client.collection('users')
        
        query = users_ref.where(filter=FieldFilter('username', '==', username))
        for doc in query.stream():
            doc.reference.update({
                'is_online': is_online,
                'last_seen': datetime.datetime.now(datetime.timezone.utc),
                'updated_at': datetime.datetime.now(datetime.timezone.utc),
            })
        
    except Exception as e:
        print(f"Error updating user status: {e}")

def get_all_users():
    """Get all users (returns public-safe data)"""
    try:
        db_client = get_db_client()
        users_ref = db_client.collection('users')
        
        users = []
        for doc in users_ref.stream():
            user_data = doc.to_dict()
            user_data['id'] = doc.id
            # Return only public-safe fields
            users.append({
                'id': user_data.get('id'),
                'username': user_data.get('username'),
                'is_online': user_data.get('is_online'),
                'last_seen': user_data.get('last_seen'),
                'public_keys': user_data.get('public_keys', {}),
            })
        return users
        
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

# ============================================================================
# Message Operations
# ============================================================================

def save_message(sender_id, sender_username, recipient_id, recipient_username, 
                 content, session_id=None, formatted_timestamp=None, iso_timestamp=None):
    """Save a message to Firestore"""
    try:
        db_client = get_db_client()
        
        message_data = {
            'sender_id': sender_id,
            'sender_username': sender_username,
            'recipient_id': recipient_id,
            'recipient_username': recipient_username,
            'content': content,
            'session_id': session_id,
            'formatted_timestamp': formatted_timestamp,
            'iso_timestamp': iso_timestamp,
            'status': 'sent',
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'updated_at': datetime.datetime.now(datetime.timezone.utc),
            'delivered_at': None,
            'read_at': None,
        }
        
        doc_ref = db_client.collection('messages').add(message_data)
        message_data['id'] = doc_ref[1].id
        return message_data
        
    except Exception as e:
        print(f"Error saving message: {e}")
        return None

def get_messages_between_users(user_id_1, user_id_2, limit=50):
    """Get messages between two users"""
    try:
        db_client = get_db_client()
        messages_ref = db_client.collection('messages')
        
        # Get messages sent by user_id_1 to user_id_2
        query1 = messages_ref.where(filter=FieldFilter('sender_id', '==', user_id_1))\
            .where(filter=FieldFilter('recipient_id', '==', user_id_2))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            .limit(limit)
        
        # Get messages sent by user_id_2 to user_id_1
        query2 = messages_ref.where(filter=FieldFilter('sender_id', '==', user_id_2))\
            .where(filter=FieldFilter('recipient_id', '==', user_id_1))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            .limit(limit)
        
        messages = []
        for doc in query1.stream():
            msg = doc.to_dict()
            msg['id'] = doc.id
            messages.append(msg)
        
        for doc in query2.stream():
            msg = doc.to_dict()
            msg['id'] = doc.id
            messages.append(msg)
        
        # Sort by created_at
        messages.sort(key=lambda x: x.get('created_at', datetime.datetime.now()), reverse=True)
        return messages[:limit]
        
    except Exception as e:
        print(f"Error getting messages: {e}")
        return []

def get_user_messages(user_id, limit=50):
    """Get all messages for a user (both sent and received)"""
    try:
        db_client = get_db_client()
        messages_ref = db_client.collection('messages')
        
        # Messages sent by user
        sent = messages_ref.where(filter=FieldFilter('sender_id', '==', user_id))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            .limit(limit)
        
        # Messages received by user
        received = messages_ref.where(filter=FieldFilter('recipient_id', '==', user_id))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            .limit(limit)
        
        messages = []
        for doc in sent.stream():
            msg = doc.to_dict()
            msg['id'] = doc.id
            messages.append(msg)
        
        for doc in received.stream():
            msg = doc.to_dict()
            msg['id'] = doc.id
            messages.append(msg)
        
        # Sort by created_at
        messages.sort(key=lambda x: x.get('created_at', datetime.datetime.now()), reverse=True)
        return messages[:limit]
        
    except Exception as e:
        print(f"Error getting user messages: {e}")
        return []

def update_message_status(message_id, status):
    """Update message status"""
    try:
        db_client = get_db_client()
        db_client.collection('messages').document(message_id).update({
            'status': status,
            'updated_at': datetime.datetime.now(datetime.timezone.utc),
        })
        
    except Exception as e:
        print(f"Error updating message status: {e}")

# ============================================================================
# Friend Request Operations
# ============================================================================

def create_friend_request(from_user_id, to_user_id):
    """Create a friend request"""
    try:
        db_client = get_db_client()
        
        # Check if request already exists
        requests_ref = db_client.collection('friend_requests')
        query = requests_ref.where(filter=FieldFilter('from_user_id', '==', from_user_id))\
            .where(filter=FieldFilter('to_user_id', '==', to_user_id))
        
        if list(query.stream()):
            return None  # Request already exists
        
        request_data = {
            'from_user_id': from_user_id,
            'to_user_id': to_user_id,
            'status': 'pending',
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'updated_at': datetime.datetime.now(datetime.timezone.utc),
        }
        
        doc_ref = requests_ref.add(request_data)
        request_data['id'] = doc_ref[1].id
        return request_data
        
    except Exception as e:
        print(f"Error creating friend request: {e}")
        return None

def get_pending_friend_requests(user_id):
    """Get pending friend requests for a user"""
    try:
        db_client = get_db_client()
        requests_ref = db_client.collection('friend_requests')
        
        query = requests_ref.where(filter=FieldFilter('to_user_id', '==', user_id))\
            .where(filter=FieldFilter('status', '==', 'pending'))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)
        
        requests = []
        for doc in query.stream():
            req = doc.to_dict()
            req['id'] = doc.id
            requests.append(req)
        
        return requests
        
    except Exception as e:
        print(f"Error getting friend requests: {e}")
        return []

def update_friend_request(request_id, status):
    """Update friend request status"""
    try:
        db_client = get_db_client()
        db_client.collection('friend_requests').document(request_id).update({
            'status': status,
            'updated_at': datetime.datetime.now(datetime.timezone.utc),
        })
        
    except Exception as e:
        print(f"Error updating friend request: {e}")

def get_friend_request_by_id(request_id):
    """Get a friend request by its ID"""
    try:
        db_client = get_db_client()
        doc = db_client.collection('friend_requests').document(request_id).get()
        
        if doc.exists:
            req_data = doc.to_dict()
            req_data['id'] = doc.id
            return req_data
        return None
        
    except Exception as e:
        print(f"Error getting friend request by ID: {e}")
        return None

# ============================================================================
# Session Key Operations
# ============================================================================

def save_session_key(user_id, session_id, key_material, expires_at=None):
    """Save a session key for a user"""
    try:
        db_client = get_db_client()
        
        key_data = {
            'user_id': user_id,
            'session_id': session_id,
            'key_material': key_material,
            'expires_at': expires_at,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
        }
        
        doc_ref = db_client.collection('session_keys').add(key_data)
        key_data['id'] = doc_ref[1].id
        return key_data
        
    except Exception as e:
        print(f"Error saving session key: {e}")
        return None

def get_session_key(session_id):
    """Get session key by session ID"""
    try:
        db_client = get_db_client()
        keys_ref = db_client.collection('session_keys')
        
        query = keys_ref.where(filter=FieldFilter('session_id', '==', session_id))
        docs = list(query.stream())
        
        if docs:
            key_data = docs[0].to_dict()
            key_data['id'] = docs[0].id
            return key_data
        return None
        
    except Exception as e:
        print(f"Error getting session key: {e}")
        return None

def get_user_session_keys(user_id):
    """Get all session keys for a user"""
    try:
        db_client = get_db_client()
        keys_ref = db_client.collection('session_keys')
        
        query = keys_ref.where(filter=FieldFilter('user_id', '==', user_id))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)
        
        keys = []
        for doc in query.stream():
            key = doc.to_dict()
            key['id'] = doc.id
            keys.append(key)
        
        return keys
        
    except Exception as e:
        print(f"Error getting user session keys: {e}")
        return []

def delete_session_key(session_id):
    """Delete a session key"""
    try:
        db_client = get_db_client()
        keys_ref = db_client.collection('session_keys')
        
        query = keys_ref.where(filter=FieldFilter('session_id', '==', session_id))
        for doc in query.stream():
            doc.reference.delete()
        
    except Exception as e:
        print(f"Error deleting session key: {e}")

# ============================================================================
# File Storage Operations
# ============================================================================

def upload_file(file_path, file_name, folder='attachments'):
    """Upload file to Firebase Storage"""
    try:
        bucket = storage.bucket()
        blob = bucket.blob(f"{folder}/{file_name}")
        blob.upload_from_filename(file_path)
        
        # Make file publicly accessible
        blob.make_public()
        
        return blob.public_url
        
    except Exception as e:
        print(f"Error uploading file: {e}")
        return None

def upload_file_content(file_content, file_name, folder='attachments'):
    """Upload file content to Firebase Storage"""
    try:
        bucket = storage.bucket()
        blob = bucket.blob(f"{folder}/{file_name}")
        blob.upload_from_string(file_content)
        
        # Make file publicly accessible
        blob.make_public()
        
        return blob.public_url
        
    except Exception as e:
        print(f"Error uploading file content: {e}")
        return None

def delete_file(file_name, folder='attachments'):
    """Delete file from Firebase Storage"""
    try:
        bucket = storage.bucket()
        blob = bucket.blob(f"{folder}/{file_name}")
        blob.delete()
        
    except Exception as e:
        print(f"Error deleting file: {e}")
