"""
Database module - Now using Firebase instead of Supabase.
For backward compatibility, this module imports from firebase_db.
"""

# Import all functions from firebase_db for backward compatibility
from firebase_db import (
    initialize_firebase,
    get_db_client,
    create_user,
    get_user_by_username,
    get_user_by_id,
    update_user_status,
    get_all_users,
    save_message,
    get_messages_between_users,
    get_user_messages,
    update_message_status,
    create_friend_request,
    get_pending_friend_requests,
    update_friend_request,
    save_session_key,
    get_session_key,
    get_user_session_keys,
    delete_session_key,
    upload_file,
    upload_file_content,
    delete_file,
)

# Stub for compatibility - no longer used but kept for backward compatibility
class Client:
    """Stub class for backward compatibility with Supabase Client"""
    pass

# Initialize Firebase when this module is imported
try:
    initialize_firebase()
except Exception as e:
    print(f"Warning: Firebase initialization failed: {e}")
    print("Make sure firebase-credentials.json is in the backend folder")

__all__ = [
    'initialize_firebase',
    'get_db_client',
    'create_user',
    'get_user_by_username',
    'get_user_by_id',
    'update_user_status',
    'get_all_users',
    'save_message',
    'get_messages_between_users',
    'get_user_messages',
    'update_message_status',
    'create_friend_request',
    'get_pending_friend_requests',
    'update_friend_request',
    'save_session_key',
    'get_session_key',
    'get_user_session_keys',
    'delete_session_key',
    'upload_file',
    'upload_file_content',
    'delete_file',
    'Client',
]
