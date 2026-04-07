"""
Database compatibility layer.
Redirects all imports to the Firebase implementation (firebase_db.py).
"""

from firebase_db import (
    get_db_client,
    create_user,
    get_user_by_username,
    get_user_by_id,
    get_all_users,
    update_user_status,
    upload_file_content,
    upload_file,
    delete_file,
    save_message,
    get_messages_between_users,
    get_user_messages,
    save_session_key,
    get_session_key,
    get_user_session_keys,
    delete_session_key,
    create_friend_request,
    get_pending_friend_requests,
    update_friend_request,
    update_message_status,
)
