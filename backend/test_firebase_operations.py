#!/usr/bin/env python3
"""
Firebase Operations Test Suite
Run this to test all Firebase database operations
"""

import sys
import uuid
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

def test_user_operations():
    """Test user CRUD operations"""
    from firebase_db import create_user, get_user_by_username, get_user_by_id, update_user_status
    
    print("\n" + "="*60)
    print("Testing User Operations")
    print("="*60)
    
    # Create test user
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    password_hash = generate_password_hash("testpass123")
    
    print(f"\n1. Creating user: {username}")
    user = create_user(username, password_hash, public_keys={'test_key': 'value'})
    
    if user:
        user_id = user.get('id')
        print(f"   ✓ User created successfully (ID: {user_id})")
    else:
        print("   ✗ Failed to create user")
        return False
    
    # Get user by username
    print(f"\n2. Retrieving user by username: {username}")
    retrieved = get_user_by_username(username)
    if retrieved and retrieved.get('username') == username:
        print(f"   ✓ User retrieved successfully")
    else:
        print("   ✗ Failed to retrieve user by username")
        return False
    
    # Get user by ID
    print(f"\n3. Retrieving user by ID: {user_id}")
    retrieved_by_id = get_user_by_id(user_id)
    if retrieved_by_id and retrieved_by_id.get('id') == user_id:
        print(f"   ✓ User retrieved by ID successfully")
    else:
        print("   ✗ Failed to retrieve user by ID")
        return False
    
    # Update user status
    print(f"\n4. Updating user status: {username} → online=True")
    update_user_status(username, True)
    updated = get_user_by_username(username)
    if updated and updated.get('is_online'):
        print(f"   ✓ User status updated successfully")
    else:
        print("   ✗ Failed to update user status")
        return False
    
    print("\n✓ All user operations passed!")
    return True

def test_message_operations():  
    """Test message CRUD operations"""
    from firebase_db import (
        create_user, save_message, get_messages_between_users, 
        update_message_status
    )
    from werkzeug.security import generate_password_hash
    
    print("\n" + "="*60)
    print("Testing Message Operations")
    print("="*60)
    
    # Create two test users
    user1_name = f"user1_{uuid.uuid4().hex[:8]}"
    user2_name = f"user2_{uuid.uuid4().hex[:8]}"
    pass_hash = generate_password_hash("pass123")
    
    print(f"\n1. Creating test users: {user1_name}, {user2_name}")
    user1 = create_user(user1_name, pass_hash)
    user2 = create_user(user2_name, pass_hash)
    
    if not (user1 and user2):
        print("   ✗ Failed to create test users")
        return False
    
    user1_id = user1.get('id')
    user2_id = user2.get('id')
    print(f"   ✓ Users created (IDs: {user1_id}, {user2_id})")
    
    # Save a message
    print(f"\n2. Saving message from {user1_name} to {user2_name}")
    message = save_message(
        sender_id=user1_id,
        sender_username=user1_name,
        recipient_id=user2_id,
        recipient_username=user2_name,
        content="Hello Bob! This is a test message.",
        session_id=str(uuid.uuid4()),
        formatted_timestamp="2024-02-26 10:30:00",
        iso_timestamp=datetime.now().isoformat()
    )
    
    if message:
        message_id = message.get('id')
        print(f"   ✓ Message saved successfully (ID: {message_id})")
    else:
        print("   ✗ Failed to save message")
        return False
    
    # Get messages between users
    print(f"\n3. Retrieving messages between {user1_name} and {user2_name}")
    messages = get_messages_between_users(user1_id, user2_id)
    if messages and len(messages) > 0:
        print(f"   ✓ Retrieved {len(messages)} message(s)")
    else:
        print("   ✗ Failed to retrieve messages")
        return False
    
    # Update message status
    print(f"\n4. Updating message status to 'delivered'")
    update_message_status(message_id, 'delivered')
    updated_messages = get_messages_between_users(user1_id, user2_id)
    if updated_messages and updated_messages[0].get('status') == 'delivered':
        print(f"   ✓ Message status updated successfully")
    else:
        print("   ✗ Failed to update message status")
        return False
    
    print("\n✓ All message operations passed!")
    return True

def test_friend_request_operations():
    """Test friend request operations"""
    from firebase_db import (
        create_user, create_friend_request, get_pending_friend_requests,
        update_friend_request
    )
    from werkzeug.security import generate_password_hash
    
    print("\n" + "="*60)
    print("Testing Friend Request Operations")
    print("="*60)
    
    # Create test users
    user1_name = f"alice_{uuid.uuid4().hex[:8]}"
    user2_name = f"bob_{uuid.uuid4().hex[:8]}"
    pass_hash = generate_password_hash("pass123")
    
    print(f"\n1. Creating test users: {user1_name}, {user2_name}")
    user1 = create_user(user1_name, pass_hash)
    user2 = create_user(user2_name, pass_hash)
    
    if not (user1 and user2):
        print("   ✗ Failed to create test users")
        return False
    
    user1_id = user1.get('id')
    user2_id = user2.get('id')
    print(f"   ✓ Users created")
    
    # Create friend request
    print(f"\n2. Creating friend request from {user1_name} to {user2_name}")
    friend_req = create_friend_request(user1_id, user2_id)
    
    if friend_req:
        req_id = friend_req.get('id')
        print(f"   ✓ Friend request created (ID: {req_id})")
    else:
        print("   ✗ Failed to create friend request")
        return False
    
    # Get pending requests for user2
    print(f"\n3. Getting pending requests for {user2_name}")
    pending = get_pending_friend_requests(user2_id)
    if pending and len(pending) > 0:
        print(f"   ✓ Retrieved {len(pending)} pending request(s)")
    else:
        print("   ✗ Failed to get pending requests")
        return False
    
    # Update request status
    print(f"\n4. Accepting friend request")
    update_friend_request(req_id, 'accepted')
    updated_pending = get_pending_friend_requests(user2_id)
    print(f"   ✓ Friend request accepted (remaining pending: {len(updated_pending)})")
    
    print("\n✓ All friend request operations passed!")
    return True

def test_session_key_operations():
    """Test session key operations"""
    from firebase_db import (
        create_user, save_session_key, get_session_key, 
        get_user_session_keys, delete_session_key
    )
    from werkzeug.security import generate_password_hash
    
    print("\n" + "="*60)
    print("Testing Session Key Operations")
    print("="*60)
    
    # Create test user
    username = f"keyuser_{uuid.uuid4().hex[:8]}"
    pass_hash = generate_password_hash("pass123")
    
    print(f"\n1. Creating test user: {username}")
    user = create_user(username, pass_hash)
    if not user:
        print("   ✗ Failed to create user")
        return False
    
    user_id = user.get('id')
    print(f"   ✓ User created (ID: {user_id})")
    
    # Save session key
    print(f"\n2. Saving session key")
    session_id = str(uuid.uuid4())
    key_material = "encrypted_key_material_" + uuid.uuid4().hex
    expires_at = datetime.now() + timedelta(hours=24)
    
    key = save_session_key(user_id, session_id, key_material, expires_at)
    if key:
        key_id = key.get('id')
        print(f"   ✓ Session key saved (ID: {key_id})")
    else:
        print("   ✗ Failed to save session key")
        return False
    
    # Get session key
    print(f"\n3. Retrieving session key by session_id")
    retrieved_key = get_session_key(session_id)
    if retrieved_key and retrieved_key.get('session_id') == session_id:
        print(f"   ✓ Session key retrieved successfully")
    else:
        print("   ✗ Failed to retrieve session key")
        return False
    
    # Get all user session keys
    print(f"\n4. Getting all session keys for user")
    user_keys = get_user_session_keys(user_id)
    if user_keys and len(user_keys) > 0:
        print(f"   ✓ Retrieved {len(user_keys)} session key(s)")
    else:
        print("   ✗ Failed to get user session keys")
        return False
    
    # Delete session key
    print(f"\n5. Deleting session key")
    delete_session_key(session_id)
    deleted_check = get_session_key(session_id)
    if not deleted_check:
        print(f"   ✓ Session key deleted successfully")
    else:
        print("   ✗ Failed to delete session key")
        return False
    
    print("\n✓ All session key operations passed!")
    return True

def test_storage_operations():
    """Test file storage operations"""
    from firebase_db import upload_file_content, delete_file
    
    print("\n" + "="*60)
    print("Testing File Storage Operations")
    print("="*60)
    
    # Upload test file
    print(f"\n1. Uploading test file")
    test_content = b"This is a test file for Firebase Storage"
    test_filename = f"test_{uuid.uuid4().hex[:8]}.txt"
    
    url = upload_file_content(test_content, test_filename, folder='test')
    if url:
        print(f"   ✓ File uploaded successfully")
        print(f"   URL: {url}")
    else:
        print("   ✗ Failed to upload file")
        return False
    
    # Delete test file
    print(f"\n2. Deleting test file")
    delete_file(test_filename, folder='test')
    print(f"   ✓ File deleted successfully")
    
    print("\n✓ All storage operations passed!")
    return True

def main():
    """Run all tests"""
    print("=" * 60)
    print("Firebase Operations Test Suite")
    print("=" * 60)
    
    tests = [
        ("User Operations", test_user_operations),
        ("Message Operations", test_message_operations),
        ("Friend Request Operations", test_friend_request_operations),
        ("Session Key Operations", test_session_key_operations),
        ("File Storage Operations", test_storage_operations),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name} failed with error: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    total_passed = sum(1 for _, r in results if r)
    total_tests = len(results)
    
    print("\n" + "=" * 60)
    print(f"Results: {total_passed}/{total_tests} tests passed")
    print("=" * 60)
    
    return 0 if all(r for _, r in results) else 1

if __name__ == '__main__':
    sys.exit(main())
