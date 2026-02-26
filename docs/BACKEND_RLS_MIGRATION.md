# Backend Code Migration Guide for RLS

## Overview

After enabling Row Level Security (RLS) on the Supabase database, the backend code needs to be updated to properly handle authentication and work within RLS constraints.

**Current Issue**: The existing code uses session-based authentication with Supabase client keys that may not properly enforce RLS policies.

---

## Key Changes Required

### 1. Authentication Flow Update

#### Current Approach (Session-Based)
```python
# OLD - Does not enforce RLS properly
supabase = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
user = get_user_by_username(username)
```

#### New Approach (JWT-Based with Supabase Auth)
```python
# NEW - Enables proper RLS enforcement
from supabase import create_client, Client

def get_supabase_client_for_user(access_token: str) -> Client:
    """Create a Supabase client with user's JWT token for RLS enforcement"""
    return create_client(
        Config.SUPABASE_URL,
        Config.SUPABASE_KEY,
        options={
            "headers": {
                "Authorization": f"Bearer {access_token}"
            }
        }
    )
```

---

## Code Changes Required

### File: `backend/db.py`

#### Problem Functions
1. **`get_all_users()`** - Will be blocked by RLS (users can't see all users)
2. **`get_user_by_username()`** - Needs RLS-aware querying

#### Solution 1: Update `get_all_users()` to Get User's Friends

```python
def get_all_users(user_id: int, access_token: str = None):
    """Get list of users (excluding self) for friend discovery
    
    NOTE: With RLS, users cannot see all other users' data.
    This function should be updated to return only public-safe data
    or users should use the friend_requests system for discovery.
    """
    try:
        # Instead of returning all users, return only users you have
        # interacted with or are friends with
        client = supabase if not access_token else get_supabase_client_for_user(access_token)
        
        # Option 1: Return only users you have messages with
        response = client.table("messages").select("distinct sender_id, recipient_id")\
            .or_(f"sender_id.eq.{user_id},recipient_id.eq.{user_id}")\
            .execute()
        
        # Extract unique user IDs and fetch their profiles
        user_ids = set()
        for msg in response.data:
            if msg['sender_id'] != user_id:
                user_ids.add(msg['sender_id'])
            if msg['recipient_id'] != user_id:
                user_ids.add(msg['recipient_id'])
        
        # Fetch public info for these users
        users = []
        for uid in user_ids:
            # Note: With RLS, users cannot directly view other profiles
            # This requires a database-level view or service role client
            users.append({"id": uid})
        
        return users
    except Exception as e:
        print(f"Error getting users: {e}")
        return []
```

#### Solution 2: Update `get_user_by_username()` for RLS

```python
def get_user_by_username(username: str, user_id: int = None, access_token: str = None):
    """Get user by username
    
    NOTE: With RLS enabled on users table, users can only see their own profile.
    For getting other users' info, consider:
    1. Creating a public_profiles table without sensitive data
    2. Using service role for lookups
    3. Caching usernames in a separate table
    """
    try:
        # If user_id is provided and matches the requested user, use RLS-enforced query
        if user_id:
            client = supabase if not access_token else get_supabase_client_for_user(access_token)
        else:
            # Use service role client (has bypass privileges)
            client = create_client(
                Config.SUPABASE_URL,
                Config.SUPABASE_SERVICE_ROLE_KEY  # Service role key (must be protected!)
            )
        
        response = client.table("users").select("*").eq("username", username).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None
```

#### Solution 3: Update `create_user()` for RLS

```python
def create_user(username: str, email: str, password_hash: str, public_keys=None):
    """Create a new user in Supabase
    
    NOTE: The RLS policy allows unauthenticated inserts for signup,
    so this can remain mostly unchanged. However, ensure email field
    is populated as it's marked as NOT NULL in schema.
    """
    data = {
        "username": username,
        "email": email,  # NEW: Required by schema
        "password_hash": password_hash,
    }
    try:
        # Use public key (not authenticated) for signup
        response = supabase.table("users").insert(data).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        print(f"Error creating user: {e}")
        return None
```

### File: `backend/routes.py`

#### Update Authentication to Use Tokens

```python
from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from config import Config
from db import supabase

api = Blueprint('api', __name__)

# Store user session with JWT token
@api.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        # Create JWT token for this user
        token = jwt.encode(
            {
                'id': user['id'],
                'username': user['username'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            Config.JWT_SECRET,
            algorithm='HS256'
        )
        
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['access_token'] = token  # NEW: Store token for RLS
        
        return jsonify({
            "message": "Login successful",
            "access_token": token,  # NEW: Return token to frontend
            "user": {
                "id": user['id'],
                "username": user['username'],
            }
        }), 200
    
    return jsonify({"error": "Invalid credentials"}), 401

@api.route('/me', methods=['GET'])
def me():
    """Get current user's profile (RLS enforced)"""
    if 'access_token' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        # Use user's token to ensure RLS enforcement
        client = get_supabase_client_for_user(session['access_token'])
        response = client.table("users").select("id, username, email, created_at").execute()
        
        if response.data:
            return jsonify(response.data[0]), 200
    except Exception as e:
        print(f"Error fetching user profile: {e}")
    
    return jsonify({"error": "User not found"}), 404

# Deprecated: This endpoint violates RLS
# @api.route('/users', methods=['GET'])
# def list_users():
#     # REMOVE or replace with friend list
#     users = get_all_users()
#     return jsonify(users), 200

@api.route('/users/friends', methods=['GET'])
def list_friends():
    """Get list of users you have interacted with"""
    if 'access_token' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    user_id = session.get('user_id')
    try:
        client = get_supabase_client_for_user(session['access_token'])
        
        # Get users you've messaged with
        response = client.table("messages").select("sender_id, recipient_id")\
            .or_(f"sender_id.eq.{user_id},recipient_id.eq.{user_id}")\
            .execute()
        
        # Extract unique user IDs
        friend_ids = set()
        for msg in response.data:
            if msg['sender_id'] != user_id:
                friend_ids.add(msg['sender_id'])
            if msg['recipient_id'] != user_id:
                friend_ids.add(msg['recipient_id'])
        
        return jsonify({
            "friends": list(friend_ids)
        }), 200
    except Exception as e:
        print(f"Error fetching friends: {e}")
        return jsonify({"error": "Failed to fetch friends"}), 500
```

---

## Configuration Updates

### File: `backend/config.py`

Add new configuration:

```python
import os

class Config:
    SUPABASE_URL = os.getenv('SUPABASE_URL')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY')
    SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')  # NEW
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key')  # NEW
```

### Environment Variables to Add

```bash
# In your .env file
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=eyJhbGc...  # Anon key
SUPABASE_SERVICE_ROLE_KEY=eyJhbGc...  # Service role key (KEEP SECRET!)
JWT_SECRET=your-secure-jwt-secret
```

---

## Breaking Changes & Migration Path

### Endpoints Affected

| Endpoint | Issue | Solution |
|----------|-------|----------|
| `GET /users` | RLS blocks listing all users | Replace with `GET /users/friends` or remove |
| `GET /user/<id>` | RLS blocks viewing other profiles | Must authenticate and use service role or public view |
| `GET /me` | Works but requires token | Update to use JWT token |

### Frontend Changes Required

1. **Store JWT Token**:
   ```typescript
   // After login, store the token
   localStorage.setItem('access_token', response.access_token);
   ```

2. **Send Token in Requests**:
   ```typescript
   // Include token in all authenticated requests
   headers: {
       'Authorization': `Bearer ${localStorage.getItem('access_token')}`
   }
   ```

3. **Update User Discovery**:
   ```typescript
   // Instead of getting all users, use friend list
   const friends = await api.get('/users/friends');
   ```

---

## Testing RLS Enforcement

### Test Case 1: User Can See Own Profile
```python
def test_user_can_view_own_profile():
    # Login as user 1
    token = get_token_for_user(1)
    client = get_supabase_client_for_user(token)
    
    response = client.table("users").select("*").eq("id", 1).execute()
    assert len(response.data) == 1  # Should succeed
```

### Test Case 2: User Cannot See Other Profiles
```python
def test_user_cannot_view_other_profile():
    # Login as user 1, try to view user 2
    token = get_token_for_user(1)
    client = get_supabase_client_for_user(token)
    
    response = client.table("users").select("*").eq("id", 2).execute()
    assert len(response.data) == 0  # Should be blocked by RLS
```

### Test Case 3: Unauthenticated Signup Still Works
```python
def test_unauthenticated_signup():
    # Use public client (no token)
    response = supabase.table("users").insert({
        "username": "newuser",
        "email": "new@example.com",
        "password_hash": "hash123"
    }).execute()
    assert len(response.data) == 1  # Should succeed
```

---

## Deployment Checklist

- [ ] Update `backend/config.py` with new environment variables
- [ ] Update `backend/db.py` with RLS-aware functions
- [ ] Update `backend/routes.py` to use JWT tokens
- [ ] Add JWT token support to frontend
- [ ] Test all endpoints with RLS enabled
- [ ] Update .env with service role key (keep secure!)
- [ ] Document new API endpoints
- [ ] Update API documentation
- [ ] Test with real Supabase database
- [ ] Monitor logs for RLS-related errors

---

## Debugging RLS Issues

### Enable Query Logging
```sql
-- Run in Supabase SQL Editor
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
SET log_min_messages = 'DEBUG';
SET log_min_duration_statement = 0;
```

### Check Active Policies
```sql
SELECT schemaname, tablename, policyname, permissive, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
```

### Test Policy with Current User
```sql
-- After authentication
SELECT * FROM users; -- Should show only current user's row
```

---

## Performance Considerations

1. **Indexes**: Already created for common queries
2. **RLS Overhead**: Minimal for properly indexed queries
3. **Caching**: Consider caching user data in sessions
4. **Service Role**: Use carefully, only for admin operations

---

**Last Updated**: February 26, 2026  
**Status**: Ready for implementation
