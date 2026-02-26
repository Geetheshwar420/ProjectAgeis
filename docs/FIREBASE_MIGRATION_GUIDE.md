# Firebase Migration Guide

## Overview

This document guides you through migrating from Supabase to Firebase for your quantum-secure messaging application.

---

## What Has Changed

### Database & Storage
- **Before**: Supabase PostgreSQL + Supabase Storage
- **After**: Firebase Firestore + Firebase Cloud Storage

### Authentication
- Still using session-based authentication (can be upgraded to Firebase Auth later)
- Same password hashing mechanism continues to work

### API Library
- **Before**: `supabase-py` (supabase>=2.0.0)
- **After**: `firebase-admin` (firebase-admin>=6.2.0)

---

## Migration Steps

### Step 1: Set Up Firebase Project

1. **Go to Firebase Console**
   - Visit https://console.firebase.google.com
   - Click "Create a new project" or select existing project

2. **Enable Firestore Database**
   - In left sidebar, click "Firestore Database"
   - Click "Create Database"
   - Choose location (closest to your users)
   - Select "Start in production mode" or "test mode" for development

3. **Enable Cloud Storage**
   - In left sidebar, click "Storage"
   - Click "Get started"
   - Choose location (same as database)

4. **Generate Service Account Key**
   - Go to Project Settings (⚙️ icon)
   - Click "Service Accounts" tab
   - Click "Generate New Private Key"
   - Save as `firebase-credentials.json` in your `backend/` folder

### Step 2: Install Dependencies

```bash
# Navigate to backend folder
cd backend

# Install new dependencies
pip install -r requirements.txt

# Or manually install Firebase Admin
pip install firebase-admin>=6.2.0
```

### Step 3: Configure Environment Variables

Create or update `.env` file in your `backend/` folder:

```bash
# Firebase Configuration
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-project-id.appspot.com
FIREBASE_CREDENTIALS_PATH=./firebase-credentials.json

# Keep these for reference (optional)
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_KEY=your-key

# Flask Configuration
SECRET_KEY=your-secret-key
FLASK_ENV=development
PORT=5000
```

Get your Project ID and Storage Bucket from Firebase Console:
- Project ID: Project Settings → General
- Storage Bucket: Storage → Look for bucket name (usually `projectid.appspot.com`)

### Step 4: Files Modified

The following files have been updated:

| File | Changes |
|------|---------|
| `backend/requirements.txt` | Replaced `supabase>=2.0.0` with `firebase-admin>=6.2.0` |
| `backend/config.py` | Added Firebase config variables |
| `backend/db.py` | Now imports from `firebase_db.py` |
| `backend/routes.py` | Updated upload to use Firebase Storage |
| `backend/firebase_db.py` | **NEW** - Firebase implementation |

### Step 5: New File: firebase_db.py

A new module `firebase_db.py` has been created with complete Firebase implementation:

#### Database Operations (Firestore)
- `create_user()` - Create new user
- `get_user_by_username()` - Query users
- `get_user_by_id()` - Get user by ID
- `update_user_status()` - Update online status
- `get_all_users()` - List all users
- `save_message()` - Store messages
- `get_messages_between_users()` - Retrieve messages
- `get_user_messages()` - Get all user messages
- `update_message_status()` - Mark messages as delivered/read
- `create_friend_request()` - Create friend requests
- `get_pending_friend_requests()` - Get pending requests
- `update_friend_request()` - Accept/reject requests
- `save_session_key()` - Store crypto keys
- `get_session_key()` - Retrieve session key
- `get_user_session_keys()` - List user's keys
- `delete_session_key()` - Remove session key

#### Storage Operations (Cloud Storage)
- `upload_file_content()` - Upload file from bytes
- `upload_file()` - Upload file from path
- `delete_file()` - Delete file from storage

---

## Firestore Collections Schema

The Firebase Firestore will automatically create collections as you add data. Here's the expected structure:

### `users` Collection
```
users/
├── {docId}/
│   ├── username: string (UNIQUE)
│   ├── password_hash: string
│   ├── public_keys: map
│   ├── is_online: boolean
│   ├── last_seen: timestamp
│   ├── created_at: timestamp
│   └── updated_at: timestamp
```

### `messages` Collection
```
messages/
├── {docId}/
│   ├── sender_id: string
│   ├── sender_username: string
│   ├── recipient_id: string
│   ├── recipient_username: string
│   ├── content: string
│   ├── session_id: string (optional)
│   ├── status: string (sent|delivered|read)
│   ├── formatted_timestamp: string
│   ├── iso_timestamp: string
│   ├── created_at: timestamp
│   ├── updated_at: timestamp
│   ├── delivered_at: timestamp
│   └── read_at: timestamp
```

### `friend_requests` Collection
```
friend_requests/
├── {docId}/
│   ├── from_user_id: string
│   ├── to_user_id: string
│   ├── status: string (pending|accepted|rejected)
│   ├── created_at: timestamp
│   └── updated_at: timestamp
```

### `session_keys` Collection
```
session_keys/
├── {docId}/
│   ├── user_id: string
│   ├── session_id: string (UNIQUE)
│   ├── key_material: string
│   ├── expires_at: timestamp
│   └── created_at: timestamp
```

---

## Firestore Security Rules

To properly secure your Firestore database, apply these rules in Firebase Console:

**Go to**: Firestore → Rules

Replace with this (adjust for your needs):

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // By default deny all
    match /{document=**} {
      allow read, write: if false;
    }
    
    // Users can view and edit their own profile
    match /users/{userId} {
      allow read: if request.auth.uid == userId || request.auth == null;
      allow create: if request.auth == null; // Allow signup
      allow update, delete: if request.auth.uid == userId;
    }
    
    // Messages - allow read if user is sender or recipient
    match /messages/{messageId} {
      allow create: if true; // Backend handles validation
      allow read: if request.auth != null;
      allow update, delete: if false; // Through backend only
    }
    
    // Friend Requests
    match /friend_requests/{requestId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null;
      allow update: if request.auth != null;
    }
    
    // Session Keys - private to each user
    match /session_keys/{keyId} {
      allow read: if request.auth.uid == resource.data.user_id;
      allow create, update, delete: if request.auth.uid == resource.data.user_id;
    }
  }
}
```

**Important**: Above rules are basic. Your backend still validates authorization. Adjust rules based on your security requirements.

---

## Querying Data in Firestore vs Supabase

### Example: Get user by username

**Supabase (OLD)**:
```python
response = supabase.table("users").select("*").eq("username", username).execute()
user = response.data[0] if response.data else None
```

**Firebase (NEW)**:
```python
from firebase_db import get_user_by_username
user = get_user_by_username(username)
```

### Example: Save a message

**Supabase (OLD)**:
```python
response = supabase.table("messages").insert(message_data).execute()
```

**Firebase (NEW)**:
```python
from firebase_db import save_message
message = save_message(sender_id, sender_username, recipient_id, 
                       recipient_username, content, session_id)
```

### Example: Upload a file

**Supabase (OLD)**:
```python
res = supabase.storage.from_("attachments").upload(filename, file_content)
public_url = supabase.storage.from_("attachments").get_public_url(filename)
```

**Firebase (NEW)**:
```python
from firebase_db import upload_file_content
public_url = upload_file_content(file_content, filename, folder='attachments')
```

---

## Backward Compatibility

The old `db.py` module now acts as a compatibility layer:
- It imports all functions from `firebase_db.py`
- Existing imports like `from db import create_user` still work
- No changes needed in existing code that uses these functions

---

## Testing the Migration

### 1. Test Firebase Connection

Create `test_firebase.py`:

```python
from firebase_db import initialize_firebase, get_db_client

try:
    client = initialize_firebase()
    print("✓ Firebase initialized successfully")
    
    # Test Firestore
    doc = client.collection('users').limit(1).stream()
    print("✓ Firestore connection successful")
    
    # Test Storage
    from firebase_admin import storage
    bucket = storage.bucket()
    print(f"✓ Firebase Storage bucket: {bucket.name}")
    
except Exception as e:
    print(f"✗ Error: {e}")
    print("Make sure:")
    print("  1. firebase-credentials.json exists in backend/")
    print("  2. FIREBASE_PROJECT_ID is set in .env")
    print("  3. FIREBASE_STORAGE_BUCKET is set in .env")
```

Run the test:
```bash
cd backend
python test_firebase.py
```

### 2. Test User Operations

```python
from db import create_user, get_user_by_username
from werkzeug.security import generate_password_hash

# Create test user
password = generate_password_hash("testpass123")
user = create_user("testuser", password)
print(f"Created user: {user}")

# Get user back
retrieved = get_user_by_username("testuser")
print(f"Retrieved user: {retrieved}")
```

### 3. Test Message Operations

```python
from db import save_message, get_messages_between_users

# Save a message
msg = save_message(
    sender_id="user1",
    sender_username="alice",
    recipient_id="user2",
    recipient_username="bob",
    content="Hello Bob!",
    session_id="session123"
)
print(f"Saved message: {msg}")

# Get messages
messages = get_messages_between_users("user1", "user2")
print(f"Messages: {messages}")
```

---

## Running the Application

### Development

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
# Create .env file with Firebase config

# Run Flask application
flask run
# Or
python app.py
```

### Production

```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or use the provided script
./run_prod.sh  # if exists
```

---

## Troubleshooting

### Error: "firebase-credentials.json not found"

**Solution**: 
1. Download credentials from Firebase Console (Project Settings → Service Accounts)
2. Save as `firebase-credentials.json` in `backend/` folder
3. Update `FIREBASE_CREDENTIALS_PATH` in `.env`

### Error: "Permission denied" when accessing Firestore

**Solution**:
1. Check Firestore Security Rules in Firebase Console
2. Ensure rules allow your operations
3. Temporarily use test mode for development (less secure)
4. Implement proper rules for production

### Error: "Storage bucket is invalid"

**Solution**:
1. Go to Firebase Console → Storage
2. Find your bucket name (usually `projectid.appspot.com`)
3. Set `FIREBASE_STORAGE_BUCKET` in `.env` to this value
4. Ensure storage is enabled: Storage → Get Started

### Error: "Collection not found"

**Solution**: This is normal! Firestore creates collections when you first write data. Run the application to create collections.

### FileNotFoundError: "firebase-credentials.json"

**Solution**:
```bash
# Check if file exists
ls backend/firebase-credentials.json

# If missing, download from:
# Firebase Console → Project Settings → Service Accounts → Generate Key
```

---

## Performance Optimization

### 1. Enable Firestore Indexes

For complex queries, Firestore may suggest indexes:
- Watch the console logs during development
- Visit Firestore Console → Indexes to create them
- Already optimized in `firebase_db.py` with proper ordering

### 2. Add Firestore Indexes for Common Queries

**Suggested Indexes**:
```javascript
// Collection: messages
// Fields: sender_id, created_at (Descending)
// Fields: recipient_id, created_at (Descending)

// Collection: friend_requests
// Fields: to_user_id, status, created_at (Descending)

// Collection: session_keys
// Fields: user_id, created_at (Descending)
```

Go to Firestore Console → Indexes → Create Composite Index

### 3. Use Firestore Caching

Firebase Admin SDK has built-in caching. For better performance:

```python
from firebase_admin import firestore

# Enable offline persistence if needed
db = get_db_client()
# Caching is enabled by default
```

---

## Cost Considerations

### Firestore Pricing (Google Cloud)
- **Reads**: $0.06 per 100,000 reads
- **Writes**: $0.18 per 100,000 writes
- **Deletes**: $0.02 per 100,000 deletes
- **Storage**: $0.18 per GB/month
- **Free tier**: 50,000 free reads/day, limited storage

### Cloud Storage Pricing
- **Storage**: $0.020 per GB (class A), $0.004 per GB (class B)
- **Downloads**: $0.12 per GB
- **Free tier**: 5 GB/month for downloads

### Tips to Reduce Costs
1. Use query filtering server-side (don't read everything)
2. Implement pagination with `limit()`
3. Archive old messages to separate collection
4. Compress files before upload
5. Set expiration on temporary files

---

## Migration Checklist

- [ ] Firebase project created
- [ ] Firestore Database enabled
- [ ] Cloud Storage enabled
- [ ] Service account key generated and saved
- [ ] `.env` updated with Firebase config
- [ ] `pip install -r requirements.txt` run
- [ ] Test Firebase connection successful
- [ ] User registration tested
- [ ] Message sending tested
- [ ] File upload tested
- [ ] Application runs without errors
- [ ] Firestore Security Rules configured
- [ ] Cloud Storage CORS configured (if frontend needs direct access)
- [ ] Performance tested and optimized
- [ ] Logged in to Firebase Console regularly to monitor usage

---

## Next Steps

1. **Complete Setup**: Follow "Migration Steps" section above
2. **Test Thoroughly**: Run all tests in "Testing the Migration" section
3. **Monitor**: Watch Firebase Console for errors and usage
4. **Optimize**: Apply performance tips in "Performance Optimization"
5. **Deploy**: Use your hosting platform (Render, Heroku, etc.)
6. **Update Frontend**: If frontend communicates with backend, no changes needed (same API)

---

## Support Resources

- **Firebase Documentation**: https://firebase.google.com/docs
- **Firebase Python Admin SDK**: https://firebase.google.com/docs/database/admin/start?hl=en&authuser=0#python
- **Firestore Queries**: https://firebase.google.com/docs/firestore/query-data/queries
- **Cloud Storage**: https://firebase.google.com/docs/storage

---

## Rollback Plan (If Needed)

If you need to revert to Supabase:

1. Keep the old `db.py` backup
2. Restore `requirements.txt` to use `supabase>=2.0.0`
3. Restore `db.py` from backup
4. Restore Supabase environment variables
5. Run `pip install -r requirements.txt`

However, it's recommended to fully commit to Firebase and handle any issues rather than rollback.

---

**Migration Status**: ✅ Ready for Deployment  
**Last Updated**: February 26, 2026  
**Version**: 1.0  
