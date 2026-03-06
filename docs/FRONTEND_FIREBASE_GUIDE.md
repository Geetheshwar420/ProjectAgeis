# Frontend Firebase Integration Guide

## Overview

Your React/TypeScript frontend has been integrated with Firebase. This guide covers setup, usage, and best practices.

---

## What's New

### New Files Created

| File | Purpose |
|------|---------|
| `frontend/services/firebase.ts` | Firebase initialization and configuration |
| `frontend/services/firebaseService.ts` | All Firebase service modules |
| `frontend/.env.local.example` | Environment variables template |
| `frontend/context/AuthContext.tsx` | **UPDATED** - Now uses Firebase Auth |

### Packages Added

- **firebase** `^10.7.0` - Firebase SDK for web

---

## Setup Instructions

### 1. Install Dependencies

```bash
cd frontend
npm install
# or
yarn install
```

This will install the Firebase SDK along with all other dependencies.

### 2. Configure Environment Variables

Copy the environment template:

```bash
cp .env.local.example .env.local
```

The `.env.local` file already includes your Firebase config from the data you provided. No changes needed unless your config changes.

### 3. Verify Firebase Configuration

Check that your `frontend/services/firebase.ts` has the correct credentials:

```typescript
const firebaseConfig = {
  apiKey: "AIzaSyBQORbffn6XNr1V1WCPIGerXEDAejJZpRY",
  authDomain: "project-ageis.firebaseapp.com",
  projectId: "project-ageis",
  storageBucket: "project-ageis.firebasestorage.app",
  messagingSenderId: "165061572085",
  appId: "1:165061572085:web:b0f5065e049593d92a5cbc",
  measurementId: "G-FDT6RV1B0Z"
};
```

---

## Firebase Services Documentation

### Authentication Service (`authService`)

Handle user registration, login, and logout:

```typescript
import { authService } from './services/firebaseService';

// Register new user
try {
  const user = await authService.register(
    "user@example.com",
    "password123",
    "John Doe"
  );
  console.log("Registered:", user);
} catch (error) {
  console.error("Registration failed:", error);
}

// Login
try {
  const user = await authService.login("user@example.com", "password123");
  console.log("Logged in:", user);
} catch (error) {
  console.error("Login failed:", error);
}

// Logout
try {
  await authService.logout();
} catch (error) {
  console.error("Logout failed:", error);
}

// Get current user
const currentUser = authService.getCurrentUser();

// Listen to auth state changes
const unsubscribe = authService.onAuthStateChange((user) => {
  if (user) {
    console.log("User authenticated:", user.uid);
  } else {
    console.log("User logged out");
  }
});
```

### User Service (`userService`)

Manage user profiles:

```typescript
import { userService } from './services/firebaseService';

// Get user profile
const profile = await userService.getUserProfile(userId);

// Get user by username
const user = await userService.getUserByUsername("john_doe");

// Get all users
const allUsers = await userService.getAllUsers(50);

// Update profile
await userService.updateUserProfile(userId, {
  displayName: "John Updated",
  photoURL: "https://example.com/photo.jpg"
});

// Update online status
await userService.updateOnlineStatus(userId, true);

// Listen to profile changes
const unsubscribe = userService.onUserProfileChange(userId, (userData) => {
  console.log("User data updated:", userData);
});
```

### Message Service (`messageService`)

Send and receive messages:

```typescript
import { messageService } from './services/firebaseService';

// Send a message
const messageId = await messageService.sendMessage(
  senderId,
  senderUsername,
  recipientId,
  recipientUsername,
  "Hello, how are you?",
  sessionId
);

// Get messages between two users
const messages = await messageService.getMessagesBetween(user1Id, user2Id, 50);

// Listen for incoming messages
const unsubscribe = messageService.onMessagesReceived(
  currentUserId,
  otherUserId,
  (messages) => {
    console.log("Messages updated:", messages);
  }
);

// Update message status
await messageService.updateMessageStatus(messageId, "delivered");
await messageService.updateMessageStatus(messageId, "read");

// Delete message
await messageService.deleteMessage(messageId);
```

### Friend Service (`friendService`)

Manage friend requests:

```typescript
import { friendService } from './services/firebaseService';

// Send friend request
const requestId = await friendService.sendFriendRequest(userId1, userId2);

// Get pending requests
const pendingRequests = await friendService.getPendingRequests(userId);

// Accept request
await friendService.acceptFriendRequest(requestId);

// Reject request
await friendService.rejectFriendRequest(requestId);
```

### Storage Service (`storageService`)

Upload and manage files:

```typescript
import { storageService } from './services/firebaseService';

// Upload file
const result = await storageService.uploadFile(file, "attachments");
console.log("File uploaded:", result.url);

// Get download URL
const url = await storageService.getDownloadUrl(filePath);

// Delete file
await storageService.deleteFile(filePath);
```

### Realtime Service (`realtimeService`)

For real-time features like online status and typing indicators:

```typescript
import { realtimeService } from './services/firebaseService';

// Set online status
await realtimeService.setUserStatus(userId, true);

// Listen to user status
const unsubscribe = realtimeService.onUserStatusChange(userId, (data) => {
  console.log("User status:", data.isOnline);
});

// Set typing status
await realtimeService.setTypingStatus(userId, conversationId, true);

// Listen to typing indicators
const unsubscribe = realtimeService.onTypingStatusChange(
  conversationId,
  (data) => {
    console.log("Typing data:", data);
  }
);
```

### Session Key Service (`sessionKeyService`)

Manage cryptographic keys:

```typescript
import { sessionKeyService } from './services/firebaseService';

// Save session key
const keyId = await sessionKeyService.saveSessionKey(
  userId,
  sessionId,
  encryptedKeyMaterial,
  expiresAt
);

// Get session key
const key = await sessionKeyService.getSessionKey(sessionId);

// Delete session key
await sessionKeyService.deleteSessionKey(sessionId);
```

---

## Using Updated AuthContext

The `AuthContext` is now integrated with Firebase:

```typescript
import { useAuth } from './context/AuthContext';

function MyComponent() {
  const { user, isAuthenticated, isLoading, register, login, logout } = useAuth();

  // Register new user
  const handleRegister = async (email: string, password: string, displayName: string) => {
    try {
      await register(email, password, displayName);
      console.log("Registration successful");
    } catch (error) {
      console.error("Registration failed:", error);
    }
  };

  // Login
  const handleLogin = async (email: string, password: string) => {
    try {
      await login(email, password);
      console.log("Login successful");
    } catch (error) {
      console.error("Login failed:", error);
    }
  };

  // Logout
  const handleLogout = async () => {
    try {
      await logout();
      console.log("Logged out");
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <div>Not authenticated</div>;
  }

  return (
    <div>
      <h1>Welcome, {user?.username}!</h1>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
}
```

---

## Running the Application

### Development

```bash
cd frontend
npm run dev
```

This starts the Vite dev server at `http://localhost:5173`

### Build for Production

```bash
npm run build
```

This creates an optimized build in the `dist/` folder.

### Preview Production Build

```bash
npm run preview
```

---

## Firestore Security Rules

When using Firebase client SDK, security rules protect your data. Basic rules:

**In Firebase Console → Firestore → Rules:**

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can read their own document
    match /users/{userId} {
      allow read: if request.auth.uid == userId;
      allow create: if request.auth.uid == userId;
      allow update: if request.auth.uid == userId;
      allow delete: if request.auth.uid == userId;
    }
    
    // Messages - can read only if you're the sender or recipient
    match /messages/{messageId} {
      allow read: if request.auth.uid == resource.data.senderId || 
                     request.auth.uid == resource.data.recipientId;
      allow create: if request.auth.uid == request.resource.data.senderId;
      allow update: if request.auth.uid == resource.data.senderId;
      allow delete: if request.auth.uid == resource.data.senderId;
    }
    
    // Friend requests
    match /friend_requests/{requestId} {
      allow read, create, update: if request.auth.uid == resource.data.fromUserId || 
                                      request.auth.uid == resource.data.toUserId;
    }
    
    // Session keys - private to user
    match /session_keys/{keyId} {
      allow read, write: if request.auth.uid == resource.data.userId;
    }
  }
}
```

---

## Common Use Cases

### Authentication Flow

```typescript
// Sign up
const { register } = useAuth();
await register("user@example.com", "password", "John Doe");

// User is automatically logged in after registration
// AuthContext updates user state automatically
```

### Real-time Messaging

```typescript
const { user } = useAuth();
const [messages, setMessages] = useState([]);

useEffect(() => {
  if (!user) return;
  
  // Listen for messages
  const unsubscribe = messageService.onMessagesReceived(
    user.uid,
    otherUserId,
    (newMessages) => {
      setMessages(newMessages);
    }
  );
  
  return () => unsubscribe();
}, [user]);
```

### File Upload

```typescript
const handleFileUpload = async (file: File) => {
  try {
    const { url, name } = await storageService.uploadFile(file);
    console.log("File uploaded:", url);
    return url;
  } catch (error) {
    console.error("Upload failed:", error);
  }
};
```

---

## Troubleshooting

### "Firebase not initialized"
- Make sure `firebase.ts` is properly imported
- Check that `package.json` includes `"firebase": "^10.7.0"`
- Run `npm install` to ensure dependencies are installed

### "Authentication failed"
- Verify Firebase config in `.env.local` matches credentials
- Check Firebase Console → Authentication is enabled
- Ensure user email/password is valid

### "Firestore permission denied"
- Check Firestore security rules in Firebase Console
- Make sure user UID matches document UID for read/write
- Temporarily switch to test mode for development (less secure)

### "File upload failed"
- Enable Cloud Storage in Firebase Console
- Check storage bucket CORS settings
- Ensure file size is within limits

### "Real-time updates not working"
- Verify Realtime Database is enabled in Firebase Console
- Check that unsubscribe function is NOT called immediately
- Look for errors in browser console

---

## Performance Tips

1. **Pagination**: Use `limit()` to fetch fewer documents
2. **Indexes**: Create Firestore indexes for complex queries
3. **Caching**: Firebase SDK caches data automatically
4. **Unsubscribe**: Always unsubscribe from listeners when component unmounts
5. **Lazy Loading**: Load user data only when needed

Example - Unsubscribe on unmount:

```typescript
useEffect(() => {
  const unsubscribe = messageService.onMessagesReceived(
    user1Id,
    user2Id,
    (messages) => {
      setMessages(messages);
    }
  );
  
  // Cleanup on unmount
  return () => unsubscribe();
}, [user1Id, user2Id]);
```

---

## Security Best Practices

1. **Never expose keys in client code** ✅ (Using environment variables)
2. **Use security rules** ✅ (Provided in guide)
3. **Validate on client and backend** ✅ (Firebase rules + backend checks)
4. **Enable authentication** ✅ (Firebase Auth required)
5. **Use HTTPS in production** ✅ (Firebase enforces this)

---

## API Compatibility

The Vite/Firebase setup still supports the backend API for:
- WebSocket connections (Socket.io)
- Custom endpoints not in Firebase
- Quantum cryptography operations

Backend API is optional but can coexist with Firebase.

---

## Next Steps

1. ✅ Install dependencies: `npm install`
2. ✅ Set up `.env.local` with Firebase config
3. ✅ Run development server: `npm run dev`
4. ✅ Test authentication (register/login)
5. ✅ Test messaging features
6. ✅ Test file uploads
7. ✅ Configure Firestore security rules
8. ✅ Build and deploy: `npm run build`

---

## Resources

- **Firebase Docs**: https://firebase.google.com/docs/web/setup
- **Firestore Guide**: https://firebase.google.com/docs/firestore/quickstart
- **Firebase Auth**: https://firebase.google.com/docs/auth/web/start
- **Cloud Storage**: https://firebase.google.com/docs/storage/web/start
- **Realtime Database**: https://firebase.google.com/docs/database/web/start

---

**Frontend Firebase Integration**: ✅ Complete  
**Status**: Ready for Development  
**Last Updated**: February 26, 2026
