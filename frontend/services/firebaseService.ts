// Firebase Service Module
// Handles all Firebase operations for the frontend

import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  User,
  updateProfile,
  setPersistence,
  browserLocalPersistence,
  Auth,
} from "firebase/auth";
import {
  collection,
  doc,
  setDoc,
  getDoc,
  query,
  where,
  getDocs,
  updateDoc,
  addDoc,
  deleteDoc,
  Timestamp,
  Firestore,
  onSnapshot,
  orderBy,
  limit,
  QuerySnapshot,
  DocumentData,
} from "firebase/firestore";
import {
  ref,
  uploadBytes,
  getDownloadURL,
  deleteObject,
  Storage,
  UploadResult,
} from "firebase/storage";
import {
  ref as dbRef,
  set,
  get,
  onValue,
  Database,
} from "firebase/database";
import { auth, db, storage, realtimeDb } from "./firebase";

// ============================================================================
// Authentication Service
// ============================================================================

export const authService = {
  /**
   * Register a new user with email and password
   */
  async register(email: string, password: string, displayName: string) {
    try {
      // Set persistence
      await setPersistence(auth, browserLocalPersistence);
      
      // Create user account
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      const user = userCredential.user;
      
      // Update profile with display name
      if (user) {
        await updateProfile(user, {
          displayName: displayName,
        });
      }
      
      // Create user document in Firestore
      await setDoc(doc(db, "users", user.uid), {
        uid: user.uid,
        email: email,
        username: displayName,
        displayName: displayName,
        createdAt: Timestamp.now(),
        updatedAt: Timestamp.now(),
        isOnline: true,
        lastSeen: Timestamp.now(),
        publicKeys: {},
        photoURL: user.photoURL || null,
      });
      
      return user;
    } catch (error: any) {
      console.error("Registration error:", error.message);
      throw new Error(error.message);
    }
  },

  /**
   * Sign in an existing user
   */
  async login(email: string, password: string) {
    try {
      // Set persistence
      await setPersistence(auth, browserLocalPersistence);
      
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      const user = userCredential.user;
      
      // Update online status
      if (user) {
        await updateDoc(doc(db, "users", user.uid), {
          isOnline: true,
          lastSeen: Timestamp.now(),
        });
      }
      
      return user;
    } catch (error: any) {
      console.error("Login error:", error.message);
      throw new Error(error.message);
    }
  },

  /**
   * Sign out the current user
   */
  async logout() {
    try {
      const user = auth.currentUser;
      
      // Update online status before logout
      if (user) {
        await updateDoc(doc(db, "users", user.uid), {
          isOnline: false,
          lastSeen: Timestamp.now(),
        });
      }
      
      await signOut(auth);
    } catch (error: any) {
      console.error("Logout error:", error.message);
      throw new Error(error.message);
    }
  },

  /**
   * Get current authenticated user
   */
  getCurrentUser(): User | null {
    return auth.currentUser;
  },

  /**
   * Listen to authentication state changes
   */
  onAuthStateChange(callback: (user: User | null) => void) {
    return onAuthStateChanged(auth, callback);
  },
};

// ============================================================================
// User Service
// ============================================================================

export const userService = {
  /**
   * Get user profile by UID
   */
  async getUserProfile(uid: string) {
    try {
      const userDoc = await getDoc(doc(db, "users", uid));
      return userDoc.exists() ? userDoc.data() : null;
    } catch (error: any) {
      console.error("Get user profile error:", error.message);
      throw error;
    }
  },

  /**
   * Get user by username
   */
  async getUserByUsername(username: string) {
    try {
      const q = query(collection(db, "users"), where("username", "==", username));
      const querySnapshot = await getDocs(q);
      return querySnapshot.empty ? null : querySnapshot.docs[0].data();
    } catch (error: any) {
      console.error("Get user by username error:", error.message);
      throw error;
    }
  },

  /**
   * Get all users (for user discovery)
   */
  async getAllUsers(limit: number = 50) {
    try {
      const q = query(
        collection(db, "users"),
        orderBy("createdAt", "desc"),
        limit
      );
      const querySnapshot = await getDocs(q);
      return querySnapshot.docs.map((doc) => ({
        uid: doc.id,
        ...doc.data(),
      }));
    } catch (error: any) {
      console.error("Get all users error:", error.message);
      throw error;
    }
  },

  /**
   * Update user profile
   */
  async updateUserProfile(uid: string, updates: any) {
    try {
      await updateDoc(doc(db, "users", uid), {
        ...updates,
        updatedAt: Timestamp.now(),
      });
    } catch (error: any) {
      console.error("Update user profile error:", error.message);
      throw error;
    }
  },

  /**
   * Update user online status
   */
  async updateOnlineStatus(uid: string, isOnline: boolean) {
    try {
      await updateDoc(doc(db, "users", uid), {
        isOnline: isOnline,
        lastSeen: Timestamp.now(),
      });
    } catch (error: any) {
      console.error("Update online status error:", error.message);
      throw error;
    }
  },

  /**
   * Listen to user profile changes in real-time
   */
  onUserProfileChange(uid: string, callback: (userData: any) => void) {
    try {
      return onSnapshot(doc(db, "users", uid), (doc) => {
        if (doc.exists()) {
          callback(doc.data());
        }
      });
    } catch (error: any) {
      console.error("Listen to user profile error:", error.message);
      throw error;
    }
  },
};

// ============================================================================
// Message Service
// ============================================================================

export const messageService = {
  /**
   * Send a message
   */
  async sendMessage(
    senderId: string,
    senderUsername: string,
    recipientId: string,
    recipientUsername: string,
    content: string,
    sessionId?: string
  ) {
    try {
      const messageRef = await addDoc(collection(db, "messages"), {
        senderId: senderId,
        senderUsername: senderUsername,
        recipientId: recipientId,
        recipientUsername: recipientUsername,
        content: content,
        sessionId: sessionId || null,
        status: "sent",
        createdAt: Timestamp.now(),
        updatedAt: Timestamp.now(),
        deliveredAt: null,
        readAt: null,
        formattedTimestamp: new Date().toLocaleString(),
        isoTimestamp: new Date().toISOString(),
      });
      
      return messageRef.id;
    } catch (error: any) {
      console.error("Send message error:", error.message);
      throw error;
    }
  },

  /**
   * Get messages between two users
   */
  async getMessagesBetween(userId1: string, userId2: string, limitCount: number = 50) {
    try {
      const q = query(
        collection(db, "messages"),
        where("senderId", "in", [userId1, userId2]),
        orderBy("createdAt", "desc"),
        limit(limitCount)
      );
      
      const querySnapshot = await getDocs(q);
      const allMessages = querySnapshot.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }));
      
      // Filter to only messages between these two users
      return allMessages.filter(
        (msg: any) =>
          (msg.senderId === userId1 && msg.recipientId === userId2) ||
          (msg.senderId === userId2 && msg.recipientId === userId1)
      );
    } catch (error: any) {
      console.error("Get messages between error:", error.message);
      throw error;
    }
  },

  /**
   * Listen to messages in real-time
   */
  onMessagesReceived(
    userId1: string,
    userId2: string,
    callback: (messages: any[]) => void
  ) {
    try {
      const q = query(
        collection(db, "messages"),
        orderBy("createdAt", "desc"),
        limit(50)
      );
      
      return onSnapshot(q, (querySnapshot) => {
        const messages = querySnapshot.docs
          .map((doc) => ({
            id: doc.id,
            ...doc.data(),
          }))
          .filter(
            (msg: any) =>
              (msg.senderId === userId1 && msg.recipientId === userId2) ||
              (msg.senderId === userId2 && msg.recipientId === userId1)
          );
        
        callback(messages);
      });
    } catch (error: any) {
      console.error("Listen to messages error:", error.message);
      throw error;
    }
  },

  /**
   * Update message status (delivered/read)
   */
  async updateMessageStatus(messageId: string, status: "delivered" | "read") {
    try {
      const statusField = status === "delivered" ? "deliveredAt" : "readAt";
      await updateDoc(doc(db, "messages", messageId), {
        status: status,
        [statusField]: Timestamp.now(),
        updatedAt: Timestamp.now(),
      });
    } catch (error: any) {
      console.error("Update message status error:", error.message);
      throw error;
    }
  },

  /**
   * Delete a message
   */
  async deleteMessage(messageId: string) {
    try {
      await deleteDoc(doc(db, "messages", messageId));
    } catch (error: any) {
      console.error("Delete message error:", error.message);
      throw error;
    }
  },
};

// ============================================================================
// Friend Request Service
// ============================================================================

export const friendService = {
  /**
   * Send a friend request
   */
  async sendFriendRequest(fromUserId: string, toUserId: string) {
    try {
      const requestRef = await addDoc(collection(db, "friend_requests"), {
        fromUserId: fromUserId,
        toUserId: toUserId,
        status: "pending",
        createdAt: Timestamp.now(),
        updatedAt: Timestamp.now(),
      });
      
      return requestRef.id;
    } catch (error: any) {
      console.error("Send friend request error:", error.message);
      throw error;
    }
  },

  /**
   * Get pending friend requests for a user
   */
  async getPendingRequests(userId: string) {
    try {
      const q = query(
        collection(db, "friend_requests"),
        where("toUserId", "==", userId),
        where("status", "==", "pending"),
        orderBy("createdAt", "desc")
      );
      
      const querySnapshot = await getDocs(q);
      return querySnapshot.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }));
    } catch (error: any) {
      console.error("Get pending requests error:", error.message);
      throw error;
    }
  },

  /**
   * Accept a friend request
   */
  async acceptFriendRequest(requestId: string) {
    try {
      await updateDoc(doc(db, "friend_requests", requestId), {
        status: "accepted",
        updatedAt: Timestamp.now(),
      });
    } catch (error: any) {
      console.error("Accept friend request error:", error.message);
      throw error;
    }
  },

  /**
   * Reject a friend request
   */
  async rejectFriendRequest(requestId: string) {
    try {
      await updateDoc(doc(db, "friend_requests", requestId), {
        status: "rejected",
        updatedAt: Timestamp.now(),
      });
    } catch (error: any) {
      console.error("Reject friend request error:", error.message);
      throw error;
    }
  },
};

// ============================================================================
// File Storage Service
// ============================================================================

export const storageService = {
  /**
   * Upload a file to Firebase Storage
   */
  async uploadFile(file: File, path: string = "attachments") {
    try {
      const fileName = `${Date.now()}_${file.name}`;
      const fileRef = ref(storage, `${path}/${fileName}`);
      
      const snapshot = await uploadBytes(fileRef, file);
      const downloadURL = await getDownloadURL(snapshot.ref);
      
      return {
        url: downloadURL,
        path: snapshot.ref.fullPath,
        name: fileName,
      };
    } catch (error: any) {
      console.error("Upload file error:", error.message);
      throw error;
    }
  },

  /**
   * Get download URL for a file
   */
  async getDownloadUrl(filePath: string) {
    try {
      const fileRef = ref(storage, filePath);
      return await getDownloadURL(fileRef);
    } catch (error: any) {
      console.error("Get download URL error:", error.message);
      throw error;
    }
  },

  /**
   * Delete a file from storage
   */
  async deleteFile(filePath: string) {
    try {
      const fileRef = ref(storage, filePath);
      await deleteObject(fileRef);
    } catch (error: any) {
      console.error("Delete file error:", error.message);
      throw error;
    }
  },
};

// ============================================================================
// Realtime Database Service (for real-time features)
// ============================================================================

export const realtimeService = {
  /**
   * Set user status in realtime database
   */
  async setUserStatus(userId: string, isOnline: boolean) {
    try {
      const userStatusRef = dbRef(realtimeDb, `status/${userId}`);
      await set(userStatusRef, {
        isOnline: isOnline,
        lastSeen: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error("Set user status error:", error.message);
      throw error;
    }
  },

  /**
   * Listen to user status in realtime
   */
  onUserStatusChange(userId: string, callback: (data: any) => void) {
    try {
      const userStatusRef = dbRef(realtimeDb, `status/${userId}`);
      return onValue(userStatusRef, callback);
    } catch (error: any) {
      console.error("Listen to user status error:", error.message);
      throw error;
    }
  },

  /**
   * Send typing indicator
   */
  async setTypingStatus(userId: string, conversationId: string, isTyping: boolean) {
    try {
      const typingRef = dbRef(realtimeDb, `typing/${conversationId}/${userId}`);
      if (isTyping) {
        await set(typingRef, {
          userId: userId,
          timestamp: new Date().toISOString(),
        });
      } else {
        await set(typingRef, null);
      }
    } catch (error: any) {
      console.error("Set typing status error:", error.message);
      throw error;
    }
  },

  /**
   * Listen to typing indicators
   */
  onTypingStatusChange(conversationId: string, callback: (data: any) => void) {
    try {
      const typingRef = dbRef(realtimeDb, `typing/${conversationId}`);
      return onValue(typingRef, callback);
    } catch (error: any) {
      console.error("Listen to typing status error:", error.message);
      throw error;
    }
  },
};

// ============================================================================
// Session Key Service (for cryptography)
// ============================================================================

export const sessionKeyService = {
  /**
   * Save a session key
   */
  async saveSessionKey(
    userId: string,
    sessionId: string,
    keyMaterial: string,
    expiresAt?: Date
  ) {
    try {
      const keyRef = await addDoc(collection(db, "session_keys"), {
        userId: userId,
        sessionId: sessionId,
        keyMaterial: keyMaterial,
        expiresAt: expiresAt ? Timestamp.fromDate(expiresAt) : null,
        createdAt: Timestamp.now(),
      });
      
      return keyRef.id;
    } catch (error: any) {
      console.error("Save session key error:", error.message);
      throw error;
    }
  },

  /**
   * Get a session key
   */
  async getSessionKey(sessionId: string) {
    try {
      const q = query(
        collection(db, "session_keys"),
        where("sessionId", "==", sessionId)
      );
      
      const querySnapshot = await getDocs(q);
      return querySnapshot.empty ? null : querySnapshot.docs[0].data();
    } catch (error: any) {
      console.error("Get session key error:", error.message);
      throw error;
    }
  },

  /**
   * Delete a session key
   */
  async deleteSessionKey(sessionId: string) {
    try {
      const q = query(
        collection(db, "session_keys"),
        where("sessionId", "==", sessionId)
      );
      
      const querySnapshot = await getDocs(q);
      for (const doc of querySnapshot.docs) {
        await deleteDoc(doc.ref);
      }
    } catch (error: any) {
      console.error("Delete session key error:", error.message);
      throw error;
    }
  },
};

export default {
  authService,
  userService,
  messageService,
  friendService,
  storageService,
  realtimeService,
  sessionKeyService,
};
