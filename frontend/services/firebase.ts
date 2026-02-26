// Firebase Initialization Configuration
// This file sets up Firebase for the React application

import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";
import { getDatabase } from "firebase/database";
import { getAnalytics } from "firebase/analytics";

// Firebase configuration from Firebase Console
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyBQORbffn6XNr1V1WCPIGerXEDAejJZpRY",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "project-ageis.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "project-ageis",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "project-ageis.firebasestorage.app",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "165061572085",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:165061572085:web:b0f5065e049593d92a5cbc",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-FDT6RV1B0Z",
  // Optional: Realtime Database URL (if using Realtime Database)
  databaseURL: import.meta.env.VITE_FIREBASE_DATABASE_URL || "https://project-ageis.firebaseio.com"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firebase Services
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
export const realtimeDb = getDatabase(app);

// Initialize Analytics (optional)
let analytics;
try {
  analytics = getAnalytics(app);
} catch (error) {
  console.warn("Analytics initialization failed:", error);
}

export { analytics };
export default app;
