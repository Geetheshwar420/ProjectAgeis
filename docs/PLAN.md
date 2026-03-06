# 🎼 Orchestration Plan: Active Connections & Schema Alignment

## 1. Issue Analysis
**Symptom**: The Left Sidebar's "Active Connections" tab displays every single user registered on the database instead of only the accepted friends.
**Root Cause**: In `frontend/App.tsx`, the initialization `useEffect` calls `api.get('/users')` and maps every single registered user into the local `chats` array. The sidebar unconditionally renders the `chats` state.
**Database Schema**: You asked to review the `SUPABASE_SCHEMA_WITH_RLS.sql` and align the Firebase account. Good news: The current `firebase_db.py` perfectly maps the Supabase relational schema into NoSQL equivalents natively (`users`, `messages`, `friend_requests`, `session_keys`). It uses a `friends` subcollection in Firestore as a fast NoSQL junction table for accepted relationships. No destructive backend schema rewrite is needed!

---

## 2. Implementation Plan (Phase 2)

We will invoke specialized agents (Frontend Specialist & Testing Engineer) to accomplish the following fixes:

### A. Frontend Adjustments (`frontend/App.tsx`)
- Modify the `fetchChats` initialization function.
- Change the API call from `api.get('/users')` to `api.get('/friends')`.
- Map the resulting friends into the `Chat` objects (using the returned friend details like `username` and `is_online`).
- *Result*: Only accepted friends will populate the active connections list.

### B. Verification & Testing
- Use `playwright` or manual validation to ensure that upon login, the "Active Connections" list is restricted.
- Send a new friend request using the Modal, accept it, and verify the new friend dynamically populates the sidebar.

---

## 3. Approval Request
Do you approve this plan to swap the `/users` fetch for `/friends` fetch on the frontend to solve the sidebar issue?

*(If approved, I will instantly invoke the implementation agents in parallel to fix the logic!)*
