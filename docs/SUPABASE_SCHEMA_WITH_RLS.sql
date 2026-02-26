-- ============================================================================
-- SUPABASE DATABASE SCHEMA WITH ROW LEVEL SECURITY (RLS) ENABLED
-- ============================================================================
-- This schema includes proper RLS policies for all tables to ensure
-- users can only access data they are authorized to view/modify.
--
-- Run this SQL in Supabase SQL Editor:
-- 1. Go to: https://app.supabase.com/project/[YOUR_PROJECT]/sql/new
-- 2. Click: New Query
-- 3. Paste entire contents of this file
-- 4. Click: Run
-- ============================================================================

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Users Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Users can view their own profile
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT
    USING (id = auth.uid()::integer);

-- Users can update their own profile
CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE
    USING (id = auth.uid()::integer);

-- Allow public signup (insert without authentication)
CREATE POLICY "Anyone can create a user account" ON users
    FOR INSERT
    WITH CHECK (true);

-- ============================================================================
-- Messages Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP,
    read_at TIMESTAMP,
    status VARCHAR(50) DEFAULT 'sent',
    session_id UUID,
    formatted_timestamp VARCHAR(255),
    iso_timestamp VARCHAR(255),
    CONSTRAINT fk_sender FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Enable RLS on messages table
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

-- Users can view messages they sent
CREATE POLICY "Users can view messages they sent" ON messages
    FOR SELECT
    USING (sender_id = auth.uid()::integer);

-- Users can view messages they received
CREATE POLICY "Users can view messages they received" ON messages
    FOR SELECT
    USING (recipient_id = auth.uid()::integer);

-- Users can only insert messages they are sending
CREATE POLICY "Users can send messages" ON messages
    FOR INSERT
    WITH CHECK (sender_id = auth.uid()::integer);

-- Users can update their own messages
CREATE POLICY "Users can update their own messages" ON messages
    FOR UPDATE
    USING (sender_id = auth.uid()::integer);

-- ============================================================================
-- Friend Requests Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS friend_requests (
    id SERIAL PRIMARY KEY,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_from_user FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_to_user FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(from_user_id, to_user_id)
);

-- Enable RLS on friend_requests table
ALTER TABLE friend_requests ENABLE ROW LEVEL SECURITY;

-- Users can view friend requests they sent
CREATE POLICY "Users can view sent friend requests" ON friend_requests
    FOR SELECT
    USING (from_user_id = auth.uid()::integer);

-- Users can view friend requests they received
CREATE POLICY "Users can view received friend requests" ON friend_requests
    FOR SELECT
    USING (to_user_id = auth.uid()::integer);

-- Users can only send friend requests from themselves
CREATE POLICY "Users can send friend requests" ON friend_requests
    FOR INSERT
    WITH CHECK (from_user_id = auth.uid()::integer);

-- Users can only update friend requests they sent or received
CREATE POLICY "Users can update friend requests" ON friend_requests
    FOR UPDATE
    USING (from_user_id = auth.uid()::integer OR to_user_id = auth.uid()::integer);

-- ============================================================================
-- Session Keys Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS session_keys (
    id SERIAL PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    key_material TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Enable RLS on session_keys table
ALTER TABLE session_keys ENABLE ROW LEVEL SECURITY;

-- Users can view their own session keys
CREATE POLICY "Users can view own session keys" ON session_keys
    FOR SELECT
    USING (user_id = auth.uid()::integer);

-- Users can create their own session keys
CREATE POLICY "Users can create own session keys" ON session_keys
    FOR INSERT
    WITH CHECK (user_id = auth.uid()::integer);

-- Users can delete their own session keys
CREATE POLICY "Users can delete own session keys" ON session_keys
    FOR DELETE
    USING (user_id = auth.uid()::integer);

-- ============================================================================
-- Create Indexes for Performance
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender_recipient ON messages(sender_id, recipient_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests(from_user_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_user_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests(status);
CREATE INDEX IF NOT EXISTS idx_session_keys_user ON session_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_session_keys_session_id ON session_keys(session_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================================================
-- Verification Queries
-- ============================================================================
-- Run these AFTER the schema is created to verify:

-- 1. Check that all tables exist:
--    SELECT table_name FROM information_schema.tables 
--    WHERE table_schema = 'public' 
--    ORDER BY table_name;

-- 2. Verify RLS is enabled on all tables:
--    SELECT tablename, rowsecurity 
--    FROM pg_tables 
--    WHERE schemaname = 'public' 
--    AND tablename IN ('users', 'messages', 'friend_requests', 'session_keys');

-- 3. Check all RLS policies:
--    SELECT schemaname, tablename, policyname, permissive, roles, qual, with_check
--    FROM pg_policies
--    WHERE schemaname = 'public'
--    ORDER BY tablename, policyname;

-- ============================================================================
-- Expected output for RLS verification:
-- ============================================================================
-- Table: users
--   - Users can view own profile (SELECT)
--   - Users can update own profile (UPDATE)
--   - Anyone can create a user account (INSERT)
--
-- Table: messages
--   - Users can view messages they sent (SELECT)
--   - Users can view messages they received (SELECT)
--   - Users can send messages (INSERT)
--   - Users can update their own messages (UPDATE)
--
-- Table: friend_requests
--   - Users can view sent friend requests (SELECT)
--   - Users can view received friend requests (SELECT)
--   - Users can send friend requests (INSERT)
--   - Users can update friend requests (UPDATE)
--
-- Table: session_keys
--   - Users can view own session keys (SELECT)
--   - Users can create own session keys (INSERT)
--   - Users can delete own session keys (DELETE)
-- ============================================================================
