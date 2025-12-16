"""
Supabase Database Setup via SQL Editor API
Creates tables using Supabase's SQL execution capabilities
"""

import os
import json
import requests
import sys
from dotenv import load_dotenv

# Load environment
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=dotenv_path)

SUPABASE_URL = os.getenv('SUPABASE_URL', '').rstrip('/')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_KEY', '')
PROJECT_ID = SUPABASE_URL.split('//')[1].split('.')[0] if SUPABASE_URL else ''

print("=" * 70)
print("SUPABASE SCHEMA SETUP VIA API")
print("=" * 70)

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    print("✗ Missing SUPABASE_URL or SUPABASE_KEY")
    sys.exit(1)

print(f"\nProject: {PROJECT_ID}")

# Use the Management API to execute SQL
# Note: This requires admin access, not just anon key

print("""
To execute SQL commands on Supabase, you have two options:

OPTION 1: Use Supabase Dashboard (Recommended - 1 minute)
1. Go to: https://app.supabase.com
2. Open project: nlzvqtbsevtoevwgbbfc
3. Go to: SQL Editor
4. Click: "New Query"
5. Copy and paste the SQL from: db_schema.sql
6. Click: Run

OPTION 2: Use Management API (Requires Service Role Key)
1. Go to: Settings → API Preferences
2. Copy the "Service Role" key (secret key)
3. Update .env with: SUPABASE_SERVICE_ROLE_KEY=<your_service_role_key>
4. Run this script again

OPTION 3: Use Direct PostgreSQL Connection
1. Get database password from: Settings → Database → Database Password
2. Update .env with: DATABASE_URL=postgresql://postgres:PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
3. Run: python setup_supabase_schema.py

Your current setup uses Anon Key (read-only for non-authenticated users).
To create tables, you need:
- Service Role Key (for admin operations), OR
- Direct database password (for PostgreSQL connection), OR
- Manual setup via Supabase Dashboard
""")

# Create the SQL file for manual setup
sql_script = """
-- Supabase Database Schema for Messaging App

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
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
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Friend Requests table
CREATE TABLE IF NOT EXISTS friend_requests (
    id SERIAL PRIMARY KEY,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(from_user_id, to_user_id)
);

-- Session Keys table
CREATE TABLE IF NOT EXISTS session_keys (
    id SERIAL PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    key_material TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests(from_user_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests(to_user_id);
CREATE INDEX IF NOT EXISTS idx_session_keys_user ON session_keys(user_id);
"""

# Save SQL to file
sql_file = os.path.join(os.path.dirname(__file__), 'db_schema.sql')
with open(sql_file, 'w') as f:
    f.write(sql_script)

print(f"\n✓ SQL schema saved to: db_schema.sql")
print("\nTo manually create the schema:")
print("1. Open: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/sql")
print("2. Click: New Query")
print("3. Paste the contents of: db_schema.sql")
print("4. Click: Run")
