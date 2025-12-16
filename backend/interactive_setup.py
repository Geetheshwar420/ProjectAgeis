"""
Interactive Supabase Setup Helper
Guides you through the complete setup process
"""

import os
import webbrowser
from dotenv import load_dotenv

# Load environment
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=dotenv_path)

SUPABASE_URL = os.getenv('SUPABASE_URL', '').rstrip('/')
PROJECT_ID = SUPABASE_URL.split('//')[1].split('.')[0] if SUPABASE_URL else ''

print("=" * 70)
print("SUPABASE SETUP WIZARD")
print("=" * 70)
print(f"\nProject ID: {PROJECT_ID}")
print(f"Project URL: {SUPABASE_URL}\n")

# Instructions
print("""
STEP 1: CREATE DATABASE SCHEMA
================================

1. Open Supabase Dashboard:
   https://app.supabase.com/project/{}/sql/new

2. Copy all SQL from: backend/db_schema.sql

3. Paste into the SQL editor

4. Click the green "Run" button

5. You should see "Queries completed successfully"

STEP 2: VERIFY TABLES WERE CREATED
==================================

After Step 1, run this verification query:

SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;

You should see:
  - friend_requests
  - messages
  - session_keys
  - users

STEP 3: GET DATABASE PASSWORD (If needed for local development)
================================================================

If you want to connect from your local machine:

1. Go to: https://app.supabase.com/project/{}/settings/database

2. Look for "Database Password"

3. If you don't remember it, click "Reset Password"

4. Copy the password

5. Update backend/.env:
   DATABASE_URL=postgresql://postgres:PASSWORD@db.{}.supabase.co:5432/postgres

6. Run: python app.py

STEP 4: START YOUR APPLICATION
==============================

Once schema is created, run:

   cd backend
   python app.py

You should see:
   ✓ Database connected successfully
   Starting Quantum Secure Messaging Backend

HELP & TROUBLESHOOTING
======================

Issue: "Tables don't exist"
Fix: Run the SQL from db_schema.sql in Supabase SQL Editor

Issue: "Connection refused"
Fix: Get database password from Settings → Database

Issue: "Authentication failed"
Fix: Password might have special characters - use URL encoding

NEXT STEPS
==========

1. Go to: https://app.supabase.com
2. Open your project
3. Go to SQL Editor
4. Create a new query with the SQL from db_schema.sql
5. Click Run
6. Come back and tell me "schema created" 
7. I'll help you start the app!

""".format(PROJECT_ID, PROJECT_ID, PROJECT_ID))

# Ask if user wants to open dashboard
try:
    response = input("Would you like to open Supabase dashboard? (y/n): ").lower().strip()
    if response == 'y':
        url = f"https://app.supabase.com/project/{PROJECT_ID}/sql/new"
        webbrowser.open(url)
        print(f"\nOpened: {url}")
        print("\nPaste the SQL from db_schema.sql and click Run!")
except:
    pass

print("\n" + "=" * 70)
print("When you've created the schema, the app will be ready to run!")
print("=" * 70)
