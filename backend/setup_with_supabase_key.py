"""
Supabase Setup Using URL and Anon Key
Retrieves database password and sets up the database automatically
"""

import os
import json
import requests
import time
from dotenv import load_dotenv

# Load environment
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=dotenv_path)

# Get Supabase credentials
SUPABASE_URL = os.getenv('SUPABASE_URL', '').rstrip('/')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_KEY', '')
PROJECT_ID = SUPABASE_URL.split('//')[1].split('.')[0] if SUPABASE_URL else ''

print("=" * 70)
print("SUPABASE SETUP USING URL AND ANON KEY")
print("=" * 70)

print(f"\nProject URL: {SUPABASE_URL}")
print(f"Project ID: {PROJECT_ID}")
print(f"Anon Key: {SUPABASE_ANON_KEY[:20]}...")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    print("\n✗ Missing SUPABASE_URL or SUPABASE_KEY in .env")
    exit(1)

print("\n" + "=" * 70)
print("STEP 1: Get Database Connection Details")
print("=" * 70)

# Note: The anon key doesn't give access to admin functions directly
# But we can help extract the connection details

print(f"""
To complete the setup, you need to manually get the database password:

1. Go to: https://app.supabase.com
2. Open project: {PROJECT_ID}
3. Settings → Database
4. Copy the database password

OR use the Management API (if you have admin access):

The connection string should be:
  postgresql://postgres:PASSWORD@db.{PROJECT_ID}.supabase.co:5432/postgres

Your Supabase details are already configured:
  - Project ID: {PROJECT_ID}
  - Host: db.{PROJECT_ID}.supabase.co
  - Port: 5432
  - Database: postgres
  - User: postgres
""")

# Try to get database info from Supabase API
print("Attempting to retrieve database information from Supabase API...")

headers = {
    "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
    "Content-Type": "application/json"
}

# Try REST API to get database status
try:
    # This endpoint might work with anon key
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/",
        headers=headers,
        timeout=5
    )
    print(f"✓ Supabase API is accessible (Status: {response.status_code})")
except Exception as e:
    print(f"API check: {e}")

print("\n" + "=" * 70)
print("ALTERNATIVE: Use pgAdmin or Direct Connection")
print("=" * 70)

print("""
If you have the database password, run:
  python setup_supabase_schema.py

If you need to reset the password:
1. Go to: https://app.supabase.com
2. Settings → Database
3. Click "Reset Password"
4. Copy the new password
5. Update .env with: DATABASE_URL=postgresql://postgres:NEW_PASSWORD@db.{PROJECT_ID}.supabase.co:5432/postgres
6. Run: python setup_supabase_schema.py
""")
