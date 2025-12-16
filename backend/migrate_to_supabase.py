"""
Quick Supabase Setup Script

This script guides you through connecting to Supabase and setting up the database.
"""

import os
import subprocess
import sys
from dotenv import load_dotenv

# Load environment
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=dotenv_path)

print("=" * 70)
print("SUPABASE MIGRATION SETUP")
print("=" * 70)

# Check if password is set
db_url = os.getenv('DATABASE_URL', '')
if '[YOUR_SUPABASE_PASSWORD]' in db_url or 'password' in db_url.lower():
    print("\n⚠️  ACTION REQUIRED: Update your Supabase database password\n")
    print("Steps:")
    print("1. Go to: https://app.supabase.com")
    print("2. Open project: nlzvqtbsevtoevwgbbfc")
    print("3. Go to: Settings → Database")
    print("4. Find and copy your database password")
    print("5. Update DATABASE_URL in backend/.env file")
    print("6. Replace [YOUR_SUPABASE_PASSWORD] with your actual password")
    print("\nExample:")
    print("  DATABASE_URL=postgresql://postgres:myPassword123@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres")
    sys.exit(1)

print("\n✓ Database URL is configured\n")

# Test connection
print("Testing Supabase connection...")
import psycopg2

try:
    conn = psycopg2.connect(db_url, connect_timeout=10)
    conn.close()
    print("✓ Connection successful!\n")
except Exception as e:
    print(f"✗ Connection failed: {e}\n")
    print("Please check your database password and try again.")
    sys.exit(1)

# Create schema
print("Creating database schema...")
try:
    result = subprocess.run(
        [sys.executable, 'setup_supabase_schema.py'],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(__file__)
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)

print("\n" + "=" * 70)
print("SETUP COMPLETE!")
print("=" * 70)
print("\nYou can now run:")
print("  python run.py")
print("\nOr for development:")
print("  python app.py")
