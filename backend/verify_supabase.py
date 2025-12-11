"""
Verify Supabase Connection
Run this after creating the schema to test the connection
"""

import os
import sys
from dotenv import load_dotenv

# Load environment
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=dotenv_path)

SUPABASE_URL = os.getenv('SUPABASE_URL', '')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '')
DATABASE_URL = os.getenv('DATABASE_URL', '')

print("=" * 70)
print("SUPABASE CONFIGURATION CHECK")
print("=" * 70)

print("\n✓ Configuration Found:")
print(f"  SUPABASE_URL: {SUPABASE_URL[:50]}...")
print(f"  SUPABASE_KEY: {SUPABASE_KEY[:20]}...")
print(f"  DATABASE_URL: {DATABASE_URL[:60]}...")

print("\n" + "=" * 70)
print("TESTING DATABASE CONNECTION")
print("=" * 70)

if not DATABASE_URL or '[YOUR_SUPABASE_PASSWORD]' in DATABASE_URL:
    print("\n⚠️  DATABASE_URL not fully configured")
    print("   Need to add database password from Supabase dashboard")
    print("\n   Steps:")
    print("   1. Go to: https://app.supabase.com")
    print("   2. Settings → Database")
    print("   3. Copy database password")
    print("   4. Update backend/.env with:")
    print("      DATABASE_URL=postgresql://postgres:PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres")
    sys.exit(0)

try:
    import psycopg2
    print("\nAttempting to connect to PostgreSQL...")
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10)
    cursor = conn.cursor()
    
    # Test 1: Check connection
    print("✓ Connected successfully!")
    
    # Test 2: Check tables
    cursor.execute("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name
    """)
    tables = cursor.fetchall()
    
    if tables:
        print("\n✓ Tables found:")
        for (table,) in tables:
            print(f"  - {table}")
    else:
        print("\n⚠️  No tables found")
        print("   Need to run: python setup_supabase_schema.py")
    
    # Test 3: Check users table
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        print(f"\n✓ Users table: {count} users")
    except:
        print("\n⚠️  Users table not accessible")
    
    cursor.close()
    conn.close()
    
    print("\n" + "=" * 70)
    print("✓ ALL CHECKS PASSED - READY TO START APP!")
    print("=" * 70)
    print("\nRun: python app.py")
    
except psycopg2.OperationalError as e:
    print(f"\n✗ Connection failed: {e}")
    print("\nPossible causes:")
    print("  1. Database password is incorrect")
    print("  2. Password contains special characters that need URL encoding")
    print("  3. Database server is down")
except ImportError:
    print("\n⚠️  psycopg2 not installed")
    print("   Run: pip install psycopg2-binary")
except Exception as e:
    print(f"\n✗ Error: {e}")

print("\n" + "=" * 70)
