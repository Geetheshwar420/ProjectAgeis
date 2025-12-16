"""
Test CockroachDB connection with proper SSL/connection parameters
"""
import os
import sys
from dotenv import load_dotenv
import psycopg2

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)

db_url = os.getenv('DATABASE_URL')
if not db_url:
    print("DATABASE_URL not set")
    sys.exit(1)

# Convert postgres:// to postgresql:// if needed
connection_string = db_url
if connection_string.startswith('postgres://'):
    connection_string = connection_string.replace('postgres://', 'postgresql://', 1)

print(f"Connection string: {connection_string[:70]}...\n")

# Try different connection approaches
attempts = [
    ("Original connection string", connection_string, {}),
    ("With explicit sslmode=require", connection_string, {"sslmode": "require"}),
    ("With sslmode=disable", connection_string.replace("?sslmode=require", ""), {"sslmode": "disable"}),
]

for name, conn_str, params in attempts:
    try:
        print(f"Attempting: {name}...")
        conn = psycopg2.connect(conn_str, connect_timeout=5, **params)
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        version = cursor.fetchone()
        cursor.close()
        conn.close()
        print(f"  ✓ SUCCESS!")
        print(f"  Database: {version[0][:80]}...\n")
        break
    except Exception as e:
        error_msg = str(e)
        # Show only the meaningful part of error
        if "FATAL" in error_msg:
            error_msg = error_msg.split("FATAL")[1][:100]
        print(f"  ✗ Failed: {error_msg}\n")
