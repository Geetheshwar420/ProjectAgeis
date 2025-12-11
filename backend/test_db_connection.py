"""
Database connection diagnostic script
Tests various aspects of the database connection
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    print(f"✓ Loaded .env from: {dotenv_path}\n")
else:
    print(f"✗ .env not found at: {dotenv_path}\n")

# Get connection string
db_url = os.getenv('DATABASE_URL')
if not db_url:
    print("✗ DATABASE_URL not set in environment")
    sys.exit(1)

print(f"DATABASE_URL (first 60 chars): {db_url[:60]}...")
print()

# Parse connection string
from urllib.parse import urlparse
parsed = urlparse(db_url)
print("Connection Details:")
print(f"  Host: {parsed.hostname}")
print(f"  Port: {parsed.port}")
print(f"  Database: {parsed.path}")
print(f"  User: {parsed.username}")
print()

# Test network connectivity
print("Testing network connectivity...")
import socket

try:
    # Test DNS resolution
    ip = socket.gethostbyname(parsed.hostname)
    print(f"✓ DNS Resolution: {parsed.hostname} -> {ip}")
except socket.gaierror as e:
    print(f"✗ DNS Resolution failed: {e}")
    sys.exit(1)

# Test port connectivity
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((parsed.hostname, parsed.port or 5432))
    sock.close()
    
    if result == 0:
        print(f"✓ Port {parsed.port or 5432} is open")
    else:
        print(f"✗ Port {parsed.port or 5432} is closed or unreachable")
        print("  This likely indicates a firewall or network issue")
except Exception as e:
    print(f"✗ Port connectivity test failed: {e}")

print()
print("Testing psycopg2 connection...")

try:
    import psycopg2
    
    # Convert postgres:// to postgresql:// if needed
    connection_string = db_url
    if connection_string.startswith('postgres://'):
        connection_string = connection_string.replace('postgres://', 'postgresql://', 1)
    
    conn = psycopg2.connect(connection_string, connect_timeout=10)
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    print("✓ Successfully connected to database!")
    
except psycopg2.OperationalError as e:
    print(f"✗ Connection failed: {e}")
    print()
    print("Possible causes:")
    print("  1. Invalid credentials in DATABASE_URL")
    print("  2. Network/firewall blocking connection")
    print("  3. Database server is down")
    print("  4. IP not whitelisted in Supabase/CockroachDB security settings")
    
except Exception as e:
    print(f"✗ Unexpected error: {e}")

print()
print("Diagnostic complete.")
