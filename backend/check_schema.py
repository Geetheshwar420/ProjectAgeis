#!/usr/bin/env python3
"""Check the actual schema of friend_requests table in production database."""

from db_adapter import DatabaseAdapter
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

print("Connecting to database...")
db = DatabaseAdapter()
db.connect()

print(f"Connected to: {db.db_type.upper()}")
print(f"Host: {db._get_postgres_host() if db.db_type == 'postgresql' else 'N/A'}\n")

cur = db.cursor()

# Get friend_requests table schema
print("=" * 60)
print("friend_requests TABLE SCHEMA:")
print("=" * 60)

cur.execute("""
    SELECT column_name, data_type, is_nullable, column_default
    FROM information_schema.columns 
    WHERE table_schema='public' AND table_name='friend_requests' 
    ORDER BY ordinal_position
""")

rows = cur.fetchall()
if rows:
    for row in rows:
        col_name = row['column_name'] if isinstance(row, dict) else row[0]
        data_type = row['data_type'] if isinstance(row, dict) else row[1]
        nullable = row['is_nullable'] if isinstance(row, dict) else row[2]
        default = row['column_default'] if isinstance(row, dict) else row[3]
        
        print(f"  {col_name:20s} {data_type:15s} NULL:{nullable:3s} DEFAULT:{default or 'N/A'}")
else:
    print("  No columns found!")

print("\n" + "=" * 60)
print("FRIEND_REQUESTS DATA (if any):")
print("=" * 60)

cur.execute("SELECT * FROM friend_requests LIMIT 5")
data_rows = cur.fetchall()
if data_rows:
    for i, row in enumerate(data_rows, 1):
        print(f"\nRow {i}:")
        if isinstance(row, dict):
            for key, val in row.items():
                print(f"  {key}: {val}")
        else:
            print(f"  {row}")
else:
    print("  (empty table)")

db.close()
print("\n✅ Done!")
