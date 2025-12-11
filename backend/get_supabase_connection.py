"""
Supabase Connection String Generator

This script helps you get your Supabase connection string and test the connection.
"""

import re
import sys

print("=" * 70)
print("SUPABASE CONNECTION STRING SETUP")
print("=" * 70)

# Supabase project details (from your earlier config)
PROJECT_ID = "nlzvqtbsevtoevwgbbfc"
HOST = f"db.{PROJECT_ID}.supabase.co"
PORT = 5432
DATABASE = "postgres"
USERNAME = "postgres"

print(f"\nYour Supabase Project Details:")
print(f"  Project ID: {PROJECT_ID}")
print(f"  Host: {HOST}")
print(f"  Port: {PORT}")
print(f"  Database: {DATABASE}")
print(f"  Username: {USERNAME}")

print("\n" + "=" * 70)
print("GET YOUR DATABASE PASSWORD")
print("=" * 70)

print("""
Follow these steps to get your database password:

1. Go to: https://app.supabase.com
2. Click on your project: 'nlzvqtbsevtoevwgbbfc'
3. In the left sidebar, click "Settings" (gear icon)
4. Click "Database" in the dropdown
5. Scroll to "Database Password" section
6. You should see a password field
7. Click the "Reset password" button if you don't remember it
8. Copy the new password

Once you have the password, the connection string will be:

  postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres

Example with password "MyPassword123":
  postgresql://postgres:MyPassword123@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres

Update your backend/.env file with:
  DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
""")

print("=" * 70)
print("IMPORTANT SECURITY NOTES")
print("=" * 70)
print("""
1. NEVER commit .env files to GitHub (already in .gitignore)
2. Use strong passwords (uppercase, lowercase, numbers, symbols)
3. If password contains special characters, URL-encode them:
   - @ becomes %40
   - : becomes %3A
   - / becomes %2F
   - Example: postgresql://postgres:pass%40word@host:5432/postgres

4. Store passwords securely:
   - In production, use environment variables
   - On local machine, use .env file (in .gitignore)
   - On Vercel, use Environment Variables in project settings

5. Regular security checks:
   - Rotate passwords every 3 months
   - Monitor Supabase logs for suspicious activity
   - Review API keys periodically
""")

print("\nOnce you've updated your .env file, run:")
print("  python migrate_to_supabase.py")
