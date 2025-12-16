# MIGRATE TO SUPABASE - COMPLETE GUIDE

Your project is now configured to use **Supabase PostgreSQL** instead of CockroachDB.

## What Changed?
- ❌ Removed: CockroachDB connection (wise-weredog-17328.j77.aws...)
- ✅ Added: Supabase PostgreSQL (db.nlzvqtbsevtoevwgbbfc.supabase.co)
- ✅ Updated: `.env` files with Supabase configuration
- ✅ Created: Database schema setup scripts

## Step 1: Get Your Supabase Database Password

1. **Open Supabase Dashboard**: https://app.supabase.com
2. **Select Your Project**: nlzvqtbsevtoevwgbbfc
3. **Go to Settings**:
   - Click the gear icon (⚙️) in the left sidebar
   - Select "Database" from the dropdown
4. **Copy Database Password**:
   - You should see a "Database Password" field
   - If you don't remember it, click "Reset Password"
   - Copy the password securely
5. **Update .env Files**:
   - Update `backend/.env`:
     ```
     DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
     ```
   - Update `.env` (root):
     ```
     DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
     ```
   - Replace `YOUR_PASSWORD` with your actual password

## Step 2: Test Connection

Open terminal in `backend/` directory and run:

```bash
python get_supabase_connection.py
```

This will show you the exact connection string format and security notes.

## Step 3: Create Database Schema

Still in `backend/` directory, run:

```bash
python setup_supabase_schema.py
```

This creates all required tables:
- ✓ users
- ✓ messages
- ✓ friend_requests
- ✓ session_keys

## Step 4: Migrate Existing Data (if any)

If you had data in CockroachDB, follow these steps:

1. **Export from CockroachDB**:
   ```bash
   python export_data_from_cockroachdb.py  # (if you have this)
   ```

2. **Import to Supabase**:
   ```bash
   python import_data_to_supabase.py  # (if you have this)
   ```

Or manually migrate via SQL:
- Go to Supabase Dashboard
- Click "SQL Editor" in left sidebar
- Create tables and import data

## Step 5: Start the Application

In `backend/` directory:

```bash
python app.py
```

Or with the WSGI server:

```bash
python run.py
```

## Step 6: Test the Connection

You should see:
```
Attempting to load .env file...
.env file found at: ...backend/.env

============================================================
Starting Quantum Secure Messaging Backend
============================================================

Database connection successful!
```

## Troubleshooting

### Error: "connection refused"
- ❌ Check: Incorrect password
- ❌ Check: Wrong project ID
- ✅ Fix: Copy password directly from Supabase dashboard

### Error: "authentication failed"
- ❌ Check: Password contains special characters that aren't URL-encoded
- ✅ Fix: If password has @, :, /, %, URL-encode them:
  ```
  @ = %40
  : = %3A
  / = %2F
  % = %25
  ```

### Error: "database does not exist"
- ❌ Check: Database name is wrong (should be "postgres")
- ✅ Fix: Use "postgres" as the database name

### Connection works but tables don't exist
- ✅ Run: `python setup_supabase_schema.py`

## Verify in Supabase Dashboard

1. Open: https://app.supabase.com
2. Go to your project
3. Click "SQL Editor" in the left sidebar
4. Run:
   ```sql
   SELECT table_name 
   FROM information_schema.tables 
   WHERE table_schema = 'public'
   ORDER BY table_name;
   ```
5. You should see your tables listed

## Security Notes

⚠️ **IMPORTANT**:
- Never commit `.env` files to GitHub (already in .gitignore)
- Your `.env` file should NEVER be visible to anyone else
- Store credentials securely in production environments
- Use Supabase environment variables for cloud deployment

## Next Steps

1. ✅ Get Supabase password (from Step 1)
2. ✅ Update .env files
3. ✅ Run `python setup_supabase_schema.py`
4. ✅ Start application with `python app.py`
5. ✅ Test in browser or Postman
6. ✅ Commit changes to GitHub (excluding .env):
   ```bash
   git add -A
   git commit -m "Migrate to Supabase PostgreSQL from CockroachDB"
   git push origin main
   ```

## Support

- Supabase Docs: https://supabase.com/docs
- Supabase Dashboard: https://app.supabase.com
- Flask Docs: https://flask.palletsprojects.com
- PostgreSQL Docs: https://www.postgresql.org/docs/

Good luck! 🚀
