# SUPABASE MIGRATION - QUICK START

Your project is now configured to use **Supabase PostgreSQL**. Follow these simple steps to complete the setup.

## 🚀 Quick Setup (5 minutes)

### Step 1: Create Database Schema (2 minutes)

**Option A: Automated (Recommended)**
```bash
cd backend
python interactive_setup.py
```
This will guide you through the process and optionally open your browser.

**Option B: Manual Setup**
1. Go to: https://app.supabase.com
2. Select project: **nlzvqtbsevtoevwgbbfc**
3. Click **SQL Editor** → **New Query**
4. Copy all SQL from: `backend/db_schema.sql`
5. Paste into editor and click **Run**

### Step 2: Get Database Password (1 minute) - *Optional for Local Dev*

If you want to connect from your local machine:

1. Go to: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/settings/database
2. Find **Database Password** section
3. Copy your password (or click "Reset Password" if needed)
4. Update `backend/.env`:
   ```
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
   ```

### Step 3: Test & Start App (2 minutes)

```bash
cd backend
python app.py
```

You should see:
```
Attempting to load .env file...
.env file found at: ...backend/.env

============================================================
Starting Quantum Secure Messaging Backend
============================================================
```

## ✅ What's Already Done

- ✓ Supabase project created (nlzvqtbsevtoevwgbbfc)
- ✓ Credentials configured in .env files
- ✓ Database schema SQL prepared (db_schema.sql)
- ✓ Setup scripts created for guidance
- ✓ Documentation prepared

## 📋 Files Created for Setup

| File | Purpose |
|------|---------|
| `db_schema.sql` | Database schema (run in Supabase SQL Editor) |
| `setup_supabase_schema.py` | Auto-schema creator (needs database password) |
| `interactive_setup.py` | Interactive setup wizard |
| `setup_via_api.py` | API-based setup helper |
| `get_supabase_connection.py` | Connection string helper |

## 🔧 Connection Details

- **Project**: nlzvqtbsevtoevwgbbfc
- **URL**: https://nlzvqtbsevtoevwgbbfc.supabase.co
- **Host**: db.nlzvqtbsevtoevwgbbfc.supabase.co
- **Port**: 5432
- **Database**: postgres
- **User**: postgres
- **Password**: Get from Supabase dashboard (Settings → Database)

## 📊 Database Tables Created

1. **users** - User accounts and authentication
2. **messages** - Message content and metadata
3. **friend_requests** - Friend request management
4. **session_keys** - Cryptographic session keys

## 🐛 Troubleshooting

**Can't connect to database?**
- Verify password is correct: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/settings/database
- Check that DATABASE_URL in .env has correct password
- Try resetting password in Supabase dashboard

**Tables don't exist?**
- Run the SQL from db_schema.sql in Supabase SQL Editor
- Or run: `python setup_supabase_schema.py` (requires database password)

**Port already in use?**
```bash
python app.py --port 5001
```

## 🔐 Security Notes

⚠️ **IMPORTANT**:
- `.env` files are in `.gitignore` - NEVER commit them
- Keep database password secret
- Don't share connection strings publicly
- In production, use environment variables (Vercel, Render, etc.)

## 📚 Documentation

- Full migration guide: `MIGRATE_TO_SUPABASE.md`
- Setup guide: `SETUP_SUPABASE.md`
- Connection troubleshooting: `docs/SUPABASE_CONNECTION_GUIDE.md`

## ✨ Next Steps

1. ✅ Create schema using `interactive_setup.py` or manual SQL
2. ✅ Get database password (optional, for local development)
3. ✅ Update `.env` with password (optional)
4. ✅ Start app: `python app.py`
5. ✅ Test in browser or Postman
6. ✅ Commit changes to GitHub:
   ```bash
   git add -A
   git commit -m "Migrate to Supabase PostgreSQL"
   git push origin main
   ```

---

**Questions?** Check the documentation files in `/docs` or your `MIGRATE_TO_SUPABASE.md` file for detailed instructions.

Good luck! 🚀
