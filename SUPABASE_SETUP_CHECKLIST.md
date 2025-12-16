# ✅ SUPABASE MIGRATION CHECKLIST

## Your Configuration is Ready! ✓

### Supabase Project Details
- **Project ID**: nlzvqtbsevtoevwgbbfc
- **Project URL**: https://nlzvqtbsevtoevwgbbfc.supabase.co
- **Host**: db.nlzvqtbsevtoevwgbbfc.supabase.co
- **API Anon Key**: ✓ Configured in .env

---

## 📋 Complete Setup Steps (5 minutes)

### ✅ Step 1: Create Database Tables (2 minutes)

**Location**: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/sql/new

**What to do**:
1. Go to the link above
2. In the SQL Editor, click "New Query"
3. Copy the entire SQL from: `backend/db_schema.sql`
4. Paste it into the editor
5. Click the green **Run** button
6. You should see: "Queries completed successfully"

**SQL to run** (from db_schema.sql):
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- (Plus 3 more tables - friend_requests, messages, session_keys)
-- See backend/db_schema.sql for full schema
```

### ✅ Step 2: Get Database Password (1 minute) - *Optional*

**Location**: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/settings/database

**What to do**:
1. Go to Settings → Database
2. Find "Database Password" section
3. Copy the password
4. Update `backend/.env`:
   ```
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
   ```

**Note**: This is only needed if you want to connect from your local machine.

### ✅ Step 3: Verify Tables Created (30 seconds)

**In Supabase SQL Editor**, run:
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;
```

**You should see**:
- ✓ friend_requests
- ✓ messages  
- ✓ session_keys
- ✓ users

### ✅ Step 4: Start Your Application (1 minute)

```bash
cd backend
python app.py
```

**Expected output**:
```
Attempting to load .env file...
.env file found at: ...backend\.env

============================================================
Starting Quantum Secure Messaging Backend
============================================================
```

---

## 📁 Files Created for Setup

✓ `db_schema.sql` - Database schema (copy to Supabase)
✓ `setup_supabase_schema.py` - Auto-setup script (needs password)
✓ `interactive_setup.py` - Interactive wizard
✓ `setup_via_api.py` - API helper
✓ `setup_with_supabase_key.py` - Key-based setup
✓ `MIGRATE_TO_SUPABASE.md` - Detailed migration guide
✓ `SUPABASE_QUICK_START.md` - Quick reference
✓ `.env` files updated with Supabase config

---

## 🔗 Quick Links

- 🔑 Supabase Dashboard: https://app.supabase.com
- 📊 SQL Editor: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/sql/new
- ⚙️ Settings: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/settings/database
- 📝 API: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/api

---

## ⚠️ Important Notes

1. **Never commit `.env` files** - Already in .gitignore ✓
2. **Database password is secret** - Don't share it
3. **Tables must exist first** - Run the SQL before starting app
4. **Use Supabase dashboard** - Easiest way to create schema

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| "Tables don't exist" | Run the SQL from db_schema.sql in Supabase SQL Editor |
| "Connection refused" | Get password from Settings → Database, update DATABASE_URL |
| "Authentication failed" | Check password is correct and copied exactly |
| "Permission denied" | Use Supabase dashboard (manual SQL method) |

---

## ✨ Next: Commit to GitHub

Once everything is working:

```bash
git add -A
git commit -m "Migrate from CockroachDB to Supabase PostgreSQL"
git push origin main
```

---

**Status**: 🟢 **READY FOR SETUP**
**Next Action**: Go to Supabase SQL Editor and run db_schema.sql

Good luck! 🚀
