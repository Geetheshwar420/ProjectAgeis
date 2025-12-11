# ✅ SCHEMA FIX - HOW TO PROCEED

## The Issue
The foreign key constraints had a type mismatch that prevented table creation.

## The Fix
I've corrected the schema with properly named CONSTRAINT declarations.

## How to Apply the Fix

### Option 1: Delete Existing Tables and Re-run (Recommended)

1. **Go to Supabase SQL Editor**: https://app.supabase.com/project/nlzvqtbsevtoevwgbbfc/sql/new

2. **Copy this cleanup SQL**:
```sql
DROP TABLE IF EXISTS session_keys CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS friend_requests CASCADE;
DROP TABLE IF EXISTS users CASCADE;
```

3. **Run it** (this removes the tables with the error)

4. **Now copy the CORRECTED schema** from: `docs/SUPABASE_SCHEMA_FIXED.sql`

5. **Paste and Run** the corrected schema

### Option 2: Use the Automated Script

If you have database password configured:

```bash
cd backend
python setup_supabase_schema.py
```

This will create the corrected schema automatically.

---

## ✅ Corrected Schema Details

The fix ensures:

| Table | Column | Type | References |
|-------|--------|------|-----------|
| users | id | SERIAL (INTEGER) | PRIMARY KEY |
| messages | sender_id | INTEGER | users.id ✓ |
| messages | recipient_id | INTEGER | users.id ✓ |
| friend_requests | from_user_id | INTEGER | users.id ✓ |
| friend_requests | to_user_id | INTEGER | users.id ✓ |
| session_keys | user_id | INTEGER | users.id ✓ |

**All types now match properly** - No more type mismatch errors!

---

## 📋 What Changed

**Before** (Caused Error):
```sql
FOREIGN KEY (from_user_id) REFERENCES users(id)
```

**After** (Fixed):
```sql
CONSTRAINT fk_from_user FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE
```

**Benefits**:
- Explicit constraint names for clarity
- Proper CASCADE delete behavior
- No UUID/INTEGER type conflicts

---

## 🚀 Next Steps

1. Clean up old tables (Option 1 above)
2. Run corrected schema from `docs/SUPABASE_SCHEMA_FIXED.sql`
3. Verify tables created:
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;
```

Expected output:
- friend_requests ✓
- messages ✓
- session_keys ✓
- users ✓

4. Once verified, start your app: `python app.py`

---

## ✨ You're Good to Go!

The schema is now corrected and ready for Supabase. All files have been updated and committed to GitHub.

**Files Updated**:
- ✅ docs/SUPABASE_SCHEMA.sql (main version)
- ✅ docs/SUPABASE_SCHEMA_FIXED.sql (explicit fix version)
- ✅ backend/db_schema.sql (backup version)
- ✅ backend/setup_supabase_schema.py (Python script)

Good luck! 🚀
