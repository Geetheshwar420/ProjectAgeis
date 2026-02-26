# Row Level Security (RLS) Implementation Guide

## Issue Summary

**Problem**: The `public.users` table (and other tables) in the Supabase database does not have Row Level Security (RLS) enabled.

**Severity**: High - This is a security vulnerability that could allow unauthorized access to sensitive user data.

**Affects**: 
- `users` table
- `messages` table
- `friend_requests` table
- `session_keys` table

---

## What is Row Level Security (RLS)?

Row Level Security is a PostgreSQL feature that controls which rows users can access in a table. Without RLS:
- Any authenticated user can potentially access any user's data
- Data exposure risk increases significantly
- No fine-grained access control for sensitive data

With RLS enabled:
- Users can only access rows they are authorized to view/modify
- Access is enforced at the database level (strongest protection)
- Policies are transparent and auditable

---

## RLS Policies Implemented

### Users Table
| Policy | Type | Rule |
|--------|------|------|
| Users can view own profile | SELECT | `id = auth.uid()::integer` |
| Users can update own profile | UPDATE | `id = auth.uid()::integer` |
| Anyone can create a user account | INSERT | `true` (allows signup) |

**Security Rationale**: Prevents users from viewing/modifying other users' profiles while allowing public signup.

### Messages Table
| Policy | Type | Rule |
|--------|------|------|
| Users can view messages they sent | SELECT | `sender_id = auth.uid()::integer` |
| Users can view messages they received | SELECT | `recipient_id = auth.uid()::integer` |
| Users can send messages | INSERT | `sender_id = auth.uid()::integer` |
| Users can update their own messages | UPDATE | `sender_id = auth.uid()::integer` |

**Security Rationale**: Users can only access messages they sent or received. Cannot view other users' private messages.

### Friend Requests Table
| Policy | Type | Rule |
|--------|------|------|
| Users can view sent friend requests | SELECT | `from_user_id = auth.uid()::integer` |
| Users can view received friend requests | SELECT | `to_user_id = auth.uid()::integer` |
| Users can send friend requests | INSERT | `from_user_id = auth.uid()::integer` |
| Users can update friend requests | UPDATE | `from_user_id = auth.uid()::integer OR to_user_id = auth.uid()::integer` |

**Security Rationale**: Users can only see and manage friend requests they are involved in.

### Session Keys Table
| Policy | Type | Rule |
|--------|------|------|
| Users can view own session keys | SELECT | `user_id = auth.uid()::integer` |
| Users can create own session keys | INSERT | `user_id = auth.uid()::integer` |
| Users can delete own session keys | DELETE | `user_id = auth.uid()::integer` |

**Security Rationale**: Each user can only manage their own cryptographic session keys.

---

## How to Apply RLS to Your Database

### Option 1: Using Supabase Dashboard (Recommended)

1. **Log in to Supabase**: https://app.supabase.com
2. **Navigate to SQL Editor**: Select your project → SQL Editor
3. **Create new query**: Click "New Query"
4. **Copy the schema file**: Open `SUPABASE_SCHEMA_WITH_RLS.sql` from the docs folder
5. **Paste and execute**: Paste the entire contents and click "Run"
6. **Verify**: Check the "Verification Queries" section at the bottom of the SQL file

### Option 2: Using psql (Command Line)

```bash
# Connect to your Supabase database
psql -h db.xxx.supabase.co -U postgres -d postgres

# Run the schema file
\i SUPABASE_SCHEMA_WITH_RLS.sql
```

### Option 3: Using Programmatic Migration

If you prefer code-based migrations, the schema file can be run during application startup:

```python
# backend/db.py or similar
from your_db_module import run_sql_file

def apply_rls_policies():
    with open('docs/SUPABASE_SCHEMA_WITH_RLS.sql', 'r') as f:
        sql_statements = f.read().split(';')
        for statement in sql_statements:
            if statement.strip():
                run_sql_file(statement)
```

---

## Verification Steps

After applying RLS, verify it's working correctly:

### 1. Check RLS is Enabled
```sql
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('users', 'messages', 'friend_requests', 'session_keys');
```

Expected output:
```
 tablename     | rowsecurity
---------------+-------------
 users         | t
 messages      | t
 friend_requests | t
 session_keys  | t
```

### 2. Check RLS Policies
```sql
SELECT schemaname, tablename, policyname, permissive
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
```

You should see all policies listed (see "RLS Policies Implemented" section above).

### 3. Test Access Control
```sql
-- As user with id=1, try to view user 2's profile
SELECT * FROM users WHERE id = 2;
-- Should return no rows (denied by RLS)

-- View own profile
SELECT * FROM users WHERE id = 1;
-- Should return own user row (allowed by RLS)
```

---

## Important: Supabase Auth Configuration

For RLS policies to work correctly with PostgREST:

1. **Ensure `auth.uid()` function is available**:
   - Supabase automatically provides this function
   - It returns the current user's ID from JWT tokens

2. **JWT Configuration in Supabase**:
   - Go to: Project Settings → API
   - Verify "JWT Secret" is set
   - Verify JWT expiration is reasonable

3. **PostgREST Configuration**:
   - Should not restrict RLS (it's handled at DB level)
   - Verify authentication headers are properly passed

---

## Troubleshooting

### Issue: "RLS policy references missing USING clause"
**Solution**: Use the provided policies which include proper USING/WITH CHECK clauses.

### Issue: "auth.uid() returns NULL"
**Solution**: Ensure JWT token is properly configured in Supabase settings. Users must be authenticated.

### Issue: "INSERT allowed for unauthenticated users but SELECT is blocked"
**This is expected for the users table** - allows signup but prevents data access without authentication.

### Issue: "Cannot view messages after RLS is enabled"
**Solution**: Ensure application sends proper JWT token in Authorization header:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Rollback Instructions

If you need to disable RLS (not recommended):

```sql
-- Disable RLS on all tables
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE messages DISABLE ROW LEVEL SECURITY;
ALTER TABLE friend_requests DISABLE ROW LEVEL SECURITY;
ALTER TABLE session_keys DISABLE ROW LEVEL SECURITY;

-- Drop all RLS policies
DROP POLICY IF EXISTS "Users can view own profile" ON users;
DROP POLICY IF EXISTS "Users can update own profile" ON users;
DROP POLICY IF EXISTS "Anyone can create a user account" ON users;
-- ... (repeat for other policies)
```

⚠️ **Warning**: Disabling RLS removes critical security protections. Only do this if absolutely necessary.

---

## Best Practices

1. **Always enable RLS on public tables** exposed to external applications
2. **Test RLS policies** with different user roles before deployment
3. **Keep RLS policies simple** but comprehensive
4. **Monitor RLS policy performance** for large tables (add indexes as needed)
5. **Document all RLS policies** for audit and compliance
6. **Review RLS policies regularly** as application requirements change

---

## Next Steps

1. ✅ Review this guide and understand the RLS policies
2. ✅ Back up your current database (Supabase provides automated backups)
3. ✅ Test RLS in a development branch first
4. ✅ Apply the RLS schema (`SUPABASE_SCHEMA_WITH_RLS.sql`) to your database
5. ✅ Verify RLS is working correctly using the verification queries
6. ✅ Test the application with RLS policies enabled
7. ✅ Update documentation and deployment guides

---

## File References

- **RLS Schema File**: `docs/SUPABASE_SCHEMA_WITH_RLS.sql`
- **Original Schema (No RLS)**: `docs/SUPABASE_SCHEMA.sql` (for reference)
- **Fixed Schema (No RLS)**: `docs/SUPABASE_SCHEMA_FIXED.sql` (for reference)

---

## Related Documentation

- [PostgreSQL RLS Documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Supabase Security Documentation](https://supabase.com/docs/guides/auth/row-level-security)
- [PostgREST Security](https://postgrest.org/en/stable/auth.html)

---

**Status**: Ready to deploy  
**Last Updated**: February 26, 2026  
**Author**: Security Implementation  
