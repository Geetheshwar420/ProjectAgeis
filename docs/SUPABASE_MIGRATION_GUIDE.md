# Supabase Database Migration Guide

## Overview

This guide walks through migrating data from local SQLite to Supabase PostgreSQL.

**Current State**: 
- SQLite: 3 users, 11 messages (0.26 MB)
- PostgreSQL: Currently unreachable (will be restored)

**Migration Timeline**: ~30 minutes

---

## Todo Checklist

### Phase 1: Pre-Migration (Tasks 1-3)

- [ ] **Task 1**: Verify Supabase project status and credentials
  - Navigate to https://app.supabase.com
  - Check project status (should be "Active")
  - Verify connection string in .env matches
  - Test credentials validity
  
- [ ] **Task 2**: Test PostgreSQL connection to Supabase
  - Command: `psql "postgresql://user:pass@host:26257/messaging_app?sslmode=require"`
  - Should connect without errors
  - If fails, check network/firewall
  
- [ ] **Task 3**: Backup current SQLite database
  - Copy `backend/messaging_app.db` to `backend/backups/messaging_app.db.backup`
  - Create backups directory if needed
  - Verify backup file integrity

### Phase 2: Database Migration (Tasks 4-10)

- [ ] **Task 4**: Create database migration script
  - Use provided `migrate_to_supabase.py`
  - Script will read from SQLite
  - Write to PostgreSQL
  - Handle data type conversions
  
- [ ] **Task 5**: Migrate users table to PostgreSQL
  - Extract all users from SQLite
  - Insert into PostgreSQL with proper sequences
  - Verify user IDs are preserved
  
- [ ] **Task 6**: Migrate messages table to PostgreSQL
  - Extract all messages with timestamps
  - Maintain sender/receiver relationships
  - Verify foreign key constraints
  
- [ ] **Task 7**: Migrate friend_requests table to PostgreSQL
  - Migrate request status and timestamps
  - Ensure requester/recipient IDs are correct
  - Check unique constraints
  
- [ ] **Task 8**: Migrate friendships table to PostgreSQL
  - Migrate bidirectional relationships
  - Verify unique constraints on pairs
  - Check no duplicate friendships
  
- [ ] **Task 9**: Create indexes on PostgreSQL tables
  - Create performance indexes
  - Match original SQLite indexes
  - Verify index creation success
  
- [ ] **Task 10**: Test data integrity after migration
  - Verify record counts match
  - Check data values are identical
  - Validate foreign key relationships
  - Run query consistency tests

### Phase 3: Backend Integration (Tasks 11-14)

- [ ] **Task 11**: Verify backend connection to Supabase PostgreSQL
  - Start backend normally
  - Check logs for connection status
  - Should show PostgreSQL connection (not SQLite fallback)
  - Test database queries work
  
- [ ] **Task 12**: Run smoke tests with Supabase backend
  - Test user login/registration
  - Test message sending/receiving
  - Test friend request operations
  - Verify all features work with PostgreSQL
  
- [ ] **Task 13**: Update .env DATABASE_URL if needed
  - Verify correct connection string
  - Ensure credentials are fresh
  - Check sslmode setting
  
- [ ] **Task 14**: Disable SQLite fallback for production
  - For development: keep fallback enabled
  - For production: disable or restrict fallback
  - Update logging to alert on fallback events

### Phase 4: Documentation & Rollback (Task 15)

- [ ] **Task 15**: Document migration steps and rollback plan
  - Document what was done
  - Record any issues encountered
  - Create rollback procedures
  - Update deployment docs

---

## Required Files

### Migration Script
Create file: `backend/migrate_to_supabase.py`

### Backup Location
Create directory: `backend/backups/`

---

## Quick Reference

### Connection String Format
```
postgresql://user:password@host:port/database?sslmode=require
```

### Verify Supabase Connection
```bash
psql "postgresql://geetheshwar:pDq_Lq_r8oVRMuF17VAKCw@wise-weredog-17328.j77.aws-ap-south-1.cockroachlabs.cloud:26257/messaging_app?sslmode=require"
```

### Check SQLite Data
```bash
sqlite3 backend/messaging_app.db
sqlite> .tables
sqlite> SELECT COUNT(*) FROM users;
sqlite> SELECT COUNT(*) FROM messages;
```

### Create Backup
```bash
cp backend/messaging_app.db backend/backups/messaging_app.db.backup
```

### Run Migration
```bash
python backend/migrate_to_supabase.py
```

### Verify Migration
```bash
python backend/check_database.py
```

---

## Rollback Plan

If migration fails:

1. **Stop Backend**: `Ctrl+C`
2. **Restore Database URL**: Point back to SQLite or old PostgreSQL
3. **Restart Backend**: Should fallback to SQLite
4. **Restore Data**: SQLite backup remains intact
5. **Troubleshoot**: Identify and fix issues
6. **Retry**: Run migration again after fixes

---

## Common Issues & Solutions

### Issue: Connection Refused
**Solution**: 
- Check Supabase project is running
- Verify IP whitelisting
- Check firewall allows port 26257
- Verify credentials are correct

### Issue: SSL Certificate Error
**Solution**:
- Use `sslmode=require` (not `verify-full` without cert)
- Check sslmode in connection string

### Issue: Foreign Key Constraint Error
**Solution**:
- Migrate parent tables first (users)
- Then child tables (messages, friend_requests, friendships)
- Ensure IDs are consistent

### Issue: Duplicate Key Error
**Solution**:
- Check for duplicate entries in SQLite
- Reset sequences in PostgreSQL
- Handle duplicates before migration

---

## Estimated Time

- Pre-Migration: 5 minutes
- Data Migration: 5-10 minutes
- Testing: 10-15 minutes
- Total: 20-30 minutes

---

## Success Criteria

✅ All 3 users migrated with same IDs  
✅ All 11 messages migrated with correct relationships  
✅ All friend requests migrated  
✅ All friendships migrated  
✅ Foreign key constraints working  
✅ Backend connects to PostgreSQL (not SQLite)  
✅ All features tested and working  
✅ Backup exists for rollback  

---

## Next Steps

1. Start with Task 1
2. Work through each task in order
3. Mark completed when verified
4. Document any issues found
5. Update this guide with lessons learned

