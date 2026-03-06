# SUPABASE/COCKROACHDB CONNECTION TROUBLESHOOTING GUIDE

## Issue: FATAL codeProxyRefusedConnection: connection refused

This error occurs when the CockroachDB proxy rejects the connection. Common causes:

### 1. **Invalid Credentials**
- Double-check your CockroachDB username and password in `.env`
- Verify the password doesn't have special characters that need escaping
- If password contains `@`, `%`, `:`, or `/`, URL-encode it

### 2. **Cluster Paused**
- Log in to https://cockroachlabs.cloud
- Check if your cluster is in "Paused" state
- If paused, click "Resume" to activate it

### 3. **Connection String Format**
- Must be: `postgresql://username:password@host:port/database`
- Replace `username` with your actual username
- Replace `password` with your actual password
- Ensure `?sslmode=require` is at the end

### 4. **Database Name Issue**
- The database name in the URL should be "postgres" or "messaging_app"
- Make sure you're connecting to an existing database

### 5. **Network/Firewall Issues** (Less Common)
- CockroachDB allows connections from anywhere
- If behind corporate firewall, you might need proxy settings

## Steps to Fix:

1. **Get Fresh Connection String from CockroachDB Dashboard**:
   - Go to https://cockroachlabs.cloud
   - Click on your cluster
   - Go to "Connect" → "Connection String"
   - Copy the PostgreSQL connection string
   - Paste into `.env` as `DATABASE_URL`

2. **Verify Cluster Status**:
   - Make sure cluster is "Running" (not "Paused")
   - Check that cluster size is sufficient

3. **Test Connection**:
   - Run: `python test_db_connection.py`
   - Run: `python test_cockroachdb.py`

4. **If Still Failing**:
   - Check password for special characters
   - Reset database password in CockroachDB dashboard
   - Try a simpler password for testing (alphanumeric only)

## Example Valid Connection Strings:

```
postgresql://geetheshwar:mypassword@wise-weredog-17328.j77.aws-ap-south-1.cockroachlabs.cloud:26257/postgres?sslmode=require

postgresql://admin:SimplePass123@myhost.cockroachlabs.cloud:26257/messaging_app?sslmode=require
```

## To Use Local SQLite Instead (Development Only):

Add to backend/app.py after imports:
```python
# Use SQLite for development if DATABASE_URL is invalid
import os
if not os.getenv('DATABASE_URL'):
    os.environ['DATABASE_URL'] = 'sqlite:///messaging_app.db'
```

Then modify db_adapter.py to support SQLite fallback.

## Need More Help?

- CockroachDB Docs: https://www.cockroachlabs.com/docs/
- Check CockroachDB Cluster Events for errors
- Contact CockroachDB support at https://cockroachlabs.com/support
