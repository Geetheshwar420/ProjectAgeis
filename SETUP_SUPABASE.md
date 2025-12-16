# GET YOUR SUPABASE DATABASE PASSWORD

Follow these steps to get your Supabase PostgreSQL connection details:

## Step 1: Go to Supabase Dashboard
- Open: https://app.supabase.com
- Select your project: **nlzvqtbsevtoevwgbbfc**

## Step 2: Get Database Password
- Click **Settings** (gear icon) in the left sidebar
- Go to **Database** section
- Look for "Database Password" - copy it
- If you haven't set one, create a new password there

## Step 3: Get Connection String
- In the same **Database** settings page
- Find **Connection String** section
- Select **PostgreSQL** tab
- Copy the connection string (format: postgresql://postgres:PASSWORD@host:5432/postgres)

## Step 4: Update .env File
Replace the DATABASE_URL in `backend/.env` with your actual connection string:

```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.nlzvqtbsevtoevwgbbfc.supabase.co:5432/postgres
```

## What You Need:
1. Supabase Project ID: nlzvqtbsevtoevwgbbfc ✓
2. Supabase API Key: (already have) ✓
3. Database Password: (get from Step 2)
4. Host: db.nlzvqtbsevtoevwgbbfc.supabase.co ✓
5. Port: 5432 ✓
6. Database: postgres ✓

Once you update the .env file with the actual password, the connection should work!
