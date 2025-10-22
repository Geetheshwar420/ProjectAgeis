#!/usr/bin/env python3
"""Check users in database"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_adapter import DatabaseAdapter

def main():
    db = None
    cursor = None
    try:
        db = DatabaseAdapter()
        db.connect()

        cursor = db.cursor()
        cursor.execute('SELECT id, username, email, created_at FROM users')
        users = cursor.fetchall()

        print('\n' + '='*60)
        print('REGISTERED USERS IN DATABASE')
        print('='*60)

        if not users:
            print('No users found in database.')
        else:
            for user in users:
                print(f'\nID: {user[0]}')
                print(f'Username: {user[1]}')
                print(f'Email: {user[2]}')
                print(f'Created: {user[3]}')
                print('-'*60)

            print(f'\nTotal: {len(users)} user(s)')

        print('='*60 + '\n')

    except Exception as e:
        print(f"❌ Database connection/query error: {e}")
    finally:
        # Ensure resources are always cleaned up
        try:
            if cursor:
                cursor.close()
        except Exception as e:
            print(f"⚠️  Failed to close cursor: {e}")
        try:
            if db:
                db.close()
        except Exception as e:
            print(f"⚠️  Failed to close database connection: {e}")

if __name__ == '__main__':
    main()
