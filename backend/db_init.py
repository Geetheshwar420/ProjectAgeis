"""
Database initialization and schema definition for both SQLite and PostgreSQL/CockroachDB.
This module creates the necessary tables for the messaging application.
"""
import os
import logging
from db_adapter import DatabaseAdapter

def get_db_adapter():
    """Get database adapter from environment or use default SQLite"""
    return DatabaseAdapter()

def init_database(db_adapter=None):
    """
    Initialize the database with all required tables.
    This function is idempotent - safe to call multiple times.
    Works with both SQLite and PostgreSQL/CockroachDB.
    
    Args:
        db_adapter: DatabaseAdapter instance. If None, creates one from environment.
    """
    if db_adapter is None:
        db_adapter = get_db_adapter()
    
    db_adapter.connect()
    
    # Detect database type for appropriate SQL syntax
    is_postgres = db_adapter.db_type == 'postgresql'
    
    # Auto-increment syntax differs between SQLite and PostgreSQL
    id_type = 'SERIAL PRIMARY KEY' if is_postgres else 'INTEGER PRIMARY KEY AUTOINCREMENT'
    timestamp_default = 'CURRENT_TIMESTAMP' if is_postgres else 'CURRENT_TIMESTAMP'
    
    print(f"🔧 Initializing {db_adapter.db_type.upper()} database schema...")
    
    # Users table
    # ⚠️ SECURITY: Only public keys are stored. Secret keys never leave secure memory.
    users_table_sql = f'''
        CREATE TABLE IF NOT EXISTS users (
            id {id_type},
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT {timestamp_default},
            kyber_public_key TEXT,
            dilithium_public_key TEXT
        )
    '''
    db_adapter.execute(users_table_sql)
    
    # Create indexes on users table
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    
    # Messages table  
    messages_table_sql = f'''
        CREATE TABLE IF NOT EXISTS messages (
            id {id_type},
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            encrypted_message TEXT NOT NULL,
            signature TEXT NOT NULL,
            nonce TEXT,
            tag TEXT,
            session_id TEXT,
            timestamp TIMESTAMP DEFAULT {timestamp_default},
            formatted_timestamp TEXT,
            iso_timestamp TEXT
        )
    '''
    db_adapter.execute(messages_table_sql)
    
    # Session keys table - stores persistent session keys for user pairs
    session_keys_table_sql = f'''
        CREATE TABLE IF NOT EXISTS session_keys (
            id {id_type},
            session_id TEXT UNIQUE NOT NULL,
            user_a TEXT NOT NULL,
            user_b TEXT NOT NULL,
            session_key TEXT NOT NULL,
            bb84_key TEXT,
            kyber_shared_secret TEXT,
            created_at TIMESTAMP DEFAULT {timestamp_default},
            expires_at TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    '''
    db_adapter.execute(session_keys_table_sql)
    
    # Create indexes on session_keys for efficient lookups
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_session_keys_session_id ON session_keys(session_id)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_session_keys_users ON session_keys(user_a, user_b)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_session_keys_status ON session_keys(status)')
    
    # Create indexes on messages table for efficient queries
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender_id, recipient_id)')
    
    # Friend requests table
    # Foreign keys reference users.id (INTEGER/SERIAL) with CASCADE for referential integrity
    friend_requests_sql = f'''
        CREATE TABLE IF NOT EXISTS friend_requests (
            id {id_type},
            requester INTEGER NOT NULL,
            recipient INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT {timestamp_default},
            FOREIGN KEY(requester) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
            FOREIGN KEY(recipient) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
            UNIQUE(requester, recipient)
        )
    '''
    db_adapter.execute(friend_requests_sql)
    
    # Create indexes on friend_requests table for query performance
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_friend_requests_requester ON friend_requests(requester)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_friend_requests_recipient ON friend_requests(recipient)')
    db_adapter.execute('CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests(status)')
    
    db_adapter.commit()
    db_adapter.close()
    
    print(f'✅ Database initialized successfully!')
    return True

def drop_all_tables(db_adapter=None):
    """
    Drop all tables - USE WITH CAUTION!
    This is useful for testing or complete resets.
    
    Args:
        db_adapter: DatabaseAdapter instance. If None, creates one from environment.
    """
    if db_adapter is None:
        db_adapter = get_db_adapter()
    
    db_adapter.connect()
    
    print('⚠️  Dropping all tables...')
    db_adapter.execute('DROP TABLE IF EXISTS friend_requests')
    db_adapter.execute('DROP TABLE IF EXISTS session_keys')
    db_adapter.execute('DROP TABLE IF EXISTS messages')
    db_adapter.execute('DROP TABLE IF EXISTS users')
    
    db_adapter.commit()
    db_adapter.close()
    
    print('✅ All tables dropped')
    return True

if __name__ == '__main__':
    # When run directly, initialize the database
    print('🔧 Initializing database...')
    init_database()
    print('✅ Database initialization complete!')
