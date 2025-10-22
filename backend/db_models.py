import sqlite3
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from crypto.quantum_service import QuantumCryptoService
import json

class User:
    def __init__(self, username, password, email):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.email = email
        # Use timezone-aware UTC timestamp for consistency
        self.created_at = datetime.datetime.now(datetime.timezone.utc)
        self.keys = QuantumCryptoService().generate_user_keypairs(username)

    def save(self, db):
        """
        Save user to database. Returns the user ID on success.
        Works with both SQLite and PostgreSQL.
        """
        try:
            if db.db_type == 'postgresql':
                query = (
                    """
                    INSERT INTO users (username, password_hash, email, created_at,
                                       kyber_public_key, dilithium_public_key)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """
                )
                cursor = db.execute(query, (
                    self.username,
                    self.password_hash,
                    self.email,
                    self.created_at,
                    self.keys.get('kyber_public_key'),
                    self.keys.get('dilithium_public_key')
                ))
                user_id = db.get_last_insert_id(cursor)
            else:
                query = (
                    """
                    INSERT INTO users (username, password_hash, email, created_at,
                                       kyber_public_key, dilithium_public_key)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """
                )
                cursor = db.execute(query, (
                    self.username,
                    self.password_hash,
                    self.email,
                    self.created_at,
                    self.keys.get('kyber_public_key'),
                    self.keys.get('dilithium_public_key')
                ), add_returning_id=False)
                user_id = db.get_last_insert_id(cursor)
            db.commit()
            return user_id
        except Exception as e:
            db.rollback()
            raise ValueError(f'User creation failed: {e}') from e

    @staticmethod
    def find_by_username(db, username):
        """
        Find a user by username.
        Returns a dictionary-like Row object or None.
        
        ⚠️ SECURITY: Only public keys are retrieved from database.
        Secret keys are never persisted.
        """
        try:
            if db.db_type == 'postgresql':
                query = (
                    """
                    SELECT id, username, password_hash, email, created_at,
                           kyber_public_key, dilithium_public_key
                      FROM users WHERE username = %s
                    """
                )
                cursor = db.execute(query, (username,), add_returning_id=False)
            else:
                query = (
                    """
                    SELECT id, username, password_hash, email, created_at,
                           kyber_public_key, dilithium_public_key
                      FROM users WHERE username = ?
                    """
                )
                cursor = db.execute(query, (username,), add_returning_id=False)

            row = cursor.fetchone()
            if row:
                # Normalize to dict
                if isinstance(row, sqlite3.Row):
                    user_dict = dict(row)
                else:
                    try:
                        user_dict = dict(row)
                    except Exception:
                        # Fallback for tuple-based rows
                        cols = ['id','username','password_hash','email','created_at','kyber_public_key','dilithium_public_key']
                        user_dict = {k: v for k, v in zip(cols, row)}

                user_dict['keys'] = {
                    'kyber_public_key': user_dict.pop('kyber_public_key'),
                    'dilithium_public_key': user_dict.pop('dilithium_public_key')
                }
                return user_dict
            return None
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    @staticmethod
    def find_by_email(db, email):
        """
        Find a user by email.
        Returns a dictionary-like Row object or None.
        
        ⚠️ SECURITY: Only public keys are retrieved from database.
        Secret keys are never persisted.
        """
        try:
            if db.db_type == 'postgresql':
                query = (
                    """
                    SELECT id, username, password_hash, email, created_at,
                           kyber_public_key, dilithium_public_key
                      FROM users WHERE email = %s
                    """
                )
                cursor = db.execute(query, (email,), add_returning_id=False)
            else:
                query = (
                    """
                    SELECT id, username, password_hash, email, created_at,
                           kyber_public_key, dilithium_public_key
                      FROM users WHERE email = ?
                    """
                )
                cursor = db.execute(query, (email,), add_returning_id=False)

            row = cursor.fetchone()
            if row:
                if isinstance(row, sqlite3.Row):
                    user_dict = dict(row)
                else:
                    try:
                        user_dict = dict(row)
                    except Exception:
                        cols = ['id','username','password_hash','email','created_at','kyber_public_key','dilithium_public_key']
                        user_dict = {k: v for k, v in zip(cols, row)}

                user_dict['keys'] = {
                    'kyber_public_key': user_dict.pop('kyber_public_key'),
                    'dilithium_public_key': user_dict.pop('dilithium_public_key')
                }
                return user_dict
            return None
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    @staticmethod
    def check_password(user, password):
        """Check if the provided password matches the user's password hash."""
        return check_password_hash(user['password_hash'], password)

    @staticmethod
    def hash_password(password):
        """Generate a password hash."""
        return generate_password_hash(password)


class Message:
    def __init__(self, sender_id, recipient_id, encrypted_message, signature, nonce=None, tag=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_message = encrypted_message
        self.signature = signature
        self.nonce = nonce
        self.tag = tag
        # Generate server-side timestamp - never trust client input
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        # Human-readable format for display
        self.formatted_timestamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        # ISO 8601 format with timezone for ordering and auditing
        self.iso_timestamp = self.timestamp.isoformat()

    def save(self, db):
        """
        Save message to database; returns message ID. Works on SQLite and PostgreSQL.
        """
        try:
            if db.db_type == 'postgresql':
                query = (
                    """
                    INSERT INTO messages (sender_id, recipient_id, encrypted_message, signature,
                                          nonce, tag, timestamp, formatted_timestamp, iso_timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                )
                cursor = db.execute(query, (
                    self.sender_id,
                    self.recipient_id,
                    self.encrypted_message,
                    self.signature,
                    self.nonce,
                    self.tag,
                    self.timestamp,
                    self.formatted_timestamp,
                    self.iso_timestamp
                ))
                message_id = db.get_last_insert_id(cursor)
            else:
                query = (
                    """
                    INSERT INTO messages (sender_id, recipient_id, encrypted_message, signature,
                                          nonce, tag, timestamp, formatted_timestamp, iso_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                )
                cursor = db.execute(query, (
                    self.sender_id,
                    self.recipient_id,
                    self.encrypted_message,
                    self.signature,
                    self.nonce,
                    self.tag,
                    self.timestamp,
                    self.formatted_timestamp,
                    self.iso_timestamp
                ), add_returning_id=False)
                message_id = db.get_last_insert_id(cursor)
            db.commit()
            return message_id
        except Exception as e:
            db.rollback()
            print(f"❌ Error saving message: {e}")
            raise ValueError(f'Message save failed: {e}')
