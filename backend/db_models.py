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
        Save user to SQLite database.
        Returns the user ID (integer) on success.
        
        ⚠️ SECURITY: Only public keys are stored in database.
        Secret keys remain in-memory only in QuantumCryptoService.
        """
        cursor = None
        try:
            cursor = db.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, created_at,
                                 kyber_public_key, dilithium_public_key)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                self.username,
                self.password_hash,
                self.email,
                self.created_at,
                self.keys.get('kyber_public_key'),
                self.keys.get('dilithium_public_key')
            ))
            db.commit()
            return cursor.lastrowid
        except sqlite3.DatabaseError as e:
            # Roll back on any database-related error (covers IntegrityError, OperationalError, etc.)
            db.rollback()
            raise ValueError(f'User creation failed: {e}') from e
        finally:
            # Always close the cursor to avoid leaks
            if cursor:
                cursor.close()

    @staticmethod
    def find_by_username(db, username):
        """
        Find a user by username.
        Returns a dictionary-like Row object or None.
        
        ⚠️ SECURITY: Only public keys are retrieved from database.
        Secret keys are never persisted.
        """
        cursor = None
        try:
            cursor = db.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, email, created_at,
                       kyber_public_key, dilithium_public_key
                FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            
            if row:
                # Convert Row to dict and reconstruct keys structure
                user_dict = dict(row)
                user_dict['keys'] = {
                    'kyber_public_key': user_dict.pop('kyber_public_key'),
                    'dilithium_public_key': user_dict.pop('dilithium_public_key')
                }
                return user_dict
            return None
        finally:
            if cursor:
                cursor.close()

    @staticmethod
    def find_by_email(db, email):
        """
        Find a user by email.
        Returns a dictionary-like Row object or None.
        
        ⚠️ SECURITY: Only public keys are retrieved from database.
        Secret keys are never persisted.
        """
        cursor = None
        try:
            cursor = db.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, email, created_at,
                       kyber_public_key, dilithium_public_key
                FROM users WHERE email = ?
            ''', (email,))
            row = cursor.fetchone()
            
            if row:
                # Convert Row to dict and reconstruct keys structure
                user_dict = dict(row)
                user_dict['keys'] = {
                    'kyber_public_key': user_dict.pop('kyber_public_key'),
                    'dilithium_public_key': user_dict.pop('dilithium_public_key')
                }
                return user_dict
            return None
        finally:
            if cursor:
                cursor.close()

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
        Save message to SQLite database.
        Returns the message ID (integer) on success.
        
        Implements proper transaction management:
        - Wraps INSERT in try/except for error handling
        - Commits on success, rolls back on failure
        - Ensures cursor cleanup in finally block
        """
        cursor = None
        try:
            cursor = db.cursor()
            cursor.execute('''
                INSERT INTO messages (sender_id, recipient_id, encrypted_message, signature,
                                    nonce, tag, timestamp, formatted_timestamp, iso_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
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
            db.commit()
            message_id = cursor.lastrowid
            return message_id
        except Exception as e:
            # Rollback transaction on any error to maintain database consistency
            db.rollback()
            print(f"❌ Error saving message: {e}")
            raise ValueError(f'Message save failed: {e}')
        finally:
            # Always close cursor to prevent resource leaks
            if cursor:
                cursor.close()
