from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from crypto.quantum_service import QuantumCryptoService
class User:
    def __init__(self, username, password, email):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.email = email
        self.created_at = datetime.datetime.utcnow()
        self.keys = QuantumCryptoService().generate_user_keypairs(username)

    def save(self, db):
        users_collection = db.users
        user_id = users_collection.insert_one({
            'username': self.username,
            'password_hash': self.password_hash,
            'email': self.email,
            'created_at': self.created_at,
            'keys': self.keys
        }).inserted_id
        return user_id

    @staticmethod
    def find_by_username(db, username):
        users_collection = db.users
        return users_collection.find_one({'username': username})

    @staticmethod
    def find_by_email(db, email):
        users_collection = db.users
        return users_collection.find_one({'email': email})

    @staticmethod
    def check_password(user, password):
        return check_password_hash(user['password_hash'], password)

    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)

class Message:
    def __init__(self, sender_id, recipient_id, encrypted_message, signature, nonce=None, tag=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_message = encrypted_message
        self.signature = signature
        self.nonce = nonce
        self.tag = tag
        self.timestamp = datetime.datetime.utcnow()
        self.formatted_timestamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')

    def save(self, db):
        messages_collection = db.messages
        message_doc = {
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'encrypted_message': self.encrypted_message,
            'signature': self.signature,
            'timestamp': self.timestamp,
            'formatted_timestamp': self.formatted_timestamp
        }
        
        # Add nonce and tag if provided
        if self.nonce:
            message_doc['nonce'] = self.nonce
        if self.tag:
            message_doc['tag'] = self.tag
            
        message_id = messages_collection.insert_one(message_doc).inserted_id
        return message_id
