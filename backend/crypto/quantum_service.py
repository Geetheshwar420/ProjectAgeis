"""
Quantum Cryptography Service
This service provides a unified interface for quantum and post-quantum cryptographic operations
"""
import asyncio
import json
import secrets
import hashlib
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Try relative imports first, fall back to absolute imports
from .bb84 import BB84Protocol
from .kyber import KyberKEM
from .dilithium import DilithiumSignature
from .crypto_models import CryptoSession


class QuantumCryptoService:
    """
    Unified Quantum Cryptography Service
    
    This service provides:
    - BB84 quantum key distribution
    - Crystal-Kyber key encapsulation
    - Crystal-Dilithium digital signatures
    - Hybrid encryption using all three methods
    """
    
    def __init__(self):
        self.bb84 = BB84Protocol(key_length=256)
        self.kyber = KyberKEM(security_level=512)
        self.dilithium = DilithiumSignature(security_level=2)
        
        # Store active sessions
        self.sessions: Dict[str, CryptoSession] = {}
        self.user_keypairs: Dict[str, Dict[str, bytes]] = {}
        
        print("🔐 Quantum Cryptography Service initialized")
        print(f"   - BB84 Protocol: {self.bb84.key_length}-bit keys")
        print(f"   - Kyber KEM: Security level {self.kyber.security_level}")
        print(f"   - Dilithium: Security level {self.dilithium.security_level}")
    
    def generate_user_keypairs(self, user_id: str) -> Dict[str, Any]:
        """
        Generate all cryptographic keypairs for a user
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            Dictionary containing all public keys and metadata
        """
        print(f"🔑 Generating keypairs for user: {user_id}")
        
        # Generate Kyber keypair
        kyber_public, kyber_secret = self.kyber.generate_keypair()
        
        # Generate Dilithium keypair
        dilithium_public, dilithium_secret = self.dilithium.generate_keypair()
        
        # Store keypairs
        self.user_keypairs[user_id] = {
            'kyber_public': kyber_public,
            'kyber_secret': kyber_secret,
            'dilithium_public': dilithium_public,
            'dilithium_secret': dilithium_secret,
            'created_at': datetime.now().isoformat()
        }
        
        # Return public keys only
        return {
            'user_id': user_id,
            'kyber_public_key': base64.b64encode(kyber_public).decode(),
            'dilithium_public_key': base64.b64encode(dilithium_public).decode(),
            'key_sizes': {
                'kyber_public': len(kyber_public),
                'dilithium_public': len(dilithium_public)
            },
            'created_at': self.user_keypairs[user_id]['created_at']
        }
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Returns a list of all users with public keys"""
        user_list = []
        for user_id, key_data in self.user_keypairs.items():
            user_list.append({
                "user_id": user_id,
                "kyber_pk": base64.b64encode(key_data['kyber_public']).decode('utf-8'),
                "dilithium_pk": base64.b64encode(key_data['dilithium_public']).decode('utf-8'),
            })
        return user_list

    def initiate_quantum_key_exchange(self, user_a: str, user_b: str) -> Dict[str, Any]:
        """
        Initiate quantum key exchange between two users
        
        Args:
            user_a: First user ID
            user_b: Second user ID
            
        Returns:
            Session information and BB84 protocol data
        """
        # Generate session ID
        session_id = secrets.token_hex(16)
        
        # Create new session
        session = CryptoSession(
            session_id=session_id,
            user_a=user_a,
            user_b=user_b,
            status="bb84_initiated"
        )
        
        print(f"🌀 Initiating quantum key exchange: {user_a} ↔ {user_b}")
        print(f"   Session ID: {session_id}")
        
        # Perform BB84 protocol
        try:
            bb84_result = self.bb84.perform_protocol()
            session.bb84_key = self.bb84.get_shared_key()
            session.status = "bb84_complete"
            
            print(f"✅ BB84 protocol completed successfully")
            print(f"   Key length: {bb84_result['key_length']} bits")
            print(f"   Error rate: {bb84_result['error_rate']:.2%}")
            
        except Exception as e:
            print(f"❌ BB84 protocol failed: {e}")
            session.status = "bb84_failed"
            bb84_result = {'error': str(e)}
        
        # Store session
        self.sessions[session_id] = session
        
        return {
            'session_id': session_id,
            'status': session.status,
            'bb84_result': bb84_result,
            'session_info': {
                'user_a': user_a,
                'user_b': user_b,
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat()
            }
        }
    
    def perform_kyber_encapsulation(self, session_id: str, target_user: str) -> Dict[str, Any]:
        """
        Perform Kyber key encapsulation for a session
        
        Args:
            session_id: Active session ID
            target_user: User whose public key to encapsulate against
            
        Returns:
            Encapsulation result with ciphertext and shared secret info
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        if target_user not in self.user_keypairs:
            raise ValueError(f"User {target_user} keypairs not found")
        
        session = self.sessions[session_id]
        target_public_key = self.user_keypairs[target_user]['kyber_public']
        
        print(f"📦 Performing Kyber encapsulation for session {session_id}")
        
        try:
            # Perform encapsulation
            ciphertext, shared_secret = self.kyber.encapsulate(target_public_key)
            
            # Store shared secret in session
            session.kyber_shared_secret = shared_secret
            session.status = "kyber_complete"
            
            print(f"✅ Kyber encapsulation successful")
            print(f"   Ciphertext size: {len(ciphertext)} bytes")
            print(f"   Shared secret size: {len(shared_secret)} bytes")
            
            return {
                'session_id': session_id,
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'shared_secret_hash': hashlib.sha256(shared_secret).hexdigest()[:16],
                'ciphertext_size': len(ciphertext),
                'status': 'success'
            }
            
        except Exception as e:
            print(f"❌ Kyber encapsulation failed: {e}")
            session.status = "kyber_failed"
            return {
                'session_id': session_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def perform_kyber_decapsulation(self, session_id: str, user_id: str, ciphertext_b64: str) -> Dict[str, Any]:
        """
        Perform Kyber key decapsulation
        
        Args:
            session_id: Active session ID
            user_id: User performing decapsulation
            ciphertext_b64: Base64 encoded ciphertext
            
        Returns:
            Decapsulation result
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        if user_id not in self.user_keypairs:
            raise ValueError(f"User {user_id} keypairs not found")
        
        session = self.sessions[session_id]
        user_secret_key = self.user_keypairs[user_id]['kyber_secret']
        
        print(f"🔓 Performing Kyber decapsulation for session {session_id}")
        
        try:
            # Decode ciphertext
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Perform decapsulation
            shared_secret = self.kyber.decapsulate(user_secret_key, ciphertext)
            
            # Verify shared secret matches (if we have it stored)
            if session.kyber_shared_secret:
                if shared_secret == session.kyber_shared_secret:
                    print("✅ Shared secrets match!")
                else:
                    print("⚠️  Shared secrets don't match - possible issue")
            
            # Store or update shared secret
            session.kyber_shared_secret = shared_secret
            
            print(f"✅ Kyber decapsulation successful")
            
            return {
                'session_id': session_id,
                'shared_secret_hash': hashlib.sha256(shared_secret).hexdigest()[:16],
                'status': 'success'
            }
            
        except Exception as e:
            print(f"❌ Kyber decapsulation failed: {e}")
            return {
                'session_id': session_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def derive_session_key(self, session_id: str) -> Dict[str, Any]:
        """
        Derive final session key from BB84 and Kyber keys
        
        Args:
            session_id: Session ID
            
        Returns:
            Session key derivation result
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        if not session.bb84_key or not session.kyber_shared_secret:
            raise ValueError("BB84 key and Kyber shared secret are required for session key derivation")

        print(f"🔗 Deriving session key for session {session_id}")

        # Combine BB84 key and Kyber shared secret
        combined_material = session.bb84_key + session.kyber_shared_secret

        # Optionally add user dilithium keys if both users exist
        if session.user_a in self.user_keypairs and session.user_b in self.user_keypairs:
            combined_material += (
                self.user_keypairs[session.user_a]['dilithium_secret'] +
                self.user_keypairs[session.user_b]['dilithium_secret']
            )

        # Derive session key using SHA-256
        session_key = hashlib.sha256(combined_material).digest()

        # Store session key
        session.session_key = session_key
        session.status = "ready"
        
        print(f"✅ Session key derived successfully")
        print(f"   Key length: {len(session_key) * 8} bits")
        
        return {
            'session_id': session_id,
            'key_length': len(session_key) * 8,
            'key_hash': hashlib.sha256(session_key).hexdigest()[:16],
            'status': 'ready',
            'session_status': session.status
        }
    
    def sign_message(self, user_id: str, message: bytes) -> Dict[str, Any]:
        """
        Sign a message using Dilithium
        
        Args:
            user_id: User signing the message
            message: Message to sign
            
        Returns:
            Signature information
        """
        if user_id not in self.user_keypairs:
            raise ValueError(f"User {user_id} keypairs not found")
        
        secret_key = self.user_keypairs[user_id]['dilithium_secret']
        
        print(f"✍️  Signing message for user {user_id}")
        print(f"   Message length: {len(message)} bytes")
        
        try:
            signature = self.dilithium.sign(secret_key, message)
            
            print(f"✅ Message signed successfully")
            print(f"   Signature size: {len(signature)} bytes")
            
            return {
                'user_id': user_id,
                'message_hash': hashlib.sha256(message).hexdigest(),
                'signature': base64.b64encode(signature).decode(),
                'signature_size': len(signature),
                'algorithm': 'dilithium',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Message signing failed: {e}")
            return {
                'user_id': user_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def verify_signature(self, user_id: str, message: bytes, signature_b64: str) -> Dict[str, Any]:
        """
        Verify a message signature
        
        Args:
            user_id: User who signed the message
            message: Original message
            signature_b64: Base64 encoded signature
            
        Returns:
            Verification result
        """
        if user_id not in self.user_keypairs:
            raise ValueError(f"User {user_id} keypairs not found")
        
        public_key = self.user_keypairs[user_id]['dilithium_public']
        
        print(f"🔍 Verifying signature for user {user_id}")
        
        try:
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            is_valid = self.dilithium.verify(public_key, message, signature)
            
            print(f"{'✅' if is_valid else '❌'} Signature verification: {'valid' if is_valid else 'invalid'}")
            
            return {
                'user_id': user_id,
                'message_hash': hashlib.sha256(message).hexdigest(),
                'signature_valid': is_valid,
                'algorithm': 'dilithium',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Signature verification failed: {e}")
            return {
                'user_id': user_id,
                'signature_valid': False,
                'error': str(e)
            }
    
    def encrypt_message(self, session_id: str, message: bytes) -> Dict[str, Any]:
        """
        Encrypt a message using the session key
        
        Args:
            session_id: Session with derived key
            message: Message to encrypt
            
        Returns:
            Encrypted message data
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        if not session.session_key:
            raise ValueError("Session key not available")
        
        print(f"🔒 Encrypting message for session {session_id}")
        print(f"   Message length: {len(message)} bytes")
        
        try:
            # Use AES-GCM with session key
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            cipher = Cipher(
                algorithms.AES(session.session_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            print(f"✅ Message encrypted successfully")
            print(f"   Ciphertext length: {len(ciphertext)} bytes")
            
            return {
                'session_id': session_id,
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'tag': base64.b64encode(encryptor.tag).decode(),
                'algorithm': 'AES-256-GCM',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Message encryption failed: {e}")
            return {
                'session_id': session_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def decrypt_message(self, session_id: str, ciphertext_b64: str, 
                       nonce_b64: str, tag_b64: str) -> Dict[str, Any]:
        """
        Decrypt a message using the session key
        
        Args:
            session_id: Session with derived key
            ciphertext_b64: Base64 encoded ciphertext
            nonce_b64: Base64 encoded nonce
            tag_b64: Base64 encoded authentication tag
            
        Returns:
            Decrypted message data
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        if not session.session_key:
            raise ValueError("Session key not available")
        
        print(f"🔓 Decrypting message for session {session_id}")
        
        try:
            # Decode components
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            tag = base64.b64decode(tag_b64)
            
            # Use AES-GCM with session key
            cipher = Cipher(
                algorithms.AES(session.session_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            print(f"✅ Message decrypted successfully")
            print(f"   Plaintext length: {len(plaintext)} bytes")
            
            return {
                'session_id': session_id,
                'plaintext': plaintext.decode('utf-8', errors='replace'),
                'plaintext_bytes': len(plaintext),
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Message decryption failed: {e}")
            return {
                'session_id': session_id,
                'status': 'failed',
                'error': str(e)
            }
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Get information about a cryptographic session"""
        if session_id not in self.sessions:
            return {'error': 'Session not found'}
        
        session = self.sessions[session_id]
        
        return {
            'session_id': session_id,
            'users': [session.user_a, session.user_b],
            'status': session.status,
            'created_at': session.created_at.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'has_bb84_key': session.bb84_key is not None,
            'has_kyber_secret': session.kyber_shared_secret is not None,
            'has_session_key': session.session_key is not None,
            'key_info': {
                'bb84_key_bits': len(session.bb84_key) * 8 if session.bb84_key else 0,
                'kyber_secret_bits': len(session.kyber_shared_secret) * 8 if session.kyber_shared_secret else 0,
                'session_key_bits': len(session.session_key) * 8 if session.session_key else 0
            }
        }
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """Returns statistics about the service"""
        total_sessions = len(self.sessions)
        active_sessions = len([s for s in self.sessions.values() if s.status == 'ready'])
        total_users = len(self.user_keypairs)
        
        return {
            'service_status': 'active',
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'total_users': total_users,
            'algorithms': {
                'bb84': {
                    'key_length': self.bb84.key_length,
                    'error_rate': self.bb84.error_rate
                },
                'kyber': {
                    'security_level': self.kyber.security_level,
                    'key_sizes': self.kyber.get_key_sizes()
                },
                'dilithium': {
                    'security_level': self.dilithium.security_level,
                    'signature_size': self.dilithium.get_signature_size()
                }
            },
            'timestamp': datetime.now().isoformat()
        }