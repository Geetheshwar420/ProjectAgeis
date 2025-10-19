"""
Quantum cryptography implementations
"""

# Import will be handled by the modules themselves
# This allows for lazy loading and better error handling

__all__ = ['BB84Protocol', 'KyberKEM', 'DilithiumSignature']

def get_bb84_protocol():
    from .bb84 import BB84Protocol
    return BB84Protocol

def get_kyber_kem():
    from .kyber import KyberKEM
    return KyberKEM

def get_dilithium_signature():
    from .dilithium import DilithiumSignature
    return DilithiumSignature