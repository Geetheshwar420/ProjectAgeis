from crypto.quantum_service import QuantumCryptoService

# Initialize Quantum Service Singleton lazily
_quantum_service = None

def get_quantum_service():
    """Lazy initialization of the Quantum Crypto Service"""
    global _quantum_service
    if _quantum_service is None:
        print("[SECURE] Initializing Quantum Crypto Service (Lazy Load)...")
        _quantum_service = QuantumCryptoService()
    return _quantum_service

# For backward compatibility with existing imports
# This proxy ensures that calls to quantum_service.method() 
# only trigger initialization when the method is actually called.
class QuantumServiceProxy:
    def __getattr__(self, name):
        return getattr(get_quantum_service(), name)

quantum_service = QuantumServiceProxy()
