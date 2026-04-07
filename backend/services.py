# services.py
# Removed redundant QuantumCryptoService initialization to stabilize backend.
# The frontend now handles all cryptographic operations.

class _DeprecatedQuantumService:
    """Stub to catch accidental usage of removed quantum_service."""
    def __getattr__(self, name):
        raise NotImplementedError(
            "quantum_service has been removed. "
            "Cryptographic operations are now handled by the frontend."
        )

# Deprecated: raises NotImplementedError on any method call.
quantum_service = _DeprecatedQuantumService()
