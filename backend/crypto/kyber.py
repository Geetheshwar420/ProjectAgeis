"""
Crystal-Kyber Key Encapsulation Mechanism (KEM) Implementation
This module implements the Kyber post-quantum cryptographic algorithm
"""
import os
import hashlib
import secrets
from typing import Tuple, Optional
from unittest import result
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import numpy as np

class KyberKEM:
    """
    Implementation of Crystal-Kyber Key Encapsulation Mechanism
    
    """
    
    # Kyber512 parameters (simplified)
    KYBER_N = 256
    KYBER_Q = 3329
    KYBER_K = 2  # For Kyber512
    KYBER_ETA = 3
    KYBER_DU = 10
    KYBER_DV = 4
    
    def __init__(self, security_level: int = 512):
        self.security_level = security_level
        
        # Adjust parameters based on security level
        if security_level == 512:
            self.k = 2
            self.eta1 = 3
            self.eta2 = 2
        elif security_level == 768:
            self.k = 3
            self.eta1 = 2
            self.eta2 = 2
        elif security_level == 1024:
            self.k = 4
            self.eta1 = 2
            self.eta2 = 2
        else:
            raise ValueError("Unsupported security level. Use 512, 768, or 1024.")
            
        self.n = self.KYBER_N
        self.q = self.KYBER_Q
        
        # OPTIMIZATION: Precompute twiddle factors for NTT
        self._twiddle_factors = self._precompute_twiddle_factors()
        self._inv_twiddle_factors = self._precompute_inv_twiddle_factors()
        self._n_inv = pow(self.n, -1, self.q)
        
        # OPTIMIZATION: Cache for polynomial operations
        self._poly_cache = {}
        
    def _precompute_twiddle_factors(self) -> np.ndarray:
        """Precompute twiddle factors for NTT - O(n) computation done once"""
        factors = np.zeros(self.n, dtype=np.int64)
        for k in range(self.n):
            factors[k] = pow(3, k, self.q)
        return factors
    
    def _precompute_inv_twiddle_factors(self) -> np.ndarray:
        """Precompute inverse twiddle factors for INTT"""
        factors = np.zeros(self.n, dtype=np.int64)
        for k in range(self.n):
            factors[k] = pow(3, -k, self.q)
        return factors
    
    def _shake256(self, data: bytes, output_length: int) -> bytes:
        """SHAKE256 extendable output function with caching"""
        # OPTIMIZATION: Cache hash results for repeated inputs
        cache_key = (data, output_length)
        if cache_key in self._poly_cache:
            return self._poly_cache[cache_key]
        
        # Simplified implementation using SHA3-256 iteratively
        result = b''
        counter = 0
        while len(result) < output_length:
            hasher = hashlib.sha3_256()
            hasher.update(data)
            hasher.update(counter.to_bytes(4, 'little'))
            result += hasher.digest()
            counter += 1
        result = result[:output_length]
        
        # Cache if not too large
        if len(self._poly_cache) < 1000:
            self._poly_cache[cache_key] = result
        return result
    
    def _prf(self, seed: bytes, nonce: int, output_length: int) -> bytes:
        """Pseudorandom function"""
        hasher = hashlib.sha3_256()
        hasher.update(seed)
        hasher.update(nonce.to_bytes(1, 'little'))
        return hasher.digest()[:output_length]
    
    def _centered_binomial_distribution(self, eta: int, randomness: bytes) -> np.ndarray:
        samples = np.zeros(self.n, dtype=np.int16)
        
        for i in range(self.n):
            # Simple centered binomial sampling
            byte_idx = (i * eta) // 8
            if byte_idx < len(randomness):
                random_byte = randomness[byte_idx]
                # Count bits for binomial distribution
                a = bin(random_byte).count('1')
                b = eta - a
                samples[i] = (a - b) % self.q
                
        return samples
    
    def _ntt(self, poly: np.ndarray) -> np.ndarray:
        """OPTIMIZED: Fast NTT using precomputed twiddle factors and vectorization"""
        # Ensure input is always self.n elements
        if poly.shape[0] != self.n:
            poly = np.resize(poly, self.n)
        
        result = poly.astype(np.int64)
        transformed = np.zeros(self.n, dtype=np.int64)
        
        # OPTIMIZATION: Vectorized computation using precomputed twiddle factors
        for k in range(self.n):
            # Vectorized multiplication and modulo
            twiddle_powers = np.power(self._twiddle_factors, k, dtype=np.int64) % self.q
            terms = (result * twiddle_powers) % self.q
            transformed[k] = np.sum(terms) % self.q
        
        return transformed.astype(np.int32)

    def _intt(self, poly: np.ndarray) -> np.ndarray:
        """OPTIMIZED: Fast inverse NTT using precomputed twiddle factors"""
        # Ensure input is always self.n elements
        if poly.shape[0] != self.n:
            poly = np.resize(poly, self.n)
        
        result = poly.astype(np.int64)
        transformed = np.zeros(self.n, dtype=np.int64)
        
        # OPTIMIZATION: Vectorized computation using precomputed inverse twiddle factors
        for k in range(self.n):
            # Vectorized multiplication and modulo
            twiddle_powers = np.power(self._inv_twiddle_factors, k, dtype=np.int64) % self.q
            terms = (result * twiddle_powers) % self.q
            transformed[k] = (np.sum(terms) * self._n_inv) % self.q
        
        return transformed.astype(np.int32)
    
    def _poly_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """OPTIMIZED: Vectorized polynomial addition"""
        return ((a.astype(np.int32) + b.astype(np.int32)) % self.q).astype(np.int16)
    
    def _poly_sub(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """OPTIMIZED: Vectorized polynomial subtraction"""
        return ((a.astype(np.int32) - b.astype(np.int32)) % self.q).astype(np.int16)
    
    def _poly_mul_ntt(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """OPTIMIZED: Fast polynomial multiplication using NTT with caching"""
        # Cache NTT results for frequently used polynomials
        a_key = hash(a.tobytes())
        b_key = hash(b.tobytes())
        
        if a_key in self._poly_cache:
            a_ntt = self._poly_cache[a_key]
        else:
            a_ntt = self._ntt(a)
            if len(self._poly_cache) < 500:
                self._poly_cache[a_key] = a_ntt
        
        if b_key in self._poly_cache:
            b_ntt = self._poly_cache[b_key]
        else:
            b_ntt = self._ntt(b)
            if len(self._poly_cache) < 500:
                self._poly_cache[b_key] = b_ntt
        
        result_ntt = (a_ntt.astype(np.int64) * b_ntt.astype(np.int64)) % self.q
        return self._intt(result_ntt.astype(np.int32))
    
    def _compress(self, poly: np.ndarray, d: int) -> np.ndarray:
        """OPTIMIZED: Vectorized compression"""
        # Use numpy vectorized operations throughout
        compressed = np.round((poly.astype(np.float32) * (2**d)) / self.q).astype(np.int16) % (2**d)
        if compressed.shape[0] != self.n:
            compressed = np.resize(compressed, self.n)
        return compressed
    
    def _decompress(self, poly: np.ndarray, d: int) -> np.ndarray:
        """OPTIMIZED: Vectorized decompression"""
        # Use numpy vectorized operations throughout
        decompressed = np.round((poly.astype(np.float32) * self.q) / (2**d)).astype(np.int16) % self.q
        if decompressed.shape[0] != self.n:
            decompressed = np.resize(decompressed, self.n)
        return decompressed
    
    def _encode_polynomial(self, poly: np.ndarray, bits: int) -> bytes:
        """OPTIMIZED: Vectorized polynomial encoding"""
        # Ensure coefficients are in valid range
        poly_int = poly.astype(np.int16)
        # Use numpy's tobytes for fast conversion
        return poly_int.tobytes()
    
    def _decode_polynomial(self, data: bytes, bits: int) -> np.ndarray:
        """OPTIMIZED: Vectorized polynomial decoding"""
        # Fast conversion using numpy frombuffer
        poly = np.frombuffer(data, dtype=np.int16, count=self.n)
        # Pad if needed
        if len(poly) < self.n:
            poly = np.pad(poly, (0, self.n - len(poly)), 'constant')
        return poly[:self.n]
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        # Generate random seed
        seed = secrets.token_bytes(32)
        
        # Expand seed
        rho = self._shake256(seed, 32)
        sigma = self._shake256(seed + b'\x01', 32)
        
        # Generate matrix A from rho (simplified)
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                # Generate polynomial from seed
                poly_seed = self._prf(rho, i * self.k + j, 32)
                poly = np.frombuffer(poly_seed, dtype=np.uint16)
                if poly.shape[0] < self.n:
                    poly = np.pad(poly, (0, self.n - poly.shape[0]), 'constant')
                poly = poly[:self.n] % self.q
                row.append(poly.astype(np.int16))
            A.append(row)
        
        # Generate secret vector s
        s = []
        for i in range(self.k):
            randomness = self._prf(sigma, i, 32)
            s_i = self._centered_binomial_distribution(self.eta1, randomness)
            s.append(s_i)
        
        # Generate error vector e
        e = []
        for i in range(self.k):
            randomness = self._prf(sigma, self.k + i, 32)
            e_i = self._centered_binomial_distribution(self.eta1, randomness)
            e.append(e_i)
        
        # Compute t = As + e
        t = []
        for i in range(self.k):
            t_i = np.zeros(self.n, dtype=np.int16)
            for j in range(self.k):
                t_i = self._poly_add(t_i, self._poly_mul_ntt(A[i][j], s[j]))
            t_i = self._poly_add(t_i, e[i])
            t.append(t_i)
        
        # Encode public key (simplified)
        pk_data = rho
        for t_i in t:
            pk_data += self._encode_polynomial(t_i, 12)
        
        # Encode secret key (simplified)
        sk_data = b''
        for s_i in s:
            sk_data += self._encode_polynomial(s_i, 12)
        sk_data += pk_data  # Include public key in secret key
        sk_data += hashlib.sha3_256(pk_data).digest()  # Hash of public key
        sk_data += secrets.token_bytes(32)  # Random z value
        
        return pk_data, sk_data
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        # Extract components from public key
        rho = public_key[:32]
        t_encoded = public_key[32:]
        
        # Decode t vector
        t = []
        offset = 0
        for i in range(self.k):
            poly_data = t_encoded[offset:offset + self.n * 2]
            t_i = self._decode_polynomial(poly_data, 12)
            t.append(t_i)
            offset += self.n * 2
        
        # Generate random message
        m = secrets.token_bytes(32)
        
        # Generate random coins
        coins = hashlib.sha3_256(m + hashlib.sha3_256(public_key).digest()).digest()
        
        # Regenerate matrix A
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                poly_seed = self._prf(rho, i * self.k + j, 32)
                poly = np.frombuffer(poly_seed, dtype=np.uint16)
                if poly.shape[0] < self.n:
                    poly = np.pad(poly, (0, self.n - poly.shape[0]), 'constant')
                poly = poly[:self.n] % self.q
                row.append(poly.astype(np.int16))
            A.append(row)
        
        # Generate r vector
        r = []
        for i in range(self.k):
            randomness = self._prf(coins, i, 32)
            r_i = self._centered_binomial_distribution(self.eta1, randomness)
            r.append(r_i)
        
        # Generate e1 vector
        e1 = []
        for i in range(self.k):
            randomness = self._prf(coins, self.k + i, 32)
            e1_i = self._centered_binomial_distribution(self.eta2, randomness)
            e1.append(e1_i)
        
        # Generate e2
        randomness = self._prf(coins, 2 * self.k, 32)
        e2 = self._centered_binomial_distribution(self.eta2, randomness)
        
        # Compute u = A^T * r + e1
        u = []
        for i in range(self.k):
            u_i = np.zeros(self.n, dtype=np.int16)
            for j in range(self.k):
                u_i = self._poly_add(u_i, self._poly_mul_ntt(A[j][i], r[j]))
            u_i = self._poly_add(u_i, e1[i])
            u.append(u_i)
        
        # Compute v = t^T * r + e2 + Decompress(Encode(m))
        v = np.zeros(self.n, dtype=np.int16)
        for i in range(self.k):
            v = self._poly_add(v, self._poly_mul_ntt(t[i], r[i]))
        v = self._poly_add(v, e2)
        
        # Add message (simplified encoding)
        m_poly = np.frombuffer(m, dtype=np.uint16)
        if m_poly.shape[0] < self.n:
            m_poly = np.pad(m_poly, (0, self.n - m_poly.shape[0]), 'constant')
        m_poly = m_poly[:self.n]
        m_scaled = (m_poly * (self.q // 2)) % self.q
        v = self._poly_add(v, m_scaled.astype(np.int16))
        
        # Compress and encode ciphertext
        c1_data = b''
        for u_i in u:
            c1_data += self._encode_polynomial(self._compress(u_i, self.KYBER_DU), self.KYBER_DU)

        c2_data = self._encode_polynomial(self._compress(v, self.KYBER_DV), self.KYBER_DV)

        # Finalize the ciphertext by combining its components.
        # The random message 'm' is NOT part of the ciphertext.
        ciphertext = c1_data + c2_data

        # Derive shared secret from the random message 'm' and a hash of the final ciphertext.
        # This ensures the hash is computed on the exact data that will be transmitted.
        shared_secret = hashlib.sha3_256(m + hashlib.sha3_256(ciphertext).digest()).digest()

        return ciphertext, shared_secret
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        # Extract components from secret key (simplified parsing)
        sk_poly_size = self.n * 2 * self.k
        pk_size = 32 + sk_poly_size
        
        s_data = secret_key[:sk_poly_size]
        public_key = secret_key[sk_poly_size:sk_poly_size + pk_size]
        pk_hash = secret_key[sk_poly_size + pk_size:sk_poly_size + pk_size + 32]
        z = secret_key[sk_poly_size + pk_size + 32:sk_poly_size + pk_size + 64]
        
        # Decode secret vector s
        s = []
        offset = 0
        for i in range(self.k):
            poly_data = s_data[offset:offset + self.n * 2]
            s_i = self._decode_polynomial(poly_data, 12)
            s.append(s_i)
            offset += self.n * 2

        # Parse ciphertext (use actual serialized sizes: 2 bytes per coefficient)
        c1_size = self.k * self.n * 2
        c2_size = self.n * 2
        # Correctly slice the ciphertext into its components first
        c1_data = ciphertext[:c1_size]
        c2_data = ciphertext[c1_size : c1_size + c2_size]
        
        # Decode u vector from c1_data
        u = []
        offset = 0
        for i in range(self.k):
            poly_size = self.n * 2
            encoded_poly = self._decode_polynomial(c1_data[offset:offset + poly_size], self.KYBER_DU)
            u_i = self._decompress(encoded_poly, self.KYBER_DU)
            u.append(u_i)
            offset += poly_size
        
        # Decode v
        encoded_v = self._decode_polynomial(c2_data, self.KYBER_DV)
        v = self._decompress(encoded_v, self.KYBER_DV)

        # This is the core of Kyber decapsulation.
        s_transpose_u = np.zeros(self.n, dtype=np.int16)
        for i in range(self.k):
            s_transpose_u = self._poly_add(s_transpose_u, self._poly_mul_ntt(s[i], u[i]))
        
        m_prime_poly = self._poly_sub(v, s_transpose_u)

        # Decode m' from polynomial to bytes.
        # Round to nearest multiple of q/2 to extract bits
        m_prime_bits = []
        threshold = self.q // 4  # Midpoint for deciding bit value
        
        for coeff in m_prime_poly:
            # Reduce modulo q to get value in [0, q)
            val = int(coeff) % self.q
            # If value is closer to q/2 than to 0 or q, bit is 1
            # Distance to 0: val
            # Distance to q/2: |val - q/2|
            dist_to_0 = min(val, self.q - val)  # Account for wrap-around
            dist_to_half = abs(val - self.q // 2)
            
            # Bit is 1 if closer to q/2, else 0
            m_prime_bits.append('1' if dist_to_half < dist_to_0 else '0')

        # Convert bit string to bytes
        # Take first 256 bits (32 bytes) for the message
        m_bit_string = "".join(m_prime_bits[:256])
        # Pad with zeros if needed
        if len(m_bit_string) < 256:
            m_bit_string = m_bit_string.ljust(256, '0')
        
        # Convert to bytes
        m = int(m_bit_string, 2).to_bytes(32, 'big')

        # Derive shared secret using same method as encapsulation
        shared_secret = hashlib.sha3_256(m + hashlib.sha3_256(ciphertext).digest()).digest()

        return shared_secret
    
    def get_key_sizes(self) -> dict:
        """Get key and ciphertext sizes for this security level"""
        return {
            'public_key_size': 32 + self.k * self.n * 12 // 8,
            'secret_key_size': self.k * self.n * 12 // 8 + 32 + self.k * self.n * 12 // 8 + 32 + 32,
            'ciphertext_size': self.k * self.n * self.KYBER_DU // 8 + self.n * self.KYBER_DV // 8,
            'shared_secret_size': 32
        }

# Example usage and testing
if __name__ == "__main__":
    print("Testing Crystal-Kyber Key Encapsulation Mechanism")
    print("=" * 50)
    
    kyber = KyberKEM(security_level=512)
    
    try:
        # Generate keypair
        print("🔑 Generating Kyber keypair...")
        public_key, secret_key = kyber.generate_keypair()
        
        sizes = kyber.get_key_sizes()
        print(f"   Public key size: {len(public_key)} bytes")
        print(f"   Secret key size: {len(secret_key)} bytes")
        
        # Encapsulation
        print("\n📦 Performing encapsulation...")
        ciphertext, shared_secret1 = kyber.encapsulate(public_key)
        print(f"   Ciphertext size: {len(ciphertext)} bytes")
        print(f"   Shared secret: {shared_secret1.hex()[:32]}...")
        
        # Decapsulation
        print("\n🔓 Performing decapsulation...")
        shared_secret2 = kyber.decapsulate(secret_key, ciphertext)
        print(f"   Recovered secret: {shared_secret2.hex()[:32]}...")
        
        # Verify
        if shared_secret1 == shared_secret2:
            print("\n✅ Kyber KEM test successful! Shared secrets match.")
        else:
            print("\n❌ Kyber KEM test failed! Shared secrets don't match.")
            
        print(f"\n📊 Key Sizes:")
        for key, value in sizes.items():
            print(f"   {key}: {value} bytes")
            
    except Exception as e:
        print(f"❌ Kyber KEM test failed: {e}")
        import traceback
        traceback.print_exc()