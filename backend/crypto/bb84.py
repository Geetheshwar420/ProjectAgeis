"""
BB84 Quantum Key Distribution Protocol Implementation
This module implements the BB84 protocol for quantum key distribution
"""
import random
import numpy as np
import hashlib
from typing import List, Tuple, Dict, Optional
from enum import Enum
import secrets

class PolarizationBasis(Enum):
    """Polarization basis for photons"""
    RECTILINEAR = 0  # + basis (0°, 90°)
    DIAGONAL = 1     # × basis (45°, 135°)

class PhotonPolarization(Enum):
    """Photon polarization states"""
    HORIZONTAL = 0    # 0° (bit 0 in + basis)
    VERTICAL = 1      # 90° (bit 1 in + basis)
    DIAGONAL_45 = 2   # 45° (bit 0 in × basis)
    DIAGONAL_135 = 3  # 135° (bit 1 in × basis)

class BB84Protocol:
    """
    Implementation of the BB84 Quantum Key Distribution Protocol
    
    This is a simulation of the BB84 protocol which would normally
    require quantum hardware. For demonstration purposes, we simulate
    the quantum channel and measurements.
    """
    
    def __init__(self, key_length: int = 256, error_rate: float = 0.05):
        self.key_length = key_length
        self.error_rate = error_rate
        self.alice_bits: List[int] = []
        self.alice_bases: List[PolarizationBasis] = []
        self.bob_bases: List[PolarizationBasis] = []
        self.bob_measurements: List[int] = []
        self.shared_key: Optional[bytes] = None
        
    def generate_random_bits(self, length: int) -> List[int]:
        """Generate cryptographically secure random bits"""
        return [secrets.randbits(1) for _ in range(length)]
    
    def generate_random_bases(self, length: int) -> List[PolarizationBasis]:
        """Generate random polarization bases"""
        return [PolarizationBasis(secrets.randbits(1)) for _ in range(length)]
    
    def encode_photon(self, bit: int, basis: PolarizationBasis) -> PhotonPolarization:
        if basis == PolarizationBasis.RECTILINEAR:
            return PhotonPolarization.HORIZONTAL if bit == 0 else PhotonPolarization.VERTICAL
        else:  # DIAGONAL
            return PhotonPolarization.DIAGONAL_45 if bit == 0 else PhotonPolarization.DIAGONAL_135
    
    def measure_photon(self, photon: PhotonPolarization, basis: PolarizationBasis) -> int:
        # If we're measuring in the correct basis, we get the right answer
        # (with some channel noise)
        if (photon in [PhotonPolarization.HORIZONTAL, PhotonPolarization.VERTICAL] and 
            basis == PolarizationBasis.RECTILINEAR):
            correct_bit = 0 if photon == PhotonPolarization.HORIZONTAL else 1
        elif (photon in [PhotonPolarization.DIAGONAL_45, PhotonPolarization.DIAGONAL_135] and 
              basis == PolarizationBasis.DIAGONAL):
            correct_bit = 0 if photon == PhotonPolarization.DIAGONAL_45 else 1
        else:
            # Wrong basis - result is random
            correct_bit = secrets.randbits(1)
        
        # Apply channel noise
        if random.random() < self.error_rate:
            return 1 - correct_bit
        else:
            return correct_bit
    
    def alice_prepare_photons(self, num_photons: int) -> List[PhotonPolarization]:
        self.alice_bits = self.generate_random_bits(num_photons)
        self.alice_bases = self.generate_random_bases(num_photons)
        
        photons = []
        for bit, basis in zip(self.alice_bits, self.alice_bases):
            photon = self.encode_photon(bit, basis)
            photons.append(photon)
            
        return photons
    
    def bob_measure_photons(self, photons: List[PhotonPolarization]) -> List[int]:
        self.bob_bases = self.generate_random_bases(len(photons))
        self.bob_measurements = []
        
        for photon, basis in zip(photons, self.bob_bases):
            measurement = self.measure_photon(photon, basis)
            self.bob_measurements.append(measurement)
            
        return self.bob_measurements
    
    def sift_key(self) -> Tuple[List[int], List[int]]:
        alice_sifted = []
        bob_sifted = []
        
        for i in range(len(self.alice_bases)):
            if self.alice_bases[i] == self.bob_bases[i]:
                alice_sifted.append(self.alice_bits[i])
                bob_sifted.append(self.bob_measurements[i])
                
        return alice_sifted, bob_sifted
    
    def estimate_error_rate(self, alice_bits: List[int], bob_bits: List[int], 
                          sample_size: int = None) -> float:
        if sample_size is None:
            sample_size = min(len(alice_bits) // 4, 100)  # Use 25% or 100 bits max
            
        if len(alice_bits) < sample_size:
            sample_size = len(alice_bits)
            
        # Randomly sample bits for error estimation
        indices = random.sample(range(len(alice_bits)), sample_size)
        
        errors = 0
        for i in indices:
            if alice_bits[i] != bob_bits[i]:
                errors += 1
                
        return errors / sample_size if sample_size > 0 else 0.0
    
    def privacy_amplification(self, bits: List[int]) -> bytes:
        # Convert bits to bytes
        bit_string = ''.join(map(str, bits))
        bit_bytes = int(bit_string, 2).to_bytes((len(bit_string) + 7) // 8, byteorder='big')
        
        # Use SHA-256 for privacy amplification
        # In practice, you might use more sophisticated techniques
        hash_obj = hashlib.sha256()
        hash_obj.update(bit_bytes)
        
        # Generate the desired key length
        key = hash_obj.digest()
        
        # If we need more bits, use HKDF-like expansion
        while len(key) * 8 < self.key_length:
            hash_obj = hashlib.sha256()
            hash_obj.update(key)
            hash_obj.update(b'expansion')
            key += hash_obj.digest()
            
        # Truncate to desired length
        key_bits = self.key_length // 8
        return key[:key_bits]
    
    def perform_protocol(self, max_attempts: int = 3) -> Dict:
        for attempt in range(max_attempts):
            # Step 1: Alice prepares photons (4x the desired key length for overhead)
            num_photons = self.key_length * 4
            photons = self.alice_prepare_photons(num_photons)
            
            # Step 2: Bob measures photons
            measurements = self.bob_measure_photons(photons)
            
            # Step 3: Basis sifting
            alice_sifted, bob_sifted = self.sift_key()
            
            # Step 4: Error estimation
            if len(alice_sifted) < self.key_length:
                continue  # Not enough bits, try again
                
            error_rate = self.estimate_error_rate(alice_sifted, bob_sifted)
            
            # Step 5: Check if error rate is acceptable (should be < 11% for security)
            if error_rate > 0.11:
                if attempt == max_attempts - 1:
                    raise Exception(f"Error rate too high: {error_rate:.2%}")
                continue
                
            # Step 6: Error correction (simplified - just remove sampled bits)
            # In practice, you'd use error correction codes
            sample_size = min(len(alice_sifted) // 4, 100)
            remaining_bits = alice_sifted[sample_size:]
            
            # Step 7: Privacy amplification
            if len(remaining_bits) < self.key_length:
                continue  # Not enough bits after error correction
                
            self.shared_key = self.privacy_amplification(remaining_bits[:self.key_length])
            
            return {
                'success': True,
                'key_length': len(self.shared_key) * 8,
                'key': self.shared_key.hex(),
                'error_rate': error_rate,
                'efficiency': len(alice_sifted) / len(self.alice_bits),
                'attempt': attempt + 1,
                'photons_sent': len(photons),
                'bits_sifted': len(alice_sifted),
                'final_key_bits': len(remaining_bits)
            }
            
        raise Exception("Failed to generate key after maximum attempts")
    
    def get_shared_key(self) -> Optional[bytes]:
        """Get the generated shared key"""
        return self.shared_key
    
    def get_protocol_statistics(self) -> Dict:
        """Get detailed statistics about the protocol execution"""
        if not hasattr(self, 'alice_bits') or not self.alice_bits:
            return {'error': 'Protocol not executed yet'}
            
        alice_sifted, bob_sifted = self.sift_key()
        
        return {
            'total_photons': len(self.alice_bits),
            'basis_matches': len(alice_sifted),
            'efficiency': len(alice_sifted) / len(self.alice_bits) if self.alice_bits else 0,
            'alice_basis_distribution': {
                'rectilinear': self.alice_bases.count(PolarizationBasis.RECTILINEAR),
                'diagonal': self.alice_bases.count(PolarizationBasis.DIAGONAL)
            },
            'bob_basis_distribution': {
                'rectilinear': self.bob_bases.count(PolarizationBasis.RECTILINEAR),
                'diagonal': self.bob_bases.count(PolarizationBasis.DIAGONAL)
            },
            'key_generated': self.shared_key is not None,
            'key_length': len(self.shared_key) * 8 if self.shared_key else 0
        }

# Example usage and testing
if __name__ == "__main__":
    # Test the BB84 protocol
    print("Testing BB84 Quantum Key Distribution Protocol")
    print("=" * 50)
    
    bb84 = BB84Protocol(key_length=256, error_rate=0.02)
    
    try:
        result = bb84.perform_protocol()
        print(f"✅ Protocol successful!")
        print(f"   Key length: {result['key_length']} bits")
        print(f"   Error rate: {result['error_rate']:.2%}")
        print(f"   Efficiency: {result['efficiency']:.2%}")
        print(f"   Attempts: {result['attempt']}")
        print(f"   Generated key: {result['key'][:32]}...")
        
        stats = bb84.get_protocol_statistics()
        print(f"\n📊 Protocol Statistics:")
        print(f"   Total photons sent: {stats['total_photons']}")
        print(f"   Basis matches: {stats['basis_matches']}")
        print(f"   Overall efficiency: {stats['efficiency']:.2%}")
        
    except Exception as e:
        print(f"❌ Protocol failed: {e}")