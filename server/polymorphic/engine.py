#!/usr/bin/env python3
"""
Polymorphic Engine - Main Orchestrator
Generates unique malware variants with preserved functionality
"""

import logging
import hashlib
from typing import List, Dict, Tuple
from .mutator import CodeMutator

logger = logging.getLogger(__name__)


class PolymorphicEngine:
    """Main engine for generating polymorphic code variants"""
    
    def __init__(self):
        self.mutator = CodeMutator()
        self.generated_variants = []
    
    def generate_variant(
        self, 
        code: str, 
        mutation_level: str = "medium",
        seed: int = None
    ) -> Tuple[str, Dict]:
        """
        Generate a single polymorphic variant
        
        Args:
            code: Original source code
            mutation_level: low, medium, high
            seed: Random seed for reproducibility
        
        Returns:
            (variant_code, variant_info)
        """
        logger.info(f"Generating polymorphic variant (level: {mutation_level})")
        
        # Reset mutator for fresh variant
        self.mutator = CodeMutator(seed=seed)
        
        # Apply mutations
        variant_code, mutation_info = self.mutator.mutate(code, mutation_level)
        
        # Calculate variant hash
        variant_hash = self._calculate_hash(variant_code)
        original_hash = self._calculate_hash(code)
        
        # Calculate similarity
        similarity = self._calculate_similarity(code, variant_code)
        
        variant_info = {
            'original_hash': original_hash,
            'variant_hash': variant_hash,
            'original_size': len(code),
            'variant_size': len(variant_code),
            'size_change': len(variant_code) - len(code),
            'size_change_percent': ((len(variant_code) - len(code)) / len(code)) * 100 if len(code) > 0 else 0,
            'similarity_percent': similarity * 100,
            'uniqueness_percent': (1 - similarity) * 100,
            'mutation_level': mutation_level,
            'mutations_applied': mutation_info
        }
        
        logger.info(f"Variant generated: {variant_info['uniqueness_percent']:.1f}% unique")
        
        self.generated_variants.append(variant_info)
        
        return variant_code, variant_info
    
    def generate_variants(
        self,
        code: str,
        count: int = 10,
        mutation_level: str = "medium"
    ) -> List[Tuple[str, Dict]]:
        """
        Generate multiple unique variants
        
        Args:
            code: Original source code
            count: Number of variants to generate
            mutation_level: low, medium, high
        
        Returns:
            List of (variant_code, variant_info) tuples
        """
        logger.info(f"Generating {count} polymorphic variants")
        
        variants = []
        hashes_seen = set()
        
        for i in range(count):
            # Use different seed for each variant
            seed = i * 12345
            
            variant_code, variant_info = self.generate_variant(
                code, 
                mutation_level, 
                seed=seed
            )
            
            # Check uniqueness
            variant_hash = variant_info['variant_hash']
            if variant_hash in hashes_seen:
                logger.warning(f"Variant {i+1} duplicate hash, regenerating...")
                # Try again with different seed
                seed = (i + 1000) * 54321
                variant_code, variant_info = self.generate_variant(
                    code,
                    mutation_level,
                    seed=seed
                )
                variant_hash = variant_info['variant_hash']
            
            hashes_seen.add(variant_hash)
            variants.append((variant_code, variant_info))
            
            logger.info(f"Variant {i+1}/{count}: {variant_info['uniqueness_percent']:.1f}% unique")
        
        # Calculate average uniqueness
        if variants:  # Check if variants list is not empty
            avg_uniqueness = sum(v[1]['uniqueness_percent'] for v in variants) / len(variants)
            logger.info(f"Average uniqueness: {avg_uniqueness:.1f}%")
        
        return variants
    
    def _calculate_hash(self, code: str) -> str:
        """Calculate SHA256 hash of code"""
        return hashlib.sha256(code.encode()).hexdigest()[:16]
    
    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity between two code snippets (0.0-1.0)"""
        
        # Simple similarity based on common lines
        lines1 = set(line.strip() for line in code1.split('\n') if line.strip())
        lines2 = set(line.strip() for line in code2.split('\n') if line.strip())
        
        if not lines1 or not lines2:
            return 0.0
        
        common = lines1.intersection(lines2)
        total = lines1.union(lines2)
        
        return len(common) / len(total) if total else 1.0
    
    def get_statistics(self) -> Dict:
        """Get statistics about generated variants"""
        
        if not self.generated_variants:
            return {
                'total_variants': 0,
                'message': 'No variants generated yet'
            }
        
        uniqueness_values = [v['uniqueness_percent'] for v in self.generated_variants]
        size_changes = [v['size_change_percent'] for v in self.generated_variants]
        
        return {
            'total_variants': len(self.generated_variants),
            'avg_uniqueness': sum(uniqueness_values) / len(uniqueness_values) if uniqueness_values else 0,
            'min_uniqueness': min(uniqueness_values) if uniqueness_values else 0,
            'max_uniqueness': max(uniqueness_values) if uniqueness_values else 0,
            'avg_size_change': sum(size_changes) / len(size_changes) if size_changes else 0,
            'unique_hashes': len(set(v['variant_hash'] for v in self.generated_variants))
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_code = """
int main(int argc, char* argv[]) {
    int result = 0;
    DWORD counter = 0;
    BOOL success = 1;
    
    result = process_data();
    counter = get_count();
    
    if (success) {
        cleanup();
    }
    
    return 0;
}

int process_data() {
    int value = 0;
    return value;
}
"""
    
    print("=== POLYMORPHIC ENGINE TEST ===\n")
    print("Original code:")
    print(test_code)
    print(f"\nOriginal size: {len(test_code)} bytes")
    
    engine = PolymorphicEngine()
    
    # Generate 3 variants
    print("\n=== GENERATING 3 VARIANTS ===\n")
    variants = engine.generate_variants(test_code, count=3, mutation_level="high")
    
    for i, (variant_code, info) in enumerate(variants, 1):
        print(f"\n--- VARIANT {i} ---")
        print(f"Uniqueness: {info['uniqueness_percent']:.1f}%")
        print(f"Size change: {info['size_change_percent']:.1f}%")
        print(f"Hash: {info['variant_hash']}")
        print(f"\nCode preview (first 200 chars):")
        print(variant_code[:200] + "...")
    
    # Statistics
    print("\n=== STATISTICS ===")
    stats = engine.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")

