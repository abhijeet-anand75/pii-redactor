"""
Fake Generator Module for the PII Redaction Tool.

This module provides deterministic fake data generation for all PII types
using the Faker library with a seeded instance.
"""

import random
from typing import Dict, Optional
from faker import Faker
from faker.providers import BaseProvider

from src.models import PII


class ConsistentFakerProvider(BaseProvider):
    """
    Custom Faker provider to ensure consistent fake data generation
    across different PII types while maintaining realistic values.
    """
    
    def consistent_email(self) -> str:
        """
        Generate a consistent fake email address.
        
        Returns:
            A fake email address string.
        """
        # Use the same name generation for consistency
        first_name = self.generator.first_name().lower()
        last_name = self.generator.last_name().lower()
        domain = self.generator.domain_name()
        return f"{first_name}.{last_name}@{domain}"
    
    def consistent_phone(self) -> str:
        """
        Generate a consistent fake Indian phone number.
        
        Returns:
            A fake phone number string with +91 prefix.
        """
        # Generate 10-digit phone number
        digits = ''.join(str(self.generator.random_int(0, 9)) for _ in range(10))
        return f"+91 {digits[:5]} {digits[5:]}"
    
    def consistent_ssn(self) -> str:
        """
        Generate a consistent fake SSN.
        
        Returns:
            A fake SSN string in XXX-XX-XXXX format.
        """
        part1 = str(self.generator.random_int(100, 999))
        part2 = str(self.generator.random_int(10, 99))
        part3 = str(self.generator.random_int(1000, 9999))
        return f"{part1}-{part2}-{part3}"
    
    def consistent_credit_card(self) -> str:
        """
        Generate a consistent fake credit card number.
        
        Returns:
            A masked credit card number in XXXX-XXXX-XXXX-XXXX format.
        """
        # Generate 16-digit number, mask first 12 digits
        last4 = str(self.generator.random_int(1000, 9999))
        return f"XXXX-XXXX-XXXX-{last4}"
    
    def consistent_ip(self) -> str:
        """
        Generate a consistent fake IPv4 address.
        
        Returns:
            A fake IPv4 address string.
        """
        octets = [str(self.generator.random_int(1, 254)) for _ in range(4)]
        return '.'.join(octets)
    
    def consistent_date_of_birth(self) -> str:
        """
        Generate a consistent fake date of birth.
        
        Returns:
            A fake date of birth in DD/MM/YYYY format.
        """
        year = str(self.generator.random_int(1950, 2005))
        month = str(self.generator.random_int(1, 12)).zfill(2)
        day = str(self.generator.random_int(1, 28)).zfill(2)
        return f"{day}/{month}/{year}"
    
    def consistent_address(self) -> str:
        """
        Generate a consistent fake Indian address.
        
        Returns:
            A fake Indian address string.
        """
        return self.generator.address()
    
    def consistent_company(self) -> str:
        """
        Generate a consistent fake company name.
        
        Returns:
            A fake company name string.
        """
        return self.generator.company()


class FakeGenerator:
    """
    Generates deterministic fake data for PII replacement.
    
    This class uses a seeded Faker instance to ensure that the same PII
    text always produces the same fake value, maintaining consistency
    across the document.
    """
    
    def __init__(self, seed: int = 42):
        """
        Initialize the fake generator with a seed for deterministic output.
        
        Args:
            seed: Seed value for random number generation (default: 42).
        """
        self._seed = seed
        self._faker = Faker()
        self._faker.seed_instance(seed)
        self._faker.add_provider(ConsistentFakerProvider)
        
        # Cache for consistent replacements
        self._cache: Dict[str, str] = {}
        
        # Type-specific generation methods
        self._generators = {
            PII.EMAIL: self._faker.consistent_email,
            PII.PHONE: self._faker.consistent_phone,
            PII.FULL_NAME: self._faker.name,
            PII.COMPANY_NAME: self._faker.consistent_company,
            PII.IP_ADDRESS: self._faker.consistent_ip,
            PII.SSN: self._faker.consistent_ssn,
            PII.CREDIT_CARD: self._faker.consistent_credit_card,
            PII.DATE_OF_BIRTH: self._faker.consistent_date_of_birth,
            PII.ADDRESS: self._faker.consistent_address,
        }
        
        # Verify all PII types have generators
        self._validate_generators()
    
    def _validate_generators(self) -> None:
        """
        Validate that all PII types have a corresponding generator function.
        
        Raises:
            ValueError: If any PII type is missing a generator.
        """
        for pii_type in PII:
            if pii_type not in self._generators:
                raise ValueError(f"No generator defined for PII type: {pii_type}")
    
    def generate(self, pii_type: PII, original_text: str) -> str:
        """
        Generate a fake replacement for the given PII text.
        
        This method ensures that the same original text always produces
        the same fake value, even across different calls.
        
        Args:
            pii_type: The type of PII to generate a fake for.
            original_text: The original PII text to replace.
            
        Returns:
            A fake replacement string appropriate for the PII type.
            
        Raises:
            ValueError: If the PII type is not supported.
            KeyError: If the PII type has no generator.
        """
        # Check cache first
        cache_key = f"{pii_type.value}:{original_text.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Generate new fake
        generator = self._generators.get(pii_type)
        if generator is None:
            raise ValueError(f"No generator found for PII type: {pii_type}")
        
        fake_value = generator()
        
        # Cache the result
        self._cache[cache_key] = fake_value
        
        return fake_value
    
    def generate_for_type(self, pii_type: PII) -> str:
        """
        Generate a fake value for a PII type without caching.
        
        This is useful for generating initial fake values before the
        original text is known.
        
        Args:
            pii_type: The type of PII to generate a fake for.
            
        Returns:
            A fake replacement string appropriate for the PII type.
        """
        generator = self._generators.get(pii_type)
        if generator is None:
            raise ValueError(f"No generator found for PII type: {pii_type}")
        return generator()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get statistics about the current cache.
        
        Returns:
            Dictionary containing cache statistics.
        """
        return {
            "cache_size": len(self._cache),
            "unique_types": len(set(
                key.split(':')[0] for key in self._cache.keys()
            ))
        }
    
    def clear_cache(self) -> None:
        """
        Clear the replacement cache.
        
        This is useful for testing or when processing a new document.
        """
        self._cache.clear()
    
    def reset(self) -> None:
        """
        Reset the generator to its initial state.
        
        This clears the cache and resets the Faker instance.
        """
        self.clear_cache()
        self._faker = Faker()
        self._faker.seed_instance(self._seed)
        self._faker.add_provider(ConsistentFakerProvider)
    
    @property
    def seed(self) -> int:
        """
        Get the seed value used for generation.
        
        Returns:
            The seed value.
        """
        return self._seed
    
    @property
    def cache_size(self) -> int:
        """
        Get the current size of the cache.
        
        Returns:
            The number of cached replacements.
        """
        return len(self._cache)