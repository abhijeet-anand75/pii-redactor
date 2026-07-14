"""
Corporate IDs Recognizer Module for the PII Redaction Tool.

This module provides detection of SSNs and Credit Card numbers.
"""

import re
from typing import List

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class CorporateIDsRecognizer(BaseRecognizer):
    """
    Recognizer for corporate identification numbers (SSN, Credit Cards).
    
    Detects SSNs and credit card numbers using regex pattern matching.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        
        # SSN patterns (XXX-XX-XXXX, XXX XX XXXX, XXXXXXXXX)
        self._ssn_pattern = self.compile_pattern(
            r'\b\d{3}-\d{2}-\d{4}\b|\b\d{3}\s\d{2}\s\d{4}\b|\b\d{9}\b'
        )
        
        # Credit card patterns (Visa, MasterCard, Amex, Discover)
        self._credit_card_pattern = self.compile_pattern(
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'  # Visa
            r'5[1-5][0-9]{14}|'               # MasterCard
            r'3[47][0-9]{13}|'                # Amex
            r'6(?:011|5[0-9]{2})[0-9]{12})'   # Discover
            r'\b'
        )
        
        # Also detect masked/obfuscated credit cards (XXXX-XXXX-XXXX-1234)
        self._masked_credit_card_pattern = self.compile_pattern(
            r'\b(?:[Xx]{4}[- ]?){3}[0-9]{4}\b'
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.CREDIT_CARD  # Default, but will set specific type per entity
    
    def _validate_ssn(self, ssn: str) -> bool:
        """Validate that SSN doesn't contain all zeros or invalid patterns."""
        # Remove non-digit characters
        digits = re.sub(r'\D', '', ssn)
        
        # Invalid SSNs
        if digits == '000000000':
            return False
        if digits.startswith('000'):
            return False
        if digits.startswith('666'):
            return False
        if digits.startswith('900') and len(digits) == 9:
            return False
        
        return True
    
    def _validate_credit_card(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        # Remove non-digit characters
        digits = re.sub(r'\D', '', card_number)
        
        if len(digits) < 13 or len(digits) > 16:
            return False
        
        # Simple Luhn algorithm validation
        total = 0
        reverse_digits = digits[::-1]
        
        for i, digit in enumerate(reverse_digits):
            num = int(digit)
            if i % 2 == 1:
                num *= 2
                if num > 9:
                    num -= 9
            total += num
        
        return total % 10 == 0
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize SSNs and credit card numbers in the given text.
        
        Args:
            text: The text to scan for corporate IDs.
            
        Returns:
            A list of PIIEntity objects for detected IDs.
        """
        entities = []
        
        # Detect SSNs
        ssn_matches = self.get_all_matches(text, self._ssn_pattern)
        for match in ssn_matches:
            if not self.is_valid_match(match, text):
                continue
            
            ssn_text = match.group(0)
            start = match.start()
            end = match.end()
            
            if not self._validate_ssn(ssn_text):
                continue
            
            confidence = 0.95  # High confidence for SSNs
            entity = self.create_entity(
                text=ssn_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'type': 'SSN'}
            )
            
            if entity:
                entities.append(entity)
        
        # Detect credit card numbers
        credit_matches = self.get_all_matches(text, self._credit_card_pattern)
        for match in credit_matches:
            if not self.is_valid_match(match, text):
                continue
            
            card_text = match.group(0)
            start = match.start()
            end = match.end()
            
            if not self._validate_credit_card(card_text):
                continue
            
            confidence = 0.95  # High confidence for credit cards
            entity = self.create_entity(
                text=card_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'type': 'Credit Card'}
            )
            
            if entity:
                entities.append(entity)
        
        # Detect masked credit card numbers (e.g., XXXX-XXXX-XXXX-1234)
        masked_matches = self.get_all_matches(text, self._masked_credit_card_pattern)
        for match in masked_matches:
            if not self.is_valid_match(match, text):
                continue
            
            card_text = match.group(0)
            start = match.start()
            end = match.end()
            
            confidence = 0.90  # High confidence for masked cards
            entity = self.create_entity(
                text=card_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'type': 'Masked Credit Card'}
            )
            
            if entity:
                entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)