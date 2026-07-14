"""
Phone Number Recognizer Module for the PII Redaction Tool.

This module provides detection of phone numbers in text.
"""

import re
from typing import List

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class PhoneRecognizer(BaseRecognizer):
    """
    Recognizer for phone numbers.
    
    Detects phone numbers using regex pattern matching with
    support for Indian and international formats.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        # Pattern for Indian phone numbers (+91, 0, or no prefix)
        self._pattern = self.compile_pattern(
            r'(\+91\s?)?[6-9]\d{9}|[6-9]\d{9}|\+91\s?[6-9]\d{9}|0[6-9]\d{9}'
        )
        # Pattern for international phone numbers (general)
        self._international_pattern = self.compile_pattern(
            r'\+?\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}'
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.PHONE
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize phone numbers in the given text.
        
        Args:
            text: The text to scan for phone numbers.
            
        Returns:
            A list of PIIEntity objects for detected phone numbers.
        """
        entities = []
        
        # Try Indian phone number pattern first
        matches = self.get_all_matches(text, self._pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            phone_text = match.group(0)
            start = match.start()
            end = match.end()
            
            confidence = self.calculate_confidence(phone_text, self._pattern)
            
            # Boost confidence for valid Indian format
            if phone_text.startswith('+91') or phone_text.startswith('0'):
                confidence = min(1.0, confidence + 0.05)
            
            # Boost confidence for 10-digit numbers starting with 6-9
            if re.match(r'^[6-9]\d{9}$', phone_text):
                confidence = min(1.0, confidence + 0.1)
            
            entity = self.create_entity(
                text=phone_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'format': 'indian'}
            )
            
            if entity:
                entities.append(entity)
        
        # Try international pattern for any remaining numbers
        # Note: This is a fallback and may catch some false positives
        if len(entities) == 0:
            matches = self.get_all_matches(text, self._international_pattern)
            for match in matches:
                # Avoid duplicating matches already found by Indian pattern
                if any(e.start <= match.start() < e.end for e in entities):
                    continue
                
                phone_text = match.group(0)
                start = match.start()
                end = match.end()
                
                confidence = self.calculate_confidence(phone_text, self._international_pattern)
                
                # Lower confidence for international format (less context)
                confidence = max(0.5, confidence - 0.1)
                
                entity = self.create_entity(
                    text=phone_text,
                    start=start,
                    end=end,
                    confidence=confidence,
                    metadata={'format': 'international'}
                )
                
                if entity:
                    entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)