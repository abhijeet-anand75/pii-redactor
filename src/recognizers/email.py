"""
Email Recognizer Module for the PII Redaction Tool.

This module provides detection of email addresses in text.
"""

import re
from typing import List, Optional

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class EmailRecognizer(BaseRecognizer):
    """
    Recognizer for email addresses.
    
    Detects email addresses using regex pattern matching with
    context-aware confidence scoring.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        self._pattern = self.compile_pattern(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.EMAIL
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize email addresses in the given text.
        
        Args:
            text: The text to scan for email addresses.
            
        Returns:
            A list of PIIEntity objects for detected emails.
        """
        entities = []
        matches = self.get_all_matches(text, self._pattern)
        
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            email_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # Calculate confidence based on email structure
            confidence = self.calculate_confidence(email_text, self._pattern)
            
            # Adjust confidence based on specific email characteristics
            if '@' in email_text and '.' in email_text:
                # Valid email structure increases confidence
                confidence = min(1.0, confidence + 0.05)
            
            # Check for common email domains (higher confidence)
            common_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 
                            'hotmail.com', 'example.com', 'company.com']
            if any(domain in email_text.lower() for domain in common_domains):
                confidence = min(1.0, confidence + 0.05)
            
            entity = self.create_entity(
                text=email_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'domain': email_text.split('@')[1] if '@' in email_text else 'unknown'}
            )
            
            if entity:
                entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)