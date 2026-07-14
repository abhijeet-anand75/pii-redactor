"""
Address Recognizer Module for the PII Redaction Tool.

This module provides detection of physical/mailing addresses in text.
"""

import re
from typing import List

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class AddressRecognizer(BaseRecognizer):
    """
    Recognizer for physical and mailing addresses.
    
    Detects addresses using regex pattern matching for common
    address formats and keywords.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        
        # Address patterns with street, city, state, zip
        self._address_pattern = self.compile_pattern(
            r'\b\d{1,5}\s+[A-Za-z0-9\s.,-]+\s+'
            r'(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|'
            r'Drive|Dr|Court|Ct|Place|Pl|Way|Circle|Cir|Parkway|Pkwy)\b',
            re.IGNORECASE
        )
        
        # Pattern for addresses with city, state, zip
        self._city_state_zip_pattern = self.compile_pattern(
            r'[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?'
        )
        
        # Pattern for Indian addresses
        self._india_address_pattern = self.compile_pattern(
            r'\b(?:Village|Taluka|District|Pune|Mumbai|Delhi|Bangalore|Chennai|'
            r'Hyderabad|Ahmedabad|Kolkata|Maharashtra|Gujarat|Tamil Nadu|Karnataka|'
            r'Rajasthan|Uttar Pradesh)\b',
            re.IGNORECASE
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.ADDRESS
    
    def _is_valid_address(self, address: str) -> bool:
        """Basic validation that the address looks valid."""
        # Should contain at least 2 words
        words = address.split()
        if len(words) < 2:
            return False
        
        # Should contain numbers or common address keywords
        has_number = bool(re.search(r'\d', address))
        has_keyword = bool(re.search(
            r'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
            r'Court|Ct|Place|Pl|Way|Circle|Cir|Parkway|Pkwy|Village|Taluka|'
            r'District|Building|Floor|Apartment|Apt|Suite|Suit|Plot|Block|'
            r'House|H\.?O\.?|No\.|#',
            address,
            re.IGNORECASE
        ))
        
        # Should have a number OR a keyword (or both)
        return has_number or has_keyword
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize addresses in the given text.
        
        Args:
            text: The text to scan for addresses.
            
        Returns:
            A list of PIIEntity objects for detected addresses.
        """
        entities = []
        
        # Detect standard address format
        matches = self.get_all_matches(text, self._address_pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            address_text = match.group(0)
            start = match.start()
            end = match.end()
            
            if not self._is_valid_address(address_text):
                continue
            
            confidence = self.calculate_confidence(address_text, self._address_pattern)
            
            # Boost confidence for longer addresses (more specific)
            if len(address_text) > 30:
                confidence = min(1.0, confidence + 0.05)
            
            # Boost confidence if it contains numbers and keywords
            if re.search(r'\d', address_text) and re.search(r'[A-Z][a-z]+', address_text):
                confidence = min(1.0, confidence + 0.05)
            
            entity = self.create_entity(
                text=address_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'format': 'standard'}
            )
            
            if entity:
                entities.append(entity)
        
        # Detect city/state/zip format
        matches = self.get_all_matches(text, self._city_state_zip_pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            # Check if this might be part of a larger address already found
            address_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # Skip if already captured by standard address pattern
            if any(e.start <= start < e.end for e in entities):
                continue
            
            confidence = 0.75  # Lower confidence for city/state/zip only
            
            entity = self.create_entity(
                text=address_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'format': 'city_state_zip'}
            )
            
            if entity:
                entities.append(entity)
        
        # Detect Indian location indicators (works as context clues)
        matches = self.get_all_matches(text, self._india_address_pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            # Only use if there's surrounding context that suggests an address
            context_start = max(0, match.start() - 50)
            context_end = min(len(text), match.end() + 50)
            context = text[context_start:context_end]
            
            # Look for address indicators in context
            if re.search(r'\d', context):
                confidence = 0.65
                
                # Higher confidence if multiple indicators found
                if re.search(r'(?:Street|St|Avenue|Ave|Road|Rd)', context, re.IGNORECASE):
                    confidence += 0.05
                
                if re.search(r'(?:Village|Taluka|District)', context, re.IGNORECASE):
                    confidence += 0.05
                
                entity = self.create_entity(
                    text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    metadata={'format': 'indian_location'}
                )
                
                if entity:
                    entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)