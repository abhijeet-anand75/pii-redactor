"""
Name Recognizer Module for the PII Redaction Tool.

This module provides detection of full names using spaCy NER.
"""

import re
from typing import List, Optional

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class NameRecognizer(BaseRecognizer):
    """
    Recognizer for full names.
    
    Uses spaCy NER for person detection with additional rule-based
    heuristics for improved accuracy.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        self._nlp = None
        
        # Try to load spaCy model
        try:
            import spacy
            self._nlp = spacy.load('en_core_web_sm')
        except (ImportError, OSError) as e:
            # Fallback to regex if spaCy not available
            self._nlp = None
        
        # Always initialize fallback pattern (used if spaCy fails or no entities found)
        # Simple pattern for 2-3 capitalized words (names)
        self._fallback_pattern = self.compile_pattern(
            r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b'
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.FULL_NAME
    
    def _extract_names_with_spacy(self, text: str) -> List[PIIEntity]:
        """Extract names using spaCy NER."""
        entities = []
        
        if self._nlp is None:
            return entities
        
        doc = self._nlp(text)
        
        for ent in doc.ents:
            if ent.label_ == 'PERSON':
                name_text = ent.text
                start = ent.start_char
                end = ent.end_char
                
                # Calculate confidence based on name structure
                confidence = 0.85
                
                # Boost confidence for names with multiple parts
                if len(name_text.split()) >= 2:
                    confidence = min(1.0, confidence + 0.05)
                
                # Check if it's a full name (not just a single word)
                if len(name_text.split()) == 1:
                    confidence = max(0.6, confidence - 0.1)
                
                # Check for title/prefix patterns
                titles = ['Mr.', 'Ms.', 'Mrs.', 'Dr.', 'Prof.', 'Capt.', 'Maj.']
                if any(name_text.startswith(title) for title in titles):
                    confidence = min(1.0, confidence + 0.05)
                
                # Check for suffix patterns
                suffixes = ['Jr.', 'Sr.', 'II', 'III', 'IV']
                if any(name_text.endswith(suffix) for suffix in suffixes):
                    confidence = min(1.0, confidence + 0.05)
                
                entity = self.create_entity(
                    text=name_text,
                    start=start,
                    end=end,
                    confidence=confidence,
                    metadata={'method': 'spacy', 'label': ent.label_}
                )
                
                if entity:
                    entities.append(entity)
        
        return entities
    
    def _extract_names_fallback(self, text: str) -> List[PIIEntity]:
        """Extract names using regex fallback."""
        entities = []
        
        # Safety check - if fallback pattern is None, return empty list
        if self._fallback_pattern is None:
            return entities
        
        matches = self.get_all_matches(text, self._fallback_pattern)
        
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            name_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # Lower confidence for fallback method
            confidence = 0.7
            
            # Boost confidence for names with 2-3 parts
            parts = len(name_text.split())
            if parts == 2:
                confidence = 0.8
            elif parts == 3:
                confidence = 0.85
            
            # Check context to avoid false positives (e.g., company names)
            context_words = ['Ltd', 'Inc', 'Corp', 'Company', 'LLC']
            if any(word in text for word in context_words):
                confidence = max(0.5, confidence - 0.1)
            
            entity = self.create_entity(
                text=name_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'method': 'fallback'}
            )
            
            if entity:
                entities.append(entity)
        
        return entities
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize full names in the given text.
        
        Args:
            text: The text to scan for names.
            
        Returns:
            A list of PIIEntity objects for detected names.
        """
        # Try spaCy NER first
        entities = self._extract_names_with_spacy(text)
        
        # Always run fallback to catch names spaCy might miss
        fallback_entities = self._extract_names_fallback(text)
        
        # Combine and de-duplicate
        all_entities = entities + fallback_entities
        seen = set()
        unique_entities = []
        for entity in all_entities:
            key = (entity.text, entity.start, entity.end)
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)
        
        return self.filter_entities_by_confidence(unique_entities)