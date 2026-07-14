"""
Base Recognizer Module for the PII Redaction Tool.

This module defines the abstract base class that all PII recognizers
must implement to ensure a consistent interface for detection.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Optional, Pattern, Dict, Any

from src.models import PII, PIIEntity


class BaseRecognizer(ABC):
    """
    Abstract base class for all PII recognizers.
    
    This class defines the contract that all specific PII type recognizers
    must follow. It provides common functionality for pattern compilation
    and confidence calculation while requiring subclasses to implement
    the core recognition logic.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        """
        Initialize the recognizer with a confidence threshold.
        
        Args:
            confidence_threshold: Minimum confidence score for detection
                                 (default: 0.85).
        """
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError(f"Confidence threshold must be between 0.0 and 1.0, got {confidence_threshold}")
        
        self._confidence_threshold = confidence_threshold
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    @abstractmethod
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize PII entities in the given text.
        
        Args:
            text: The text to scan for PII.
            
        Returns:
            A list of PIIEntity objects representing detected PII.
            Returns an empty list if no PII is found.
        """
        pass
    
    @property
    def pii_type(self) -> PII:
        """
        Get the PII type that this recognizer detects.
        
        Returns:
            The PII type enum value.
        """
        # This must be overridden by subclasses
        raise NotImplementedError("Subclasses must define pii_type property")
    
    def compile_pattern(self, pattern: str, flags: int = re.IGNORECASE) -> Pattern:
        """
        Compile and cache a regular expression pattern.
        
        This method caches compiled patterns to improve performance
        when the same pattern is used multiple times.
        
        Args:
            pattern: The regular expression pattern string.
            flags: Regular expression flags (default: re.IGNORECASE).
            
        Returns:
            A compiled regular expression Pattern object.
        """
        cache_key = f"{pattern}_{flags}"
        if cache_key not in self._compiled_patterns:
            self._compiled_patterns[cache_key] = re.compile(pattern, flags)
        return self._compiled_patterns[cache_key]
    
    def calculate_confidence(self, text: str, pattern: Pattern) -> float:
        """
        Calculate confidence score for a match.
        
        Base implementation uses match quality factors:
        - Length of matched text (longer = more confident)
        - Number of matches found (more = less confident)
        - Context indicators (e.g., '@' for email increases confidence)
        
        Args:
            text: The matched text.
            pattern: The pattern used for matching.
            
        Returns:
            A confidence score between 0.0 and 1.0.
        """
        # Base confidence calculation
        confidence = 0.85
        
        # Increase confidence for longer matches (more specific)
        if len(text) > 20:
            confidence += 0.10
        elif len(text) > 10:
            confidence += 0.05
        
        # Decrease confidence for very short matches (likely false positives)
        if len(text) < 3:
            confidence -= 0.20
        
        # Cap confidence between 0.0 and 1.0
        return max(0.0, min(1.0, confidence))
    
    def create_entity(
        self,
        text: str,
        start: int,
        end: int,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PIIEntity:
        """
        Create a PIIEntity from detection results.
        
        This is a convenience method that handles entity creation with
        consistent validation and metadata handling.
        
        Args:
            text: The PII text found.
            start: Starting character index.
            end: Ending character index (exclusive).
            confidence: Confidence score for this detection.
            metadata: Optional metadata dictionary.
            
        Returns:
            A PIIEntity object.
        """
        if metadata is None:
            metadata = {}
        
        # Apply threshold filtering
        if confidence < self._confidence_threshold:
            return None
        
        return PIIEntity(
            text=text,
            start=start,
            end=end,
            type=self.pii_type,
            confidence=confidence,
            metadata=metadata
        )
    
    def filter_entities_by_confidence(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Filter entities by confidence threshold.
        
        Args:
            entities: List of PIIEntity objects to filter.
            
        Returns:
            Filtered list containing only entities above threshold.
        """
        return [
            entity for entity in entities
            if entity.confidence >= self._confidence_threshold
        ]
    
    def has_pattern_match(self, text: str, pattern: Pattern) -> bool:
        """
        Check if the text matches the given pattern.
        
        Args:
            text: The text to check.
            pattern: The compiled pattern to match against.
            
        Returns:
            True if the pattern matches the text, False otherwise.
        """
        return bool(pattern.search(text))
    
    def get_all_matches(self, text: str, pattern: Pattern) -> List[re.Match]:
        """
        Get all pattern matches in the text with position information.
        
        Args:
            text: The text to search.
            pattern: The compiled pattern to match against.
            
        Returns:
            A list of Match objects with position information.
        """
        return list(pattern.finditer(text))
    
    def is_valid_match(self, match: re.Match, text: str) -> bool:
        """
        Validate if a match should be considered valid.
        
        Override this method in subclasses for custom validation logic.
        
        Args:
            match: The regex match object.
            text: The full text being searched.
            
        Returns:
            True if the match is valid, False otherwise.
        """
        return True