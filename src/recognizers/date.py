"""
Date Recognizer Module for the PII Redaction Tool.

This module provides detection of dates of birth in text.
"""

import re
from datetime import datetime
from typing import List, Optional

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class DateRecognizer(BaseRecognizer):
    """
    Recognizer for dates of birth.
    
    Detects dates in various formats with context analysis
    to identify dates that are likely to be dates of birth.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        
        # Various date formats
        self._date_patterns = [
            # DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY
            self.compile_pattern(r'\b\d{2}[/.-]\d{2}[/.-]\d{4}\b'),
            # MM/DD/YYYY, MM-DD-YYYY, MM.DD.YYYY
            self.compile_pattern(r'\b\d{2}[/.-]\d{2}[/.-]\d{4}\b'),
            # DD Month YYYY (e.g., 25 December 1990)
            self.compile_pattern(
                r'\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|'
                r'January|February|March|April|May|June|July|August|September|'
                r'October|November|December)\s+\d{4}\b',
                re.IGNORECASE
            ),
            # Month DD, YYYY (e.g., December 25, 1990)
            self.compile_pattern(
                r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|'
                r'January|February|March|April|May|June|July|August|September|'
                r'October|November|December)\s+\d{1,2},\s+\d{4}\b',
                re.IGNORECASE
            ),
        ]
        
        # Common date of birth indicators
        self._dob_indicators = [
            'dob', 'date of birth', 'birth date', 'born on', 'birthday'
        ]
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.DATE_OF_BIRTH
    
    def _is_plausible_dob(self, date_str: str, context: str = '') -> bool:
        """Check if the date is likely to be a date of birth."""
        try:
            # Try to parse the date
            # Attempt various formats
            for fmt in ['%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y', '%m.%d.%Y']:
                try:
                    parsed_date = datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                # If no format matches, try natural language parsing (simplified)
                return False
            
            # Check if year is reasonable (1900-2010 for DOB)
            year = parsed_date.year
            if year < 1900 or year > 2010:
                return False
            
            # Check if date is in the past
            if parsed_date > datetime.now():
                return False
            
            return True
            
        except (ValueError, OverflowError):
            return False
    
    def _has_dob_context(self, text: str, start: int, end: int) -> float:
        """Check if surrounding context indicates this is a DOB."""
        context_start = max(0, start - 50)
        context_end = min(len(text), end + 50)
        context = text[context_start:context_end].lower()
        
        # Check for DOB indicators in context
        indicator_count = 0
        for indicator in self._dob_indicators:
            if indicator in context:
                indicator_count += 1
        
        # Return confidence boost based on indicators found
        if indicator_count >= 2:
            return 0.2
        elif indicator_count == 1:
            return 0.1
        return 0.0
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize dates of birth in the given text.
        
        Args:
            text: The text to scan for dates of birth.
            
        Returns:
            A list of PIIEntity objects for detected dates of birth.
        """
        entities = []
        
        # Try each date pattern
        for pattern in self._date_patterns:
            matches = self.get_all_matches(text, pattern)
            
            for match in matches:
                if not self.is_valid_match(match, text):
                    continue
                
                date_text = match.group(0)
                start = match.start()
                end = match.end()
                
                # Validate as plausible date of birth
                if not self._is_plausible_dob(date_text, text):
                    continue
                
                # Calculate base confidence
                confidence = 0.75
                
                # Check context for DOB indicators
                context_boost = self._has_dob_context(text, start, end)
                confidence = min(1.0, confidence + context_boost)
                
                # Boost confidence if date is within reasonable DOB range (1950-2005)
                try:
                    year_part = re.search(r'\d{4}', date_text)
                    if year_part:
                        year = int(year_part.group(0))
                        if 1950 <= year <= 2005:
                            confidence = min(1.0, confidence + 0.05)
                except ValueError:
                    pass
                
                # Lower confidence for dates that look like expiration dates
                exp_indicators = ['exp', 'expiry', 'valid', 'validity', 'expires']
                context_before = text[max(0, start-30):start].lower()
                if any(indicator in context_before for indicator in exp_indicators):
                    confidence = max(0.5, confidence - 0.2)
                    continue
                
                entity = self.create_entity(
                    text=date_text,
                    start=start,
                    end=end,
                    confidence=confidence,
                    metadata={'format': self._detect_format(date_text)}
                )
                
                if entity:
                    entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)
    
    def _detect_format(self, date_str: str) -> str:
        """Detect the format of the date string."""
        if '/' in date_str:
            return 'slash_separated'
        elif '-' in date_str:
            return 'dash_separated'
        elif '.' in date_str:
            return 'dot_separated'
        elif any(month in date_str.lower() for month in ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']):
            return 'text_month'
        else:
            return 'unknown'