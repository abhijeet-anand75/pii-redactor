"""
Unit tests for detector (src/detector.py).
"""

import pytest
from src.detector import Detector
from src.models import PII, PIIEntity


class TestDetector:
    """Test the Detector class."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = Detector()
        assert detector.threshold == 0.85
        assert len(detector._recognizers) == 7
    
    def test_initialization_custom_threshold(self):
        """Test detector with custom threshold."""
        detector = Detector(threshold=0.9)
        assert detector.threshold == 0.9
        
        # All recognizers should have the same threshold
        for recognizer in detector._recognizers:
            assert recognizer._confidence_threshold == 0.9
    
    def test_detect_entities(self):
        """Test detecting entities in text."""
        detector = Detector()
        text = "Contact john@example.com and +91 9876543210"
        entities = detector.detect(text)
        
        # Should detect at least email and phone
        assert len(entities) >= 2
        
        types_found = {e.type for e in entities}
        assert PII.EMAIL in types_found or PII.PHONE in types_found
    
    def test_detect_empty_text(self):
        """Test detection with empty text."""
        detector = Detector()
        entities = detector.detect("")
        assert len(entities) == 0
    
    def test_overlap_resolution(self):
        """Test resolving overlapping entities."""
        detector = Detector()
        
        # Create overlapping entities
        entities = [
            PIIEntity(text="John", start=0, end=4, type=PII.FULL_NAME, confidence=0.8),
            PIIEntity(text="John Smith", start=0, end=10, type=PII.FULL_NAME, confidence=0.9),
            PIIEntity(text="Smith", start=5, end=10, type=PII.FULL_NAME, confidence=0.7),
        ]
        
        resolved = detector._resolve_overlaps(entities)
        
        # Should keep only the highest confidence one
        assert len(resolved) == 1
        assert resolved[0].text == "John Smith"
    
    def test_deduplication(self):
        """Test deduplicating entities."""
        detector = Detector()
        
        # Create duplicate entities
        entities = [
            PIIEntity(text="test@example.com", start=0, end=16, type=PII.EMAIL, confidence=0.9),
            PIIEntity(text="test@example.com", start=0, end=16, type=PII.EMAIL, confidence=0.9),
            PIIEntity(text="other@example.com", start=17, end=33, type=PII.EMAIL, confidence=0.8),
        ]
        
        deduped = detector._deduplicate_entities(entities)
        assert len(deduped) == 2
    
    def test_threshold_update(self):
        """Test updating threshold."""
        detector = Detector(threshold=0.85)
        detector.threshold = 0.90
        
        assert detector.threshold == 0.90
        for recognizer in detector._recognizers:
            assert recognizer._confidence_threshold == 0.90
    
    def test_threshold_invalid(self):
        """Test setting invalid threshold."""
        detector = Detector()
        
        with pytest.raises(ValueError, match="Threshold must be between 0.0 and 1.0"):
            detector.threshold = 1.5
        
        with pytest.raises(ValueError, match="Threshold must be between 0.0 and 1.0"):
            detector.threshold = -0.5
    
    def test_recognizer_info(self):
        """Test getting recognizer information."""
        detector = Detector()
        info = detector.get_recognizer_info()
        
        assert len(info) == 7
        for recognizer_info in info:
            assert "name" in recognizer_info
            assert "type" in recognizer_info
            assert "threshold" in recognizer_info