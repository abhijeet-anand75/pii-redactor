"""
Unit tests for shared models (src/models.py).
"""

import pytest
from pathlib import Path
from src.models import PII, PIIEntity, DocumentContext, RedactionReport


class TestPIIEnum:
    """Test the PII enum."""
    
    def test_enum_values(self):
        """Test all PII types are defined."""
        assert len(PII) == 9
        assert PII.FULL_NAME is not None
        assert PII.EMAIL is not None
        assert PII.PHONE is not None
        assert PII.IP_ADDRESS is not None
        assert PII.SSN is not None
        assert PII.CREDIT_CARD is not None
        assert PII.DATE_OF_BIRTH is not None
        assert PII.ADDRESS is not None
        assert PII.COMPANY_NAME is not None
    
    def test_enum_uniqueness(self):
        """Test all enum values are unique."""
        values = [e.value for e in PII]
        assert len(values) == len(set(values))


class TestPIIEntity:
    """Test the PIIEntity dataclass."""
    
    def test_creation_valid(self):
        """Test creating a valid PIIEntity."""
        entity = PIIEntity(
            text="test@example.com",
            start=0,
            end=16,
            type=PII.EMAIL,
            confidence=0.95
        )
        assert entity.text == "test@example.com"
        assert entity.start == 0
        assert entity.end == 16
        assert entity.type == PII.EMAIL
        assert entity.confidence == 0.95
        assert entity.length == 16
    
    def test_creation_invalid_confidence(self):
        """Test confidence validation."""
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            PIIEntity(
                text="test",
                start=0,
                end=4,
                type=PII.EMAIL,
                confidence=1.5
            )
        
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            PIIEntity(
                text="test",
                start=0,
                end=4,
                type=PII.EMAIL,
                confidence=-0.5
            )
    
    def test_creation_invalid_positions(self):
        """Test position validation."""
        with pytest.raises(ValueError, match="Start index.*must be less than end index"):
            PIIEntity(
                text="test",
                start=5,
                end=3,
                type=PII.EMAIL,
                confidence=0.5
            )
    
    def test_creation_empty_text(self):
        """Test empty text validation."""
        with pytest.raises(ValueError, match="Start index 0 must be less than end index 0"):
            PIIEntity(
                text="",
                start=0,
                end=0,
                type=PII.EMAIL,
                confidence=0.5
            )
    
    def test_overlap_detection(self):
        """Test overlap detection between entities."""
        e1 = PIIEntity(text="John Doe", start=0, end=8, type=PII.FULL_NAME, confidence=0.9)
        e2 = PIIEntity(text="Doe", start=4, end=7, type=PII.FULL_NAME, confidence=0.7)
        e3 = PIIEntity(text="Jane", start=9, end=13, type=PII.FULL_NAME, confidence=0.8)
        
        assert e1.overlaps_with(e2) is True
        assert e1.overlaps_with(e3) is False
        assert e2.overlaps_with(e3) is False
    
    def test_contains(self):
        """Test containment detection."""
        e1 = PIIEntity(text="John Doe", start=0, end=8, type=PII.FULL_NAME, confidence=0.9)
        e2 = PIIEntity(text="Doe", start=4, end=7, type=PII.FULL_NAME, confidence=0.7)
        e3 = PIIEntity(text="Jane", start=9, end=13, type=PII.FULL_NAME, confidence=0.8)
        
        assert e1.contains(e2) is True
        assert e1.contains(e3) is False
    
    def test_sorting(self):
        """Test entity sorting by start position."""
        e1 = PIIEntity(text="B", start=5, end=6, type=PII.EMAIL, confidence=0.5)
        e2 = PIIEntity(text="A", start=0, end=1, type=PII.EMAIL, confidence=0.5)
        e3 = PIIEntity(text="C", start=10, end=11, type=PII.EMAIL, confidence=0.5)
        
        sorted_entities = sorted([e1, e2, e3])
        assert sorted_entities[0] == e2
        assert sorted_entities[1] == e1
        assert sorted_entities[2] == e3
    
    def test_equality(self):
        """Test entity equality."""
        e1 = PIIEntity(text="John Doe", start=0, end=8, type=PII.FULL_NAME, confidence=0.9)
        e2 = PIIEntity(text="John Doe", start=0, end=8, type=PII.FULL_NAME, confidence=0.7)
        e3 = PIIEntity(text="Jane Doe", start=0, end=8, type=PII.FULL_NAME, confidence=0.9)
        
        assert e1 == e2  # Same text, position, type
        assert e1 != e3  # Different text


class TestDocumentContext:
    """Test the DocumentContext dataclass."""
    
    def test_creation_valid(self, tmp_path):
        """Test creating a valid DocumentContext."""
        # Create a temporary file
        test_file = tmp_path / "test.pdf"
        test_file.write_text("test content")
        
        context = DocumentContext(
            source_path=test_file,
            raw_text="test content",
            page_count=1,
            char_count=12,
            word_count=2,
            file_size_bytes=test_file.stat().st_size
        )
        
        assert context.source_path == test_file
        assert context.raw_text == "test content"
        assert context.page_count == 1
        assert context.char_count == 12
        assert context.word_count == 2
        assert context.file_size_bytes > 0
    
    def test_creation_nonexistent_file(self, tmp_path):
        """Test validation for non-existent file."""
        with pytest.raises(FileNotFoundError):
            DocumentContext(
                source_path=tmp_path / "nonexistent.pdf",
                raw_text="test",
                page_count=1,
                char_count=4,
                word_count=1,
                file_size_bytes=0
            )


class TestRedactionReport:
    """Test the RedactionReport dataclass."""
    
    def test_creation_valid(self, tmp_path):
        """Test creating a valid RedactionReport."""
        test_file = tmp_path / "test.pdf"
        test_file.write_text("test")
        
        context = DocumentContext(
            source_path=test_file,
            raw_text="test",
            page_count=1,
            char_count=4,
            word_count=1,
            file_size_bytes=test_file.stat().st_size
        )
        
        entity = PIIEntity(
            text="test@example.com",
            start=0,
            end=16,
            type=PII.EMAIL,
            confidence=0.95
        )
        
        report = RedactionReport(
            original_document=context,
            detected_entities=[entity],
            redacted_entities=[entity],
            replacement_map=[(entity, "fake@example.com")],
            offset_map={0: 0, 16: 19}
        )
        
        assert report.original_document == context
        assert len(report.detected_entities) == 1
        assert len(report.redacted_entities) == 1
        assert len(report.replacement_map) == 1
        assert len(report.offset_map) == 2
    
    def test_creation_invalid_replacement_map(self, tmp_path):
        """Test validation for invalid replacement map."""
        test_file = tmp_path / "test.pdf"
        test_file.write_text("test")
        
        context = DocumentContext(
            source_path=test_file,
            raw_text="test",
            page_count=1,
            char_count=4,
            word_count=1,
            file_size_bytes=test_file.stat().st_size
        )
        
        entity1 = PIIEntity(
            text="test@example.com",
            start=0,
            end=16,
            type=PII.EMAIL,
            confidence=0.95
        )
        
        entity2 = PIIEntity(
            text="other@example.com",
            start=0,
            end=16,
            type=PII.EMAIL,
            confidence=0.95
        )
        
        with pytest.raises(ValueError, match="Replacement map does not match redacted entities"):
            RedactionReport(
                original_document=context,
                detected_entities=[entity1],
                redacted_entities=[entity1],
                replacement_map=[(entity2, "fake@example.com")],
                offset_map={}
            )
    
    def test_get_stats(self, tmp_path):
        """Test statistics generation."""
        test_file = tmp_path / "test.pdf"
        test_file.write_text("test")
        
        context = DocumentContext(
            source_path=test_file,
            raw_text="test",
            page_count=1,
            char_count=4,
            word_count=1,
            file_size_bytes=test_file.stat().st_size
        )
        
        entity = PIIEntity(
            text="test@example.com",
            start=0,
            end=16,
            type=PII.EMAIL,
            confidence=0.95
        )
        
        report = RedactionReport(
            original_document=context,
            detected_entities=[entity],
            redacted_entities=[entity],
            replacement_map=[(entity, "fake@example.com")],
            offset_map={0: 0, 16: 19}
        )
        
        stats = report.get_stats()
        assert stats["total_pii_detected"] == 1
        assert stats["total_pii_redacted"] == 1
        assert stats["total_replaced"] == 1
        assert stats["page_count"] == 1
        assert stats["word_count"] == 1
        assert "EMAIL" in stats["unique_pii_types"]
        assert stats["unique_pii_types"]["EMAIL"] == 1