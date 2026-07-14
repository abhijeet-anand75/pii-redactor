"""
Shared Data Models for the PII Redaction Tool.

This module defines all core dataclasses and enums that serve as
the system's data contracts for passing information between modules.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path


class PII(Enum):
    """
    Enumeration of all Personally Identifiable Information (PII) types
    that the system can detect and redact.
    """
    FULL_NAME = auto()
    EMAIL = auto()
    PHONE = auto()
    IP_ADDRESS = auto()
    SSN = auto()
    CREDIT_CARD = auto()
    DATE_OF_BIRTH = auto()
    ADDRESS = auto()
    COMPANY_NAME = auto()


@dataclass
class PIIEntity:
    """
    Represents a single detected PII instance within a document.
    
    Attributes:
        text: The original PII text found in the document.
        start: Starting character index of the PII in the original text.
        end: Ending character index (exclusive) of the PII in the original text.
        type: The type of PII detected (from PII enum).
        confidence: A score between 0.0 and 1.0 indicating detection confidence.
        metadata: Optional dictionary for additional context or debugging info.
    """
    text: str
    start: int
    end: int
    type: PII
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """
        Validate that confidence is within the acceptable range.
        """
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.start >= self.end:
            raise ValueError(f"Start index {self.start} must be less than end index {self.end}")
        if not self.text:
            raise ValueError("Text cannot be empty")
    
    @property
    def length(self) -> int:
        """
        Length of the PII text.
        
        Returns:
            Number of characters in the PII text.
        """
        return self.end - self.start
    
    def overlaps_with(self, other: 'PIIEntity') -> bool:
        """
        Check if this entity overlaps with another entity.
        
        Args:
            other: Another PIIEntity to check overlap against.
            
        Returns:
            True if the entities overlap, False otherwise.
        """
        return self.start < other.end and other.start < self.end
    
    def contains(self, other: 'PIIEntity') -> bool:
        """
        Check if this entity fully contains another entity.
        
        Args:
            other: Another PIIEntity to check containment against.
            
        Returns:
            True if this entity contains the other, False otherwise.
        """
        return self.start <= other.start and other.end <= self.end
    
    def __lt__(self, other: 'PIIEntity') -> bool:
        """
        Sort by start position, then by end position.
        
        Args:
            other: Another PIIEntity to compare against.
            
        Returns:
            True if this entity should come before the other.
        """
        if self.start != other.start:
            return self.start < other.start
        return self.end < other.end
    
    def __eq__(self, other: object) -> bool:
        """
        Two entities are equal if they have the same text, position, and type.
        
        Args:
            other: Another object to compare against.
            
        Returns:
            True if the entities are equal, False otherwise.
        """
        if not isinstance(other, PIIEntity):
            return False
        return (self.text == other.text and 
                self.start == other.start and 
                self.end == other.end and 
                self.type == other.type)


@dataclass
class DocumentContext:
    """
    Metadata about the document being processed.
    
    Attributes:
        source_path: File path of the original document.
        raw_text: The full extracted text from the document.
        page_count: Number of pages in the document.
        char_count: Total number of characters in the document.
        word_count: Total number of words in the document.
        file_size_bytes: Size of the original file in bytes.
    """
    source_path: Path
    raw_text: str
    page_count: int
    char_count: int
    word_count: int
    file_size_bytes: int
    
    def __post_init__(self) -> None:
        """
        Validate that the document context contains valid data.
        """
        if not self.source_path.exists():
            raise FileNotFoundError(f"Source file not found: {self.source_path}")
        if not self.raw_text and self.page_count > 0:
            # This is a warning situation - some PDFs have no extractable text
            pass
        if self.char_count != len(self.raw_text):
            # Recalculate to ensure consistency
            self.char_count = len(self.raw_text)


@dataclass
class RedactionReport:
    """
    The final output containing the results of the redaction process.
    
    Attributes:
        original_document: Information about the source document.
        detected_entities: The list of all detected PII before filtering.
        redacted_entities: The list of PII that were actually redacted.
        replacement_map: Mapping of PIIEntity to its fake replacement value.
        offset_map: Mapping from byte offset in original text to byte offset 
                    in redacted text.
        precision: Precision score (TP / (TP + FP)), or None if not evaluated.
        recall: Recall score (TP / (TP + FN)), or None if not evaluated.
        f1_score: F1-score, or None if not evaluated.
        processing_time_seconds: Time taken to process the document.
        errors: List of error messages encountered during processing.
        warnings: List of warning messages encountered during processing.
    """
    original_document: DocumentContext
    detected_entities: List[PIIEntity]
    redacted_entities: List[PIIEntity]
    replacement_map: List[Tuple[PIIEntity, str]]
    offset_map: Dict[int, int]  # original_byte_offset -> redacted_byte_offset
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    processing_time_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """
        Validate that the report contains consistent data.
        """
        # Validate that all redacted entities were in the detected list
        redacted_set = set((e.text, e.start, e.end) for e in self.redacted_entities)
        detected_set = set((e.text, e.start, e.end) for e in self.detected_entities)
        
        if not redacted_set.issubset(detected_set):
            missing = redacted_set - detected_set
            raise ValueError(f"Some redacted entities were not in detected list: {missing}")
        
        # Validate replacement map consistency
        map_set = set((e.text, e.start, e.end) for e, _ in self.replacement_map)
        if map_set != redacted_set:
            raise ValueError("Replacement map does not match redacted entities")
        
        # Validate offset map
        if self.offset_map:
            if not isinstance(self.offset_map, dict):
                raise ValueError("Offset map must be a dictionary")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics about the redaction process.
        
        Returns:
            Dictionary containing statistics about the redaction.
        """
        stats = {
            "total_pii_detected": len(self.detected_entities),
            "total_pii_redacted": len(self.redacted_entities),
            "total_replaced": len(self.replacement_map),
            "unique_pii_types": {},
            "file_size_mb": self.original_document.file_size_bytes / (1024 * 1024),
            "page_count": self.original_document.page_count,
            "word_count": self.original_document.word_count,
            "processing_time_seconds": self.processing_time_seconds,
        }
        
        # Count by PII type
        type_counts = {}
        for entity in self.redacted_entities:
            type_name = entity.type.name
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        stats["unique_pii_types"] = type_counts
        
        # Add metrics if available
        if self.precision is not None:
            stats["precision"] = self.precision
        if self.recall is not None:
            stats["recall"] = self.recall
        if self.f1_score is not None:
            stats["f1_score"] = self.f1_score
        
        return stats
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the report to a dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of the report.
        """
        return {
            "original_document": {
                "source_path": str(self.original_document.source_path),
                "page_count": self.original_document.page_count,
                "char_count": self.original_document.char_count,
                "word_count": self.original_document.word_count,
                "file_size_bytes": self.original_document.file_size_bytes,
            },
            "detected_entities_count": len(self.detected_entities),
            "redacted_entities_count": len(self.redacted_entities),
            "replacement_map": [
                {
                    "original": e.text,
                    "start": e.start,
                    "end": e.end,
                    "type": e.type.name,
                    "replacement": replacement
                }
                for e, replacement in self.replacement_map
            ],
            "offset_map": self.offset_map,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "processing_time_seconds": self.processing_time_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
            "stats": self.get_stats(),
        }