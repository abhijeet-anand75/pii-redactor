"""
Detection Engine Module for the PII Redaction Tool.

This module orchestrates all PII recognizers to provide unified detection.
"""

import logging
from typing import List, Optional, Dict, Any, Set, Tuple
from collections import defaultdict

from src.models import PII, PIIEntity
from src.recognizers import (
    BaseRecognizer,
    EmailRecognizer,
    PhoneRecognizer,
    NameRecognizer,
    CorporateIDsRecognizer,
    AddressRecognizer,
    DateRecognizer,
    IPRecognizer,
)


class Detector:
    """
    Orchestrates all PII recognizers and provides unified detection.
    
    This class initializes all recognizers, runs them on input text,
    resolves conflicts, filters by confidence, and returns a deduplicated
    list of PII entities.
    """
    
    def __init__(self, threshold: Optional[float] = None):
        """
        Initialize the detector with all recognizers.
        
        Args:
            threshold: Confidence threshold for detection (default: 0.85).
        """
        self._threshold = threshold or 0.85
        self._logger = logging.getLogger(__name__)
        
        # Initialize all recognizers
        self._recognizers: List[BaseRecognizer] = [
            EmailRecognizer(self._threshold),
            PhoneRecognizer(self._threshold),
            NameRecognizer(self._threshold),
            CorporateIDsRecognizer(self._threshold),
            AddressRecognizer(self._threshold),
            DateRecognizer(self._threshold),
            IPRecognizer(self._threshold),
        ]
        
        self._logger.info(f"Initialized Detector with {len(self._recognizers)} recognizers")
    
    def detect(self, text: str) -> List[PIIEntity]:
        """
        Detect all PII entities in the given text.
        
        The detection process:
        1. Run all recognizers on the text
        2. Collect all detected entities
        3. Resolve overlapping entities
        4. Filter by confidence threshold
        5. Deduplicate identical entities
        
        Args:
            text: The text to scan for PII.
            
        Returns:
            A sorted list of PIIEntity objects (by start position).
            Returns empty list if no PII is found.
        """
        if not text or not text.strip():
            self._logger.debug("Empty text provided to detector")
            return []
        
        self._logger.debug(f"Detecting PII in text of length {len(text)}")
        
        # Step 1: Run all recognizers
        all_entities: List[PIIEntity] = []
        recognizer_stats: Dict[str, int] = {}
        
        for recognizer in self._recognizers:
            try:
                entities = recognizer.recognize(text)
                all_entities.extend(entities)
                recognizer_stats[recognizer.__class__.__name__] = len(entities)
                
                if entities:
                    self._logger.debug(
                        f"{recognizer.__class__.__name__} found {len(entities)} entities"
                    )
            except Exception as e:
                self._logger.error(
                    f"Error in {recognizer.__class__.__name__}: {e}",
                    exc_info=True
                )
                continue
        
        if not all_entities:
            self._logger.info("No PII entities detected")
            return []
        
        self._logger.debug(
            f"Total entities detected before filtering: {len(all_entities)}"
        )
        
        # Step 2: Resolve overlapping entities
        resolved_entities = self._resolve_overlaps(all_entities)
        self._logger.debug(
            f"Entities after overlap resolution: {len(resolved_entities)}"
        )
        
        # Step 3: Filter by confidence threshold
        filtered_entities = [
            e for e in resolved_entities
            if e.confidence >= self._threshold
        ]
        self._logger.debug(
            f"Entities after confidence filtering: {len(filtered_entities)}"
        )
        
        # Step 4: Deduplicate identical entities
        deduplicated_entities = self._deduplicate_entities(filtered_entities)
        self._logger.debug(
            f"Entities after deduplication: {len(deduplicated_entities)}"
        )
        
        # Step 5: Sort by start position
        sorted_entities = sorted(deduplicated_entities)
        
        # Log summary
        if sorted_entities:
            type_counts = self._count_types(sorted_entities)
            self._logger.info(
                f"Detection complete: {len(sorted_entities)} entities found. "
                f"Types: {type_counts}"
            )
        
        return sorted_entities
    
    def _resolve_overlaps(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Resolve overlapping entities by keeping the one with higher confidence.
        
        When entities overlap, the one with higher confidence is kept.
        If confidence is equal, the longer entity is kept.
        
        Args:
            entities: List of entities that may overlap.
            
        Returns:
            List of entities with overlaps resolved.
        """
        if not entities:
            return []
        
        # Sort by start position
        sorted_entities = sorted(entities)
        resolved: List[PIIEntity] = []
        
        for entity in sorted_entities:
            # Check if this entity overlaps with any already resolved entity
            overlap_found = False
            
            for idx, resolved_entity in enumerate(resolved):
                if entity.overlaps_with(resolved_entity):
                    overlap_found = True
                    
                    # Keep the one with higher confidence
                    if entity.confidence > resolved_entity.confidence:
                        # Replace the resolved entity with the new one
                        resolved[idx] = entity
                        self._logger.debug(
                            f"Replaced overlapping entity: {resolved_entity.text} "
                            f"(conf: {resolved_entity.confidence:.2f}) with "
                            f"{entity.text} (conf: {entity.confidence:.2f})"
                        )
                    elif entity.confidence == resolved_entity.confidence:
                        # If same confidence, keep the longer one
                        if entity.length > resolved_entity.length:
                            resolved[idx] = entity
                            self._logger.debug(
                                f"Replaced overlapping entity (equal confidence): "
                                f"{resolved_entity.text} (len: {resolved_entity.length}) "
                                f"with {entity.text} (len: {entity.length})"
                            )
                    break
            
            if not overlap_found:
                resolved.append(entity)
        
        return resolved
    
    def _deduplicate_entities(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Remove duplicate entities (exact same text, position, and type).
        
        Args:
            entities: List of entities that may contain duplicates.
            
        Returns:
            List of entities with duplicates removed.
        """
        if not entities:
            return []
        
        seen: Set[Tuple[str, int, int, PII]] = set()
        unique: List[PIIEntity] = []
        
        for entity in entities:
            key = (entity.text, entity.start, entity.end, entity.type)
            if key not in seen:
                seen.add(key)
                unique.append(entity)
            else:
                self._logger.debug(f"Removed duplicate entity: {entity.text}")
        
        return unique
    
    def _count_types(self, entities: List[PIIEntity]) -> Dict[str, int]:
        """
        Count entities by PII type.
        
        Args:
            entities: List of entities to count.
            
        Returns:
            Dictionary mapping type names to counts.
        """
        counts: Dict[str, int] = defaultdict(int)
        for entity in entities:
            counts[entity.type.name] += 1
        return dict(counts)
    
    def get_recognizer_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered recognizers.
        
        Returns:
            List of dictionaries with recognizer information.
        """
        return [
            {
                'name': r.__class__.__name__,
                'type': r.pii_type.name,
                'threshold': r._confidence_threshold,
            }
            for r in self._recognizers
        ]
    
    @property
    def threshold(self) -> float:
        """Get the current confidence threshold."""
        return self._threshold
    
    @threshold.setter
    def threshold(self, value: float) -> None:
        """
        Set a new confidence threshold and update all recognizers.
        
        Args:
            value: New confidence threshold value.
        """
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"Threshold must be between 0.0 and 1.0, got {value}")
        
        self._threshold = value
        for recognizer in self._recognizers:
            recognizer._confidence_threshold = value
        self._logger.info(f"Updated confidence threshold to {value}")