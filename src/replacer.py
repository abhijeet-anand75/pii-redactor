"""
Replacement Engine Module for the PII Redaction Tool.

This module handles text replacement with offset mapping for
PII entities.
"""

import logging
from typing import List, Tuple, Dict, Optional
from bisect import bisect_left, insort

from src.models import PIIEntity, PII
from src.fake_generator import FakeGenerator


class Replacer:
    """
    Replaces PII entities with fake values and maintains offset mapping.
    
    This class processes entities in reverse order to maintain valid
    character indices, generates deterministic replacements, and
    builds an offset map for tracking changes.
    """
    
    def __init__(self, fake_generator: Optional[FakeGenerator] = None):
        """
        Initialize the replacer with a fake generator.
        
        Args:
            fake_generator: FakeGenerator instance for generating replacements.
                           If None, creates a new instance.
        """
        self._logger = logging.getLogger(__name__)
        self._fake_generator = fake_generator or FakeGenerator()
        self._replacement_cache: Dict[str, str] = {}
    
    def replace(
        self,
        text: str,
        entities: List[PIIEntity]
    ) -> Tuple[str, Dict[int, int], List[Tuple[PIIEntity, str]]]:
        """
        Replace PII entities with fake values and build offset mapping.
        
        The replacement process:
        1. Sort entities by start position (descending for reverse processing)
        2. Process entities in reverse order to maintain valid indices
        3. Generate deterministic fake values for each entity
        4. Build offset map for tracking original to redacted positions
        
        Args:
            text: The original text containing PII.
            entities: List of PIIEntity objects to replace.
            
        Returns:
            Tuple containing:
            - Redacted text with all replacements applied
            - Offset map (original_byte_offset -> redacted_byte_offset)
            - Replacement map (PIIEntity -> fake_value)
            
        Raises:
            ValueError: If entities overlap (should be resolved by detector).
        """
        if not text:
            self._logger.warning("Empty text provided to replacer")
            return "", {}, []
        
        if not entities:
            self._logger.info("No entities to replace")
            return text, {i: i for i in range(len(text))}, []
        
        # Validate entities don't overlap
        self._validate_entities(entities)
        
        # Sort entities by start position (descending for reverse processing)
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        
        self._logger.info(f"Replacing {len(sorted_entities)} entities in text of length {len(text)}")
        
        # Initialize variables
        redacted_text = text
        offset_map: Dict[int, int] = {}
        replacement_map: List[Tuple[PIIEntity, str]] = []
        original_positions: List[Tuple[int, int]] = []  # (original_start, original_end)
        
        # Process entities in reverse order
        for entity in sorted_entities:
            # Generate fake value
            fake_value = self._generate_fake(entity)
            
            # Get current positions (may have shifted due to previous replacements)
            current_start = self._get_current_position(redacted_text, entity)
            if current_start is None:
                self._logger.warning(
                    f"Could not find entity '{entity.text}' at position {entity.start} "
                    f"in redacted text"
                )
                continue
            
            # Perform replacement
            redacted_text = (
                redacted_text[:current_start] +
                fake_value +
                redacted_text[current_start + entity.length:]
            )
            
            # Record replacement
            replacement_map.append((entity, fake_value))
            original_positions.append((entity.start, entity.end))
            
            self._logger.debug(
                f"Replaced '{entity.text}' with '{fake_value}' at position {entity.start}"
            )
        
        # Build offset map
        offset_map = self._build_offset_map(
            text,
            redacted_text,
            entities,
            replacement_map,
            original_positions
        )
        
        # Validate replacement
        self._validate_replacement(text, redacted_text, entities, replacement_map)
        
        self._logger.info(f"Replacement complete. Final text length: {len(redacted_text)}")
        
        return redacted_text, offset_map, replacement_map
    
    def _validate_entities(self, entities: List[PIIEntity]) -> None:
        """
        Validate that entities don't overlap.
        
        Args:
            entities: List of entities to validate.
            
        Raises:
            ValueError: If overlapping entities are found.
        """
        sorted_entities = sorted(entities, key=lambda e: e.start)
        
        for i in range(len(sorted_entities) - 1):
            current = sorted_entities[i]
            next_entity = sorted_entities[i + 1]
            
            if current.overlaps_with(next_entity):
                raise ValueError(
                    f"Overlapping entities found: '{current.text}' "
                    f"({current.start}-{current.end}) and '{next_entity.text}' "
                    f"({next_entity.start}-{next_entity.end})"
                )
    
    def _generate_fake(self, entity: PIIEntity) -> str:
        """
        Generate a fake replacement for an entity.
        
        Uses cache to ensure the same original text always gets the same fake.
        
        Args:
            entity: The PIIEntity to generate a fake for.
            
        Returns:
            A fake replacement string.
        """
        cache_key = f"{entity.type.value}:{entity.text.lower()}"
        
        if cache_key not in self._replacement_cache:
            fake_value = self._fake_generator.generate(entity.type, entity.text)
            self._replacement_cache[cache_key] = fake_value
            self._logger.debug(
                f"Generated new fake for '{entity.text}': '{fake_value}'"
            )
        
        return self._replacement_cache[cache_key]
    
    def _get_current_position(
        self,
        current_text: str,
        entity: PIIEntity
    ) -> Optional[int]:
        """
        Find the current position of an entity in the redacted text.
        
        Since the text may have been modified by previous replacements,
        we need to find the entity by its position and text.
        
        Args:
            current_text: The current redacted text.
            entity: The entity to find.
            
        Returns:
            The current start position, or None if not found.
        """
        # Try to find at the original position (may have shifted)
        # Since we process in reverse order, positions before the entity
        # haven't changed, so we can use the original start position
        # if the text still matches
        if entity.start < len(current_text):
            # Check if the text at the original position matches
            end_pos = min(entity.start + entity.length, len(current_text))
            if current_text[entity.start:end_pos] == entity.text:
                return entity.start
        
        # Fallback: search for the entity text
        # This should rarely happen, but handles edge cases
        pos = current_text.find(entity.text)
        if pos != -1:
            self._logger.warning(
                f"Entity '{entity.text}' found at position {pos} "
                f"instead of expected {entity.start}"
            )
            return pos
        
        self._logger.error(f"Could not find entity '{entity.text}' in text")
        return None
    
    def _build_offset_map(
        self,
        original_text: str,
        redacted_text: str,
        entities: List[PIIEntity],
        replacement_map: List[Tuple[PIIEntity, str]],
        original_positions: List[Tuple[int, int]]
    ) -> Dict[int, int]:
        """
        Build a mapping from original byte offsets to redacted byte offsets.
        
        The offset map allows tracking where text has been moved or replaced.
        
        Args:
            original_text: The original text.
            redacted_text: The redacted text.
            entities: List of PII entities.
            replacement_map: Mapping of entities to fake values.
            original_positions: Original positions of entities.
            
        Returns:
            Dictionary mapping original_byte_offset -> redacted_byte_offset.
        """
        offset_map: Dict[int, int] = {}
        
        # Build mapping for all positions
        # We need to handle the fact that replacements change text length
        
        # Use two-pointer approach to build offset map
        orig_pos = 0
        redact_pos = 0
        
        # Create lookup for entity replacements
        replacement_lookup: Dict[Tuple[int, int], str] = {}
        for (entity, fake_value), (orig_start, orig_end) in zip(
            replacement_map,
            original_positions
        ):
            replacement_lookup[(orig_start, orig_end)] = fake_value
        
        while orig_pos < len(original_text):
            # Check if we're at a replacement position
            found_replacement = False
            for (orig_start, orig_end), fake_value in replacement_lookup.items():
                if orig_pos == orig_start:
                    # This position is replaced
                    # Map all original positions in this range to redacted positions
                    orig_length = orig_end - orig_start
                    redact_length = len(fake_value)
                    
                    for i in range(orig_length):
                        offset_map[orig_start + i] = redact_pos + min(i, redact_length - 1)
                    
                    # Move pointers past the replacement
                    orig_pos = orig_end
                    redact_pos += redact_length
                    found_replacement = True
                    break
            
            if not found_replacement:
                # Regular character (no replacement)
                offset_map[orig_pos] = redact_pos
                orig_pos += 1
                redact_pos += 1
        
        # Verify mapping covers all original positions
        if len(offset_map) != len(original_text):
            self._logger.warning(
                f"Offset map size ({len(offset_map)}) doesn't match original text "
                f"size ({len(original_text)})"
            )
        
        return offset_map
    
    def _validate_replacement(
        self,
        original_text: str,
        redacted_text: str,
        entities: List[PIIEntity],
        replacement_map: List[Tuple[PIIEntity, str]]
    ) -> None:
        """
        Validate that replacements were applied correctly.
        
        Args:
            original_text: The original text.
            redacted_text: The redacted text.
            entities: List of PII entities.
            replacement_map: Mapping of entities to fake values.
        """
        # Check that none of the original PII text remains
        for entity, _ in replacement_map:
            if entity.text in redacted_text:
                # The entity might be part of a longer string, so check carefully
                self._logger.warning(
                    f"Original PII '{entity.text}' may still be present in redacted text"
                )
        
        # Check that replacements were inserted
        for _, fake_value in replacement_map:
            if fake_value not in redacted_text:
                self._logger.warning(
                    f"Fake value '{fake_value}' not found in redacted text"
                )
        
        # Check that text length changed as expected
        original_len = len(original_text)
        redacted_len = len(redacted_text)
        expected_len = original_len + sum(
            len(fake) - len(entity.text)
            for entity, fake in replacement_map
        )
        
        if redacted_len != expected_len:
            self._logger.warning(
                f"Unexpected redacted text length: expected {expected_len}, "
                f"got {redacted_len} (difference: {redacted_len - expected_len})"
            )
    
    def get_replacement_stats(self) -> Dict[str, int]:
        """
        Get statistics about the replacement process.
        
        Returns:
            Dictionary containing replacement statistics.
        """
        return {
            "cache_size": len(self._replacement_cache),
            "unique_types": len(set(
                key.split(':')[0] for key in self._replacement_cache.keys()
            ))
        }
    
    def clear_cache(self) -> None:
        """
        Clear the replacement cache.
        
        This is useful for testing or when processing a new document.
        """
        self._replacement_cache.clear()
        self._logger.debug("Replacement cache cleared")