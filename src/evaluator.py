"""
Evaluator Module for the PII Redaction Tool.

This module calculates precision, recall, and F1-score by comparing
detected PII entities against ground truth annotations.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Set
from datetime import datetime

from src.models import PIIEntity, RedactionReport, DocumentContext, PII


class Evaluator:
    """
    Evaluates the performance of PII detection and redaction.
    
    This class compares detected PII entities against ground truth
    annotations to calculate precision, recall, and F1-score.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        self._logger = logging.getLogger(__name__)
        self._ground_truth_cache: Dict[Path, List[PIIEntity]] = {}
    
    def evaluate(
        self,
        detected_entities: List[PIIEntity],
        ground_truth_entities: List[PIIEntity],
        report: Optional[RedactionReport] = None
    ) -> Tuple[float, float, float, Dict[str, Any]]:
        """
        Evaluate detection performance against ground truth.
        
        Args:
            detected_entities: List of entities detected by the system.
            ground_truth_entities: List of ground truth entities.
            report: Optional RedactionReport to update with metrics.
            
        Returns:
            Tuple containing (precision, recall, f1_score, detailed_metrics).
        """
        if not ground_truth_entities:
            self._logger.warning("No ground truth entities provided")
            return 0.0, 0.0, 0.0, {"error": "No ground truth available"}
        
        if not detected_entities:
            self._logger.warning("No detected entities provided")
            return 0.0, 0.0, 0.0, {
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": len(ground_truth_entities),
                "ground_truth_count": len(ground_truth_entities)
            }
        
        # Calculate metrics
        tp, fp, fn = self._calculate_metrics(detected_entities, ground_truth_entities)
        
        # Calculate precision, recall, F1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Get detailed metrics
        detailed_metrics = self._get_detailed_metrics(
            detected_entities,
            ground_truth_entities,
            tp,
            fp,
            fn
        )
        
        self._logger.info(
            f"Evaluation complete: Precision={precision:.3f}, "
            f"Recall={recall:.3f}, F1={f1:.3f}"
        )
        self._logger.debug(
            f"TP={tp}, FP={fp}, FN={fn}, "
            f"Detected={len(detected_entities)}, Ground={len(ground_truth_entities)}"
        )
        
        # Update report if provided
        if report:
            report.precision = precision
            report.recall = recall
            report.f1_score = f1
        
        return precision, recall, f1, detailed_metrics
    
    def _calculate_metrics(
        self,
        detected: List[PIIEntity],
        ground_truth: List[PIIEntity]
    ) -> Tuple[int, int, int]:
        """
        Calculate True Positives, False Positives, and False Negatives.
        
        Args:
            detected: List of detected entities.
            ground_truth: List of ground truth entities.
            
        Returns:
            Tuple of (tp, fp, fn).
        """
        # Create sets for quick comparison
        # Use a normalized representation: (start, end, type)
        detected_set: Set[Tuple[int, int, PII]] = set()
        for entity in detected:
            detected_set.add((entity.start, entity.end, entity.type))
        
        ground_truth_set: Set[Tuple[int, int, PII]] = set()
        for entity in ground_truth:
            ground_truth_set.add((entity.start, entity.end, entity.type))
        
        # Calculate TP, FP, FN
        tp = len(detected_set & ground_truth_set)  # Intersection
        fp = len(detected_set - ground_truth_set)  # Detected but not in ground truth
        fn = len(ground_truth_set - detected_set)  # In ground truth but not detected
        
        # For entity-level matching (considering partial overlaps)
        # We also check for overlapping entities that might be partially correct
        # This is a more lenient matching for names with slight position differences
        
        # If we have a mismatch, check for partial overlaps
        if fp > 0 or fn > 0:
            # Check for partial overlaps (entities that overlap but don't exactly match)
            for detected_entity in detected:
                if detected_entity not in ground_truth:
                    # Check if this entity overlaps with any ground truth entity
                    for gt_entity in ground_truth:
                        if detected_entity.overlaps_with(gt_entity):
                            # Partial match - count as TP and adjust FP/FN
                            # This is a more lenient scoring approach
                            if detected_entity.type == gt_entity.type:
                                # Same type, partial overlap - count as correct
                                # But don't double count exact matches already counted
                                if (detected_entity.start, detected_entity.end, detected_entity.type) not in ground_truth_set:
                                    # This is a partial match, adjust counts
                                    # For simplicity, we'll keep the strict matching
                                    pass
                            break
        
        # Also check for type-level accuracy
        type_counts = self._calculate_type_metrics(detected, ground_truth)
        
        self._logger.debug(
            f"Metric calculation: TP={tp}, FP={fp}, FN={fn}, "
            f"Type metrics: {type_counts}"
        )
        
        return tp, fp, fn
    
    def _calculate_type_metrics(
        self,
        detected: List[PIIEntity],
        ground_truth: List[PIIEntity]
    ) -> Dict[str, Dict[str, int]]:
        """
        Calculate per-type metrics.
        
        Args:
            detected: List of detected entities.
            ground_truth: List of ground truth entities.
            
        Returns:
            Dictionary mapping type names to TP/FP/FN counts.
        """
        type_metrics: Dict[str, Dict[str, int]] = {}
        
        # Group by type
        detected_by_type: Dict[PII, List[PIIEntity]] = {}
        ground_by_type: Dict[PII, List[PIIEntity]] = {}
        
        for entity in detected:
            detected_by_type.setdefault(entity.type, []).append(entity)
        
        for entity in ground_truth:
            ground_by_type.setdefault(entity.type, []).append(entity)
        
        # Calculate metrics for each type
        all_types = set(detected_by_type.keys()) | set(ground_by_type.keys())
        
        for pii_type in all_types:
            detected_of_type = detected_by_type.get(pii_type, [])
            ground_of_type = ground_by_type.get(pii_type, [])
            
            tp, fp, fn = self._calculate_metrics(
                detected_of_type,
                ground_of_type
            )
            
            type_metrics[pii_type.name] = {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": tp / (tp + fp) if (tp + fp) > 0 else 0.0,
                "recall": tp / (tp + fn) if (tp + fn) > 0 else 0.0,
                "f1": 2 * (tp / (tp + fp) if (tp + fp) > 0 else 0.0) *
                      (tp / (tp + fn) if (tp + fn) > 0 else 0.0) /
                      ((tp / (tp + fp) if (tp + fp) > 0 else 0.0) +
                       (tp / (tp + fn) if (tp + fn) > 0 else 0.0))
                      if ((tp / (tp + fp) if (tp + fp) > 0 else 0.0) +
                          (tp / (tp + fn) if (tp + fn) > 0 else 0.0)) > 0 else 0.0
            }
        
        return type_metrics
    
    def _get_detailed_metrics(
        self,
        detected: List[PIIEntity],
        ground_truth: List[PIIEntity],
        tp: int,
        fp: int,
        fn: int
    ) -> Dict[str, Any]:
        """
        Get detailed metrics including per-entity information.
        
        Args:
            detected: List of detected entities.
            ground_truth: List of ground truth entities.
            tp: True positive count.
            fp: False positive count.
            fn: False negative count.
            
        Returns:
            Dictionary with detailed metrics.
        """
        # Create ground truth set for quick lookup
        gt_set = {(e.start, e.end, e.type): e for e in ground_truth}
        detected_set = {(e.start, e.end, e.type): e for e in detected}
        
        # Find false positives (detected but not in ground truth)
        false_positives: List[Dict[str, Any]] = []
        for (start, end, pii_type), entity in detected_set.items():
            if (start, end, pii_type) not in gt_set:
                false_positives.append({
                    "text": entity.text,
                    "start": start,
                    "end": end,
                    "type": pii_type.name,
                    "confidence": entity.confidence
                })
        
        # Find false negatives (in ground truth but not detected)
        false_negatives: List[Dict[str, Any]] = []
        for (start, end, pii_type), entity in gt_set.items():
            if (start, end, pii_type) not in detected_set:
                false_negatives.append({
                    "text": entity.text,
                    "start": start,
                    "end": end,
                    "type": pii_type.name
                })
        
        # Find true positives
        true_positives: List[Dict[str, Any]] = []
        for (start, end, pii_type), entity in detected_set.items():
            if (start, end, pii_type) in gt_set:
                true_positives.append({
                    "text": entity.text,
                    "start": start,
                    "end": end,
                    "type": pii_type.name,
                    "confidence": entity.confidence
                })
        
        return {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "tp_count": tp,
            "fp_count": fp,
            "fn_count": fn,
            "detected_count": len(detected),
            "ground_truth_count": len(ground_truth),
            "type_metrics": self._calculate_type_metrics(detected, ground_truth)
        }
    
    def load_ground_truth(
        self,
        ground_truth_path: Path
    ) -> List[PIIEntity]:
        """
        Load ground truth annotations from a JSON file.
        
        Args:
            ground_truth_path: Path to the ground truth JSON file.
            
        Returns:
            List of PIIEntity objects.
            
        Raises:
            FileNotFoundError: If the ground truth file doesn't exist.
            ValueError: If the JSON format is invalid.
        """
        if not ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file not found: {ground_truth_path}")
        
        # Check cache first
        if ground_truth_path in self._ground_truth_cache:
            self._logger.debug(f"Using cached ground truth from {ground_truth_path}")
            return self._ground_truth_cache[ground_truth_path]
        
        self._logger.info(f"Loading ground truth from {ground_truth_path}")
        
        try:
            with open(ground_truth_path, 'r') as f:
                data = json.load(f)
            
            entities: List[PIIEntity] = []
            
            # Expect list of objects with fields: text, start, end, type, confidence
            for item in data:
                # Convert type string to PII enum
                pii_type = self._parse_pii_type(item.get('type', 'EMAIL'))
                
                entity = PIIEntity(
                    text=item.get('text', ''),
                    start=item.get('start', 0),
                    end=item.get('end', 0),
                    type=pii_type,
                    confidence=item.get('confidence', 0.95)
                )
                entities.append(entity)
            
            # Cache for future use
            self._ground_truth_cache[ground_truth_path] = entities
            
            self._logger.info(f"Loaded {len(entities)} ground truth entities")
            return entities
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in ground truth file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading ground truth: {e}")
    
    def _parse_pii_type(self, type_str: str) -> PII:
        """
        Parse a string to a PII enum value.
        
        Args:
            type_str: String representation of PII type.
            
        Returns:
            PII enum value.
            
        Raises:
            ValueError: If the type is not recognized.
        """
        type_map = {
            'FULL_NAME': PII.FULL_NAME,
            'EMAIL': PII.EMAIL,
            'PHONE': PII.PHONE,
            'IP_ADDRESS': PII.IP_ADDRESS,
            'SSN': PII.SSN,
            'CREDIT_CARD': PII.CREDIT_CARD,
            'DATE_OF_BIRTH': PII.DATE_OF_BIRTH,
            'ADDRESS': PII.ADDRESS,
            'COMPANY_NAME': PII.COMPANY_NAME
        }
        
        if type_str not in type_map:
            raise ValueError(f"Unknown PII type: {type_str}")
        
        return type_map[type_str]
    
    def save_report(
        self,
        report: RedactionReport,
        output_path: Path
    ) -> Path:
        """
        Save the evaluation report to a JSON file.
        
        Args:
            report: The RedactionReport to save.
            output_path: Path where the report should be saved.
            
        Returns:
            Path to the saved report file.
        """
        self._logger.info(f"Saving evaluation report to {output_path}")
        
        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert report to dictionary
        report_data = {
            "report_generated": datetime.now().isoformat(),
            "original_document": {
                "source_path": str(report.original_document.source_path),
                "page_count": report.original_document.page_count,
                "char_count": report.original_document.char_count,
                "word_count": report.original_document.word_count,
                "file_size_bytes": report.original_document.file_size_bytes
            },
            "detection_summary": {
                "total_detected": len(report.detected_entities),
                "total_redacted": len(report.redacted_entities),
                "unique_types": {
                    type_name: count
                    for type_name, count in report.get_stats()["unique_pii_types"].items()
                }
            },
            "metrics": {
                "precision": report.precision,
                "recall": report.recall,
                "f1_score": report.f1_score
            },
            "performance": {
                "processing_time_seconds": report.processing_time_seconds
            },
            "errors": report.errors,
            "warnings": report.warnings,
            "detailed_replacement": [
                {
                    "original": entity.text,
                    "replacement": replacement,
                    "type": entity.type.name,
                    "start": entity.start,
                    "end": entity.end,
                    "confidence": entity.confidence
                }
                for entity, replacement in report.replacement_map
            ]
        }
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self._logger.info(f"Report saved successfully")
        return output_path
    
    def load_report(self, report_path: Path) -> Dict[str, Any]:
        """
        Load a previously saved evaluation report.
        
        Args:
            report_path: Path to the report JSON file.
            
        Returns:
            Dictionary containing the report data.
            
        Raises:
            FileNotFoundError: If the report file doesn't exist.
            ValueError: If the JSON format is invalid.
        """
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
            self._logger.info(f"Loaded report from {report_path}")
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in report file: {e}")