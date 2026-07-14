"""
PII Redaction Tool - Main Entry Point.

This module orchestrates the entire PII redaction pipeline.
"""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

import config
from src.pdf_handler import PDFHandler
from src.detector import Detector
from src.replacer import Replacer
from src.evaluator import Evaluator
from src.fake_generator import FakeGenerator
from src.models import DocumentContext, RedactionReport, PIIEntity


def setup_logging(debug_mode: bool = False) -> None:
    """
    Configure logging for the application.
    
    Args:
        debug_mode: If True, set log level to DEBUG.
    """
    log_level = logging.DEBUG if debug_mode else config.LOG_LEVEL
    
    logging.basicConfig(
        level=log_level,
        format=config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific log levels for noisy libraries
    logging.getLogger("pypdf").setLevel(logging.WARNING)
    logging.getLogger("faker").setLevel(logging.WARNING)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="PII Redaction Tool - Detect and redact PII from PDF documents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py input/document.pdf
  python main.py input/document.pdf --output-dir ./redacted --threshold 0.9
  python main.py input/document.pdf --ground-truth ground_truth.json --debug
        """
    )
    
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input PDF file."
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(config.OUTPUT_DIR),
        help=f"Output directory for redacted files (default: {config.OUTPUT_DIR})"
    )
    
    parser.add_argument(
        "--threshold",
        type=float,
        default=config.DEFAULT_CONFIDENCE_THRESHOLD,
        help=f"Confidence threshold for PII detection (default: {config.DEFAULT_CONFIDENCE_THRESHOLD})"
    )
    
    parser.add_argument(
        "--ground-truth",
        type=str,
        help="Path to ground truth JSON file for evaluation"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="Disable evaluation report generation"
    )
    
    parser.add_argument(
        "--seed",
        type=int,
        default=config.FAKER_SEED,
        help=f"Seed for fake data generation (default: {config.FAKER_SEED})"
    )
    
    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the PII redaction tool.
    
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    start_time = time.time()
    errors: List[str] = []
    warnings: List[str] = []
    
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging
        setup_logging(args.debug)
        logger = logging.getLogger(__name__)
        
        logger.info("=" * 60)
        logger.info("PII Redaction Tool v1.0.0")
        logger.info("=" * 60)
        logger.info(f"Input file: {args.input_file}")
        logger.info(f"Output directory: {args.output_dir}")
        logger.info(f"Confidence threshold: {args.threshold}")
        logger.info(f"Faker seed: {args.seed}")
        logger.info(f"Debug mode: {args.debug}")
        logger.info(f"Evaluation: {'Disabled' if args.no_eval else 'Enabled'}")
        if args.ground_truth:
            logger.info(f"Ground truth: {args.ground_truth}")
        logger.info("-" * 60)
        
        # Validate input file
        input_path = Path(args.input_file)
        if not input_path.exists():
            logger.error(f"Input file not found: {args.input_file}")
            return 1
        
        if input_path.suffix.lower() not in config.SUPPORTED_INPUT_EXTENSIONS:
            logger.error(f"Unsupported file type: {input_path.suffix}. Expected .pdf")
            return 1
        
        # Create output directory
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory created: {output_path}")
        
        # Initialize components
        logger.info("Initializing components...")
        pdf_handler = PDFHandler()
        detector = Detector(threshold=args.threshold)
        fake_generator = FakeGenerator(seed=args.seed)
        replacer = Replacer(fake_generator)
        evaluator = Evaluator() if not args.no_eval else None
        
        logger.info("Components initialized successfully")
        logger.info("-" * 60)
        
        # Stage 1: Extract text from PDF
        logger.info("Stage 1: Extracting text from PDF...")
        try:
            document_context = pdf_handler.extract_text(input_path)
            logger.info(f"Extracted {document_context.page_count} pages, "
                       f"{document_context.char_count} characters, "
                       f"{document_context.word_count} words")
        except Exception as e:
            logger.error(f"Failed to extract text: {e}")
            errors.append(f"Extraction failed: {str(e)}")
            return 1
        
        # Stage 2: Detect PII
        logger.info("Stage 2: Detecting PII...")
        try:
            detected_entities = detector.detect(document_context.raw_text)
            logger.info(f"Detected {len(detected_entities)} PII entities")
        except Exception as e:
            logger.error(f"Failed to detect PII: {e}")
            errors.append(f"Detection failed: {str(e)}")
            return 1
        
        # If no entities found, return original text
        if not detected_entities:
            logger.warning("No PII detected in document")
            warnings.append("No PII detected in document")
            
            # Create report with no redactions
            report = RedactionReport(
                original_document=document_context,
                detected_entities=[],
                redacted_entities=[],
                replacement_map=[],
                offset_map={i: i for i in range(len(document_context.raw_text))},
                errors=errors,
                warnings=warnings,
                processing_time_seconds=time.time() - start_time
            )
            
            # Save report
            report_path = output_path / f"{input_path.stem}_report.json"
            evaluator.save_report(report, report_path) if evaluator else None
            
            # Generate unredacted PDF
            redacted_pdf_path = output_path / f"{input_path.stem}_redacted.pdf"
            pdf_handler.generate_redacted_pdf(
                input_path,
                document_context.raw_text,
                redacted_pdf_path,
                document_context
            )
            
            logger.info(f"Unredacted PDF saved to: {redacted_pdf_path}")
            logger.info(f"Report saved to: {report_path}")
            logger.info("=" * 60)
            return 0
        
        # Log detected entities by type
        type_counts: Dict[str, int] = {}
        for entity in detected_entities:
            type_counts[entity.type.name] = type_counts.get(entity.type.name, 0) + 1
        logger.info(f"PII types detected: {type_counts}")
        
        # Stage 3: Replace PII with fake values
        logger.info("Stage 3: Replacing PII with fake values...")
        try:
            redacted_text, offset_map, replacement_map = replacer.replace(
                document_context.raw_text,
                detected_entities
            )
            logger.info(f"Replaced {len(replacement_map)} PII entities")
        except Exception as e:
            logger.error(f"Failed to replace PII: {e}")
            errors.append(f"Replacement failed: {str(e)}")
            return 1
        
        # Stage 4: Generate redacted PDF
        logger.info("Stage 4: Generating redacted PDF...")
        try:
            redacted_pdf_path = output_path / f"{input_path.stem}_redacted.pdf"
            pdf_handler.generate_redacted_pdf(
                input_path,
                redacted_text,
                redacted_pdf_path,
                document_context
            )
            logger.info(f"Redacted PDF saved to: {redacted_pdf_path}")
        except Exception as e:
            logger.error(f"Failed to generate redacted PDF: {e}")
            errors.append(f"PDF generation failed: {str(e)}")
            return 1
        
        # Stage 5: Evaluate (if enabled)
        precision = None
        recall = None
        f1_score = None
        ground_truth_entities: Optional[List[PIIEntity]] = None
        
        if evaluator and not args.no_eval:
            logger.info("Stage 5: Evaluating detection performance...")
            
            # Load ground truth if provided
            if args.ground_truth:
                try:
                    ground_truth_path = Path(args.ground_truth)
                    ground_truth_entities = evaluator.load_ground_truth(ground_truth_path)
                    logger.info(f"Loaded {len(ground_truth_entities)} ground truth entities")
                    
                    # Evaluate
                    precision, recall, f1_score, metrics = evaluator.evaluate(
                        detected_entities,
                        ground_truth_entities
                    )
                    
                    logger.info(f"Evaluation results: Precision={precision:.3f}, "
                               f"Recall={recall:.3f}, F1={f1_score:.3f}")
                    
                    # Log detailed metrics
                    if metrics:
                        logger.debug(f"TP: {metrics.get('tp_count', 0)}, "
                                    f"FP: {metrics.get('fp_count', 0)}, "
                                    f"FN: {metrics.get('fn_count', 0)}")
                        
                        # Log type metrics if available
                        type_metrics = metrics.get('type_metrics', {})
                        for type_name, type_data in type_metrics.items():
                            logger.debug(f"  {type_name}: "
                                        f"P={type_data.get('precision', 0):.3f}, "
                                        f"R={type_data.get('recall', 0):.3f}, "
                                        f"F1={type_data.get('f1', 0):.3f}")
                except Exception as e:
                    logger.error(f"Failed to evaluate: {e}")
                    warnings.append(f"Evaluation failed: {str(e)}")
            else:
                logger.info("No ground truth provided, skipping evaluation")
                warnings.append("No ground truth provided for evaluation")
        
        # Stage 6: Generate report
        logger.info("Stage 6: Generating report...")
        try:
            # Create report
            report = RedactionReport(
                original_document=document_context,
                detected_entities=detected_entities,
                redacted_entities=[e for e, _ in replacement_map],
                replacement_map=replacement_map,
                offset_map=offset_map,
                precision=precision,
                recall=recall,
                f1_score=f1_score,
                processing_time_seconds=time.time() - start_time,
                errors=errors,
                warnings=warnings
            )
            
            # Save report
            report_path = output_path / f"{input_path.stem}_report.json"
            if evaluator:
                evaluator.save_report(report, report_path)
            else:
                # Manual save if evaluator not available
                import json
                with open(report_path, 'w') as f:
                    json.dump(report.to_dict(), f, indent=2)
            
            logger.info(f"Report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            warnings.append(f"Report generation failed: {str(e)}")
        
        # Final summary
        elapsed_time = time.time() - start_time
        logger.info("-" * 60)
        logger.info("REDACTION COMPLETE")
        logger.info("-" * 60)
        logger.info(f"Processing time: {elapsed_time:.2f} seconds")
        logger.info(f"Pages processed: {document_context.page_count}")
        logger.info(f"PII detected: {len(detected_entities)}")
        logger.info(f"PII redacted: {len(replacement_map)}")
        
        if precision is not None:
            logger.info(f"Precision: {precision:.3f}")
            logger.info(f"Recall: {recall:.3f}")
            logger.info(f"F1 Score: {f1_score:.3f}")
        
        if errors:
            logger.warning(f"Errors encountered: {len(errors)}")
        if warnings:
            logger.warning(f"Warnings encountered: {len(warnings)}")
        
        logger.info("-" * 60)
        logger.info(f"Redacted PDF: {redacted_pdf_path}")
        logger.info(f"Report: {report_path}")
        logger.info("=" * 60)
        
        # Return success if no errors, but warnings are acceptable
        return 0 if not errors else 1
        
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Process interrupted by user")
        return 130
    except Exception as e:
        logging.getLogger(__name__).error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())