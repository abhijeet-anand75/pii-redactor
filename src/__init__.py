"""
PII Redaction Tool - Source Package.

This package contains all core modules for detecting and redacting
personally identifiable information (PII) from documents.
"""

__version__ = "1.0.0"
__author__ = "Principal Software Architect"

# Package exports for cleaner imports
from src.models import PII, PIIEntity, DocumentContext, RedactionReport
from src.detector import Detector
from src.replacer import Replacer
from src.pdf_handler import PDFHandler
from src.fake_generator import FakeGenerator
from src.evaluator import Evaluator

__all__ = [
    "PII",
    "PIIEntity",
    "DocumentContext",
    "RedactionReport",
    "Detector",
    "Replacer",
    "PDFHandler",
    "FakeGenerator",
    "Evaluator",
]