"""
Configuration module for the PII Redaction Tool.

This module centralizes all configuration constants and settings
used throughout the application.
"""

from pathlib import Path
import logging


# ============================================================================
# Path Configuration
# ============================================================================
OUTPUT_DIR: Path = Path("output")

# ============================================================================
# Detection Configuration
# ============================================================================
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.85

# ============================================================================
# PDF Processing Configuration
# ============================================================================
MIN_FONT_SCALE_FOR_REDACTION: float = 0.75

# ============================================================================
# Fake Data Configuration
# ============================================================================
FAKER_SEED: int = 42

# ============================================================================
# Evaluation Configuration
# ============================================================================
PERFORM_EVALUATION: bool = True

# ============================================================================
# Logging Configuration
# ============================================================================
LOG_LEVEL: int = logging.INFO
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# ============================================================================
# File Extension Configuration
# ============================================================================
SUPPORTED_INPUT_EXTENSIONS: tuple = (".pdf",)
REDACTED_FILE_SUFFIX: str = "_redacted"
EVALUATION_REPORT_FILE_NAME: str = "evaluation_report.json"

# ============================================================================
# Debug Configuration
# ============================================================================
DEBUG_MODE: bool = False
LOG_PII_CONTENT: bool = False  # MUST remain False for security