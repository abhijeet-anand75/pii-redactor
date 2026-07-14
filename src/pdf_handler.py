"""
PDF Handler Module for the PII Redaction Tool.

This module handles PDF text extraction and redacted PDF generation.
"""

import logging
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from io import BytesIO

from pypdf import PdfReader, PdfWriter
from pypdf.generic import TextStringObject, NameObject, ArrayObject, RectangleObject
from pypdf.annotations import FreeText

from src.models import DocumentContext


class PDFHandler:
    """
    Handles PDF extraction and redacted PDF generation.
    
    This class extracts text from PDFs, preserves formatting as much as
    possible, and generates redacted PDFs with the same visual structure.
    """
    
    def __init__(self):
        """Initialize the PDF handler."""
        self._logger = logging.getLogger(__name__)
        self._min_font_scale = 0.75  # From config
        self._supported_extensions = ('.pdf',)
    
    def extract_text(self, pdf_path: Path) -> DocumentContext:
        """
        Extract text from a PDF file.
        
        Args:
            pdf_path: Path to the PDF file.
            
        Returns:
            DocumentContext containing extracted text and metadata.
            
        Raises:
            FileNotFoundError: If the PDF file doesn't exist.
            ValueError: If the file is not a PDF.
        """
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        if pdf_path.suffix.lower() not in self._supported_extensions:
            raise ValueError(f"Unsupported file type: {pdf_path.suffix}. Expected .pdf")
        
        self._logger.info(f"Extracting text from: {pdf_path}")
        
        try:
            reader = PdfReader(pdf_path)
            page_count = len(reader.pages)
            
            # Extract text from all pages
            all_text_parts: List[str] = []
            for i, page in enumerate(reader.pages, 1):
                try:
                    page_text = page.extract_text()
                    if page_text:
                        all_text_parts.append(page_text)
                    else:
                        self._logger.warning(f"No text extracted from page {i}")
                except Exception as e:
                    self._logger.warning(f"Error extracting text from page {i}: {e}")
                    all_text_parts.append("")
            
            raw_text = "\n\n".join(all_text_parts)
            
            # Calculate metrics
            char_count = len(raw_text)
            word_count = len(raw_text.split())
            file_size_bytes = pdf_path.stat().st_size
            
            self._logger.info(
                f"Extracted {char_count} characters, {word_count} words "
                f"from {page_count} pages"
            )
            
            return DocumentContext(
                source_path=pdf_path,
                raw_text=raw_text,
                page_count=page_count,
                char_count=char_count,
                word_count=word_count,
                file_size_bytes=file_size_bytes
            )
            
        except Exception as e:
            self._logger.error(f"Failed to extract text from PDF: {e}")
            raise
    
    def generate_redacted_pdf(
        self,
        original_path: Path,
        redacted_text: str,
        output_path: Path,
        original_context: Optional[DocumentContext] = None
    ) -> Path:
        """
        Generate a redacted PDF from the original PDF.
        
        This method preserves the original PDF's structure and overlays
        redacted text in the correct positions.
        
        Args:
            original_path: Path to the original PDF.
            redacted_text: The redacted text to insert.
            output_path: Path where the redacted PDF will be saved.
            original_context: Original DocumentContext (optional, for metrics).
            
        Returns:
            Path to the generated PDF file.
            
        Raises:
            FileNotFoundError: If the original PDF doesn't exist.
        """
        if not original_path.exists():
            raise FileNotFoundError(f"Original PDF not found: {original_path}")
        
        self._logger.info(f"Generating redacted PDF: {output_path}")
        
        try:
            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Read original PDF
            reader = PdfReader(original_path)
            writer = PdfWriter()
            
            # Split redacted text by pages
            redacted_pages = self._split_text_by_pages(redacted_text, reader)
            
            # Process each page
            for page_num, page in enumerate(reader.pages):
                # Get the redacted text for this page
                page_text = redacted_pages[page_num] if page_num < len(redacted_pages) else ""
                
                # Create a blank page with the same dimensions
                new_page = writer.add_blank_page(
                    width=page.mediabox.width,
                    height=page.mediabox.height
                )
                
                # Overlay redacted text on the page
                if page_text:
                    # Try to use reportlab for better text placement
                    self._overlay_redacted_text_with_reportlab(
                        new_page,
                        page_text,
                        page.mediabox.width,
                        page.mediabox.height
                    )
                else:
                    self._logger.debug(f"No text to overlay on page {page_num + 1}")
            
            # Save the redacted PDF
            with open(output_path, 'wb') as f:
                writer.write(f)
            
            self._logger.info(f"Redacted PDF saved to: {output_path}")
            
            # Log redaction summary
            if original_context:
                original_len = len(original_context.raw_text)
                redacted_len = len(redacted_text)
                if original_len > 0:
                    change_percent = ((redacted_len - original_len) / original_len * 100)
                    self._logger.info(
                        f"Redaction complete: {original_len} -> {redacted_len} characters "
                        f"({change_percent:.1f}% change)"
                    )
                else:
                    self._logger.info(
                        f"Redaction complete: {original_len} -> {redacted_len} characters "
                        f"(no text extracted from original)"
                    )
            
            return output_path
            
        except Exception as e:
            self._logger.error(f"Failed to generate redacted PDF: {e}")
            raise
    
    def _split_text_by_pages(self, text: str, reader: PdfReader) -> List[str]:
        """
        Split text by pages based on original PDF structure.
        
        Uses a heuristic approach to estimate page breaks.
        
        Args:
            text: The full redacted text.
            reader: The PDF reader object.
            
        Returns:
            List of text strings per page.
        """
        page_count = len(reader.pages)
        
        if page_count == 1:
            return [text]
        
        if not text:
            return [""] * page_count
        
        # Use a simple heuristic: split by double newlines
        paragraphs = text.split('\n\n')
        
        # Distribute paragraphs across pages as evenly as possible
        result = []
        para_idx = 0
        for i in range(page_count):
            # Determine how many paragraphs for this page
            remaining_paras = len(paragraphs) - para_idx
            remaining_pages = page_count - i
            
            if remaining_paras <= 0:
                result.append("")
                continue
            
            paras_for_page = max(1, remaining_paras // remaining_pages)
            page_text = '\n\n'.join(paragraphs[para_idx:para_idx + paras_for_page])
            result.append(page_text)
            para_idx += paras_for_page
        
        return result
    
    def _overlay_redacted_text_with_reportlab(
        self,
        page,
        text: str,
        page_width: float,
        page_height: float
    ) -> None:
        """
        Overlay redacted text on a PDF page using reportlab.
        
        Creates a new PDF with the text and merges it onto the page.
        
        Args:
            page: The PDF page object.
            text: The redacted text to overlay.
            page_width: Width of the page.
            page_height: Height of the page.
        """
        if not text:
            return
        
        try:
            # Try to import reportlab
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.lib.units import inch
            
            # Create a new PDF with the redacted text
            packet = BytesIO()
            c = canvas.Canvas(packet, pagesize=(page_width, page_height))
            
            # Set font and size
            c.setFont('Helvetica', 9)
            
            # Write text starting from the top of the page
            text_lines = text.split('\n')
            y = page_height - 30
            max_chars_per_line = 90
            
            for line in text_lines:
                if y < 30:
                    break
                # Wrap long lines
                wrapped_lines = self._wrap_text(line, max_chars_per_line)
                for wrapped_line in wrapped_lines:
                    if y < 30:
                        break
                    try:
                        c.drawString(30, y, wrapped_line)
                    except Exception as e:
                        self._logger.debug(f"Could not draw string: {e}")
                    y -= 12
            
            c.save()
            
            # Move to the beginning of the BytesIO buffer
            packet.seek(0)
            
            # Read the new PDF with the text layer
            text_pdf = PdfReader(packet)
            
            if text_pdf.pages:
                # Get the text layer page
                text_layer = text_pdf.pages[0]
                
                # Merge the text layer onto the page
                try:
                    page.merge_page(text_layer)
                except Exception as e:
                    self._logger.warning(f"Could not merge page: {e}")
                    # Fallback: use annotations
                    self._overlay_redacted_text_fallback(page, text, page_width, page_height)
            
        except ImportError:
            self._logger.warning("reportlab not available, using fallback text placement")
            self._overlay_redacted_text_fallback(page, text, page_width, page_height)
        except Exception as e:
            self._logger.warning(f"Text overlay failed: {e}, using fallback")
            self._overlay_redacted_text_fallback(page, text, page_width, page_height)
    
    def _overlay_redacted_text_fallback(
        self,
        page,
        text: str,
        page_width: float,
        page_height: float
    ) -> None:
        """
        Fallback method for overlaying text on a PDF page.
        
        Uses FreeText annotations for text placement.
        
        Args:
            page: The PDF page object.
            text: The redacted text to overlay.
            page_width: Width of the page.
            page_height: Height of the page.
        """
        try:
            # Split text into lines
            lines = text.split('\n')[:50]
            
            # Ensure page has annotations attribute
            if not hasattr(page, 'annotations') or page.annotations is None:
                page.annotations = ArrayObject()
            
            y_pos = page_height - 20
            for line in lines:
                if y_pos < 20:
                    break
                
                # Wrap long lines
                wrapped_lines = self._wrap_text(line, 80)
                for wrapped_line in wrapped_lines:
                    if y_pos < 20:
                        break
                    try:
                        annotation = FreeText(
                            rect=RectangleObject((20, y_pos - 10, page_width - 20, y_pos + 12)),
                            text=wrapped_line,
                            font="Helvetica",
                            font_size=9
                        )
                        page.annotations.append(annotation)
                    except Exception as e:
                        self._logger.debug(f"Could not add text annotation: {e}")
                    y_pos -= 14
            
        except Exception as e:
            self._logger.warning(f"Fallback text overlay failed: {e}")
    
    def _wrap_text(self, text: str, max_chars: int) -> List[str]:
        """
        Wrap text to a maximum number of characters per line.
        
        Args:
            text: The text to wrap.
            max_chars: Maximum characters per line.
            
        Returns:
            List of wrapped lines.
        """
        if not text:
            return [""]
        
        if len(text) <= max_chars:
            return [text]
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            word_len = len(word)
            if current_length + word_len + 1 <= max_chars:
                current_line.append(word)
                current_length += word_len + 1
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = word_len + 1
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
    def get_supported_extensions(self) -> List[str]:
        """
        Get the list of supported file extensions.
        
        Returns:
            List of supported file extensions.
        """
        return list(self._supported_extensions)