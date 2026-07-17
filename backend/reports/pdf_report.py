import logging
from typing import Optional

logger = logging.getLogger(__name__)

WEASYPRINT_AVAILABLE = False
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception as e:
    logger.warning(f"WeasyPrint is not functional on this host (missing system libraries like Pango/Cairo): {e}")

def generate_pdf_report(html_content: str) -> Optional[bytes]:
    """
    Converts HTML report content into PDF bytes using WeasyPrint.
    Returns None if WeasyPrint is not available or if conversion fails.
    """
    if not WEASYPRINT_AVAILABLE:
        logger.error("Cannot generate PDF: WeasyPrint is not loaded.")
        return None
    
    try:
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
    except Exception as e:
        logger.error(f"WeasyPrint PDF conversion failed: {e}")
        return None
