import logging
from typing import List
from backend.detectors.schema import Finding

logger = logging.getLogger(__name__)

class SemgrepDetector:
    def __init__(self):
        self.is_available = False

    def scan(self, project_dir: str) -> List[Finding]:
        # Disabled locally to prevent Windows background hangs and connection timeouts
        logger.info("Semgrep scan skipped (local bypass enabled).")
        return []
