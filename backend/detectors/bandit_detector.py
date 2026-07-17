import json
import subprocess
import os
import shutil
import logging
from typing import List
from backend.detectors.schema import Finding

logger = logging.getLogger(__name__)

class BanditDetector:
    def __init__(self):
        # Check if bandit is available on the system PATH
        self.is_available = shutil.which("bandit") is not None

    def scan(self, project_dir: str) -> List[Finding]:
        if not self.is_available:
            logger.warning("Bandit CLI is not installed or not in PATH. Skipping Bandit scan.")
            return []

        try:
            # Run bandit: bandit -r <project_dir> -f json -q
            result = subprocess.run(
                ["bandit", "-r", project_dir, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                check=False
            )
            
            output_str = result.stdout.strip()
            if not output_str:
                logger.warning("Bandit scan returned empty stdout.")
                return []
                
            data = json.loads(output_str)
            findings = []
            
            for issue in data.get("results", []):
                filename = issue.get("filename", "")
                # Convert absolute path to relative path inside the project directory
                rel_path = os.path.relpath(filename, project_dir).replace("\\", "/")
                
                # Get snippet
                code = issue.get("code", "")
                
                # Map bandit severity to standard levels
                bandit_sev = issue.get("issue_severity", "LOW").upper()
                severity = "low"
                if bandit_sev == "HIGH":
                    severity = "high"
                elif bandit_sev == "MEDIUM":
                    severity = "medium"
                
                # Map confidence to float
                conf_str = issue.get("issue_confidence", "HIGH").upper()
                confidence = 1.0
                if conf_str == "MEDIUM":
                    confidence = 0.7
                elif conf_str == "LOW":
                    confidence = 0.4
                
                # Map CWE ID if present
                cwe_ref = issue.get("cwe", {})
                cwe_id = None
                if cwe_ref and cwe_ref.get("id"):
                    cwe_id = f"CWE-{cwe_ref.get('id')}"

                finding = Finding(
                    file_path=rel_path,
                    line_number=issue.get("line_number", 1),
                    type=issue.get("test_name", "Bandit Finding"),
                    severity=severity,
                    description=issue.get("issue_text", ""),
                    recommendation="Verify linter recommendation. Refactor vulnerable code pattern.",
                    code_snippet=code,
                    cwe_id=cwe_id,
                    confidence=confidence,
                    source_tool="bandit"
                )
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            logger.error(f"Error executing Bandit: {e}")
            return []
