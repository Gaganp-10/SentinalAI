import json
import subprocess
import os
import shutil
import logging
import re
from typing import List
from backend.detectors.schema import Finding

logger = logging.getLogger(__name__)

class SemgrepDetector:
    def __init__(self):
        # Check if semgrep CLI is available on the system PATH
        self.is_available = shutil.which("semgrep") is not None

    def scan(self, project_dir: str) -> List[Finding]:
        if not self.is_available:
            logger.warning("Semgrep CLI is not installed or not in PATH. Skipping Semgrep scan.")
            return []

        try:
            # Run semgrep: semgrep scan --config p/security-audit --config p/owasp-top-ten --json --quiet <project_dir>
            result = subprocess.run(
                ["semgrep", "scan", "--config", "p/security-audit", "--config", "p/owasp-top-ten", "--json", "--quiet", project_dir],
                capture_output=True,
                text=True,
                check=False
            )
            
            output_str = result.stdout.strip()
            if not output_str:
                logger.warning("Semgrep scan returned empty stdout.")
                return []
                
            data = json.loads(output_str)
            findings = []
            
            for issue in data.get("results", []):
                filename = issue.get("path", "")
                # Convert absolute path to relative path
                if os.path.isabs(filename):
                    rel_path = os.path.relpath(filename, project_dir).replace("\\", "/")
                else:
                    rel_path = os.path.normpath(filename).replace("\\", "/")
                
                # Get line number
                start_info = issue.get("start", {})
                line_number = start_info.get("line", 1)
                
                extra = issue.get("extra", {})
                code = extra.get("lines", "")
                
                # Map Semgrep severity: ERROR, WARNING, INFO
                sem_sev = extra.get("severity", "WARNING").upper()
                severity = "medium"
                if sem_sev == "ERROR":
                    severity = "high"
                elif sem_sev == "INFO":
                    severity = "low"
                
                # Extract metadata: cwe, owasp
                metadata = extra.get("metadata", {})
                
                # CWE mapping
                cwe_raw = metadata.get("cwe", [])
                cwe_id = None
                if cwe_raw:
                    cwe_str = cwe_raw[0] if isinstance(cwe_raw, list) else cwe_raw
                    match = re.search(r"CWE-\d+", cwe_str, re.IGNORECASE)
                    if match:
                        cwe_id = match.group(0).upper()
                    else:
                        cwe_id = cwe_str
                
                # OWASP mapping
                owasp_raw = metadata.get("owasp", [])
                owasp_category = None
                if owasp_raw:
                    owasp_category = owasp_raw[0] if isinstance(owasp_raw, list) else owasp_raw
                
                confidence = 1.0
                
                # Clean up rule ID to be user-friendly as type
                rule_id = issue.get("check_id", "Semgrep Finding")
                vuln_type = rule_id.split(".")[-1].replace("-", " ").title()

                finding = Finding(
                    file_path=rel_path,
                    line_number=line_number,
                    type=vuln_type,
                    severity=severity,
                    description=extra.get("message", ""),
                    recommendation="Review Semgrep ruleset recommendations and fix the warning pattern.",
                    code_snippet=code,
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    confidence=confidence,
                    source_tool="semgrep"
                )
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            logger.error(f"Error executing Semgrep scan: {e}")
            return []
