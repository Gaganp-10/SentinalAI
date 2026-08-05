import json
import re
import subprocess
import os
import shutil
import logging
from typing import List
from backend.detectors.schema import Finding

# Pattern Bandit uses: each line in the `code` field is prefixed with
# "<line_number><one mandatory space><code_indentation><code>"
# e.g. "3     cursor = ..."  →  line number "3", separator " " (one space),
# then "    cursor = ..." which is the code with its real 4-space indent.
# We strip ONLY the digit group plus that single separator space so the
# code's own leading indentation is preserved for exact-match file patching.
_BANDIT_LINE_PREFIX = re.compile(r'^\d+ ')


logger = logging.getLogger(__name__)


def _strip_bandit_line_numbers(code: str) -> str:
    """
    Remove Bandit's line-number prefixes from each line of a ``code`` field.

    Bandit's JSON ``code`` value formats each source line as::

        "<line_number><one-or-more-spaces><actual_source_code>\\n"

    e.g.  ``"10   cursor.execute(query)\\n"``

    We strip only the leading ``<digits><whitespace>`` portion so the
    remaining text exactly matches what is stored in the real source file
    (preserving the code's own indentation).  Lines that don't start with
    the pattern (e.g. a trailing empty line) are left unchanged.
    """
    cleaned_lines = []
    for line in code.split("\n"):
        cleaned_lines.append(_BANDIT_LINE_PREFIX.sub("", line))
    return "\n".join(cleaned_lines)



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
                
                # Get snippet and strip Bandit's line-number prefixes.
                # Bandit formats each line as "{line_num}{whitespace}{actual_code}\n".
                # We must remove these prefixes so the snippet exactly matches
                # the real file content, enabling the apply-fix endpoint to
                # locate and replace the correct region.
                raw_code = issue.get("code", "")
                code = _strip_bandit_line_numbers(raw_code)
                
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
