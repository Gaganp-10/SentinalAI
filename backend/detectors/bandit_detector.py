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


BANDIT_FALLBACK_CWE_MAP = {
    # Test IDs
    "B101": "CWE-703",
    "B102": "CWE-95",
    "B103": "CWE-732",
    "B104": "CWE-605",
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-377",
    "B110": "CWE-703",
    "B112": "CWE-703",
    "B201": "CWE-215",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-95",
    "B308": "CWE-79",
    "B320": "CWE-611",
    "B324": "CWE-327",
    "B403": "CWE-502",
    "B404": "CWE-78",
    "B413": "CWE-327",
    "B501": "CWE-295",
    "B506": "CWE-502",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-78",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B701": "CWE-79",
    "B702": "CWE-79",
    "B703": "CWE-79",
    # Test names as fallback
    "hardcoded_password_string": "CWE-259",
    "hardcoded_sql_expressions": "CWE-89",
    "subprocess_popen_with_shell_equals_true": "CWE-78",
    "blacklist": "CWE-502",
    "hashlib": "CWE-327",
    "eval": "CWE-95",
}


def _extract_bandit_cwe(issue: dict) -> str | None:
    # 1. Primary: Bandit JSON issue_cwe object
    issue_cwe = issue.get("issue_cwe")
    if isinstance(issue_cwe, dict) and issue_cwe.get("id"):
        return f"CWE-{issue_cwe.get('id')}"

    # 2. Fallback: check test_id or test_name in fallback map
    test_id = issue.get("test_id", "")
    test_name = issue.get("test_name", "")
    fallback = BANDIT_FALLBACK_CWE_MAP.get(test_id) or BANDIT_FALLBACK_CWE_MAP.get(test_name)
    if fallback:
        return fallback

    return None



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
                cwe_id = _extract_bandit_cwe(issue)

                test_id = issue.get("test_id", "")
                test_name = issue.get("test_name", "")
                rule_id = test_id or test_name
                from backend.detectors.issue_classes import get_issue_class
                issue_class = get_issue_class(test_id) or get_issue_class(test_name)

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
                    source_tool="bandit",
                    rule_id=rule_id,
                    issue_class=issue_class
                )
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            logger.error(f"Error executing Bandit: {e}")
            return []
