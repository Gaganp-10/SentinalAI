import json
import subprocess
import os
import shutil
import logging
import re
from typing import List
from backend.detectors.schema import Finding, DetectorError

logger = logging.getLogger(__name__)


def _extract_semgrep_cwe(metadata: dict) -> str | None:
    cwe_raw = metadata.get("cwe")
    if not cwe_raw:
        return None

    cwe_str = cwe_raw[0] if isinstance(cwe_raw, list) else str(cwe_raw)
    if not cwe_str:
        return None

    match = re.search(r"CWE-(\d+)", str(cwe_str), re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"

    num_match = re.search(r"\b(\d+)\b", str(cwe_str))
    if num_match:
        return f"CWE-{num_match.group(1)}"

    return None


class SemgrepDetector:
    def __init__(self, rules_path: str = None):
        self.semgrep_bin = shutil.which("semgrep")
        self.is_available = self.semgrep_bin is not None
        if rules_path:
            self.rules_path = rules_path
        else:
            default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "semgrep_rules.yaml"))
            self.rules_path = default_path

    def scan(self, project_dir: str) -> List[Finding]:
        if not self.is_available:
            msg = "Semgrep CLI is not installed or not found on PATH."
            logger.error(msg)
            raise DetectorError(msg)

        if not os.path.exists(self.rules_path):
            msg = f"Semgrep rules file not found at: {self.rules_path}"
            logger.error(msg)
            raise DetectorError(msg)

        cmd = [
            self.semgrep_bin,
            "scan",
            "--config", self.rules_path,
            "--exclude=requirements*.txt",
            "--exclude=package*.json",
            "--exclude=pom.xml",
            "--metrics=off",
            "--disable-version-check",
            "--timeout=10",
            "--json",
            "--quiet",
            project_dir
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            # Return codes: 0 = no findings, 1 = findings found. Return codes >= 2 are errors.
            if result.returncode not in (0, 1):
                err_msg = f"Semgrep execution failed with exit code {result.returncode}: {result.stderr.strip()}"
                logger.error(err_msg)
                raise DetectorError(err_msg)

            output_str = result.stdout.strip()
            if not output_str:
                logger.warning("Semgrep returned empty stdout.")
                return []

            data = json.loads(output_str)
            findings = []

            for issue in data.get("results", []):
                filename = issue.get("path", "")
                full_issue_path = filename if os.path.isabs(filename) else os.path.abspath(filename)
                rel_path = os.path.relpath(full_issue_path, os.path.abspath(project_dir)).replace("\\", "/")

                start_info = issue.get("start", {})
                line_number = start_info.get("line", 1)

                extra = issue.get("extra", {})
                code = extra.get("lines", "")
                # If semgrep outputs placeholder or blank, fetch line from file
                if not code or code == "requires login":
                    full_path = os.path.join(project_dir, rel_path)
                    if os.path.exists(full_path):
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                for idx, line in enumerate(f, start=1):
                                    if idx == line_number:
                                        code = line.rstrip()
                                        break
                        except Exception:
                            code = ""

                # Map severity: ERROR -> high, WARNING -> medium, INFO -> low
                sem_sev = extra.get("severity", "WARNING").upper()
                severity = "medium"
                if sem_sev == "ERROR":
                    severity = "high"
                elif sem_sev == "INFO":
                    severity = "low"

                # Parse CWE from metadata
                metadata = extra.get("metadata", {})
                cwe_id = _extract_semgrep_cwe(metadata)

                rule_id = issue.get("check_id", "Semgrep Finding")
                from backend.detectors.issue_classes import get_issue_class
                issue_class = get_issue_class(rule_id)
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
                    confidence=1.0,
                    source_tool="semgrep",
                    rule_id=rule_id,
                    issue_class=issue_class
                )
                findings.append(finding)

            return findings

        except DetectorError:
            raise
        except Exception as e:
            err_msg = f"Unexpected error executing Semgrep scan: {e}"
            logger.error(err_msg, exc_info=True)
            raise DetectorError(err_msg)
