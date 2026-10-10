from dataclasses import dataclass
from typing import Optional

class DetectorError(Exception):
    """Raised when a detector fails during execution or configuration."""
    pass

@dataclass
class Finding:
    file_path: str        # relative path within project
    line_number: int
    type: str             # e.g., SQL Injection, Hardcoded Secret
    severity: str         # critical/high/medium/low/info
    description: str
    recommendation: Optional[str] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 1.0
    source_tool: str = ""  # bandit/semgrep/ast/ai
    fixed: bool = False
    auto_fixable: bool = True
    fix_source: Optional[str] = None
    rule_id: Optional[str] = None
    issue_class: Optional[str] = None

    def dedup_key(self) -> tuple:
        import os
        norm_path = os.path.normpath(self.file_path).replace("\\", "/")
        if self.cwe_id:
            return (norm_path, self.line_number, self.cwe_id.strip().upper())
        return (norm_path, self.line_number, self.type.lower().strip())
