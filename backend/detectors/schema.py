from dataclasses import dataclass
from typing import Optional

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

    def dedup_key(self) -> tuple:
        import os
        norm_path = os.path.normpath(self.file_path).replace("\\", "/")
        return (norm_path, self.line_number, self.type.lower().strip())
