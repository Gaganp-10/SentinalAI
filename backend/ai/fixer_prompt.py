from backend.detectors.schema import Finding

def get_fixer_system_prompt() -> str:
    return (
        "You are an expert secure coder. Your task is to fix security vulnerabilities "
        "in the provided file source code. You must output the entire corrected file "
        "without changing other parts of the logic unless necessary to resolve the vulnerability. "
        "Output ONLY the corrected code, with no markdown styling and no extra words."
    )

def get_fixer_user_prompt(finding: Finding, full_file_source: str) -> str:
    return f"""
Vulnerability detected:
Type: {finding.type}
Severity: {finding.severity}
Description: {finding.description}
Line: {finding.line_number}
Vulnerable Snippet: {finding.code_snippet or "N/A"}

Please patch the following file content to fix this security issue:

--- START OF FILE ---
{full_file_source}
--- END OF FILE ---

Return ONLY the patched file contents.
"""
