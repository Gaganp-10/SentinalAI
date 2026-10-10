import ast
import difflib
import logging
import re
from typing import Tuple, Optional
from backend.detectors.schema import Finding
from backend.ai.provider import get_ai_provider, FallbackTemplateProvider

logger = logging.getLogger(__name__)


def generate_template_fix(finding: Finding, file_content: Optional[str] = None) -> Tuple[str, bool]:
    """
    Generates a deterministic mechanical code fix for common vulnerability types
    when running in local template-fallback mode (no AI key).
    
    Preserves all non-vulnerable lines from multi-line snippets verbatim.
    
    Returns:
        suggested_fix (str): The code snippet that fixes the vulnerability.
        auto_fixable (bool): True if the fix is a safe mechanical replacement,
                             False if the finding is advisory or cannot be safely fixed automatically.
    """
    snippet = finding.code_snippet or ""
    if not snippet or not snippet.strip():
        return snippet, False

    type_lower = (finding.type or "").lower().strip()
    has_trailing_newline = snippet.endswith("\n")
    
    lines = snippet.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    # Rule 1: hardcoded_sql_expressions / SQL Injection
    if "hardcoded_sql_expressions" in type_lower or "sql_injection" in type_lower or "sql injection" in type_lower or "sql" in type_lower:
        from backend.fixer.fix_runtime import detect_sql_placeholder
        placeholder, driver_name = detect_sql_placeholder(file_content or snippet)
        if not placeholder:
            if file_content is None:
                placeholder = "%s"
            else:
                finding.recommendation = (
                    "Automatic fix not applied: SQL parameter placeholder style depends on the database driver in use "
                    "(e.g. '?' for sqlite3, '%s' for psycopg2/PyMySQL). "
                    "Because no supported database driver import was detected, please parameterize this query manually."
                )
                return snippet, False

        fixed_lines = []
        i = 0
        transformed = False

        while i < len(lines):
            line = lines[i]
            indent_len = len(line) - len(line.lstrip())
            indent_str = line[:indent_len]

            # Try to match string concatenation / formatting pattern on current line
            f_match = re.search(r'f(["\'])(.*?)\{([a-zA-Z_][a-zA-Z0-9_\.]*)\}(.*?)\1', line)
            concat_match = re.search(r'(["\'])(.*?)\1\s*\+\s*([a-zA-Z_][a-zA-Z0-9_\.]*)\s*(?:\+\s*(["\'])(.*?)\4)?', line)
            mod_match = re.search(r'(["\'])(.*?)\1\s*%\s*\(?([a-zA-Z_][a-zA-Z0-9_\.]*)\)?', line)
            fmt_match = re.search(r'(["\'])(.*?)\1\.format\(\s*([a-zA-Z_][a-zA-Z0-9_\.]*)\s*\)', line)

            match_tuple = None
            if f_match:
                prefix = f_match.group(2).rstrip("'\"")
                var_name = f_match.group(3)
                suffix = f_match.group(4).lstrip("'\"")
                match_tuple = (prefix, var_name, suffix)
            elif concat_match:
                prefix = concat_match.group(2).rstrip("'\"")
                var_name = concat_match.group(3)
                suffix = (concat_match.group(5) or "").lstrip("'\"")
                match_tuple = (prefix, var_name, suffix)
            elif mod_match:
                sql_str = mod_match.group(2).replace("'%s'", placeholder).replace('"%s"', placeholder).replace("%s", placeholder)
                var_name = mod_match.group(3)
                match_tuple = (sql_str, var_name, "")
            elif fmt_match:
                sql_str = fmt_match.group(2).replace("'{}'", placeholder).replace('"{}"', placeholder).replace("{}", placeholder)
                var_name = fmt_match.group(3)
                match_tuple = (sql_str, var_name, "")

            if match_tuple:
                prefix, var_name, suffix = match_tuple
                sql_pattern = f"{prefix}{placeholder}{suffix}"
                
                # Check if this line is an assignment e.g. query = "SELECT..."
                assign_match = re.search(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=', line)
                assigned_var = assign_match.group(1) if assign_match else None
                
                # Check if next line is execution of assigned_var e.g. cursor.execute(query)
                next_executes = False
                if assigned_var and (i + 1 < len(lines)):
                    next_line = lines[i + 1]
                    if re.search(r'\b(cursor|db|conn)\.execute\(\s*' + re.escape(assigned_var) + r'\s*\)', next_line):
                        next_executes = True

                if next_executes:
                    # Replace both query assignment and execute call with parameterized execute
                    fixed_lines.append(f'{indent_str}cursor.execute("{sql_pattern}", ({var_name},))')
                    i += 2  # consume current line and next line
                    transformed = True
                    continue
                else:
                    # Line is single execute call or assignment alone
                    fixed_lines.append(f'{indent_str}cursor.execute("{sql_pattern}", ({var_name},))')
                    i += 1
                    transformed = True
                    continue

            # Non-vulnerable line (e.g. cursor = conn.cursor()): preserve verbatim
            fixed_lines.append(line)
            i += 1

        if transformed:
            res = "\n".join(fixed_lines)
            if has_trailing_newline:
                res += "\n"
            return res, True
        return snippet, False

    # Rule 2: hardcoded_password_string / Hardcoded Secret
    if "hardcoded_password_string" in type_lower or "hardcoded secret" in type_lower or "hardcoded_secret" in type_lower or "hardcoded password string" in type_lower or "password" in type_lower or "secret" in type_lower:
        fixed_lines = []
        transformed = False
        for line in lines:
            indent_len = len(line) - len(line.lstrip())
            indent_str = line[:indent_len]
            match = re.search(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\'"].*?[\'"]', line)
            if match:
                var_name = match.group(1)
                fixed_lines.append(f'{indent_str}{var_name} = os.environ.get("{var_name}")')
                transformed = True
            else:
                fixed_lines.append(line)
        if transformed:
            res = "\n".join(fixed_lines)
            if has_trailing_newline:
                res += "\n"
            return res, True
        return snippet, False

    # Rule 3: subprocess_popen_with_shell_equals_true / shell=True
    if "subprocess_popen_with_shell_equals_true" in type_lower or "subprocess_run_with_shell_equals_true" in type_lower or "command injection" in type_lower or "command_injection" in type_lower or "shell_equals_true" in type_lower or ("subprocess" in type_lower and "shell" in type_lower):
        if any(op in snippet for op in ["|", ";", "&&", "||", ">", "<", "\\"]):
            return snippet, False
        fixed_lines = []
        transformed = False
        for line in lines:
            if "subprocess." in line and ("shell=True" in line or "shell = True" in line):
                f_match = re.search(r'subprocess\.(run|Popen|call)\(\s*f(["\'])(.*?)\{([a-zA-Z_][a-zA-Z0-9_\.]*)\}(.*?)\2', line)
                add_match = re.search(r'subprocess\.(run|Popen|call)\(\s*(["\'])(.*?)\2\s*\+\s*([a-zA-Z_][a-zA-Z0-9_\.]*)', line)
                if f_match:
                    func = f_match.group(1)
                    prefix = f_match.group(3).strip()
                    var_name = f_match.group(4)
                    cmd_tokens = [f'"{token}"' for token in prefix.split() if token]
                    cmd_list = "[" + ", ".join(cmd_tokens) + f", {var_name}]"
                    fixed_line = re.sub(r'subprocess\.(run|Popen|call)\(\s*f(["\'].*?["\'])', f'subprocess.{func}({cmd_list}', line)
                    fixed_line = re.sub(r'shell\s*=\s*True', 'shell=False', fixed_line)
                    fixed_lines.append(fixed_line)
                    transformed = True
                elif add_match:
                    func = add_match.group(1)
                    prefix = add_match.group(3).strip()
                    var_name = add_match.group(4)
                    cmd_tokens = [f'"{token}"' for token in prefix.split() if token]
                    cmd_list = "[" + ", ".join(cmd_tokens) + f", {var_name}]"
                    fixed_line = re.sub(r'subprocess\.(run|Popen|call)\(\s*(["\'].*?["\']\s*\+\s*[a-zA-Z_][a-zA-Z0-9_\.]*)', f'subprocess.{func}({cmd_list}', line)
                    fixed_line = re.sub(r'shell\s*=\s*True', 'shell=False', fixed_line)
                    fixed_lines.append(fixed_line)
                    transformed = True
                elif "shell=True" in line or "shell = True" in line:
                    fixed_line = re.sub(r'shell\s*=\s*True', 'shell=False', line)
                    fixed_lines.append(fixed_line)
                    transformed = True
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        if transformed:
            res = "\n".join(fixed_lines)
            if has_trailing_newline:
                res += "\n"
            return res, True
        return snippet, False

    # Rule 4: hashlib (weak hash)
    if "weak hashing algorithm" in type_lower or "weak_hashing_algorithm" in type_lower or "hashlib" in type_lower or "md5" in type_lower or "sha1" in type_lower:
        fixed_lines = []
        transformed = False
        for line in lines:
            if "hashlib.md5(" in line or "hashlib.sha1(" in line:
                fixed_line = line.replace("hashlib.md5(", "hashlib.sha256(").replace("hashlib.sha1(", "hashlib.sha256(")
                fixed_lines.append(fixed_line)
                transformed = True
            else:
                fixed_lines.append(line)
        if transformed:
            res = "\n".join(fixed_lines)
            if has_trailing_newline:
                res += "\n"
            return res, True
        return snippet, False

    # Rule 5 & 6: pickle / blacklist / advisory import findings
    if "blacklist" in type_lower or "pickle" in type_lower or snippet.strip().startswith("import "):
        return snippet, False

    # Rule 7: Default fallback for any other vulnerability type
    return snippet, False


def is_ai_fix_eligible(finding: Finding) -> bool:
    """
    Determines if a finding is eligible for an AI-generated code fix candidate.
    Only actionable call-site / function-level vulnerabilities with a clear code context
    are eligible. Broad/advisory import-level findings stay permanently manual.
    """
    snippet = (finding.code_snippet or "").strip()
    if not snippet:
        return False

    # Advisory import-level findings must stay manual
    if snippet.startswith("import ") or snippet.startswith("from "):
        return False
    type_lower = (finding.type or "").lower().strip()
    if "blacklist_import" in type_lower or "blacklist_imports" in type_lower:
        return False
    if "blacklist" in type_lower and (snippet.startswith("import ") or snippet.startswith("from ")):
        return False

    eligible_keywords = [
        "pickle", "eval", "exec", "yaml", "deserialization",
        "random", "ssl", "tls", "xml", "subprocess", "command",
        "path_traversal", "file", "timeout", "cryptographic",
        "hashlib", "sql", "injection", "secret", "password"
    ]
    return any(kw in type_lower or kw in snippet.lower() for kw in eligible_keywords)


def _generate_ai_snippet_fix(finding: Finding, full_file_content: str, provider) -> Tuple[str, str, str, bool]:
    """
    Asks the AI provider to generate a snippet-level fix to replace finding.code_snippet.
    Validates syntax with ast.parse before confirming success.
    Returns: (corrected_file, corrected_snippet, diff, success)
    """
    snippet = finding.code_snippet or ""
    if not snippet or snippet not in full_file_content:
        return full_file_content, snippet, "", False

    prompt = f"""You are an automated secure code remediation assistant.
You must fix a security vulnerability in Python code.

Vulnerability Type: {finding.type}
Description: {finding.description}
File: {finding.file_path}

ORIGINAL VULNERABLE SNIPPET:
```python
{snippet}
```

SURROUNDING FILE CONTEXT:
```python
{full_file_content[:3000]}
```

TASK:
Provide ONLY the exact replacement code snippet that directly replaces the ORIGINAL VULNERABLE SNIPPET above.
Preserve the exact leading indentation of the original snippet so it can be replaced cleanly.
Do NOT include markdown formatting (do NOT use ``` or ```python).
Do NOT include explanations, warnings, comments about what changed, or conversational text.
Output pure, runnable Python code only.
"""
    try:
        if hasattr(provider, "_create_completion"):
            response = provider._create_completion(
                messages=[
                    {"role": "system", "content": "You are an automated secure code fixer. Output only the replacement code snippet. No markdown code fences, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
        else:
            response = provider.client.chat.completions.create(
                model=provider.model,
                messages=[
                    {"role": "system", "content": "You are an automated secure code fixer. Output only the replacement code snippet. No markdown code fences, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
        raw_fix = response.choices[0].message.content or ""
        clean_fix = raw_fix.strip()
        if clean_fix.startswith("```"):
            lines = clean_fix.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            clean_fix = "\n".join(lines).strip("\r\n")

        if not clean_fix:
            return full_file_content, snippet, "", False

        if snippet.endswith("\n") and not clean_fix.endswith("\n"):
            clean_fix += "\n"

        if snippet not in full_file_content:
            return full_file_content, clean_fix, "", False

        corrected_file = full_file_content.replace(snippet, clean_fix, 1)

        try:
            ast.parse(corrected_file)
        except SyntaxError as se:
            logger.warning(f"AI-generated fix produced invalid syntax: {se}")
            return full_file_content, clean_fix, "", False

        orig_lines = full_file_content.splitlines(keepends=True)
        fixed_lines = corrected_file.splitlines(keepends=True)
        diff_list = list(difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=finding.file_path,
            tofile=finding.file_path + " (secured)"
        ))
        diff = "".join(diff_list)
        return corrected_file, clean_fix, diff, True
    except Exception as e:
        logger.error(f"Error generating AI snippet fix: {e}")
        return full_file_content, snippet, "", False


def generate_patched_code(finding: Finding, full_file_content: str) -> Tuple[str, str, str, bool, Optional[str]]:
    """
    Generates a secure fix for the vulnerability.
    
    Returns:
        corrected_file_content (str): The full file source after applying the fix.
        corrected_snippet (str): The specific secure code block replacing the vulnerability.
        diff (str): A unified diff showing the exact code changes.
        auto_fixable (bool): True if the fix is automatically applicable, False otherwise.
        fix_source (Optional[str]): "template" | "ai" | None.
    """
    # 1. First priority: Deterministic mechanical template fix
    corrected_snippet, template_auto_fixable = generate_template_fix(finding, full_file_content)
    if template_auto_fixable and finding.code_snippet and finding.code_snippet in full_file_content:
        corrected_file = full_file_content.replace(finding.code_snippet, corrected_snippet, 1)
        # Ensure required imports are added if missing (e.g. import os for os.environ)
        from backend.fixer.fix_runtime import add_import_if_missing
        if "os.environ" in corrected_snippet or "os.getenv" in corrected_snippet:
            corrected_file = add_import_if_missing(corrected_file, "os", "import os")
        elif "hashlib." in corrected_snippet:
            corrected_file = add_import_if_missing(corrected_file, "hashlib", "import hashlib")
        elif "subprocess." in corrected_snippet:
            corrected_file = add_import_if_missing(corrected_file, "subprocess", "import subprocess")

        orig_lines = full_file_content.splitlines(keepends=True)
        fixed_lines = corrected_file.splitlines(keepends=True)
        diff_list = list(difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=finding.file_path,
            tofile=finding.file_path + " (secured)"
        ))
        diff = "".join(diff_list)
        return corrected_file, corrected_snippet, diff, True, "template"

    type_lower = (finding.type or "").lower()
    # If this is an SQL injection finding whose driver could not be determined, do not auto-apply
    if "sql" in type_lower and not template_auto_fixable:
        return full_file_content, corrected_snippet or finding.code_snippet or "", "", False, None

    provider = get_ai_provider()

    # 2. If running offline/template fallback, or finding not template-fixable
    if isinstance(provider, FallbackTemplateProvider):
        return full_file_content, corrected_snippet, "", False, None

    # 3. AI provider is configured: check eligibility for AI fix candidate
    if not is_ai_fix_eligible(finding):
        return full_file_content, finding.code_snippet or "", "", False, None

    ai_file, ai_snippet, ai_diff, success = _generate_ai_snippet_fix(finding, full_file_content, provider)
    if success:
        return ai_file, ai_snippet, ai_diff, True, "ai"

    return full_file_content, ai_snippet or finding.code_snippet or "", "", False, None
