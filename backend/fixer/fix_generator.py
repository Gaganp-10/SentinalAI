import difflib
import logging
import re
from typing import Tuple
from backend.detectors.schema import Finding
from backend.ai.provider import get_ai_provider, FallbackTemplateProvider

logger = logging.getLogger(__name__)


def generate_template_fix(finding: Finding) -> Tuple[str, bool]:
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
                sql_str = mod_match.group(2).replace("'%s'", "%s").replace('"%s"', "%s")
                var_name = mod_match.group(3)
                match_tuple = (sql_str, var_name, "")
            elif fmt_match:
                sql_str = fmt_match.group(2).replace("'{}'", "%s").replace('"{}"', "%s").replace("{}", "%s")
                var_name = fmt_match.group(3)
                match_tuple = (sql_str, var_name, "")

            if match_tuple:
                prefix, var_name, suffix = match_tuple
                sql_pattern = f"{prefix}%s{suffix}"
                
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


def generate_patched_code(finding: Finding, full_file_content: str) -> Tuple[str, str, str, bool]:
    """
    Generates a secure fix for the vulnerability.
    
    Returns:
        corrected_file_content (str): The full file source after applying the fix.
        corrected_snippet (str): The specific secure code block replacing the vulnerability.
        diff (str): A unified diff showing the exact code changes.
        auto_fixable (bool): True if the fix is automatically applicable, False otherwise.
    """
    provider = get_ai_provider()
    
    if isinstance(provider, FallbackTemplateProvider):
        corrected_snippet, auto_fixable = generate_template_fix(finding)
        if auto_fixable and finding.code_snippet and finding.code_snippet in full_file_content:
            corrected_file = full_file_content.replace(finding.code_snippet, corrected_snippet, 1)
            orig_lines = full_file_content.splitlines(keepends=True)
            fixed_lines = corrected_file.splitlines(keepends=True)
            diff_list = list(difflib.unified_diff(
                orig_lines,
                fixed_lines,
                fromfile=finding.file_path,
                tofile=finding.file_path + " (secured)"
            ))
            diff = "".join(diff_list)
        else:
            corrected_file = full_file_content
            diff = ""
        return corrected_file, corrected_snippet, diff, auto_fixable

    # AI Provider path (OpenAIProvider)
    corrected_file = provider.generate_fix(
        type_name=finding.type,
        description=finding.description,
        code_snippet=finding.code_snippet,
        full_file_source=full_file_content
    )
    
    orig_lines = full_file_content.splitlines(keepends=True)
    fixed_lines = corrected_file.splitlines(keepends=True)
    
    diff_list = list(difflib.unified_diff(
        orig_lines,
        fixed_lines,
        fromfile=finding.file_path,
        tofile=finding.file_path + " (secured)"
    ))
    diff = "".join(diff_list)

    corrected_snippet = ""
    prompt = f"""
Vulnerability Type: {finding.type}
Vulnerable Snippet:
```python
{finding.code_snippet or "N/A"}
```
Description: {finding.description}

Here is the full fixed file:
```
{corrected_file}
```

Return ONLY the specific replacement lines of code that fix the vulnerable snippet. Do NOT include markdown styling (no ```), explanation, or comments.
"""
    try:
        response = provider.client.chat.completions.create(
            model=provider.model,
            messages=[
                {"role": "system", "content": "You are a secure developer. You only output raw, valid code blocks matching the fixed snippet requested."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        corrected_snippet = response.choices[0].message.content or ""
        corrected_snippet = corrected_snippet.strip()
        if corrected_snippet.startswith("```"):
            lines = corrected_snippet.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            corrected_snippet = "\n".join(lines).strip()
    except Exception as e:
        logger.error(f"Failed to generate specific fix snippet: {e}")
        plus_lines = [line[1:] for line in diff_list if line.startswith("+") and not line.startswith("+++")]
        corrected_snippet = "".join(plus_lines).strip() or "# See file diff for suggested fix"

    auto_fixable = True
    return corrected_file, corrected_snippet, diff, auto_fixable
