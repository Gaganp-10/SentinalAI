import difflib
import logging
from typing import Tuple
from backend.detectors.schema import Finding
from backend.ai.provider import get_ai_provider, FallbackTemplateProvider

logger = logging.getLogger(__name__)

def generate_patched_code(finding: Finding, full_file_content: str) -> Tuple[str, str, str]:
    """
    Generates a secure fix for the vulnerability.
    
    Returns:
        corrected_file_content (str): The full file source after applying the fix.
        corrected_snippet (str): The specific secure code block replacing the vulnerability.
        diff (str): A unified diff showing the exact code changes.
    """
    provider = get_ai_provider()
    
    # 1. Generate corrected file contents
    corrected_file = provider.generate_fix(
        type_name=finding.type,
        description=finding.description,
        code_snippet=finding.code_snippet,
        full_file_source=full_file_content
    )
    
    # 2. Compute unified diff
    orig_lines = full_file_content.splitlines(keepends=True)
    fixed_lines = corrected_file.splitlines(keepends=True)
    
    diff_list = list(difflib.unified_diff(
        orig_lines,
        fixed_lines,
        fromfile=finding.file_path,
        tofile=finding.file_path + " (secured)"
    ))
    diff = "".join(diff_list)

    # 3. Extract the corrected snippet.
    # We will ask the AI provider for a clean corrected snippet if it's OpenAI,
    # or extract the lines that were added in the diff.
    corrected_snippet = ""
    if isinstance(provider, FallbackTemplateProvider):
        corrected_snippet = "# Fallback secure coding pattern suggestion:\n# Please review secure libraries for " + finding.type
    else:
        # Ask OpenAI for the direct corrected snippet replacing the vulnerable one
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
            # strip backticks if any
            if corrected_snippet.startswith("```"):
                lines = corrected_snippet.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                corrected_snippet = "\n".join(lines).strip()
        except Exception as e:
            logger.error(f"Failed to generate specific fix snippet: {e}")
            # Fallback to extracting "+" lines from the diff
            plus_lines = [line[1:] for line in diff_list if line.startswith("+") and not line.startswith("+++")]
            corrected_snippet = "".join(plus_lines).strip() or "# See file diff for suggested fix"

    return corrected_file, corrected_snippet, diff
