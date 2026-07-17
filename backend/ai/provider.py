import os
import logging
from abc import ABC, abstractmethod
from typing import Optional
from openai import OpenAI
from backend.utils.config import settings

logger = logging.getLogger(__name__)

class AIProvider(ABC):
    @abstractmethod
    def explain(self, type_name: str, description: str, severity: str, cwe_id: Optional[str], code_snippet: Optional[str]) -> str:
        pass

    @abstractmethod
    def generate_fix(self, type_name: str, description: str, code_snippet: Optional[str], full_file_source: str) -> str:
        """Returns the corrected code snippet or file content."""
        pass

    @abstractmethod
    def ask_question(self, question: str, type_name: str, description: str, code_snippet: Optional[str], full_file_source: Optional[str]) -> str:
        pass


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def explain(self, type_name: str, description: str, severity: str, cwe_id: Optional[str], code_snippet: Optional[str]) -> str:
        prompt = f"""
Analyze the following security finding and write a detailed explanation.
Vulnerability Type: {type_name}
Severity: {severity}
CWE ID: {cwe_id or "N/A"}
Description: {description}
Code Snippet:
```python
{code_snippet or "N/A"}
```

You MUST structure your response exactly as follows:
### Issue
Describe the specific issue clearly.

### Reason
Explain why this code pattern is insecure and how the vulnerability arises.

### Impact
Explain the security impact and what an attacker could achieve if they exploit this.

### Severity
Justify the severity rating based on exploitability and impact.

### Fix
Give general guidance on how to fix this class of vulnerability.
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert Application Security Engineer. Answer questions clearly and structure them strictly using markdown headers."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content or "No explanation generated."
        except Exception as e:
            logger.error(f"OpenAI explanation generation failed: {e}")
            return f"Error communicating with AI Provider: {e}"

    def generate_fix(self, type_name: str, description: str, code_snippet: Optional[str], full_file_source: str) -> str:
        prompt = f"""
You are an expert secure coder. Fix the security vulnerability in the provided source code.
Vulnerability Type: {type_name}
Description: {description}
Code Snippet with vulnerability:
```
{code_snippet or "N/A"}
```

Here is the full source code of the file containing the vulnerability. Modify it to fix the issue securely.

Full File Source:
```
{full_file_source}
```

Instructions:
1. Fix the vulnerability described.
2. Return ONLY the complete corrected file content. Do NOT wrap it in markdown code blocks (like ```python ... ```), do NOT write any introductory or explanatory text. Return the raw code ready to be written directly to a file.
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a secure coding assistant. You only output raw, valid source code for files, without any explanation or markdown formatting."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            # Remove any accidentally included markdown formatting
            content = response.choices[0].message.content or ""
            content = content.strip()
            if content.startswith("```"):
                # strip out block markers
                lines = content.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                content = "\n".join(lines).strip()
            return content
        except Exception as e:
            logger.error(f"OpenAI fix generation failed: {e}")
            return f"# Error generating fix: {e}\n{full_file_source}"

    def ask_question(self, question: str, type_name: str, description: str, code_snippet: Optional[str], full_file_source: Optional[str]) -> str:
        prompt = f"""
You are a security mentor answering a developer's question about a specific vulnerability finding.
Vulnerability details:
- Type: {type_name}
- Description: {description}
- Code Snippet:
```
{code_snippet or "N/A"}
```
- Full File Source:
```
{full_file_source or "N/A"}
```

Question:
{question}

Provide a concise, helpful security advice explaining what the developer should do or clarifying the concept.
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a helpful AppSec mentor guiding developers on secure coding practices."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            return response.choices[0].message.content or "No response generated."
        except Exception as e:
            logger.error(f"OpenAI Q&A failed: {e}")
            return f"Error communicating with AI Mentor: {e}"


class FallbackTemplateProvider(AIProvider):
    def explain(self, type_name: str, description: str, severity: str, cwe_id: Optional[str], code_snippet: Optional[str]) -> str:
        return f"""### Issue
A vulnerability of type **{type_name}** was detected.

### Reason
{description or "No detail provided by the linter."}

### Impact
Exploiting this could lead to unauthorized access, code execution, or information disclosure, depending on the context of the vulnerability.

### Severity
This is rated as **{severity}** based on common weakness classifications (like CWE/OWASP).

### Fix
Refactor the code snippet `{code_snippet or ""}` to follow industry secure coding guidelines:
- For SQL injections: use parameterized queries.
- For secrets: extract them to environment configuration files.
- For weak hashing: upgrade to bcrypt/argon2/PBKDF2.
- For dangerous calls (eval/exec): avoid parsing raw strings as executable code.
"""

    def generate_fix(self, type_name: str, description: str, code_snippet: Optional[str], full_file_source: str) -> str:
        # Static fallback: just return the code as-is with a comment, or try basic regex replace
        comment = f"# [FALLBACK] Please review and fix this {type_name} finding:\n# Snippet: {code_snippet}\n"
        return comment + full_file_source

    def ask_question(self, question: str, type_name: str, description: str, code_snippet: Optional[str], full_file_source: Optional[str]) -> str:
        return f"AI Mentor is running in offline template-fallback mode because no OPENAI_API_KEY was configured. The finding is a {type_name} ({description}). Please check standard OWASP top 10 rules for advice on how to address it."


def get_ai_provider() -> AIProvider:
    if settings.OPENAI_API_KEY:
        return OpenAIProvider(
            api_key=settings.OPENAI_API_KEY,
            model=settings.OPENAI_MODEL
        )
    else:
        logger.warning("OPENAI_API_KEY is not set. Falling back to local templates.")
        return FallbackTemplateProvider()
