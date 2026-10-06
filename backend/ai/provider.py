import os
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from openai import OpenAI, APIConnectionError, APITimeoutError, AuthenticationError
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


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str, base_url: Optional[str] = None, timeout: float = 30.0):
        self.client = (
            OpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=1)
            if base_url
            else OpenAI(api_key=api_key, timeout=timeout, max_retries=1)
        )
        self.model = model
        self.base_url = base_url
        self._fallback = FallbackTemplateProvider()

    def _create_completion(self, messages: List[Dict[str, str]], temperature: float) -> Any:
        try:
            return self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature
            )
        except Exception as e:
            err_msg = str(e)
            # If the requested model is not found/deprecated on Groq, attempt fallback to available Groq models
            if "model_not_found" in err_msg or "does not exist or you do not have access" in err_msg:
                if self.base_url and "groq.com" in self.base_url:
                    alt_candidates = ["openai/gpt-oss-20b", "qwen/qwen3.8-27b", "openai/gpt-oss-120b"]
                    for alt_model in alt_candidates:
                        if alt_model != self.model:
                            try:
                                logger.info(f"Model '{self.model}' not available on Groq, trying fallback model '{alt_model}'")
                                res = self.client.chat.completions.create(
                                    model=alt_model,
                                    messages=messages,
                                    temperature=temperature
                                )
                                self.model = alt_model
                                settings.GROQ_MODEL = alt_model
                                return res
                            except Exception:
                                continue
            raise e

    def _handle_error(self, e: Exception, operation: str) -> None:
        err_msg = str(e)
        if isinstance(e, APIConnectionError) or "connection" in err_msg.lower() or "connect" in err_msg.lower():
            if (settings.AI_PROVIDER == "ollama") or (self.base_url and ("11434" in self.base_url or "ollama" in self.base_url.lower())):
                logger.warning(f"Ollama not reachable at {self.base_url}, falling back to templates")
            elif self.base_url:
                logger.warning(f"AI Provider not reachable at {self.base_url} ({e}), falling back to templates")
            else:
                logger.warning(f"AI Provider connection failed ({e}), falling back to templates")
        elif isinstance(e, APITimeoutError) or "timeout" in err_msg.lower() or "timed out" in err_msg.lower():
            logger.warning(f"AI Provider request timed out ({e}), falling back to templates")
        elif isinstance(e, AuthenticationError) or "401" in err_msg or "auth" in err_msg.lower() or "invalid api key" in err_msg.lower():
            logger.warning(f"AI Provider authentication failed (invalid API key: {e}), falling back to templates")
        else:
            logger.warning(f"AI Provider {operation} failed ({e}), falling back to templates")

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
            response = self._create_completion(
                messages=[
                    {"role": "system", "content": "You are an expert Application Security Engineer. Answer questions clearly and structure them strictly using markdown headers."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content or "No explanation generated."
        except Exception as e:
            self._handle_error(e, "explanation generation")
            return self._fallback.explain(type_name, description, severity, cwe_id, code_snippet)

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
            response = self._create_completion(
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
            self._handle_error(e, "fix generation")
            return self._fallback.generate_fix(type_name, description, code_snippet, full_file_source)

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
            response = self._create_completion(
                messages=[
                    {"role": "system", "content": "You are a helpful AppSec mentor guiding developers on secure coding practices."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            return response.choices[0].message.content or "No response generated."
        except Exception as e:
            self._handle_error(e, "Q&A")
            return self._fallback.ask_question(question, type_name, description, code_snippet, full_file_source)


def get_ai_provider() -> AIProvider:
    provider_type = (settings.AI_PROVIDER or "template").strip().lower()

    if provider_type == "groq":
        if settings.GROQ_API_KEY and settings.GROQ_API_KEY.strip():
            return OpenAIProvider(
                api_key=settings.GROQ_API_KEY.strip(),
                model=settings.GROQ_MODEL,
                base_url="https://api.groq.com/openai/v1",
                timeout=30.0
            )
        else:
            logger.warning("GROQ_API_KEY is not set. Falling back to local templates.")
            return FallbackTemplateProvider()

    elif provider_type == "ollama":
        return OpenAIProvider(
            api_key="ollama",
            model=settings.OLLAMA_MODEL,
            base_url=settings.OLLAMA_BASE_URL,
            timeout=30.0
        )

    elif provider_type == "openai":
        if settings.OPENAI_API_KEY and settings.OPENAI_API_KEY.strip():
            return OpenAIProvider(
                api_key=settings.OPENAI_API_KEY.strip(),
                model=settings.OPENAI_MODEL,
                timeout=30.0
            )
        else:
            logger.warning("OPENAI_API_KEY is not set. Falling back to local templates.")
            return FallbackTemplateProvider()

    else:
        return FallbackTemplateProvider()
