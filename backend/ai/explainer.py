from typing import Optional
from backend.detectors.schema import Finding
from backend.ai.provider import get_ai_provider

def generate_vulnerability_explanation(finding: Finding) -> str:
    """
    Invokes the AI provider to generate a structured explanation for the finding.
    Falls back to static templates if AI provider is offline/not configured.
    """
    provider = get_ai_provider()
    return provider.explain(
        type_name=finding.type,
        description=finding.description,
        severity=finding.severity,
        cwe_id=finding.cwe_id,
        code_snippet=finding.code_snippet
    )
