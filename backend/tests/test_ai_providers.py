import pytest
import logging
from unittest.mock import patch, MagicMock
from openai import APIConnectionError, APITimeoutError, AuthenticationError
from backend.utils.config import settings
from backend.ai.provider import (
    AIProvider,
    OpenAIProvider,
    FallbackTemplateProvider,
    get_ai_provider,
)

def test_get_ai_provider_template(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "template")
    provider = get_ai_provider()
    assert isinstance(provider, FallbackTemplateProvider)

def test_get_ai_provider_groq_missing_key(monkeypatch, caplog):
    monkeypatch.setattr(settings, "AI_PROVIDER", "groq")
    monkeypatch.setattr(settings, "GROQ_API_KEY", "")
    with caplog.at_level(logging.WARNING):
        provider = get_ai_provider()
    assert isinstance(provider, FallbackTemplateProvider)
    assert "GROQ_API_KEY is not set" in caplog.text

def test_get_ai_provider_groq_with_key(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "groq")
    monkeypatch.setattr(settings, "GROQ_API_KEY", "gsk_test123")
    monkeypatch.setattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
    provider = get_ai_provider()
    assert isinstance(provider, OpenAIProvider)
    assert provider.model == "llama-3.3-70b-versatile"
    assert str(provider.client.base_url).rstrip("/") == "https://api.groq.com/openai/v1"

def test_get_ai_provider_ollama(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "ollama")
    monkeypatch.setattr(settings, "OLLAMA_MODEL", "qwen2.5-coder:7b")
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434/v1")
    provider = get_ai_provider()
    assert isinstance(provider, OpenAIProvider)
    assert provider.model == "qwen2.5-coder:7b"
    assert str(provider.client.base_url).rstrip("/") == "http://localhost:11434/v1"

def test_get_ai_provider_openai_with_and_without_key(monkeypatch, caplog):
    monkeypatch.setattr(settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")
    with caplog.at_level(logging.WARNING):
        provider = get_ai_provider()
    assert isinstance(provider, FallbackTemplateProvider)
    assert "OPENAI_API_KEY is not set" in caplog.text

    monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-test123")
    provider = get_ai_provider()
    assert isinstance(provider, OpenAIProvider)

def test_get_ai_provider_unrecognized(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "unknown_provider")
    provider = get_ai_provider()
    assert isinstance(provider, FallbackTemplateProvider)

def test_openai_provider_timeout_fallback(caplog):
    provider = OpenAIProvider(api_key="mock", model="test-model")
    with patch.object(provider.client.chat.completions, "create", side_effect=APITimeoutError(request=MagicMock())):
        with caplog.at_level(logging.WARNING):
            result = provider.explain("sql_injection", "desc", "critical", "CWE-89", "SELECT *")
    assert "### Issue" in result
    assert "timed out" in caplog.text

def test_openai_provider_connection_error_fallback(caplog):
    provider = OpenAIProvider(api_key="ollama", model="test-model", base_url="http://localhost:11434/v1")
    req = MagicMock()
    with patch.object(provider.client.chat.completions, "create", side_effect=APIConnectionError(request=req)):
        with caplog.at_level(logging.WARNING):
            result = provider.explain("sql_injection", "desc", "critical", "CWE-89", "SELECT *")
    assert "### Issue" in result
    assert "Ollama not reachable at http://localhost:11434/v1, falling back to templates" in caplog.text

def test_openai_provider_invalid_key_fallback(caplog):
    provider = OpenAIProvider(api_key="bad_key", model="test-model", base_url="https://api.groq.com/openai/v1")
    resp = MagicMock()
    resp.status_code = 401
    with patch.object(provider.client.chat.completions, "create", side_effect=AuthenticationError("Invalid API Key", response=resp, body=None)):
        with caplog.at_level(logging.WARNING):
            result = provider.explain("sql_injection", "desc", "critical", "CWE-89", "SELECT *")
    assert "### Issue" in result
    assert "authentication failed" in caplog.text
