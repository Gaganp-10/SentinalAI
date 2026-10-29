"""
test_copilot_factual_accuracy.py
=================================
Regression tests for the Security Copilot factual-accuracy fixes.

Covered scenarios
-----------------
1.  Grounding markers are present in the context produced by
    build_copilot_context_for_dep.
2.  The strict system prompt in ask_dependency_question explicitly
    prohibits fabricating CVE IDs, version numbers, and 'latest version'
    claims.
3.  When no advisory data is available the context and fallback response
    say so clearly without fabricating anything.
4.  The recommended_version annotation in the context clearly states it is
    NOT a claim about the latest available release.
5.  The FallbackTemplateProvider.ask_dependency_question never mentions a
    specific CVE, version, or patch claim.
6.  OpenAIProvider.ask_dependency_question calls the LLM with temperature
    <= 0.15 (minimise hallucination) and uses a grounding system message.
7.  The /api/ai/ask endpoint routes vulnerable_dependency findings through
    ask_dependency_question, NOT ask_question.
8.  When the advisory list is empty (no CVEs found), the context still
    produces a safe, non-fabricating response.
9.  The grounding footer is always appended even when all advisories are
    hidden by the MAX_ADVISORIES_SHOWN cap.
10. A dependency with an outdated recommended_version annotation is
    correctly marked as advisory-derived rather than "latest".
"""

import pytest
from unittest.mock import MagicMock, patch, call
from typing import List, Dict, Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_advisory(
    adv_id: str,
    cve: Optional[str],
    severity: str,
    summary: str,
    fixed: List[str],
) -> Dict:
    return {
        "id": adv_id,
        "url": f"https://osv.dev/vulnerability/{adv_id}",
        "cve": cve,
        "severity": severity,
        "summary": summary,
        "fixed": fixed,
    }


# ---------------------------------------------------------------------------
# 1. build_copilot_context_for_dep — grounding markers
# ---------------------------------------------------------------------------

class TestBuildCopilotContextGrounding:
    """Verify that build_copilot_context_for_dep always emits the grounding
    boundary markers required by the strict LLM prompt."""

    def _build(self, recommended=None, advisories=None):
        from backend.sca.findings import build_copilot_context_for_dep
        return build_copilot_context_for_dep(
            dep_name="requests",
            dep_version="2.19.1",
            ecosystem="PyPI",
            manifest_file="requirements.txt",
            recommended_version=recommended,
            advisory_details=advisories or [],
        )

    def test_verified_header_present(self):
        ctx = self._build(recommended="2.31.0", advisories=[
            _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                           "Proxy-Authorization header leak", ["2.31.0"])
        ])
        assert "=== VERIFIED ADVISORY DATA" in ctx

    def test_end_marker_present(self):
        ctx = self._build(recommended="2.31.0", advisories=[
            _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                           "Proxy-Authorization header leak", ["2.31.0"])
        ])
        assert "=== END OF VERIFIED ADVISORY DATA ===" in ctx

    def test_grounding_footer_instructs_no_fabrication(self):
        ctx = self._build(recommended="2.31.0", advisories=[
            _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                           "Proxy-Authorization header leak", ["2.31.0"])
        ])
        assert "Do NOT introduce CVE IDs" in ctx
        assert "osv.dev" in ctx

    def test_recommended_version_annotated_not_latest(self):
        """The recommended version line must NOT claim to be the latest release."""
        ctx = self._build(recommended="2.31.0", advisories=[
            _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                           "Proxy-Authorization header leak", ["2.31.0"])
        ])
        # Must include the explicit disclaimer
        assert "not a claim about the latest available release" in ctx.lower()
        # Must NOT claim that this version is the latest or currently supported
        assert "is the latest" not in ctx.lower()
        assert "currently supported" not in ctx.lower()

    def test_no_recommended_version_no_fabrication(self):
        """When no recommended version is determinable the context must say so
        clearly without inventing a version."""
        ctx = self._build(recommended=None, advisories=[
            _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                           "Proxy-Authorization header leak", [])
        ])
        assert "not determinable" in ctx
        # Must not embed a bare version number not from the advisory list
        assert "2.32" not in ctx
        assert "2.31" not in ctx

    def test_empty_advisories_still_has_grounding_markers(self):
        """Even with zero advisories, both boundary markers must be present."""
        ctx = self._build(recommended=None, advisories=[])
        assert "=== VERIFIED ADVISORY DATA" in ctx
        assert "=== END OF VERIFIED ADVISORY DATA ===" in ctx

    def test_grounding_footer_present_when_advisories_exceed_cap(self):
        """Footer must still appear when advisories are truncated by the cap."""
        from backend.sca.findings import MAX_ADVISORIES_SHOWN
        many_advisories = [
            _make_advisory(f"GHSA-fake-{i:04d}", None, "MEDIUM", f"Issue {i}", [f"1.{i}.0"])
            for i in range(MAX_ADVISORIES_SHOWN + 5)
        ]
        ctx = self._build(recommended="1.14.0", advisories=many_advisories)
        assert "=== END OF VERIFIED ADVISORY DATA ===" in ctx
        assert "Do NOT introduce CVE IDs" in ctx

    def test_advisory_ids_and_fixed_versions_present(self):
        ctx = self._build(
            recommended="2.31.0",
            advisories=[
                _make_advisory("GHSA-j8r2-6x86-q33q", "CVE-2023-32681", "MEDIUM",
                               "Proxy-Authorization header leak", ["2.31.0"]),
            ]
        )
        assert "GHSA-j8r2-6x86-q33q" in ctx
        assert "CVE-2023-32681" in ctx
        assert "2.31.0" in ctx

    def test_package_line_embedded(self):
        ctx = self._build(recommended="2.31.0", advisories=[])
        assert "requests==2.19.1" in ctx


# ---------------------------------------------------------------------------
# 2. FallbackTemplateProvider.ask_dependency_question
# ---------------------------------------------------------------------------

class TestFallbackProviderDependencyQuestion:
    """The fallback provider must never fabricate CVEs or version claims."""

    def _answer(self, question="What should I do?", dep_context="No advisories found.",
                dep_name="requests", dep_version="2.19.1"):
        from backend.ai.provider import FallbackTemplateProvider
        p = FallbackTemplateProvider()
        return p.ask_dependency_question(
            question=question,
            dep_context=dep_context,
            dep_name=dep_name,
            dep_version=dep_version,
        )

    def test_offline_mode_indicator_present(self):
        ans = self._answer()
        assert "offline" in ans.lower() or "fallback" in ans.lower() or "no ai" in ans.lower()

    def test_package_name_mentioned(self):
        ans = self._answer(dep_name="requests", dep_version="2.19.1")
        assert "requests" in ans

    def test_no_invented_cve_ids(self):
        ans = self._answer()
        # Fallback must not fabricate any CVE IDs
        import re
        assert not re.search(r"CVE-\d{4}-\d+", ans), \
            f"Fallback invented a CVE ID: {ans}"

    def test_no_invented_version_numbers(self):
        ans = self._answer()
        # Fallback must not invent a recommended or 'latest' version
        import re
        # Allow the installed version itself (2.19.1) to appear, but not any other version
        versions = re.findall(r"\d+\.\d+\.\d+", ans)
        for v in versions:
            assert v == "2.19.1", f"Fallback invented version '{v}': {ans}"

    def test_directs_to_authoritative_source(self):
        ans = self._answer()
        # Should mention at least one authoritative source
        assert any(src in ans for src in ["osv.dev", "changelog", "registry", "package"]), \
            f"Fallback didn't direct to authoritative source: {ans}"


# ---------------------------------------------------------------------------
# 3. OpenAIProvider.ask_dependency_question — prompt grounding
# ---------------------------------------------------------------------------

class TestOpenAIProviderDependencyQuestionPrompt:
    """Verify the strict grounding constraints in the LLM prompt for
    ask_dependency_question."""

    def _capture_messages(self, dep_context="ctx", dep_name="requests",
                          dep_version="2.19.1", question="What to do?"):
        from backend.ai.provider import OpenAIProvider

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "grounded answer"

        provider = OpenAIProvider.__new__(OpenAIProvider)
        provider.model = "gpt-4"
        provider.base_url = None
        provider._fallback = MagicMock()

        captured = {}

        def fake_create(messages, temperature):
            captured["messages"] = messages
            captured["temperature"] = temperature
            return mock_response

        provider._create_completion = fake_create

        result = provider.ask_dependency_question(
            question=question,
            dep_context=dep_context,
            dep_name=dep_name,
            dep_version=dep_version,
        )
        return captured, result

    def test_system_message_prohibits_fabrication(self):
        captured, _ = self._capture_messages()
        system_msg = captured["messages"][0]["content"]
        # Must explicitly ban fabrication of CVE IDs, version numbers, etc.
        assert "fabricate" in system_msg.lower() or "hallucinate" in system_msg.lower()
        assert "CVE" in system_msg or "cve" in system_msg.lower()

    def test_system_message_prohibits_latest_version_claims(self):
        captured, _ = self._capture_messages()
        system_msg = captured["messages"][0]["content"]
        assert "latest" in system_msg.lower() or "currently supported" in system_msg.lower()

    def test_system_message_instructs_insufficient_data_disclosure(self):
        captured, _ = self._capture_messages()
        system_msg = captured["messages"][0]["content"]
        # Model must be told to disclose when context is insufficient
        assert "not confirm" in system_msg.lower() or "does not contain" in system_msg.lower() \
               or "insufficient" in system_msg.lower() or "say so" in system_msg.lower()

    def test_user_message_contains_verified_advisory_records(self):
        captured, _ = self._capture_messages(dep_context="ADVISORY DATA HERE")
        user_msg = captured["messages"][1]["content"]
        assert "ADVISORY DATA HERE" in user_msg

    def test_user_message_contains_do_not_introduce_constraint(self):
        captured, _ = self._capture_messages()
        user_msg = captured["messages"][1]["content"]
        assert "Do NOT introduce" in user_msg or "do not introduce" in user_msg.lower()

    def test_temperature_is_low(self):
        """Low temperature (≤ 0.15) maximises faithfulness to the provided records."""
        captured, _ = self._capture_messages()
        assert captured["temperature"] <= 0.15, \
            f"Temperature {captured['temperature']} too high for grounded dependency Q&A"

    def test_package_name_in_user_message(self):
        captured, _ = self._capture_messages(dep_name="flask", dep_version="0.12.0")
        user_msg = captured["messages"][1]["content"]
        assert "flask" in user_msg
        assert "0.12.0" in user_msg

    def test_returns_model_response(self):
        _, result = self._capture_messages()
        assert result == "grounded answer"

    def test_falls_back_on_error(self):
        from backend.ai.provider import OpenAIProvider

        provider = OpenAIProvider.__new__(OpenAIProvider)
        provider.model = "gpt-4"
        provider.base_url = None
        provider._fallback = MagicMock()
        provider._fallback.ask_dependency_question.return_value = "fallback"

        def fake_create(**_):
            raise RuntimeError("boom")

        provider._create_completion = fake_create
        provider._handle_error = MagicMock()

        result = provider.ask_dependency_question(
            question="q",
            dep_context="ctx",
            dep_name="requests",
            dep_version="2.19.1",
        )
        provider._fallback.ask_dependency_question.assert_called_once()
        assert result == "fallback"


# ---------------------------------------------------------------------------
# 4. API routing — /api/ai/ask routes dep findings to ask_dependency_question
# ---------------------------------------------------------------------------

class TestApiDependencyRouting:
    """Ensure the endpoint uses ask_dependency_question (not ask_question) for
    vulnerable_dependency findings."""

    def _setup_dep_vuln(self, db, user, project):
        from backend.models.models import File, Vulnerability
        req_file = File(
            project_id=project.id,
            filename="requirements.txt",
            filepath="requirements.txt",
            size=40
        )
        db.add(req_file)
        db.commit()
        db.refresh(req_file)

        dep_vuln = Vulnerability(
            file_id=req_file.id,
            type="vulnerable_dependency",
            line_number=1,
            severity="high",
            description="Package 'requests' version '2.19.1' in requirements.txt has 1 advisory(s). Recommended version: >= 2.31.0",
            code_snippet="requests==2.19.1",
            suggested_fix="Update requests to >= 2.31.0",
            recommendation=(
                "### Vulnerable Dependency: `requests` (PyPI)\n"
                "- **Installed Version**: `2.19.1`\n\n"
                "#### Known Vulnerabilities (1 advisories)\n"
                "- **[GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) (CVE-2023-32681)** [MEDIUM]: "
                "Proxy-Authorization header leak in requests — Fixed in: `2.31.0`\n"
            ),
            source_tool="osv"
        )
        db.add(dep_vuln)
        db.commit()
        db.refresh(dep_vuln)
        return dep_vuln

    def test_uses_ask_dependency_question_not_ask_question(self, client, db, monkeypatch):
        from backend.models.models import User, Project
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user = User(username="routing_test", email="routing@test.com", hashed_password="x")
        db.add(user)
        db.commit()
        db.refresh(user)
        project = Project(project_name="P", user_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        dep_vuln = self._setup_dep_vuln(db, user, project)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "grounded answer"
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        res = client.post(
            "/api/ai/ask",
            json={"vuln_id": str(dep_vuln.id), "question": "What CVEs are fixed by 2.31.0?"},
            headers=headers
        )
        assert res.status_code == 200
        mock_provider.ask_dependency_question.assert_called_once()
        mock_provider.ask_question.assert_not_called()

    def test_dep_name_and_version_passed_to_method(self, client, db, monkeypatch):
        from backend.models.models import User, Project
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user = User(username="params_test", email="params@test.com", hashed_password="x")
        db.add(user)
        db.commit()
        db.refresh(user)
        project = Project(project_name="P2", user_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        dep_vuln = self._setup_dep_vuln(db, user, project)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "grounded"
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        client.post(
            "/api/ai/ask",
            json={"vuln_id": str(dep_vuln.id), "question": "How do I upgrade?"},
            headers=headers
        )

        call_kwargs = mock_provider.ask_dependency_question.call_args[1]
        assert call_kwargs["dep_name"] == "requests"
        assert call_kwargs["dep_version"] == "2.19.1"

    def test_dep_context_contains_grounding_markers(self, client, db, monkeypatch):
        from backend.models.models import User, Project
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user = User(username="markers_test", email="markers@test.com", hashed_password="x")
        db.add(user)
        db.commit()
        db.refresh(user)
        project = Project(project_name="P3", user_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        dep_vuln = self._setup_dep_vuln(db, user, project)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "grounded"
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        client.post(
            "/api/ai/ask",
            json={"vuln_id": str(dep_vuln.id), "question": "Any CVEs?"},
            headers=headers
        )

        call_kwargs = mock_provider.ask_dependency_question.call_args[1]
        ctx = call_kwargs["dep_context"]
        assert "=== VERIFIED ADVISORY DATA" in ctx
        assert "=== END OF VERIFIED ADVISORY DATA ===" in ctx

    def test_code_finding_still_uses_ask_question(self, client, db, monkeypatch):
        """Code findings must continue to use the generic ask_question path."""
        from backend.models.models import User, Project, File, Vulnerability
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user = User(username="code_routing", email="code_routing@test.com", hashed_password="x")
        db.add(user)
        db.commit()
        db.refresh(user)
        project = Project(project_name="CodeP", user_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        f = File(project_id=project.id, filename="app.py", filepath="app.py", size=100)
        db.add(f)
        db.commit()
        db.refresh(f)

        code_vuln = Vulnerability(
            file_id=f.id,
            type="SQL Injection",
            line_number=10,
            severity="high",
            description="SQL injection via string concatenation",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            source_tool="bandit",
        )
        db.add(code_vuln)
        db.commit()
        db.refresh(code_vuln)

        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}
        mock_provider = MagicMock()
        mock_provider.ask_question.return_value = "use parameterized queries"
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        res = client.post(
            "/api/ai/ask",
            json={"vuln_id": str(code_vuln.id), "question": "How do I fix this?"},
            headers=headers
        )
        assert res.status_code == 200
        mock_provider.ask_question.assert_called_once()
        mock_provider.ask_dependency_question.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Missing / absent advisory data — no hallucination
# ---------------------------------------------------------------------------

class TestMissingAdvisoryData:
    """When advisory details list is empty (e.g. OSV.dev returned nothing),
    the context and fallback must not invent any claims."""

    def test_context_with_no_advisories_no_cve_fabrication(self):
        from backend.sca.findings import build_copilot_context_for_dep
        import re
        ctx = build_copilot_context_for_dep(
            dep_name="requests",
            dep_version="2.19.1",
            ecosystem="PyPI",
            manifest_file="requirements.txt",
            recommended_version=None,
            advisory_details=[],
        )
        # No CVE IDs should appear (none were supplied)
        assert not re.search(r"CVE-\d{4}-\d+", ctx), \
            f"Context fabricated a CVE ID with empty advisories: {ctx}"

    def test_context_with_no_advisories_no_version_claims(self):
        from backend.sca.findings import build_copilot_context_for_dep
        import re
        ctx = build_copilot_context_for_dep(
            dep_name="requests",
            dep_version="2.19.1",
            ecosystem="PyPI",
            manifest_file="requirements.txt",
            recommended_version=None,
            advisory_details=[],
        )
        # Should not embed any version not explicitly provided
        versions = re.findall(r"\b\d+\.\d+\.\d+\b", ctx)
        for v in versions:
            assert v == "2.19.1", \
                f"Context introduced unlisted version '{v}' with empty advisories: {ctx}"

    def test_fallback_with_empty_context_no_cve(self):
        from backend.ai.provider import FallbackTemplateProvider
        import re
        p = FallbackTemplateProvider()
        ans = p.ask_dependency_question(
            question="Is this safe?",
            dep_context="No advisories found.",
            dep_name="requests",
            dep_version="2.19.1",
        )
        assert not re.search(r"CVE-\d{4}-\d+", ans), \
            f"Fallback invented a CVE ID: {ans}"


# ---------------------------------------------------------------------------
# 6. Outdated recommended_version — annotation required
# ---------------------------------------------------------------------------

class TestOutdatedVersionAnnotation:
    """Regardless of how old the recommended_version is, the context must
    annotate it as advisory-derived and not as the 'latest' release."""

    def test_old_recommended_version_annotated(self):
        from backend.sca.findings import build_copilot_context_for_dep
        ctx = build_copilot_context_for_dep(
            dep_name="requests",
            dep_version="2.19.1",
            ecosystem="PyPI",
            manifest_file="requirements.txt",
            recommended_version="2.20.0",  # Deliberately very old
            advisory_details=[
                _make_advisory("GHSA-old-xxxx-yyyy", None, "HIGH",
                               "Old advisory fixed in 2.20.0", ["2.20.0"])
            ],
        )
        assert "2.20.0" in ctx
        # Must be qualified — NOT presented as the latest release
        assert "not a claim about the latest available release" in ctx.lower()
        assert "is the latest" not in ctx.lower()
        assert "currently supported" not in ctx.lower()

    def test_context_does_not_say_currently_supported(self):
        from backend.sca.findings import build_copilot_context_for_dep
        ctx = build_copilot_context_for_dep(
            dep_name="requests",
            dep_version="2.19.1",
            ecosystem="PyPI",
            manifest_file="requirements.txt",
            recommended_version="2.20.0",
            advisory_details=[
                _make_advisory("GHSA-old-xxxx-yyyy", None, "HIGH",
                               "Old advisory", ["2.20.0"])
            ],
        )
        assert "currently supported" not in ctx.lower()


# ---------------------------------------------------------------------------
# 7. Real workflow with OSV-backed dependency finding
# ---------------------------------------------------------------------------

class TestRealWorkflowDependencyCopilot:
    """Simulates the real user workflow: uploading a vulnerable requirements.txt,
    scanning it with OSV.dev, persisting the findings, and querying Copilot
    both with a specific vuln_id and from the project view (project_id)."""

    def _setup_real_project(self, db, tmp_path):
        import uuid
        from backend.models.models import User, Project, File as DBFile, Vulnerability, ScanFinding, ScanHistory
        from backend.sca.scanner import scan_dependencies

        # 1. Create user and project
        user = User(username=f"wf_user_{uuid.uuid4().hex[:6]}", email=f"wf_{uuid.uuid4().hex[:6]}@test.com", hashed_password="x")
        db.add(user)
        db.commit()
        db.refresh(user)

        project = Project(project_name="Vulnerable Dep Project", user_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        # 2. Write requirements.txt with requests==2.19.1
        req_file_path = tmp_path / "requirements.txt"
        req_file_path.write_text("requests==2.19.1\n", encoding="utf-8")

        db_file = DBFile(
            project_id=project.id,
            filename="requirements.txt",
            filepath="requirements.txt",
            language="pip",
            size=len("requests==2.19.1\n")
        )
        db.add(db_file)
        db.commit()
        db.refresh(db_file)

        # 3. Run real scan_dependencies
        findings, warnings, summary = scan_dependencies(str(tmp_path))
        assert len(findings) >= 1, "Expected at least 1 finding from OSV for requests==2.19.1"
        finding = findings[0]
        assert finding.type == "vulnerable_dependency"

        # 4. Persist finding exactly as done in scans.py
        db_vuln = Vulnerability(
            file_id=db_file.id,
            type=finding.type,
            line_number=finding.line_number,
            severity=finding.severity,
            description=finding.description,
            recommendation=finding.recommendation,
            code_snippet=finding.code_snippet,
            suggested_fix=finding.suggested_fix,
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            confidence=finding.confidence,
            source_tool=finding.source_tool,
            fixed=False,
            auto_fixable=False,
            fix_source=None,
        )
        db.add(db_vuln)
        db.commit()
        db.refresh(db_vuln)

        # Also create a ScanHistory and ScanFinding snapshot
        scan_hist = ScanHistory(
            project_id=project.id,
            total_issues=1,
            critical_count=1 if finding.severity == "critical" else 0,
            high_count=1 if finding.severity == "high" else 0,
            status="completed",
        )
        db.add(scan_hist)
        db.commit()
        db.refresh(scan_hist)

        scan_finding = ScanFinding(
            scan_id=scan_hist.id,
            project_id=project.id,
            fingerprint="test_fp_123",
            file_path="requirements.txt",
            type=finding.type,
            severity=finding.severity,
            line_number=1,
            vulnerability_id=db_vuln.id,
            package_name=getattr(finding, "package_name", "requests"),
            package_version=getattr(finding, "package_version", "2.19.1"),
        )
        db.add(scan_finding)
        db.commit()
        db.refresh(scan_finding)

        return user, project, db_vuln, scan_finding

    def test_real_scan_finding_passes_osv_records_to_copilot(self, client, db, tmp_path, monkeypatch):
        """Verifies that Copilot receives real OSV.dev advisory records (CVEs, fixes)
        when queried with a real persisted finding ID."""
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user, project, db_vuln, _ = self._setup_real_project(db, tmp_path)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "Verified upgrade instructions."
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        # User asks a question from the Finding Detail page
        res = client.post(
            "/api/ai/ask",
            json={
                "vuln_id": str(db_vuln.id),
                "project_id": str(project.id),
                "question": "Which CVEs affect requests and what version fixes them?"
            },
            headers=headers
        )
        assert res.status_code == 200
        mock_provider.ask_dependency_question.assert_called_once()
        call_kwargs = mock_provider.ask_dependency_question.call_args[1]

        ctx = call_kwargs["dep_context"]
        dep_name = call_kwargs["dep_name"]
        dep_version = call_kwargs["dep_version"]

        assert dep_name == "requests"
        assert dep_version == "2.19.1"

        # Verified OSV records MUST be present in the context
        assert "CVE-2018-18074" in ctx
        assert "2.20.0" in ctx
        assert "requests==2.19.1" in ctx

        # Boundary markers MUST be present to enforce anti-hallucination
        assert "=== VERIFIED ADVISORY DATA (source: OSV.dev) — answer ONLY from this section ===" in ctx
        assert "=== END OF VERIFIED ADVISORY DATA ===" in ctx
        assert "Do NOT introduce CVE IDs, version numbers, patch dates, or 'latest version' claims" in ctx

    def test_real_scan_project_id_auto_binds_single_dependency_finding(self, client, db, tmp_path, monkeypatch):
        """When the user opens Copilot from the Scan page or Findings page where
        vuln_id is not passed but project_id is, Copilot automatically binds the
        project's vulnerable dependency and receives the real OSV advisory records."""
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user, project, db_vuln, _ = self._setup_real_project(db, tmp_path)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "Verified upgrade instructions."
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        # User asks from the project scan page (no vuln_id passed, only project_id)
        res = client.post(
            "/api/ai/ask",
            json={
                "project_id": str(project.id),
                "question": "What vulnerabilities were found in requests?"
            },
            headers=headers
        )
        assert res.status_code == 200
        mock_provider.ask_dependency_question.assert_called_once()
        call_kwargs = mock_provider.ask_dependency_question.call_args[1]

        ctx = call_kwargs["dep_context"]
        assert "requests==2.19.1" in ctx
        assert "CVE-2018-18074" in ctx
        assert "=== VERIFIED ADVISORY DATA" in ctx

    def test_scan_finding_id_fallback_resolves_vulnerability(self, client, db, tmp_path, monkeypatch):
        """If a caller passes a ScanFinding snapshot ID instead of Vulnerability ID,
        the backend resolves it through vulnerability_id and passes real advisory records."""
        from backend.api.auth import create_access_token
        from backend.api import ai as ai_module

        user, project, _, scan_finding = self._setup_real_project(db, tmp_path)
        headers = {"Authorization": f"Bearer {create_access_token(subject=str(user.id))}"}

        mock_provider = MagicMock()
        mock_provider.ask_dependency_question.return_value = "Verified upgrade instructions."
        monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

        res = client.post(
            "/api/ai/ask",
            json={
                "vuln_id": str(scan_finding.id),
                "question": "How do I fix this finding?"
            },
            headers=headers
        )
        assert res.status_code == 200
        mock_provider.ask_dependency_question.assert_called_once()
        call_kwargs = mock_provider.ask_dependency_question.call_args[1]
        assert "requests==2.19.1" in call_kwargs["dep_context"]
        assert "CVE-2018-18074" in call_kwargs["dep_context"]



# ---------------------------------------------------------------------------
# 8. compute_minimum_fixed_version -- correct version comparison
# ---------------------------------------------------------------------------

class TestComputeMinimumFixedVersion:
    """compute_minimum_fixed_version must return the LOWEST fixed version
    strictly greater than the installed version, not the highest."""

    def test_minimum_not_maximum_pypi(self):
        """Fixed versions [2.20.0,2.31.0,2.32.0,2.32.4,2.33.0], installed 2.19.1
        -> minimum is 2.20.0, NOT 2.33.0."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            [["2.20.0"], ["2.31.0"], ["2.32.0"], ["2.32.4"], ["2.33.0"]],
            installed_version="2.19.1",
        )
        assert result == "2.20.0", f"Expected 2.20.0 (minimum), got {result!r}"

    def test_minimum_with_flat_list_pypi(self):
        """Flat list input (not nested) is also supported."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            ["2.33.0", "2.20.0", "2.32.4", "2.31.0"],
            installed_version="2.19.1",
        )
        assert result == "2.20.0", f"Expected 2.20.0 (minimum), got {result!r}"

    def test_minimum_skips_versions_lte_installed(self):
        """Versions <= installed must be discarded."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            ["2.19.0", "2.19.1", "2.20.0", "2.31.0"],
            installed_version="2.19.1",
        )
        assert result == "2.20.0", f"Expected 2.20.0, got {result!r}"

    def test_none_when_all_fixes_lte_installed(self):
        """Returns None when every fixed version is <= installed version."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            ["2.18.0", "2.19.0", "2.19.1"],
            installed_version="2.19.1",
        )
        assert result is None, f"Expected None, got {result!r}"

    def test_none_when_no_fixed_versions(self):
        """Returns None when no fixed versions are supplied."""
        from backend.sca.findings import compute_minimum_fixed_version
        assert compute_minimum_fixed_version("PyPI", [], installed_version="2.19.1") is None
        assert compute_minimum_fixed_version("PyPI", [[]], installed_version="2.19.1") is None

    def test_minimum_from_mixed_sublists(self):
        """Mixed empty/populated sublists: returns minimum from populated ones."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            [[], ["2.31.0"], []],
            installed_version="2.19.1",
        )
        assert result == "2.31.0", f"Expected 2.31.0, got {result!r}"

    def test_minimum_npm(self):
        """npm version comparison works correctly."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "npm",
            [["4.17.21"], ["4.18.0"], ["5.0.0"]],
            installed_version="4.17.15",
        )
        assert result == "4.17.21", f"Expected 4.17.21, got {result!r}"

    def test_minimum_maven(self):
        """Maven version comparison works correctly."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "Maven",
            [["2.17.2"], ["2.18.0"], ["3.0.0"]],
            installed_version="2.14.1",
        )
        assert result == "2.17.2", f"Expected 2.17.2, got {result!r}"

    def test_minimum_fixed_differs_from_covering_version(self):
        """For the real requests==2.19.1 advisory set:
        minimum_fixed=2.20.0 (EARLIEST fix) vs covering=2.33.0 (ALL advisories)."""
        from backend.sca.findings import compute_minimum_fixed_version, compute_minimum_covering_version
        fixed_by_advisory = [
            ["2.20.0"], ["2.20.0"],   # CVE-2018-18074
            ["2.31.0"], ["2.31.0"],   # CVE-2023-32681
            ["2.32.0"], ["2.32.0"],   # CVE-2024-35195
            ["2.32.4"], ["2.32.4"],   # CVE-2024-47081
            ["2.33.0"], ["2.33.0"],   # CVE-2026-25645
        ]
        installed = "2.19.1"
        minimum_fixed = compute_minimum_fixed_version("PyPI", fixed_by_advisory, installed)
        covering = compute_minimum_covering_version("PyPI", fixed_by_advisory, installed)
        assert minimum_fixed == "2.20.0", \
            f"Minimum fixed version must be 2.20.0, got {minimum_fixed!r}"
        assert covering == "2.33.0", \
            f"Covering version must be 2.33.0, got {covering!r}"
        assert minimum_fixed != covering

    def test_numeric_not_lexicographical_pypi(self):
        """Python package version comparison must be numeric (PEP 440), NOT string-based.
        In string comparison, '2.10.0' < '2.2.0', which would be incorrect."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            ["2.10.0", "2.2.0", "2.9.0"],
            installed_version="2.1.0",
        )
        assert result == "2.2.0", f"Expected 2.2.0 (numeric minimum), got {result!r}"

    def test_pep440_prerelease_and_post_comparison(self):
        """PEP 440 prereleases and post releases are compared correctly."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            ["2.20.0rc1", "2.20.0", "2.20.0.post1"],
            installed_version="2.20.0rc1",
        )
        assert result == "2.20.0", f"Expected 2.20.0 strictly greater than rc1, got {result!r}"

    def test_missing_and_unknown_fixed_versions_handled(self):
        """Advisories with None, empty lists, or invalid strings ('unknown') are filtered safely."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "PyPI",
            [None, [], ["unknown"], ["invalid-ver-format"], ["2.20.0"], ["2.31.0"]],
            installed_version="2.19.1",
        )
        assert result == "2.20.0", f"Expected 2.20.0, got {result!r}"

    def test_all_missing_or_unknown_returns_none(self):
        """Returns None when only invalid/unknown/empty versions are provided."""
        from backend.sca.findings import compute_minimum_fixed_version
        assert compute_minimum_fixed_version("PyPI", [None, [], ["unknown"], [""], ["   "]], installed_version="2.19.1") is None

    def test_npm_numeric_not_lexicographical(self):
        """npm semver comparison must be numeric ('1.2.0' < '1.10.0')."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "npm",
            ["1.10.0", "1.2.0"],
            installed_version="1.1.0",
        )
        assert result == "1.2.0", f"Expected 1.2.0, got {result!r}"

    def test_maven_numeric_not_lexicographical(self):
        """Maven dotted comparison must be numeric ('2.2.1' < '2.10.1')."""
        from backend.sca.findings import compute_minimum_fixed_version
        result = compute_minimum_fixed_version(
            "Maven",
            ["2.10.1", "2.2.1"],
            installed_version="2.1.0",
        )
        assert result == "2.2.1", f"Expected 2.2.1, got {result!r}"


# ---------------------------------------------------------------------------
# 9. build_copilot_context_for_dep -- version label disambiguation
# ---------------------------------------------------------------------------

class TestBuildContextVersionLabels:
    """build_copilot_context_for_dep must emit 'Minimum fixed version' and
    'Recommended covering version' as separate, clearly-labelled fields."""

    _BASE_ADVISORIES = [
        {"id": "GHSA-x84v", "cve": "CVE-2018-18074", "severity": "MEDIUM",
         "summary": "Session redirect", "fixed": ["2.20.0"]},
        {"id": "GHSA-j8r2", "cve": "CVE-2023-32681", "severity": "MEDIUM",
         "summary": "Proxy-Auth header leak", "fixed": ["2.31.0"]},
        {"id": "GHSA-gc5v", "cve": "CVE-2026-25645", "severity": "MEDIUM",
         "summary": "CRLF injection", "fixed": ["2.33.0"]},
    ]

    def _build(self, covering="2.33.0", advisories=None):
        from backend.sca.findings import build_copilot_context_for_dep
        return build_copilot_context_for_dep(
            dep_name="requests", dep_version="2.19.1", ecosystem="PyPI",
            manifest_file="requirements.txt", recommended_version=covering,
            advisory_details=advisories or self._BASE_ADVISORIES,
        )

    def test_minimum_fixed_label_present(self):
        assert "Minimum fixed version:" in self._build()

    def test_covering_version_label_present(self):
        assert "Recommended covering version:" in self._build()

    def test_minimum_fixed_is_earliest_value(self):
        ctx = self._build()
        for line in ctx.splitlines():
            if "Minimum fixed version:" in line:
                assert "2.20.0" in line, \
                    f"Minimum fixed version line must contain 2.20.0, got: {line!r}"
                return
        pytest.fail("No 'Minimum fixed version:' line found in context")

    def test_covering_version_is_correct_value(self):
        ctx = self._build(covering="2.33.0")
        for line in ctx.splitlines():
            if "Recommended covering version:" in line:
                assert "2.33.0" in line, \
                    f"Covering version line must contain 2.33.0, got: {line!r}"
                return
        pytest.fail("No 'Recommended covering version:' line found in context")

    def test_labels_are_not_confused(self):
        ctx = self._build(covering="2.33.0")
        for line in ctx.splitlines():
            if "Minimum fixed version:" in line:
                assert "2.33.0" not in line, \
                    f"Minimum line must NOT contain the covering version 2.33.0: {line!r}"
            if "Recommended covering version:" in line:
                assert "2.20.0" not in line, \
                    f"Covering line must NOT contain the minimum fixed version 2.20.0: {line!r}"

    def test_missing_fix_advisory_flagged(self):
        from backend.sca.findings import build_copilot_context_for_dep
        advisories = [
            {"id": "GHSA-fixed", "cve": "CVE-2023-0001", "severity": "HIGH",
             "summary": "Has a fix", "fixed": ["1.2.0"]},
            {"id": "GHSA-missing", "cve": "CVE-2023-9999", "severity": "CRITICAL",
             "summary": "No known fix", "fixed": []},
        ]
        ctx = build_copilot_context_for_dep(
            dep_name="foo", dep_version="1.0.0", ecosystem="PyPI",
            manifest_file="requirements.txt", recommended_version=None,
            advisory_details=advisories,
        )
        assert "GHSA-missing" in ctx
        assert "manual review" in ctx.lower()
        assert ("no fixed version available" in ctx.lower() or
                "missing/unknown" in ctx.lower())

    def test_no_missing_fixes_states_none(self):
        assert "Advisories with missing/unknown fixed versions: None" in self._build()

    def test_covering_version_not_a_latest_release_claim(self):
        ctx = self._build(covering="2.33.0")
        assert "is the latest" not in ctx.lower()
        assert ("not a claim about the latest available release" in ctx.lower() or
                "not the latest" in ctx.lower())

    def test_installed_version_shown(self):
        ctx = self._build()
        assert "Installed version: 2.19.1" in ctx or "installed `2.19.1`" in ctx.lower()

    def test_unknown_fixed_string_flagged_as_missing(self):
        from backend.sca.findings import build_copilot_context_for_dep
        advisories = [
            {"id": "GHSA-has-fix", "cve": "CVE-2023-0001", "severity": "HIGH",
             "summary": "Valid fix", "fixed": ["2.20.0"]},
            {"id": "GHSA-unknown-fix", "cve": "CVE-2023-0002", "severity": "MEDIUM",
             "summary": "Fix unknown", "fixed": ["unknown"]},
        ]
        ctx = build_copilot_context_for_dep(
            dep_name="requests", dep_version="2.19.1", ecosystem="PyPI",
            manifest_file="requirements.txt", recommended_version=None,
            advisory_details=advisories,
        )
        assert "GHSA-unknown-fix" in ctx
        assert "Advisories with missing/unknown fixed versions: GHSA-unknown-fix" in ctx
        assert "Minimum fixed version: 2.20.0" in ctx

    def test_minimum_not_determinable_when_no_fixes_gt_installed(self):
        from backend.sca.findings import build_copilot_context_for_dep
        advisories = [
            {"id": "GHSA-old-1", "severity": "MEDIUM", "summary": "Old", "fixed": ["2.18.0"]},
            {"id": "GHSA-old-2", "severity": "LOW", "summary": "Old2", "fixed": ["2.19.1"]},
        ]
        ctx = build_copilot_context_for_dep(
            dep_name="requests", dep_version="2.19.1", ecosystem="PyPI",
            manifest_file="requirements.txt", recommended_version=None,
            advisory_details=advisories,
        )
        assert "Minimum fixed version: not determinable" in ctx
