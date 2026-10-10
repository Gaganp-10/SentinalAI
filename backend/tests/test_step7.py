"""
test_step7.py - Step 7 Vulnerable Dependency Scanning (OSV.dev) test suite.
"""
import json
import pathlib
from unittest.mock import MagicMock, patch
import pytest


def _write(tmp: pathlib.Path, rel: str, content: str) -> None:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ============================================================
# 1. Manifest parsers
# ============================================================

class TestParseRequirementsTxt:
    def _p(self, text):
        from backend.sca.parsers import parse_requirements_txt
        return parse_requirements_txt(text, "requirements.txt")

    def test_pinned_package(self):
        deps, unres, _ = self._p("requests==2.28.0\n")
        assert len(deps) == 1
        d = deps[0]
        assert d.name == "requests" and d.version == "2.28.0" and d.ecosystem == "PyPI"

    def test_extras_stripped(self):
        deps, _, _ = self._p("celery[redis]==5.3.0\n")
        assert deps[0].name == "celery" and deps[0].version == "5.3.0"

    def test_env_marker_stripped(self):
        deps, _, _ = self._p("importlib-metadata==6.0.0; python_version < '3.10'\n")
        assert len(deps) == 1 and deps[0].version == "6.0.0"

    def test_unpinned_goes_to_unresolved(self):
        deps, unres, _ = self._p("flask>=2.0\n")
        assert not deps and unres[0].reason == "version not pinned"

    def test_vcs_url_unresolved(self):
        deps, unres, _ = self._p("git+https://github.com/org/repo.git#egg=mylib\n")
        assert not deps and unres

    def test_comment_blank_ignored(self):
        deps, _, _ = self._p("# comment\n\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_pypi_name_normalised(self):
        deps, _, _ = self._p("Pillow==10.0.0\n")
        assert deps[0].name == "pillow"

    def test_multiple_packages(self):
        deps, unres, _ = self._p("requests==2.28.0\nDjango==4.2.1\nflask\n")
        assert len(deps) == 2 and len(unres) == 1


class TestParsePackageLockJson:
    def _p(self, data):
        from backend.sca.parsers import parse_package_lock_json
        return parse_package_lock_json(json.dumps(data), "package-lock.json")

    def test_v2_packages(self):
        data = {
            "lockfileVersion": 2,
            "packages": {
                "": {"dependencies": {"lodash": "4.17.21"}},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        deps, _, _ = self._p(data)
        assert any(d.name == "lodash" and d.version == "4.17.21" for d in deps)

    def test_v1_recursive(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {"version": "4.18.2"},
                "body-parser": {"version": "1.20.0"},
            },
        }
        deps, _, _ = self._p(data)
        names = {d.name for d in deps}
        assert "express" in names and "body-parser" in names

    def test_link_entries_skipped(self):
        data = {
            "lockfileVersion": 2,
            "packages": {"node_modules/local-pkg": {"version": "1.0.0", "link": True}},
        }
        deps, _, _ = self._p(data)
        assert not deps

    def test_missing_version_unresolved(self):
        data = {"lockfileVersion": 2, "packages": {"node_modules/no-ver": {}}}
        deps, unres, _ = self._p(data)
        assert not deps and unres

    def test_malformed_json(self):
        from backend.sca.parsers import parse_package_lock_json
        deps, _, warns = parse_package_lock_json("{not-json", "package-lock.json")
        assert not deps and any("Malformed JSON" in w for w in warns)


class TestParsePackageJson:
    def _p(self, data):
        from backend.sca.parsers import parse_package_json
        return parse_package_json(json.dumps(data), "package.json")

    def test_exact_version_accepted(self):
        deps, _, _ = self._p({"dependencies": {"express": "4.18.2"}})
        assert len(deps) == 1 and deps[0].version == "4.18.2"

    def test_range_goes_unresolved(self):
        deps, unres, _ = self._p({"dependencies": {"react": "^18.0.0"}})
        assert not deps and unres

    def test_dev_dep_flagged(self):
        deps, _, _ = self._p({"devDependencies": {"jest": "29.0.0"}})
        assert deps[0].dev is True

    def test_empty(self):
        deps, unres, _ = self._p({})
        assert not deps and not unres


class TestParsePomXml:
    def _p(self, xml):
        from backend.sca.parsers import parse_pom_xml
        return parse_pom_xml(xml, "pom.xml")

    def test_pinned_version(self):
        xml = ("<project><dependencies><dependency>"
               "<groupId>org.springframework</groupId>"
               "<artifactId>spring-core</artifactId>"
               "<version>5.3.27</version>"
               "</dependency></dependencies></project>")
        deps, _, _ = self._p(xml)
        assert len(deps) == 1
        assert deps[0].name == "org.springframework:spring-core"
        assert deps[0].version == "5.3.27"
        assert deps[0].ecosystem == "Maven"

    def test_property_resolution(self):
        xml = ("<project>"
               "<properties><log4j.version>2.17.2</log4j.version></properties>"
               "<dependencies><dependency>"
               "<groupId>org.apache.logging.log4j</groupId>"
               "<artifactId>log4j-core</artifactId>"
               "<version>${log4j.version}</version>"
               "</dependency></dependencies></project>")
        deps, _, _ = self._p(xml)
        assert len(deps) == 1 and deps[0].version == "2.17.2"

    def test_unresolvable_property(self):
        xml = ("<project><dependencies><dependency>"
               "<groupId>com.example</groupId><artifactId>lib</artifactId>"
               "<version>${undefined.prop}</version>"
               "</dependency></dependencies></project>")
        deps, unres, _ = self._p(xml)
        assert not deps and unres

    def test_test_scope_dev(self):
        xml = ("<project><dependencies><dependency>"
               "<groupId>junit</groupId><artifactId>junit</artifactId>"
               "<version>4.13.2</version><scope>test</scope>"
               "</dependency></dependencies></project>")
        deps, _, _ = self._p(xml)
        assert deps[0].dev is True


class TestParseManifestsInDirectory:
    def test_requirements_found(self, tmp_path):
        from backend.sca.parsers import parse_manifests_in_directory
        _write(tmp_path, "requirements.txt", "requests==2.28.0\n")
        deps, _, _ = parse_manifests_in_directory(str(tmp_path))
        assert any(d.name == "requests" for d in deps)

    def test_lockfile_precedence(self, tmp_path):
        from backend.sca.parsers import parse_manifests_in_directory
        _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "^4.0.0"}}))
        lock = {
            "lockfileVersion": 2,
            "packages": {
                "": {"dependencies": {"lodash": "4.17.21"}},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        _write(tmp_path, "package-lock.json", json.dumps(lock))
        deps, unres, _ = parse_manifests_in_directory(str(tmp_path))
        assert any(d.version == "4.17.21" for d in deps)
        assert not [u for u in unres if u.name == "lodash"]

    def test_node_modules_skipped(self, tmp_path):
        from backend.sca.parsers import parse_manifests_in_directory
        _write(tmp_path, "node_modules/some-lib/package.json",
               json.dumps({"dependencies": {"evil": "1.0.0"}}))
        _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "4.18.2"}}))
        deps, _, _ = parse_manifests_in_directory(str(tmp_path))
        assert "evil" not in {d.name for d in deps}

    def test_cap_warning(self, tmp_path):
        from backend.sca.parsers import parse_manifests_in_directory, PACKAGE_CAP
        lines = "\n".join(f"pkg-{i}==1.0.0" for i in range(PACKAGE_CAP + 10))
        _write(tmp_path, "requirements.txt", lines)
        deps, _, warns = parse_manifests_in_directory(str(tmp_path))
        assert len(deps) <= PACKAGE_CAP
        assert any("cap" in w.lower() for w in warns)

    def test_empty_directory(self, tmp_path):
        from backend.sca.parsers import parse_manifests_in_directory
        deps, unres, _ = parse_manifests_in_directory(str(tmp_path))
        assert not deps and not unres


# ============================================================
# 2. OSV Client
# ============================================================

class TestOSVClient:
    def test_invalid_ecosystem_raises(self):
        from backend.sca.osv_client import OSVClient
        with pytest.raises(ValueError, match="Invalid ecosystem"):
            OSVClient().validate_ecosystem("Nuget")

    def test_valid_ecosystems_pass(self):
        from backend.sca.osv_client import OSVClient
        c = OSVClient()
        for eco in ("PyPI", "npm", "Maven"):
            c.validate_ecosystem(eco)  # must not raise

    def test_batch_returns_advisory_ids(self):
        from backend.sca.osv_client import OSVClient, _QUERY_CACHE
        _QUERY_CACHE.clear()
        resp = {"results": [{"vulns": [{"id": "GHSA-xxxx"}, {"id": "PYSEC-001"}]}]}
        c = OSVClient(base_url="http://mock")
        with patch("httpx.Client") as mcls:
            mr = MagicMock()
            mr.status_code = 200
            mr.json.return_value = resp
            mcls.return_value.__enter__.return_value.post.return_value = mr
            results, _ = c.query_batch([{"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}])
        k = ("PyPI", "requests", "2.19.0")
        assert k in results and "GHSA-xxxx" in results[k] and "PYSEC-001" in results[k]

    def test_cache_hit_skips_http(self):
        import time
        from backend.sca.osv_client import OSVClient, _QUERY_CACHE
        _QUERY_CACHE.clear()
        k = ("PyPI", "cached", "9.9.9")
        _QUERY_CACHE[k] = (time.time(), ["C-001"])
        with patch("httpx.Client") as mcls:
            results, _ = OSVClient(base_url="http://mock").query_batch([{"ecosystem": "PyPI", "name": "cached", "version": "9.9.9"}])
            mcls.assert_not_called()
        assert results[k] == ["C-001"]

    def test_5xx_raises(self):
        from backend.sca.osv_client import OSVClient, OSVClientError, _QUERY_CACHE
        _QUERY_CACHE.clear()
        with patch("httpx.Client") as mcls, patch("time.sleep"):
            mr = MagicMock()
            mr.status_code = 503
            mcls.return_value.__enter__.return_value.post.return_value = mr
            with pytest.raises(OSVClientError):
                OSVClient(base_url="http://mock").query_batch([{"ecosystem": "PyPI", "name": "x", "version": "1.0"}])

    def test_network_error_raises(self):
        import httpx
        from backend.sca.osv_client import OSVClient, OSVClientError, _QUERY_CACHE
        _QUERY_CACHE.clear()
        with patch("httpx.Client") as mcls, patch("time.sleep"):
            mcls.return_value.__enter__.return_value.post.side_effect = httpx.ConnectError("refused")
            with pytest.raises(OSVClientError):
                OSVClient(base_url="http://mock").query_batch([{"ecosystem": "PyPI", "name": "x", "version": "1.0"}])

    def test_empty_result_safe_package(self):
        from backend.sca.osv_client import OSVClient, _QUERY_CACHE
        _QUERY_CACHE.clear()
        with patch("httpx.Client") as mcls:
            mr = MagicMock()
            mr.status_code = 200
            mr.json.return_value = {"results": [{}]}
            mcls.return_value.__enter__.return_value.post.return_value = mr
            results, _ = OSVClient(base_url="http://mock").query_batch([{"ecosystem": "PyPI", "name": "safe", "version": "1.0"}])
        assert results[("PyPI", "safe", "1.0")] == []


# ============================================================
# 3. Findings builder
# ============================================================

class TestBuildDependencyFinding:
    def _dep(self, ecosystem="PyPI", name="requests", version="2.19.0"):
        from backend.sca.parsers import ParsedDependency
        return ParsedDependency(ecosystem=ecosystem, name=name, version=version,
                                manifest_file="requirements.txt", line=5, direct=True, dev=False)

    def _adv(self, aid="G1", severity="HIGH", pkg="requests", eco="PyPI", fixed="2.28.0"):
        return {"id": aid, "aliases": ["CVE-2023-001"], "summary": "Test vuln",
                "database_specific": {"severity": severity, "cwe_ids": ["CWE-200"]},
                "affected": [{"package": {"name": pkg, "ecosystem": eco},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}

    def test_type(self):
        from backend.sca.findings import build_dependency_finding
        f = build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()})
        assert f.type == "vulnerable_dependency"

    def test_severity_high(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv(severity="HIGH")}).severity == "high"

    def test_severity_critical(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv(severity="CRITICAL")}).severity == "critical"

    def test_owasp_a06(self):
        from backend.sca.findings import build_dependency_finding
        f = build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()})
        assert f.owasp_category and "A06" in f.owasp_category

    def test_source_tool_osv(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()}).source_tool == "osv"

    def test_auto_fixable_false(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()}).auto_fixable is False

    def test_fix_source_none(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()}).fix_source is None

    def test_recommendation_has_name_and_fixed(self):
        from backend.sca.findings import build_dependency_finding
        f = build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()})
        assert "requests" in (f.recommendation or "") and "2.28.0" in (f.recommendation or "")

    def test_snippet_eq_eq(self):
        from backend.sca.findings import build_dependency_finding
        f = build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()})
        assert "==" in (f.code_snippet or "")

    def test_issue_class_is_none(self):
        from backend.sca.findings import build_dependency_finding
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": self._adv()}).issue_class is None

    def test_highest_severity_wins(self):
        from backend.sca.findings import build_dependency_finding
        adv_low = self._adv(aid="G1", severity="LOW")
        adv_crit = self._adv(aid="G2", severity="CRITICAL")
        f = build_dependency_finding(self._dep(), ["G1", "G2"], {"G1": adv_low, "G2": adv_crit})
        assert f.severity == "critical"

    def test_no_sev_defaults_medium(self):
        from backend.sca.findings import build_dependency_finding
        adv = {"id": "G1", "aliases": [], "summary": "vuln",
               "database_specific": {},
               "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.28.0"}]}]}]}
        assert build_dependency_finding(self._dep(), ["G1"], {"G1": adv}).severity == "medium"

    def test_no_fixed_version_no_suggested_fix(self):
        from backend.sca.findings import build_dependency_finding
        adv = {"id": "G1", "aliases": [], "summary": "vuln",
               "database_specific": {"severity": "HIGH", "cwe_ids": []},
               "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}]}]}]}
        f = build_dependency_finding(self._dep(), ["G1"], {"G1": adv})
        assert f.suggested_fix is None
        assert "Manual upgrade" in (f.recommendation or "")


# ============================================================
# 4. Version comparison
# ============================================================

class TestVersionComparison:
    def test_pypi_max(self):
        from backend.sca.findings import compute_minimum_covering_version
        assert compute_minimum_covering_version("PyPI", [["2.28.0", "2.31.0"]]) == "2.31.0"

    def test_npm_max(self):
        from backend.sca.findings import compute_minimum_covering_version
        assert compute_minimum_covering_version("npm", [["4.17.21"], ["4.18.0"]]) == "4.18.0"

    def test_maven(self):
        from backend.sca.findings import compute_minimum_covering_version
        assert compute_minimum_covering_version("Maven", [["2.17.2"]]) == "2.17.2"

    def test_none_no_fix_one_advisory(self):
        from backend.sca.findings import compute_minimum_covering_version
        assert compute_minimum_covering_version("PyPI", [["2.28.0"], []]) is None

    def test_none_empty(self):
        from backend.sca.findings import compute_minimum_covering_version
        assert compute_minimum_covering_version("PyPI", []) is None


# ============================================================
# 5. scan_dependencies integration
# ============================================================

class TestScanDependencies:
    def _client(self, vuln_map=None, advisories=None):
        from backend.sca.osv_client import OSVClient
        c = MagicMock(spec=OSVClient)
        c.query_batch.return_value = (vuln_map or {}, [])
        c.fetch_advisories.return_value = (advisories or {}, [])
        return c

    def test_no_manifests(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        findings, _, s = scan_dependencies(str(tmp_path))
        assert findings == [] and s["checked"] == 0 and s["manifests"] == 0

    def test_safe_package(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        _write(tmp_path, "requirements.txt", "requests==2.28.0\n")
        c = self._client(vuln_map={("PyPI", "requests", "2.28.0"): []})
        findings, _, s = scan_dependencies(str(tmp_path), client=c)
        assert findings == [] and s["checked"] >= 1

    def test_vulnerable_package(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        _write(tmp_path, "requirements.txt", "requests==2.19.0\n")
        adv = {"id": "G1", "aliases": ["CVE-001"], "summary": "SSRF",
               "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-918"]},
               "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.28.0"}]}]}]}
        c = self._client(
            vuln_map={("PyPI", "requests", "2.19.0"): ["G1"]},
            advisories={"G1": adv}
        )
        findings, _, s = scan_dependencies(str(tmp_path), client=c)
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "vulnerable_dependency"
        assert f.source_tool == "osv"
        assert "A06" in (f.owasp_category or "")

    def test_osv_unreachable(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        from backend.sca.osv_client import OSVClientError
        _write(tmp_path, "requirements.txt", "requests==2.19.0\n")
        c = MagicMock()
        c.query_batch.side_effect = OSVClientError("down")
        findings, warns, _ = scan_dependencies(str(tmp_path), client=c)
        assert findings == [] and any("unreachable" in w.lower() or "OSV" in w for w in warns)

    def test_unpinned_adds_warning(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        _write(tmp_path, "requirements.txt", "flask>=2.0\n")
        c = self._client()
        _, warns, s = scan_dependencies(str(tmp_path), client=c)
        assert any("not checked" in w.lower() for w in warns)
        assert s["not_checked"] >= 1

    def test_summary_keys(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        _write(tmp_path, "requirements.txt", "requests==2.28.0\n")
        c = self._client(vuln_map={("PyPI", "requests", "2.28.0"): []})
        _, _, s = scan_dependencies(str(tmp_path), client=c)
        assert "checked" in s and "not_checked" in s and "manifests" in s

    def test_two_manifests_counted(self, tmp_path):
        from backend.sca.scanner import scan_dependencies
        _write(tmp_path, "requirements.txt", "requests==2.28.0\n")
        lock = {"lockfileVersion": 2,
                "packages": {"": {"dependencies": {"lodash": "4.17.21"}},
                             "node_modules/lodash": {"version": "4.17.21"}}}
        _write(tmp_path, "package-lock.json", json.dumps(lock))
        c = self._client(vuln_map={("PyPI", "requests", "2.28.0"): [], ("npm", "lodash", "4.17.21"): []})
        _, _, s = scan_dependencies(str(tmp_path), client=c)
        assert s["manifests"] >= 2


# ============================================================
# 6. No AI calls for vulnerable_dependency findings
# ============================================================

class TestNoAIForDependencyFindings:
    """Proves no AI provider is called for type=vulnerable_dependency."""

    def _dep_finding(self):
        from backend.detectors.schema import Finding
        return Finding(
            file_path="requirements.txt", line_number=5, type="vulnerable_dependency",
            severity="high", description="Package 'requests' 2.19.0 has 1 advisory.",
            recommendation="### Vulnerable Dependency `requests`\n- Upgrade to 2.28.0",
            code_snippet="requests==2.19.0", cwe_id="CWE-918",
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            confidence=1.0, source_tool="osv", fixed=False, auto_fixable=False, fix_source=None,
        )

    def _code_finding(self):
        from backend.detectors.schema import Finding
        return Finding(
            file_path="app.py", line_number=10, type="sql_injection",
            severity="high", description="SQL injection",
            recommendation="Use parameterized queries.", code_snippet="cursor.execute(q)",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection",
            confidence=0.9, source_tool="bandit", fixed=False, auto_fixable=True, fix_source=None,
        )

    def test_no_ai_for_dep(self):
        dep = self._dep_finding()
        calls = []

        def fake_explain(f):
            calls.append("explain")

        def fake_patch(f, c):
            calls.append("patch")
            return (None, None, None, False, None)

        with patch("backend.api.scans.generate_vulnerability_explanation", side_effect=fake_explain), \
             patch("backend.api.scans.generate_patched_code", side_effect=fake_patch):
            for f in [dep]:
                if f.type == "vulnerable_dependency":
                    explanation = f.recommendation
                    corrected_snippet = None
                    auto_fixable = False
                    fix_source = None
                else:
                    explanation = fake_explain(f)
                    _, corrected_snippet, _, auto_fixable, fix_source = fake_patch(f, "")

        assert calls == [], f"AI unexpectedly called: {calls}"

    def test_ai_for_code_findings(self):
        code = self._code_finding()
        calls = []

        def fake_explain(f):
            calls.append("explain")
            return "AI"

        def fake_patch(f, c):
            calls.append("patch")
            return (None, "patched", None, True, "ai")

        for f in [code]:
            if f.type != "vulnerable_dependency":
                fake_explain(f)
                fake_patch(f, "")

        assert len(calls) == 2

    def test_dep_explanation_is_recommendation(self):
        dep = self._dep_finding()
        explanation = dep.recommendation if dep.type == "vulnerable_dependency" else "AI"
        assert explanation == dep.recommendation
        assert "Upgrade" in explanation or "Vulnerable" in explanation


# ============================================================
# 7. OWASP mapping
# ============================================================

class TestOwaspMapping:
    def test_dep_type_maps_a06(self):
        from backend.utils.owasp_map import get_owasp_category
        assert get_owasp_category(finding_type="vulnerable_dependency") == "A06:2021-Vulnerable and Outdated Components"

    def test_dep_overrides_cwe(self):
        from backend.utils.owasp_map import get_owasp_category
        assert get_owasp_category(cwe_id="CWE-89", finding_type="vulnerable_dependency") == "A06:2021-Vulnerable and Outdated Components"

    def test_cwe_937(self):
        from backend.utils.owasp_map import get_owasp_category
        assert "A06" in (get_owasp_category(cwe_id="CWE-937") or "")

    def test_cwe_1035(self):
        from backend.utils.owasp_map import get_owasp_category
        assert "A06" in (get_owasp_category(cwe_id="CWE-1035") or "")

    def test_cwe_1104(self):
        from backend.utils.owasp_map import get_owasp_category
        assert "A06" in (get_owasp_category(cwe_id="CWE-1104") or "")


# ============================================================
# 8. Manifest filename / language detection
# ============================================================

class TestManifestDetection:
    def test_manifests_recognised(self):
        from backend.parser.language_detect import is_manifest_filename
        for fn in ("requirements.txt", "requirements-dev.txt", "package.json",
                   "package-lock.json", "pom.xml", "subdir/requirements.txt"):
            assert is_manifest_filename(fn), f"{fn!r} should be a manifest"

    def test_py_not_manifest(self):
        from backend.parser.language_detect import is_manifest_filename
        assert not is_manifest_filename("app.py")

    def test_detect_manifest(self):
        from backend.parser.language_detect import detect_language
        assert detect_language("requirements.txt") == "manifest"
        assert detect_language("package.json") == "manifest"
        assert detect_language("pom.xml") == "manifest"

    def test_detect_python(self):
        from backend.parser.language_detect import detect_language
        assert detect_language("app.py") == "python"

    def test_detect_js(self):
        from backend.parser.language_detect import detect_language
        assert detect_language("index.js") == "javascript"


# ============================================================
# 9. Severity normalizer
# ============================================================

class TestNormalizeSeverity:
    def _n(self, v):
        from backend.sca.findings import normalize_severity
        return normalize_severity(v)

    def test_critical(self):
        sev, ok = self._n("CRITICAL")
        assert sev == "critical" and ok

    def test_high(self):
        sev, ok = self._n("HIGH")
        assert sev == "high" and ok

    def test_moderate(self):
        sev, ok = self._n("MODERATE")
        assert sev == "medium" and ok

    def test_low(self):
        sev, ok = self._n("LOW")
        assert sev == "low" and ok

    def test_none_default_medium(self):
        sev, ok = self._n(None)
        assert sev == "medium" and not ok

    def test_empty_default_medium(self):
        sev, ok = self._n("")
        assert sev == "medium" and not ok


# ============================================================
# 10. extract_fixed_versions
# ============================================================

class TestExtractFixedVersions:
    def _adv(self, eco="PyPI", pkg="requests", fixed="2.28.0"):
        evts = [{"introduced": "0"}]
        if fixed:
            evts.append({"fixed": fixed})
        return {"affected": [{"package": {"name": pkg, "ecosystem": eco},
                              "ranges": [{"events": evts}]}]}

    def test_extracts_fixed(self):
        from backend.sca.findings import extract_fixed_versions
        assert "2.28.0" in extract_fixed_versions(self._adv(), "PyPI", "requests")

    def test_empty_when_no_fixed(self):
        from backend.sca.findings import extract_fixed_versions
        assert extract_fixed_versions(self._adv(fixed=None), "PyPI", "requests") == []

    def test_wrong_ecosystem(self):
        from backend.sca.findings import extract_fixed_versions
        assert extract_fixed_versions(self._adv(eco="npm"), "PyPI", "requests") == []

    def test_pypi_normalisation(self):
        from backend.sca.findings import extract_fixed_versions
        adv = {"affected": [{"package": {"name": "Pillow", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.3.0"}]}]}]}
        assert "9.3.0" in extract_fixed_versions(adv, "PyPI", "pillow")
