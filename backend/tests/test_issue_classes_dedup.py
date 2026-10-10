import pytest
from backend.detectors.schema import Finding
from backend.detectors.orchestrator import Orchestrator
from backend.detectors.issue_classes import (
    get_issue_class,
    get_canonical_cwe,
    ISSUE_CLASSES,
    RULE_TO_ISSUE_CLASS
)


def test_issue_class_canonical_cwes():
    assert get_canonical_cwe("SQL_INJECTION") == "CWE-89"
    assert get_canonical_cwe("COMMAND_INJECTION") == "CWE-78"
    assert get_canonical_cwe("HARDCODED_CREDENTIAL") == "CWE-798"
    assert get_canonical_cwe("WEAK_HASH") == "CWE-328"
    assert get_canonical_cwe("CODE_INJECTION") == "CWE-95"
    assert get_canonical_cwe("INSECURE_DESERIALIZATION") == "CWE-502"
    assert get_canonical_cwe("BUFFER_OVERFLOW") == "CWE-120"


def test_rule_mapping_resolution():
    # Bandit rule IDs
    assert get_issue_class("B105") == "HARDCODED_CREDENTIAL"
    assert get_issue_class("B324") == "WEAK_HASH"
    assert get_issue_class("B307") == "CODE_INJECTION"
    assert get_issue_class("B608") == "SQL_INJECTION"
    assert get_issue_class("B602") == "COMMAND_INJECTION"
    assert get_issue_class("B301") == "INSECURE_DESERIALIZATION"

    # Semgrep check IDs (with and without prefix)
    assert get_issue_class("python-sqli") == "SQL_INJECTION"
    assert get_issue_class("backend.python-sqli") == "SQL_INJECTION"
    assert get_issue_class("backend.python-hashlib-md5") == "WEAK_HASH"
    assert get_issue_class("backend.python-eval") == "CODE_INJECTION"
    assert get_issue_class("backend.js-hardcoded-secret") == "HARDCODED_CREDENTIAL"

    # AST rule IDs
    assert get_issue_class("ast-hardcoded-secret") == "HARDCODED_CREDENTIAL"
    assert get_issue_class("Hardcoded Secret") == "HARDCODED_CREDENTIAL"
    assert get_issue_class("ast-weak-hash-md5") == "WEAK_HASH"
    assert get_issue_class("ast-eval") == "CODE_INJECTION"


def test_hardcoded_credential_pair_merges():
    """Line 3/4: Bandit CWE-259 vs AST CWE-798 vs adjacent AST CWE-798 merge into 1 finding."""
    f1 = Finding(
        file_path="app.py",
        line_number=3,
        type="hardcoded_password_string",
        severity="medium",
        description="Possible hardcoded password",
        cwe_id="CWE-259",
        source_tool="bandit",
        rule_id="B105",
        code_snippet='DB_PASSWORD = "admin123"\n'
    )
    f2 = Finding(
        file_path="app.py",
        line_number=3,
        type="Hardcoded Secret",
        severity="high",
        description="Potential secret",
        cwe_id="CWE-798",
        source_tool="ast",
        rule_id="ast-hardcoded-secret",
        code_snippet='DB_PASSWORD = "admin123"'
    )
    f3 = Finding(
        file_path="app.py",
        line_number=4,
        type="Hardcoded Secret",
        severity="high",
        description="Potential secret",
        cwe_id="CWE-798",
        source_tool="ast",
        rule_id="ast-hardcoded-secret",
        code_snippet='API_KEY = "secret"'
    )

    orc = Orchestrator()
    merged = orc.dedup_findings([f1, f2, f3])
    assert len(merged) == 1
    assert merged[0].cwe_id == "CWE-798"
    assert merged[0].issue_class == "HARDCODED_CREDENTIAL"
    assert "bandit" in merged[0].source_tool
    assert "ast" in merged[0].source_tool
    assert merged[0].owasp_category.startswith("A07:2021")


def test_weak_hash_pair_merges():
    """Line 16: Bandit CWE-327 vs Semgrep CWE-328 vs AST CWE-328 merge into 1 finding."""
    f_bandit = Finding(
        file_path="app.py",
        line_number=16,
        type="hashlib",
        severity="medium",
        description="Weak MD5 hash",
        cwe_id="CWE-327",
        source_tool="bandit",
        rule_id="B324",
        code_snippet="hashlib.md5(x)"
    )
    f_semgrep = Finding(
        file_path="app.py",
        line_number=16,
        type="Python Hashlib Md5",
        severity="medium",
        description="Weak MD5",
        cwe_id="CWE-328",
        source_tool="semgrep",
        rule_id="python-hashlib-md5",
        code_snippet="hashlib.md5(x)"
    )
    f_ast = Finding(
        file_path="app.py",
        line_number=16,
        type="Weak Hashing Algorithm",
        severity="medium",
        description="Weak hash",
        cwe_id="CWE-328",
        source_tool="ast",
        rule_id="ast-weak-hash-md5",
        code_snippet="hashlib.md5(x)"
    )

    orc = Orchestrator()
    merged = orc.dedup_findings([f_bandit, f_semgrep, f_ast])
    assert len(merged) == 1
    assert merged[0].cwe_id == "CWE-328"
    assert merged[0].issue_class == "WEAK_HASH"
    assert "bandit" in merged[0].source_tool
    assert "semgrep" in merged[0].source_tool
    assert "ast" in merged[0].source_tool
    assert merged[0].owasp_category.startswith("A02:2021")


def test_eval_pair_merges():
    """Line 19: Bandit CWE-78 vs Semgrep CWE-95 vs AST CWE-95 merge into 1 finding."""
    f_bandit = Finding(
        file_path="app.py",
        line_number=19,
        type="blacklist",
        severity="high",
        description="Insecure function eval",
        cwe_id="CWE-78",
        source_tool="bandit",
        rule_id="B307",
        code_snippet="eval(code)"
    )
    f_semgrep = Finding(
        file_path="app.py",
        line_number=19,
        type="Python Eval",
        severity="high",
        description="Dangerous eval",
        cwe_id="CWE-95",
        source_tool="semgrep",
        rule_id="python-eval",
        code_snippet="eval(code)"
    )
    f_ast = Finding(
        file_path="app.py",
        line_number=19,
        type="Dangerous Function Execution",
        severity="high",
        description="Dangerous eval",
        cwe_id="CWE-95",
        source_tool="ast",
        rule_id="ast-eval",
        code_snippet="eval(code)"
    )

    orc = Orchestrator()
    merged = orc.dedup_findings([f_bandit, f_semgrep, f_ast])
    assert len(merged) == 1
    assert merged[0].cwe_id == "CWE-95"
    assert merged[0].issue_class == "CODE_INJECTION"
    assert "bandit" in merged[0].source_tool
    assert "semgrep" in merged[0].source_tool
    assert "ast" in merged[0].source_tool
    assert merged[0].owasp_category.startswith("A03:2021")


def test_separate_occurrences_stay_separate():
    """Two occurrences of the same issue_class at distant lines must stay separate."""
    f1 = Finding(
        file_path="app.py",
        line_number=10,
        type="hashlib",
        severity="medium",
        description="MD5 call 1",
        cwe_id="CWE-327",
        source_tool="bandit",
        rule_id="B324",
        code_snippet="hashlib.md5(a)"
    )
    f2 = Finding(
        file_path="app.py",
        line_number=30,
        type="Python Hashlib Md5",
        severity="medium",
        description="MD5 call 2",
        cwe_id="CWE-328",
        source_tool="semgrep",
        rule_id="python-hashlib-md5",
        code_snippet="hashlib.md5(b)"
    )

    orc = Orchestrator()
    merged = orc.dedup_findings([f1, f2])
    assert len(merged) == 2
    assert merged[0].line_number == 10
    assert merged[1].line_number == 30
    assert merged[0].cwe_id == "CWE-328"
    assert merged[1].cwe_id == "CWE-328"


def test_tolerance_boundary():
    """Findings within 1 line merge; findings 2 lines apart stay separate."""
    orc = Orchestrator()

    # Within 1 line (e.g. line 10 and line 11) -> merges
    f_10 = Finding(file_path="a.py", line_number=10, type="t", severity="low", description="d", rule_id="B608", cwe_id="CWE-89")
    f_11 = Finding(file_path="a.py", line_number=11, type="t", severity="low", description="d", rule_id="python-sqli", cwe_id="CWE-89")
    assert len(orc.dedup_findings([f_10, f_11])) == 1

    # 2 lines apart (line 10 and line 12) -> stays separate
    f_12 = Finding(file_path="a.py", line_number=12, type="t", severity="low", description="d", rule_id="python-sqli", cwe_id="CWE-89")
    assert len(orc.dedup_findings([f_10, f_12])) == 2


def test_unclassified_rules_not_merged_by_class():
    """Rules without an issue_class are not merged across different rule IDs."""
    f1 = Finding(file_path="a.py", line_number=10, type="Custom Rule A", severity="low", description="d", rule_id="custom-rule-a")
    f2 = Finding(file_path="a.py", line_number=10, type="Custom Rule B", severity="low", description="d", rule_id="custom-rule-b")

    orc = Orchestrator()
    merged = orc.dedup_findings([f1, f2])
    # They have different types and no issue class -> stay separate
    assert len(merged) == 2
