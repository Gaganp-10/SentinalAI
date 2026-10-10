"""
Issue Classes and Canonical CWE Mapping Table
==============================================
Central repository defining unified vulnerability issue classes across detectors
(Bandit test_id, Semgrep check_id, and AST rule_id).

Each issue class specifies exactly ONE canonical CWE and documents the rationale.
Detectors assign an issue_class to findings based on their rule identifier.
Rules without an issue_class are never merged by class.
"""

from typing import Optional, Dict, Any

# Canonical CWE and rationale per issue class
ISSUE_CLASSES: Dict[str, Dict[str, str]] = {
    "SQL_INJECTION": {
        "canonical_cwe": "CWE-89",
        "description": "SQL Injection",
        "rationale": "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) is the definitive MITRE CWE for SQL injection across all tools and languages.",
    },
    "COMMAND_INJECTION": {
        "canonical_cwe": "CWE-78",
        "description": "Command Injection / OS Execution",
        "rationale": "CWE-78 (OS Command Injection) is the canonical MITRE CWE for shell execution, system calls, and subprocess execution with shell=True.",
    },
    "HARDCODED_CREDENTIAL": {
        "canonical_cwe": "CWE-798",
        "description": "Hard-coded Credentials and Secrets",
        "rationale": "CWE-798 (Use of Hard-coded Credentials) is the standard parent CWE covering all hard-coded secrets, tokens, API keys, and passwords. Bandit reports CWE-259 (Hard-coded Password, a specific sub-type), while AST and Semgrep report CWE-798. Standardizing on CWE-798 unifies credential detection under OWASP A07:2021.",
    },
    "WEAK_HASH": {
        "canonical_cwe": "CWE-328",
        "description": "Weak Cryptographic Hash",
        "rationale": "CWE-328 (Use of Weak Hash) is the specific MITRE CWE for MD5/SHA-1 weak hashing. Bandit maps B324 to generic crypto CWE-327, while Semgrep and AST map to CWE-328. Canonicalizing to CWE-328 provides the precise CWE under OWASP A02:2021.",
    },
    "CODE_INJECTION": {
        "canonical_cwe": "CWE-95",
        "description": "Dynamically Evaluated Code Injection (Eval)",
        "rationale": "CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code - 'Eval Injection') is the specific MITRE CWE for eval/exec. Bandit B307 maps by default to CWE-78 (command injection), whereas Semgrep and AST report CWE-95. Canonicalizing to CWE-95 accurately reflects eval injection under OWASP A03:2021.",
    },
    "INSECURE_DESERIALIZATION": {
        "canonical_cwe": "CWE-502",
        "description": "Insecure Deserialization",
        "rationale": "CWE-502 (Deserialization of Untrusted Data) is the canonical MITRE CWE for unsafe deserialization (pickle, yaml, ObjectInputStream) under OWASP A08:2021.",
    },
    "BUFFER_OVERFLOW": {
        "canonical_cwe": "CWE-120",
        "description": "Buffer Overflow / Unsafe Copy",
        "rationale": "CWE-120 (Buffer Copy without Checking Size of Input) is the canonical CWE for unsafe string copies in C/C++.",
    },
}

# Mapping from detector-specific rule identifiers to issue class
RULE_TO_ISSUE_CLASS: Dict[str, str] = {
    # --- Bandit test_id & test_name ---
    "B608": "SQL_INJECTION",
    "B610": "SQL_INJECTION",
    "B611": "SQL_INJECTION",
    "hardcoded_sql_expressions": "SQL_INJECTION",

    "B601": "COMMAND_INJECTION",
    "B602": "COMMAND_INJECTION",
    "B603": "COMMAND_INJECTION",
    "B604": "COMMAND_INJECTION",
    "B605": "COMMAND_INJECTION",
    "B606": "COMMAND_INJECTION",
    "B607": "COMMAND_INJECTION",
    "B609": "COMMAND_INJECTION",
    "B404": "COMMAND_INJECTION",
    "subprocess_popen_with_shell_equals_true": "COMMAND_INJECTION",

    "B105": "HARDCODED_CREDENTIAL",
    "B106": "HARDCODED_CREDENTIAL",
    "B107": "HARDCODED_CREDENTIAL",
    "hardcoded_password_string": "HARDCODED_CREDENTIAL",

    "B303": "WEAK_HASH",
    "B304": "WEAK_HASH",
    "B305": "WEAK_HASH",
    "B324": "WEAK_HASH",
    "B413": "WEAK_HASH",
    "hashlib": "WEAK_HASH",

    "B307": "CODE_INJECTION",
    "B102": "CODE_INJECTION",
    "eval": "CODE_INJECTION",

    "B301": "INSECURE_DESERIALIZATION",
    "B302": "INSECURE_DESERIALIZATION",
    "B403": "INSECURE_DESERIALIZATION",
    "B506": "INSECURE_DESERIALIZATION",
    "pickle": "INSECURE_DESERIALIZATION",

    # --- Semgrep rule ids ---
    "python-sqli": "SQL_INJECTION",
    "java-sql-injection": "SQL_INJECTION",

    "python-subprocess-shell": "COMMAND_INJECTION",
    "js-child-process-exec": "COMMAND_INJECTION",
    "java-command-injection": "COMMAND_INJECTION",
    "c-system-call": "COMMAND_INJECTION",
    "php-command-injection": "COMMAND_INJECTION",

    "js-hardcoded-secret": "HARDCODED_CREDENTIAL",

    "python-hashlib-md5": "WEAK_HASH",

    "python-eval": "CODE_INJECTION",
    "js-eval": "CODE_INJECTION",
    "php-eval": "CODE_INJECTION",

    "python-pickle-loads": "INSECURE_DESERIALIZATION",

    "c-unsafe-strcpy": "BUFFER_OVERFLOW",

    # --- AST detector rule ids ---
    "ast-sql-injection": "SQL_INJECTION",
    "SQL Injection": "SQL_INJECTION",

    "ast-hardcoded-secret": "HARDCODED_CREDENTIAL",
    "Hardcoded Secret": "HARDCODED_CREDENTIAL",

    "ast-weak-hash-md5": "WEAK_HASH",
    "Weak Hashing Algorithm": "WEAK_HASH",

    "ast-eval": "CODE_INJECTION",
    "Dangerous Function Execution": "CODE_INJECTION",
}


def get_issue_class(rule_id: Optional[str]) -> Optional[str]:
    """
    Resolves a detector rule ID to its canonical issue class.
    Handles qualified check IDs (e.g. 'backend.python-sqli' -> 'python-sqli').
    Returns None if rule_id is not mapped (unclassified rules are never merged by class).
    """
    if not rule_id:
        return None
    # Strip namespace prefix if present (e.g. 'backend.python-sqli' -> 'python-sqli')
    norm_id = rule_id.split(".")[-1].strip()
    if norm_id in RULE_TO_ISSUE_CLASS:
        return RULE_TO_ISSUE_CLASS[norm_id]
    if rule_id in RULE_TO_ISSUE_CLASS:
        return RULE_TO_ISSUE_CLASS[rule_id]
    return None


def get_canonical_cwe(issue_class: Optional[str]) -> Optional[str]:
    """
    Returns the canonical CWE string (e.g. 'CWE-89') for an issue class.
    """
    if not issue_class or issue_class not in ISSUE_CLASSES:
        return None
    return ISSUE_CLASSES[issue_class]["canonical_cwe"]
