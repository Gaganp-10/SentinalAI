import hashlib
import os
import re
from typing import List, Optional
from backend.detectors.schema import Finding


def normalize_snippet(snippet: Optional[str]) -> str:
    """
    Normalizes a code snippet for stable fingerprinting.
    - Strips line number prefixes (e.g., '12: ', '12 | ', '12 ->')
    - Strips leading and trailing whitespace
    - Collapses internal whitespace into single spaces
    """
    if not snippet:
        return ""

    lines = []
    for line in snippet.splitlines():
        # Strip common line-number / pipe prefixes
        cleaned = re.sub(r"^\s*\d+[\s:|>]\s*", "", line)
        lines.append(cleaned)

    text = " ".join(lines)
    # Collapse multiple whitespace characters (including newlines and tabs)
    return re.sub(r"\s+", " ", text).strip()


def compute_code_fingerprint(
    file_path: str,
    finding_type: str,
    issue_class: Optional[str],
    code_snippet: Optional[str],
    occurrence_index: int = 1,
) -> str:
    """
    Computes a stable SHA-256 fingerprint for a code finding:
    SHA-256 of: file_path | issue_class (or normalized type) | normalized snippet

    Survives line shifts (code inserted above) and whitespace-only changes.
    If occurrence_index > 1, appends ':<occurrence_index>' to distinguish
    identical lines within the same file.

    Known limitation:
    Renaming a variable or changing the flagged line itself changes the
    fingerprint, so it shows as one new and one resolved finding.
    """
    norm_path = os.path.normpath(file_path).replace("\\", "/").strip().lower()
    norm_type = (issue_class or finding_type or "").strip().lower()
    norm_code = normalize_snippet(code_snippet)

    raw_key = f"{norm_path}|{norm_type}|{norm_code}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    if occurrence_index > 1:
        return f"{digest}:{occurrence_index}"
    return digest


def compute_dependency_fingerprint(
    manifest_path: str,
    ecosystem: str,
    package_name: str,
) -> str:
    """
    Computes a stable SHA-256 fingerprint for a dependency finding:
    SHA-256 of: manifest_path | ecosystem | package name (version excluded).

    Excluding the version ensures that upgrading to another still-vulnerable
    version counts as persisting, and downgrading later can be detected as a
    regression.
    """
    norm_manifest = os.path.normpath(manifest_path).replace("\\", "/").strip().lower()
    norm_eco = (ecosystem or "").strip().lower()
    norm_pkg = (package_name or "").strip().lower()

    raw_key = f"{norm_manifest}|{norm_eco}|{norm_pkg}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def assign_fingerprints(findings: List[Finding]) -> List[str]:
    """
    Assigns stable fingerprints to a list of findings for a project scan.
    Maintains per-file occurrence counters for code findings to distinguish
    identical occurrences within the same file.
    """
    fingerprints: List[str] = []
    # Key: (norm_file_path, base_hash) -> count
    seen_counts = {}

    for f in findings:
        if f.type == "vulnerable_dependency":
            pkg = getattr(f, "package_name", None) or f.rule_id.replace("osv-", "") if f.rule_id else ""
            eco = getattr(f, "ecosystem", None) or "pypi"
            fp = compute_dependency_fingerprint(f.file_path, eco, pkg)
            fingerprints.append(fp)
        else:
            # First compute base hash with occurrence 1
            base_fp = compute_code_fingerprint(
                file_path=f.file_path,
                finding_type=f.type,
                issue_class=f.issue_class,
                code_snippet=f.code_snippet,
                occurrence_index=1,
            )
            norm_path = os.path.normpath(f.file_path).replace("\\", "/").strip().lower()
            key = (norm_path, base_fp)
            count = seen_counts.get(key, 0) + 1
            seen_counts[key] = count

            if count > 1:
                fp = f"{base_fp}:{count}"
            else:
                fp = base_fp
            fingerprints.append(fp)

    return fingerprints
