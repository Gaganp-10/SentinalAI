import re
import logging
from typing import List, Dict, Tuple, Optional, Any
from packaging.version import parse as parse_pypi_version, InvalidVersion

from backend.detectors.schema import Finding
from backend.sca.parsers import ParsedDependency, normalize_pypi_name
from backend.utils.owasp_map import get_owasp_category

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

# Maximum advisories to include in explanations, PDFs, and Copilot context.
# Excess advisories are summarised as "and N more" with an osv.dev search link.
MAX_ADVISORIES_SHOWN = 10


def normalize_severity(sev_raw: Optional[str]) -> Tuple[str, bool]:
    """
    Normalizes advisory severity string to one of: critical, high, medium, low.
    Returns (severity, is_provided_by_source).
    """
    if not sev_raw:
        return ("medium", False)

    s = str(sev_raw).strip().upper()
    if "CRITICAL" in s:
        return ("critical", True)
    elif "HIGH" in s:
        return ("high", True)
    elif "MODERATE" in s or "MEDIUM" in s:
        return ("medium", True)
    elif "LOW" in s:
        return ("low", True)
    return ("medium", False)


def parse_semver_npm(ver_str: str) -> Optional[Tuple[int, ...]]:
    """Parses npm semver numerically, ignoring prerelease / build tags."""
    clean = ver_str.lstrip("vV").split("-")[0].split("+")[0].strip()
    parts = clean.split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def parse_dotted_maven(ver_str: str) -> Optional[Tuple[int, ...]]:
    """Parses Maven version only when it consists of plain dotted numbers."""
    parts = ver_str.strip().split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _is_valid_ecosystem_version(ecosystem: str, ver_str: str) -> bool:
    """Validates that a string looks like an ecosystem version, not a git commit SHA."""
    if not ver_str:
        return False
    # Reject 40-character hex commit hashes from git ranges
    if re.fullmatch(r"[0-9a-fA-F]{40}", ver_str):
        return False
    if ecosystem == "PyPI":
        try:
            parse_pypi_version(ver_str)
            return True
        except (InvalidVersion, TypeError):
            return False
    elif ecosystem == "npm":
        return parse_semver_npm(ver_str) is not None
    elif ecosystem == "Maven":
        return parse_dotted_maven(ver_str) is not None
    return False


def extract_fixed_versions(advisory: dict, ecosystem: str, package_name: str) -> List[str]:
    """
    Extracts valid package fixed version strings from an advisory for the matching package.
    Ignores GIT-type ranges and commit hashes in favor of ECOSYSTEM/SEMVER ranges.
    """
    fixed: List[str] = []
    for aff in advisory.get("affected", []):
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem", "")
        pname = pkg.get("name", "")

        eco_match = (eco.lower() == ecosystem.lower())
        if ecosystem == "PyPI":
            name_match = (normalize_pypi_name(pname) == normalize_pypi_name(package_name))
        else:
            name_match = (pname.lower() == package_name.lower())

        if eco_match and name_match:
            ranges = aff.get("ranges", [])
            for r in ranges:
                # Do not extract git commit SHAs from GIT ranges
                if r.get("type") == "GIT":
                    continue
                for ev in r.get("events", []):
                    if "fixed" in ev and ev["fixed"]:
                        f_ver = str(ev["fixed"]).strip()
                        if _is_valid_ecosystem_version(ecosystem, f_ver):
                            if f_ver not in fixed:
                                fixed.append(f_ver)
    return fixed


def compute_minimum_covering_version(
    ecosystem: str,
    fixed_versions_by_advisory: List[List[str]]
) -> Optional[str]:
    """
    Computes the minimum version that covers all advisories.
    If any advisory has no valid fixed version, returns None.
    """
    if not fixed_versions_by_advisory:
        return None

    # Every advisory must provide at least one valid fixed version
    for fixes in fixed_versions_by_advisory:
        if not fixes:
            return None

    if ecosystem == "PyPI":
        adv_highest = []
        for fixes in fixed_versions_by_advisory:
            parsed = []
            for v in fixes:
                try:
                    parsed.append((parse_pypi_version(v), v))
                except (InvalidVersion, TypeError):
                    continue
            if not parsed:
                return None
            adv_highest.append(max(parsed, key=lambda x: x[0]))
        highest = max(adv_highest, key=lambda x: x[0])
        return highest[1]

    elif ecosystem == "npm":
        adv_highest = []
        for fixes in fixed_versions_by_advisory:
            parsed = []
            for v in fixes:
                p = parse_semver_npm(v)
                if p is not None:
                    parsed.append((p, v))
            if not parsed:
                return None
            adv_highest.append(max(parsed, key=lambda x: x[0]))
        highest = max(adv_highest, key=lambda x: x[0])
        return highest[1]

    elif ecosystem == "Maven":
        adv_highest = []
        for fixes in fixed_versions_by_advisory:
            parsed = []
            for v in fixes:
                p = parse_dotted_maven(v)
                if p is not None:
                    parsed.append((p, v))
            if not parsed:
                return None
            adv_highest.append(max(parsed, key=lambda x: x[0]))
        highest = max(adv_highest, key=lambda x: x[0])
        return highest[1]

    return None


def build_dependency_finding(
    dep: ParsedDependency,
    advisory_ids: List[str],
    advisories_map: Dict[str, dict]
) -> Finding:
    """
    Constructs a single Finding record grouping all advisories for (manifest_file, package, version).
    """
    adv_records = [advisories_map[aid] for aid in advisory_ids if aid in advisories_map]

    # 1. Determine highest severity
    highest_sev = "low"
    highest_rank = -1
    any_sev_provided = False

    all_cwes: List[str] = []
    fixed_by_advisory: List[List[str]] = []
    advisory_details_list = []
    advisory_sev_ranks: List[int] = []

    for aid in advisory_ids:
        rec = advisories_map.get(aid, {})
        # Extract severity
        sev_raw = rec.get("database_specific", {}).get("severity")
        sev_norm, is_prov = normalize_severity(sev_raw)
        if is_prov:
            any_sev_provided = True
        rank = SEVERITY_RANKS.get(sev_norm, 1)
        if rank > highest_rank:
            highest_rank = rank
            highest_sev = sev_norm

        # Extract CWEs
        cwes = rec.get("database_specific", {}).get("cwe_ids", [])
        if isinstance(cwes, list):
            for c in cwes:
                c_str = str(c).strip().upper()
                if c_str and c_str not in all_cwes:
                    all_cwes.append(c_str)

        # Extract fixed versions for this advisory
        fixes = extract_fixed_versions(rec, dep.ecosystem, dep.name)
        fixed_by_advisory.append(fixes)

        # Collect summary & aliases
        aliases = rec.get("aliases", [])
        cve_aliases = [a for a in aliases if str(a).upper().startswith("CVE-")]
        summary = rec.get("summary") or (rec.get("details", "")[:120].strip() if rec.get("details") else "No summary provided")
        # Remove line breaks from summary for clean one-line rendering
        summary_clean = re.sub(r"\s+", " ", summary)
        if len(summary_clean) > 150:
            summary_clean = summary_clean[:147] + "..."

        advisory_details_list.append({
            "id": aid,
            "cve": cve_aliases[0] if cve_aliases else None,
            "all_aliases": aliases,
            "summary": summary_clean,
            "severity": sev_norm.upper() if is_prov else "Not provided",
            "severity_rank": rank,
            "fixed": fixes,
            "url": f"https://osv.dev/vulnerability/{aid}"
        })

    if not any_sev_provided:
        highest_sev = "medium"

    # Sort advisory details by severity descending (highest first)
    advisory_details_list.sort(key=lambda x: x["severity_rank"], reverse=True)

    first_cwe = all_cwes[0] if all_cwes else None

    # Compute recommended covering version
    recommended_version = compute_minimum_covering_version(dep.ecosystem, fixed_by_advisory)

    # Dependency metadata description
    dep_nature = "Direct" if dep.direct is True else ("Transitive" if dep.direct is False else "Unknown dependency type")
    dep_env = "Dev dependency" if dep.dev else "Production dependency"

    # Build rich deterministic Markdown explanation
    lines = []
    lines.append(f"### Vulnerable Dependency: `{dep.name}` ({dep.ecosystem})")
    lines.append(f"- **Installed Version**: `{dep.version}`")
    lines.append(f"- **Dependency Type**: {dep_nature} ({dep_env})")
    lines.append(f"- **Manifest File**: `{dep.manifest_file}`")

    if not any_sev_provided:
        lines.append("- **Severity Note**: Severity not provided by source (defaulted to medium).")

    lines.append("")
    lines.append("#### Recommended Action")
    if recommended_version:
        lines.append(f"Upgrade `{dep.name}` to **`{recommended_version}`** or newer to resolve all detected advisories.")
    else:
        lines.append(f"Manual upgrade recommended: Review and update `{dep.name}` manually. No single safe fixed version could be automatically determined.")

    total_advisories = len(advisory_details_list)
    shown_advisories = advisory_details_list[:MAX_ADVISORIES_SHOWN]
    hidden_count = total_advisories - len(shown_advisories)
    osv_search_url = f"https://osv.dev/list?ecosystem={dep.ecosystem}&q={dep.name}"

    lines.append("")
    lines.append(f"#### Known Vulnerabilities ({total_advisories} advisories)")
    for item in shown_advisories:
        alias_str = f" ({item['cve']})" if item['cve'] else ""
        fix_str = f" — Fixed in: `{', '.join(item['fixed'])}`" if item['fixed'] else " — No fixed version reported"
        lines.append(f"- **[{item['id']}]({item['url']}){alias_str}** [{item['severity']}]: {item['summary']}{fix_str}")
    if hidden_count > 0:
        lines.append(f"- *…and {hidden_count} more — [view all on osv.dev]({osv_search_url})*")

    recommendation_md = "\n".join(lines)

    short_desc = (
        f"Package '{dep.name}' version '{dep.version}' in {dep.manifest_file} has "
        f"{len(advisory_ids)} known vulnerability advisory(s). "
        f"{'Recommended version: >= ' + recommended_version if recommended_version else 'Manual upgrade recommended.'}"
    )

    code_snippet = (
        f"{dep.name}=={dep.version}" if dep.ecosystem == "PyPI"
        else f"{dep.name}@{dep.version} ({dep.manifest_file})"
    )

    return Finding(
        file_path=dep.manifest_file,
        line_number=dep.line or 1,
        type="vulnerable_dependency",
        severity=highest_sev,
        description=short_desc,
        recommendation=recommendation_md,
        code_snippet=code_snippet,
        suggested_fix=f"Update {dep.name} to >= {recommended_version}" if recommended_version else None,
        cwe_id=first_cwe,
        owasp_category=get_owasp_category(first_cwe, finding_type="vulnerable_dependency"),
        confidence=1.0,
        source_tool="osv",
        fixed=False,
        auto_fixable=False,
        fix_source=None,
        rule_id=f"osv-{dep.name}",
        issue_class=None  # Never merges with code findings
    )


def build_copilot_context_for_dep(
    dep_name: str,
    dep_version: str,
    ecosystem: str,
    manifest_file: str,
    recommended_version: Optional[str],
    advisory_details: List[Dict],
) -> str:
    """
    Builds a compact, capped context string for the AI Security Copilot for
    vulnerable_dependency findings.  Only the package declaration line,
    capped advisory summaries, and fixed versions are included.
    The manifest/lockfile content is NEVER sent.
    """
    cap = MAX_ADVISORIES_SHOWN
    shown = advisory_details[:cap]
    hidden = len(advisory_details) - len(shown)

    if ecosystem == "PyPI":
        package_line = f"{dep_name}=={dep_version}"
    elif ecosystem == "npm":
        package_line = f'"{dep_name}": "{dep_version}"'
    else:
        # Maven: groupId:artifactId:version
        package_line = f"{dep_name}:{dep_version}"

    lines = [
        f"Vulnerable dependency in `{manifest_file}`:",
        f"  Package: {package_line}",
        f"  Ecosystem: {ecosystem}",
    ]
    if recommended_version:
        lines.append(f"  Recommended minimum version: >= {recommended_version}")
    else:
        lines.append("  Recommended minimum version: not determinable — manual review needed")

    lines.append(f"\nKnown advisories ({len(advisory_details)} total, showing top {len(shown)}):")
    for adv in shown:
        cve_part = f" ({adv['cve']})" if adv.get("cve") else ""
        fix_part = f"; fixed in {', '.join(adv['fixed'])}" if adv.get("fixed") else ""
        lines.append(f"  - {adv['id']}{cve_part} [{adv['severity']}]: {adv['summary']}{fix_part}")

    if hidden > 0:
        osv_url = f"https://osv.dev/list?ecosystem={ecosystem}&q={dep_name}"
        lines.append(f"  - ...and {hidden} more: {osv_url}")

    return "\n".join(lines)
