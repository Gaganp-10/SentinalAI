import os
import logging
from typing import List, Dict, Tuple, Set, Any

from backend.detectors.schema import Finding
from backend.sca.parsers import (
    parse_manifests_in_directory,
    ParsedDependency,
    UnresolvedDependency,
)
from backend.sca.osv_client import OSVClient, OSVClientError
from backend.sca.findings import build_dependency_finding

logger = logging.getLogger(__name__)


def scan_dependencies(
    project_dir: str,
    client: OSVClient = None
) -> Tuple[List[Finding], List[str], Dict[str, int]]:
    """
    Executes Software Composition Analysis (SCA) on the uploaded project manifests.
    Returns:
        findings: List of Finding objects for vulnerable dependencies
        warnings: List of warning messages (unreachable OSV, unpinned packages, etc.)
        summary: {"checked": N, "not_checked": M, "manifests": K}
    """
    if client is None:
        client = OSVClient()

    deps, unresolved, parse_warnings = parse_manifests_in_directory(project_dir)

    # Collect distinct manifest files
    manifest_files = set()
    for d in deps:
        manifest_files.add(d.manifest_file)
    for u in unresolved:
        manifest_files.add(u.manifest_file)

    checked_count = len({(d.ecosystem, d.name, d.version) for d in deps})
    not_checked_count = len(unresolved)
    manifests_count = len(manifest_files)

    summary = {
        "checked": checked_count,
        "not_checked": not_checked_count,
        "manifests": manifests_count
    }

    warnings: List[str] = list(parse_warnings)

    if not_checked_count > 0:
        warnings.append(
            f"{not_checked_count} dependencies were not checked (unpinned versions or unresolvable)"
        )

    if not deps:
        return [], warnings, summary

    # Group dependencies by (manifest_file, name, version)
    # to preserve file and line locations
    deps_by_key: Dict[Tuple[str, str, str, str], ParsedDependency] = {}
    query_payloads: List[Dict[str, str]] = []

    for d in deps:
        # Key includes manifest_file so multiple manifests with same dependency each get a finding
        k = (d.manifest_file, d.ecosystem, d.name, d.version)
        if k not in deps_by_key:
            deps_by_key[k] = d
        query_payloads.append({
            "ecosystem": d.ecosystem,
            "name": d.name,
            "version": d.version
        })

    # Query OSV.dev
    try:
        results_map, query_warns = client.query_batch(query_payloads)
        warnings.extend(query_warns)
    except OSVClientError as e:
        warn_msg = "Dependency check could not be completed (OSV.dev unreachable)"
        logger.warning(f"{warn_msg}: {e}")
        warnings.append(warn_msg)
        return [], warnings, summary
    except Exception as e:
        warn_msg = f"Dependency check failed: {e}"
        logger.error(warn_msg, exc_info=True)
        warnings.append("Dependency check could not be completed (OSV.dev unreachable)")
        return [], warnings, summary

    # Collect all unique advisory IDs for packages with vulnerabilities
    all_adv_ids: Set[str] = set()
    for (eco, name, ver), adv_list in results_map.items():
        for aid in adv_list:
            all_adv_ids.add(aid)

    # Fetch full advisory records
    advisories_map: Dict[str, dict] = {}
    if all_adv_ids:
        try:
            advs, adv_warns = client.fetch_advisories(all_adv_ids)
            advisories_map.update(advs)
            warnings.extend(adv_warns)
        except Exception as e:
            warn_msg = f"Failed to fetch advisory details from OSV.dev: {e}"
            logger.warning(warn_msg)
            warnings.append(warn_msg)

    # Build findings
    findings: List[Finding] = []
    for (mfile, eco, name, ver), dep_obj in deps_by_key.items():
        adv_ids = results_map.get((eco, name, ver), [])
        if adv_ids:
            finding = build_dependency_finding(dep_obj, adv_ids, advisories_map)
            findings.append(finding)

    # Sort findings by file path and severity
    findings.sort(key=lambda x: (x.file_path, x.line_number))
    return findings, warnings, summary
