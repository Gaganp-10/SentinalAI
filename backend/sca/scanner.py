import os
import logging
from typing import List, Dict, Tuple, Set, Any

from backend.detectors.schema import Finding
from backend.sca.parsers import (
    parse_manifests_in_directory,
    ParsedDependency,
    UnresolvedDependency,
)
from backend.sca.osv_client import OSVClient, OSVClientError, MAX_BATCH_SIZE
from backend.sca.findings import build_dependency_finding

logger = logging.getLogger(__name__)


def scan_dependencies(
    project_dir: str,
    client: OSVClient = None
) -> Tuple[List[Finding], List[str], Dict[str, int]]:
    """
    Executes Software Composition Analysis (SCA) on the uploaded project manifests.
    Handles partial OSV failures: successful batch results are preserved even when
    other batches fail.  Returns accurate checked/failed/not_checked counts.

    Returns:
        findings: List of Finding objects for vulnerable dependencies
        warnings: List of warning messages (unreachable OSV, unpinned packages, etc.)
        summary: {"checked": N, "failed": F, "not_checked": M, "manifests": K}
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

    pinned_count = len({(d.ecosystem, d.name, d.version) for d in deps})
    not_checked_count = len(unresolved)
    manifests_count = len(manifest_files)

    summary = {
        "checked": 0,
        "failed": 0,
        "not_checked": not_checked_count,
        "manifests": manifests_count,
    }

    warnings: List[str] = list(parse_warnings)

    if not_checked_count > 0:
        warnings.append(
            f"{not_checked_count} dependencies were not checked (unpinned versions or unresolvable)"
        )

    if not deps:
        return [], warnings, summary

    # Deduplicate deps for querying (multiple manifests can reference same package)
    deps_by_key: Dict[Tuple[str, str, str, str], ParsedDependency] = {}
    unique_queries: List[Dict[str, str]] = []
    seen_query_keys: Set[Tuple[str, str, str]] = set()

    for d in deps:
        k = (d.manifest_file, d.ecosystem, d.name, d.version)
        if k not in deps_by_key:
            deps_by_key[k] = d

        qk = (d.ecosystem, d.name, d.version)
        if qk not in seen_query_keys:
            seen_query_keys.add(qk)
            unique_queries.append({
                "ecosystem": d.ecosystem,
                "name": d.name,
                "version": d.version,
            })

    # --- Partial-failure batch querying ---
    # Split unique queries into chunks; query each independently so a failure
    # in one chunk does not discard results from the others.
    results_map: Dict[Tuple[str, str, str], List[str]] = {}
    checked_count = 0
    failed_count = 0
    chunk_warnings: List[str] = []

    chunks = [
        unique_queries[i: i + MAX_BATCH_SIZE]
        for i in range(0, len(unique_queries), MAX_BATCH_SIZE)
    ]

    for chunk in chunks:
        try:
            chunk_result, q_warns = client.query_batch(chunk)
            results_map.update(chunk_result)
            chunk_warnings.extend(q_warns)
            checked_count += len(chunk)
        except (OSVClientError, Exception) as e:
            failed_count += len(chunk)
            logger.warning(f"OSV batch failed for {len(chunk)} packages: {e}")

    warnings.extend(chunk_warnings)

    if failed_count > 0 and checked_count == 0:
        # Complete failure
        summary["checked"] = 0
        summary["failed"] = pinned_count
        warn_msg = (
            f"0 checked · {pinned_count} could not be checked (OSV unreachable) · "
            f"{not_checked_count} not pinned"
        )
        warnings.append(warn_msg)
        return [], warnings, summary
    elif failed_count > 0:
        # Partial failure
        summary["checked"] = checked_count
        summary["failed"] = failed_count
        warn_msg = (
            f"{checked_count} checked · {failed_count} could not be checked (OSV batch error) · "
            f"{not_checked_count} not pinned"
        )
        warnings.append(warn_msg)
    else:
        summary["checked"] = checked_count
        summary["failed"] = 0

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

