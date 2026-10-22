import json
import os
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session

from backend.models.models import ScanHistory, ScanFinding, Project, File


def calculate_security_score(critical: int, high: int, medium: int, low: int) -> int:
    """
    Computes security score out of 100 using the standard formula:
    penalty = critical * 15 + high * 8 + medium * 3 + low * 1
    score = max(0, 100 - penalty)
    """
    penalty = (critical or 0) * 15 + (high or 0) * 8 + (medium or 0) * 3 + (low or 0) * 1
    return max(0, 100 - penalty)


def format_finding_item(
    finding: ScanFinding,
    old_version: Optional[str] = None,
    new_version: Optional[str] = None,
    note: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Formats a ScanFinding row into a standard item dictionary for diff responses."""
    tools: List[str] = []
    if finding.source_tools:
        if isinstance(finding.source_tools, str):
            try:
                tools = json.loads(finding.source_tools)
            except Exception:
                tools = [finding.source_tools]
        elif isinstance(finding.source_tools, list):
            tools = [str(t) for t in finding.source_tools]

    item = {
        "id": str(finding.id),
        "file": finding.file_path,
        "line": finding.line_number,
        "type": finding.type,
        "severity": finding.severity,
        "cwe": finding.cwe_id,
        "source_tools": tools,
        "vulnerability_id": str(finding.vulnerability_id) if finding.vulnerability_id else None,
    }

    if finding.type == "vulnerable_dependency" or finding.package_name:
        item["package_name"] = finding.package_name
        item["old_version"] = old_version
        item["new_version"] = new_version

    if note:
        item["note"] = note
    if reason:
        item["reason"] = reason

    return item


def compute_scan_diff(
    db: Session,
    target_scan: ScanHistory,
    base_scan: ScanHistory,
    project: Project,
) -> Dict[str, Any]:
    """
    Computes a deterministic, honest scan diff comparing target_scan against base_scan.

    Definitions:
    - persisting: In both base and target scan
    - resolved: In base scan, not in target scan, and comparable under honesty rules
    - new: In target scan, not in base scan, and never seen in any retained earlier scan
    - regressed: In target scan, not in base scan, but seen in an earlier retained scan
    - not_comparable: In base scan, but cannot be judged (detector didn't run or file removed)
    """
    # 1. Fetch findings for both scans
    target_findings = (
        db.query(ScanFinding)
        .filter(ScanFinding.scan_id == target_scan.id)
        .all()
    )
    base_findings = (
        db.query(ScanFinding)
        .filter(ScanFinding.scan_id == base_scan.id)
        .all()
    )

    target_by_fp: Dict[str, ScanFinding] = {f.fingerprint: f for f in target_findings}
    base_by_fp: Dict[str, ScanFinding] = {f.fingerprint: f for f in base_findings}

    # 2. Check earlier retained scans to distinguish new vs regressed findings
    target_only_fps = set(target_by_fp.keys()) - set(base_by_fp.keys())
    seen_earlier_fps: Set[str] = set()

    if target_only_fps:
        earlier_scans = (
            db.query(ScanHistory.id)
            .filter(
                ScanHistory.project_id == project.id,
                ScanHistory.status == "completed",
                ScanHistory.scan_time < target_scan.scan_time,
                ScanHistory.id != base_scan.id,
            )
            .order_by(ScanHistory.scan_time.desc())
            .limit(20)
            .all()
        )
        earlier_scan_ids = [s.id for s in earlier_scans]
        if earlier_scan_ids:
            seen_rows = (
                db.query(ScanFinding.fingerprint)
                .filter(
                    ScanFinding.project_id == project.id,
                    ScanFinding.scan_id.in_(earlier_scan_ids),
                    ScanFinding.fingerprint.in_(target_only_fps),
                )
                .distinct()
                .all()
            )
            seen_earlier_fps = {r[0] for r in seen_rows}

    # 3. Target scan file coverage for the 'file was scanned' honesty rule
    target_scanned_files: Set[str] = set()
    if target_scan.scanned_files:
        try:
            target_scanned_files = {
                os.path.normpath(p).replace("\\", "/")
                for p in json.loads(target_scan.scanned_files)
            }
        except Exception:
            pass
    if not target_scanned_files:
        # Fallback to File table only when scanned_files column was not populated (legacy)
        target_scanned_files = {
            os.path.normpath(f.filepath).replace("\\", "/")
            for f in db.query(File.filepath).filter(File.project_id == project.id).all()
        }

    # 4. Engine run lists for the detector honesty rule
    target_engines: Set[str] = set()
    if target_scan.engines_run:
        try:
            target_engines = {str(e).strip().lower() for e in json.loads(target_scan.engines_run)}
        except Exception:
            pass

    base_engines: Set[str] = set()
    if base_scan.engines_run:
        try:
            base_engines = {str(e).strip().lower() for e in json.loads(base_scan.engines_run)}
        except Exception:
            pass

    # Result item buckets
    items_persisting: List[Dict[str, Any]] = []
    items_new: List[Dict[str, Any]] = []
    items_regressed: List[Dict[str, Any]] = []
    items_resolved: List[Dict[str, Any]] = []
    items_not_comparable: List[Dict[str, Any]] = []
    notes: List[str] = []

    # Track reasons for honesty notes
    unrun_tool_counts: Dict[str, int] = {}
    removed_file_count = 0

    # 5. Process target findings: persisting, new, regressed
    for fp, tf in target_by_fp.items():
        if fp in base_by_fp:
            bf = base_by_fp[fp]
            old_ver = bf.package_version
            new_ver = tf.package_version
            version_note = None
            if old_ver and new_ver and old_ver != new_ver:
                version_note = f"Version upgraded from {old_ver} to {new_ver} (still vulnerable)"
            items_persisting.append(
                format_finding_item(tf, old_version=old_ver, new_version=new_ver, note=version_note)
            )
        else:
            if fp in seen_earlier_fps:
                items_regressed.append(
                    format_finding_item(
                        tf,
                        new_version=tf.package_version,
                        note="Finding re-appeared after being fixed or absent in base scan",
                    )
                )
            else:
                items_new.append(
                    format_finding_item(
                        tf,
                        new_version=tf.package_version,
                    )
                )

    # 6. Process base findings absent in target: resolved vs not_comparable
    for fp, bf in base_by_fp.items():
        if fp in target_by_fp:
            continue

        norm_path = os.path.normpath(bf.file_path).replace("\\", "/")

        # Honesty Rule 2: File was not covered in target scan
        if norm_path not in target_scanned_files:
            removed_file_count += 1
            items_not_comparable.append(
                format_finding_item(
                    bf,
                    old_version=bf.package_version,
                    reason="file not scanned (file removed from project or skipped)",
                )
            )
            continue

        # Honesty Rule 1: Did a detector that found this run in target scan?
        finding_tools: List[str] = []
        if bf.source_tools:
            try:
                parsed = json.loads(bf.source_tools) if isinstance(bf.source_tools, str) else bf.source_tools
                finding_tools = [str(t).strip().lower() for t in parsed]
            except Exception:
                finding_tools = [str(bf.source_tools).strip().lower()]

        # A finding is comparable if at least one tool that found it ran in target scan
        # (and in base scan if base_engines recorded)
        tools_ran_in_target = [t for t in finding_tools if t in target_engines]

        if target_engines and not tools_ran_in_target:
            # None of the tools that found this ran in target scan
            missing_tools = ", ".join(sorted(finding_tools))
            for t in finding_tools:
                unrun_tool_counts[t] = unrun_tool_counts.get(t, 0) + 1

            items_not_comparable.append(
                format_finding_item(
                    bf,
                    old_version=bf.package_version,
                    reason=f"detector did not run or failed in current scan ({missing_tools})",
                )
            )
        else:
            # Comparable: genuinely resolved!
            resolve_note = "resolved via apply-fix" if bf.fixed_by_apply_fix else None
            items_resolved.append(
                format_finding_item(
                    bf,
                    old_version=bf.package_version,
                    note=resolve_note,
                )
            )

    # 7. Generate aggregate notes
    for tool_name, count in unrun_tool_counts.items():
        notes.append(f"{tool_name.capitalize()} did not run in this scan; {count} finding(s) not comparable.")
    if removed_file_count > 0:
        notes.append(f"{removed_file_count} finding(s) not comparable (file not scanned or removed).")

    # Check for scan capping notes
    if target_scan.warnings:
        try:
            warns = json.loads(target_scan.warnings) if isinstance(target_scan.warnings, str) else target_scan.warnings
            for w in warns:
                if "capped" in str(w).lower():
                    notes.append(str(w))
        except Exception:
            pass

    # 8. Scores and deltas
    score_before = calculate_security_score(
        base_scan.critical_count,
        base_scan.high_count,
        base_scan.medium_count,
        base_scan.low_count,
    )

    if len(items_not_comparable) > 0:
        score_after = None
        severity_delta = None
        notes.append(
            f"Score and severity deltas withheld: {len(items_not_comparable)} finding(s) not comparable "
            f"(detector failed, file not scanned/removed, or capped scan). Deltas cannot be accurately evaluated."
        )
    else:
        score_after = calculate_security_score(
            target_scan.critical_count,
            target_scan.high_count,
            target_scan.medium_count,
            target_scan.low_count,
        )

        severity_delta = {
            "critical": (target_scan.critical_count or 0) - (base_scan.critical_count or 0),
            "high": (target_scan.high_count or 0) - (base_scan.high_count or 0),
            "medium": (target_scan.medium_count or 0) - (base_scan.medium_count or 0),
            "low": (target_scan.low_count or 0) - (base_scan.low_count or 0),
        }

    summary = {
        "new": len(items_new),
        "resolved": len(items_resolved),
        "persisting": len(items_persisting),
        "regressed": len(items_regressed),
        "not_comparable": len(items_not_comparable),
    }

    # Cap items lists at 200 elements per category to keep payload manageable
    CAP = 200
    capped_items = {
        "new": items_new[:CAP],
        "resolved": items_resolved[:CAP],
        "persisting": items_persisting[:CAP],
        "regressed": items_regressed[:CAP],
        "not_comparable": items_not_comparable[:CAP],
    }

    return {
        "scan_id": str(target_scan.id),
        "base_scan_id": str(base_scan.id),
        "summary": summary,
        "score_before": score_before,
        "score_after": score_after,
        "severity_delta": severity_delta,
        "items": capped_items,
        "notes": notes,
    }
