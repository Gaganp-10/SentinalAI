import os
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List, Optional
from uuid import UUID, uuid4

from backend.database.session import get_db, SessionLocal
from backend.models.models import Project, ScanHistory, File, Vulnerability, User, ScanFinding
from backend.models.schemas import ScanHistoryOut
from backend.api.auth import get_current_user
from backend.utils.config import settings
from backend.detectors.fingerprint import assign_fingerprints
from backend.detectors.diff import compute_scan_diff

router = APIRouter(tags=["Scans"])

logger = logging.getLogger(__name__)

import json
import concurrent.futures
from backend.ai.explainer import generate_vulnerability_explanation
from backend.fixer.fix_generator import generate_patched_code
from backend.ai.provider import FallbackTemplateProvider

_SEV_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _run_scan_engines(project_dir: str, engine_timeout: int = None):
    from backend.detectors.orchestrator import Orchestrator
    from backend.sca.scanner import scan_dependencies

    orchestrator = Orchestrator()
    code_findings = orchestrator.scan_project(project_dir, engine_timeout=engine_timeout)
    dep_findings, sca_warnings, dep_summary = scan_dependencies(project_dir)
    return orchestrator, code_findings, dep_findings, sca_warnings, dep_summary

def run_background_scan(project_id: UUID, scan_history_id: UUID):
    """
    Executes linter tools and dependency SCA on the uploaded files, processes the results,
    invokes the AI layer ONLY for code findings, and updates the scan database with findings,
    warnings, and dependency summary.
    """
    # Create isolated database session for the background thread
    db = SessionLocal()
    try:
        # Get scan history row
        scan = db.query(ScanHistory).filter(ScanHistory.id == scan_history_id).first()
        if not scan:
            logger.error(f"Scan history {scan_history_id} not found in database.")
            return
            
        scan.status = "running"
        db.commit()
        
        project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
        
        all_warnings: List[str] = []

        # Enforce scan timeout. SCANNER_TIMEOUT_SECONDS applies per-engine (a single engine
        # timing out yields completed+warnings, not failed). SCAN_TIMEOUT_SECONDS is the
        # hard outer wall for the entire scan pipeline.
        engine_timeout = settings.SCANNER_TIMEOUT_SECONDS or None
        outer_timeout = settings.SCAN_TIMEOUT_SECONDS or 300
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_run_scan_engines, project_dir, engine_timeout)
                orchestrator, code_findings, dep_findings, sca_warnings, dep_summary = future.result(timeout=outer_timeout)
        except concurrent.futures.TimeoutError:
            # Outer wall hit: entire scan pipeline exceeded the hard limit.
            # Set to 'completed' with a warning so the UI renders findings (there are none)
            # and shows the warning badge — 'failed' is reserved for infrastructure errors.
            logger.error(f"Scan {scan_history_id} exceeded outer timeout limit of {outer_timeout}s")
            scan.status = "completed"
            scan.warnings = json.dumps([f"Scan timed out after exceeding {outer_timeout}s limit. No findings recorded."])
            scan.engines_run = json.dumps([])
            scan.total_issues = 0
            db.commit()
            return

        all_warnings.extend(orchestrator.warnings)
        all_warnings.extend(sca_warnings)

        all_findings = code_findings + dep_findings
        # Prioritize findings by severity so top findings receive AI explanations
        all_findings.sort(key=lambda f: _SEV_PRIORITY.get((f.severity or "").lower(), 5))
        
        # 3. Clear old vulnerabilities for this project's files to allow fresh scans
        project_files = db.query(File).filter(File.project_id == project_id).all()
        file_ids = [f.id for f in project_files]
        if file_ids:
            db.query(Vulnerability).filter(Vulnerability.file_id.in_(file_ids)).delete(synchronize_session=False)
            db.commit()
            
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # 4. Assign fingerprints and process each unique finding
        fingerprints = assign_fingerprints(all_findings)
        scan_findings_to_insert = []
        ai_explanations_count = 0
        max_ai_explanations = settings.MAX_AI_EXPLANATIONS_PER_SCAN if settings.MAX_AI_EXPLANATIONS_PER_SCAN is not None else 10

        for idx, finding in enumerate(all_findings):
            norm_path = os.path.normpath(finding.file_path).replace("\\", "/")
            # Map back to DB File record
            db_file = db.query(File).filter(
                File.project_id == project_id,
                File.filepath == norm_path
            ).first()
            if not db_file:
                db_file = db.query(File).filter(
                    File.project_id == project_id,
                    File.filename == os.path.basename(norm_path)
                ).first()
            if not db_file:
                continue
                
            if finding.type == "vulnerable_dependency":
                # CRITICAL: Dependency findings must NOT go through AI explain or fix generation
                explanation = finding.recommendation
                corrected_snippet = finding.suggested_fix
                auto_fixable = False
                fix_source = None
            else:
                # Read full source code for code findings
                full_file_path = os.path.join(project_dir, finding.file_path)
                full_file_content = ""
                if os.path.exists(full_file_path):
                    try:
                        with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                            full_file_content = f.read()
                    except Exception as file_err:
                        logger.warning(f"Could not read {full_file_path} content: {file_err}")
                
                # Generate AI explanation (capped by MAX_AI_EXPLANATIONS_PER_SCAN) and fix
                if ai_explanations_count < max_ai_explanations:
                    explanation = generate_vulnerability_explanation(finding)
                    ai_explanations_count += 1
                else:
                    explanation = FallbackTemplateProvider().explain(
                        type_name=finding.type,
                        description=finding.description,
                        severity=finding.severity,
                        cwe_id=finding.cwe_id,
                        code_snippet=finding.code_snippet
                    )
                _, corrected_snippet, _, auto_fixable, fix_source = generate_patched_code(finding, full_file_content)
                orig_norm = " ".join((finding.code_snippet or "").split())
                fix_norm = " ".join((corrected_snippet or "").split())
                if not corrected_snippet or fix_norm == orig_norm:
                    auto_fixable = False
            
            # Count severity
            sev = finding.severity.lower()
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                medium_count += 1
            else:
                low_count += 1
                
            # Save vulnerability
            db_vuln = Vulnerability(
                file_id=db_file.id,
                type=finding.type,
                line_number=finding.line_number,
                severity=finding.severity,
                description=finding.description,
                recommendation=explanation,
                code_snippet=finding.code_snippet,
                suggested_fix=corrected_snippet,
                cwe_id=finding.cwe_id,
                owasp_category=finding.owasp_category,
                confidence=finding.confidence,
                source_tool=finding.source_tool,
                fixed=False,
                auto_fixable=auto_fixable,
                fix_source=fix_source
            )
            db.add(db_vuln)
            db.flush()

            # Prepare historical snapshot record
            tools_list = [t.strip() for t in (finding.source_tool or "").split(",") if t.strip()]
            scan_finding = ScanFinding(
                id=uuid4(),
                scan_id=scan.id,
                project_id=project_id,
                fingerprint=fingerprints[idx],
                file_path=norm_path,
                type=finding.type,
                issue_class=finding.issue_class,
                rule_id=finding.rule_id,
                cwe_id=finding.cwe_id,
                severity=finding.severity,
                line_number=finding.line_number,
                source_tools=json.dumps(tools_list),
                vulnerability_id=db_vuln.id,
                package_name=getattr(finding, "package_name", None),
                package_version=getattr(finding, "package_version", None),
            )
            scan_findings_to_insert.append(scan_finding)

        # Bulk insert scan findings snapshot
        if scan_findings_to_insert:
            db.bulk_save_objects(scan_findings_to_insert)

        # 5. Determine engines that ran successfully
        engines_run = list(orchestrator.engines_run)
        if dep_summary:
            if dep_summary.get("failed", 0) == 0 or dep_summary.get("checked", 0) > 0:
                engines_run.append("osv")
            
        # Collect per-scan file coverage (exact paths, normalized separators, no .lower())
        scanned_files_set = set()
        if os.path.exists(project_dir):
            for root, _, files in os.walk(project_dir):
                for file in files:
                    rel_p = os.path.relpath(os.path.join(root, file), project_dir).replace("\\", "/")
                    scanned_files_set.add(rel_p)
        for pf in project_files:
            if pf.filepath:
                scanned_files_set.add(os.path.normpath(pf.filepath).replace("\\", "/"))
        scanned_files_list = sorted(list(scanned_files_set))

        # 6. Finalize scan metadata
        scan.total_issues = len(all_findings)
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.warnings = json.dumps(all_warnings) if all_warnings else None
        scan.dependency_summary = json.dumps(dep_summary) if dep_summary else None
        scan.engines_run = json.dumps(engines_run)
        scan.scanned_files = json.dumps(scanned_files_list)
        scan.status = "completed"
        
        # Update parent project date
        project = db.query(Project).filter(Project.id == project_id).first()
        if project:
            project.scan_date = datetime.utcnow()

        # 7. Retention pruning: keep ScanFinding rows for the 20 most recent scans per project
        completed_scans = (
            db.query(ScanHistory.id)
            .filter(ScanHistory.project_id == project_id, ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_time.desc())
            .all()
        )
        if len(completed_scans) > 20:
            old_scan_ids = [s.id for s in completed_scans[20:]]
            db.query(ScanFinding).filter(
                ScanFinding.project_id == project_id,
                ScanFinding.scan_id.in_(old_scan_ids)
            ).delete(synchronize_session=False)
            
        db.commit()
        logger.info(f"Scan {scan_history_id} completed successfully. Issues: {len(all_findings)}, Warnings: {len(all_warnings)}, Engines: {engines_run}")
        
    except Exception as e:
        logger.error(f"Critical error during scan {scan_history_id}: {e}")
        try:
            scan = db.query(ScanHistory).filter(ScanHistory.id == scan_history_id).first()
            if scan:
                scan.status = "failed"
                db.commit()
        except Exception as db_err:
            logger.error(f"Failed to set scan status to FAILED: {db_err}")
    finally:
        db.close()


@router.post("/projects/{project_id}/scan", response_model=ScanHistoryOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers an asynchronous scan for the given project.
    Creates a scan_history record set to 'pending' and starts background workers.
    """
    # Verify ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    # Check if files exist
    files_count = db.query(File).filter(File.project_id == project_id).count()
    if files_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project has no uploaded files to scan. Upload files first."
        )

    # Enforce global scan concurrency limit
    if settings.MAX_CONCURRENT_SCANS is not None and settings.MAX_CONCURRENT_SCANS > 0:
        active_scans = db.query(ScanHistory).filter(ScanHistory.status.in_(["pending", "running"])).count()
        if active_scans >= settings.MAX_CONCURRENT_SCANS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Scan concurrency limit reached ({settings.MAX_CONCURRENT_SCANS} active scans). Please wait for active scans to finish."
            )

    # Register scan history entry
    scan = ScanHistory(
        project_id=project_id,
        status="pending"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Schedule background execution
    background_tasks.add_task(run_background_scan, project_id, scan.id)
    
    return scan


@router.get("/scans/{scan_id}", response_model=ScanHistoryOut)
def get_scan_status(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Polls the status and aggregate results of a security scan.
    """
    scan = db.query(ScanHistory).join(Project).filter(
        ScanHistory.id == scan_id,
        Project.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/projects/{project_id}/scans", response_model=List[ScanHistoryOut])
def get_project_scan_history(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns the scan history list for the specified project.
    """
    # Verify ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
        
    scans = db.query(ScanHistory).filter(ScanHistory.project_id == project_id).order_by(ScanHistory.scan_time.desc()).all()
    return scans


def handle_scan_diff(
    scan_id: UUID,
    base: Optional[UUID],
    db: Session,
    current_user: User,
    project_id: Optional[UUID] = None,
):
    # Verify target scan and project ownership
    target_scan = (
        db.query(ScanHistory)
        .join(Project)
        .filter(ScanHistory.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not target_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project = (
        db.query(Project)
        .filter(Project.id == target_scan.project_id, Project.user_id == current_user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_id and project.id != project_id:
        raise HTTPException(status_code=400, detail="Scan does not belong to the specified project")

    if target_scan.status == "failed":
        raise HTTPException(status_code=400, detail="Cannot compare a scan with failed status")

    # Determine base scan
    if not base:
        base_scan = (
            db.query(ScanHistory)
            .filter(
                ScanHistory.project_id == project.id,
                ScanHistory.status == "completed",
                ScanHistory.scan_time < target_scan.scan_time,
            )
            .order_by(ScanHistory.scan_time.desc())
            .first()
        )
        if not base_scan:
            return {
                "baseline": True,
                "scan_id": str(scan_id),
                "notes": ["first scan, nothing to compare"],
            }
    else:
        if base == scan_id:
            raise HTTPException(status_code=400, detail="A scan cannot be compared with itself")

        base_scan = db.query(ScanHistory).filter(ScanHistory.id == base).first()
        if not base_scan:
            raise HTTPException(status_code=404, detail="Base scan not found")

        if base_scan.project_id != target_scan.project_id:
            raise HTTPException(status_code=400, detail="Base scan belongs to a different project")

        if base_scan.status == "failed":
            raise HTTPException(status_code=400, detail="Base scan has failed status and cannot be used for comparison")

        # Retention window check (must be within the 20 most recent completed scans)
        retained = (
            db.query(ScanHistory.id)
            .filter(ScanHistory.project_id == project.id, ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_time.desc())
            .limit(20)
            .all()
        )
        retained_ids = {s.id for s in retained}
        if base_scan.id not in retained_ids:
            raise HTTPException(status_code=400, detail="Base scan is older than the retention window of 20 scans")

    return compute_scan_diff(db, target_scan, base_scan, project)


@router.get("/projects/{project_id}/scans/{scan_id}/diff")
def get_project_scan_diff(
    project_id: UUID,
    scan_id: UUID,
    base: Optional[UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Compares the given scan against a base scan (defaults to previous completed scan).
    Returns categorized findings: new, resolved, persisting, regressed, not_comparable.
    """
    return handle_scan_diff(scan_id, base, db, current_user, project_id=project_id)


@router.get("/scans/{scan_id}/diff")
def get_scan_diff(
    scan_id: UUID,
    base: Optional[UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Double-mounted scan diff endpoint.
    """
    return handle_scan_diff(scan_id, base, db, current_user)

