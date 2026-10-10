import os
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID

from backend.database.session import get_db, SessionLocal
from backend.models.models import Project, ScanHistory, File, Vulnerability, User
from backend.models.schemas import ScanHistoryOut
from backend.api.auth import get_current_user
from backend.utils.config import settings

router = APIRouter(tags=["Scans"])

logger = logging.getLogger(__name__)

import json
from backend.ai.explainer import generate_vulnerability_explanation
from backend.fixer.fix_generator import generate_patched_code

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

        # 1. Run the code scan orchestrator
        from backend.detectors.orchestrator import Orchestrator
        orchestrator = Orchestrator()
        code_findings = orchestrator.scan_project(project_dir)
        all_warnings.extend(orchestrator.warnings)

        # 2. Run Software Composition Analysis (SCA)
        from backend.sca.scanner import scan_dependencies
        dep_findings, sca_warnings, dep_summary = scan_dependencies(project_dir)
        all_warnings.extend(sca_warnings)

        all_findings = code_findings + dep_findings
        
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
        
        from backend.ai.explainer import generate_vulnerability_explanation
        from backend.fixer.fix_generator import generate_patched_code
        
        # 4. Process each unique finding
        for finding in all_findings:
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
                corrected_snippet = None
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
                
                # Generate AI explanation and fix
                explanation = generate_vulnerability_explanation(finding)
                _, corrected_snippet, _, auto_fixable, fix_source = generate_patched_code(finding, full_file_content)
            
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
            
        # 5. Finalize scan metadata
        scan.total_issues = len(all_findings)
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.warnings = json.dumps(all_warnings) if all_warnings else None
        scan.dependency_summary = json.dumps(dep_summary) if dep_summary else None
        scan.status = "completed"
        
        # Update parent project date
        project = db.query(Project).filter(Project.id == project_id).first()
        if project:
            project.scan_date = datetime.utcnow()
            
        db.commit()
        logger.info(f"Scan {scan_history_id} completed successfully. Issues: {len(all_findings)}, Warnings: {len(all_warnings)}")
        
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
