"""
OWASP Top 10:2021 coverage endpoint.

GET /projects/{project_id}/owasp
(double-mounted at /api/projects/{project_id}/owasp by main.py)

Returns open/fixed counts per category for the project's latest completed scan,
plus an honest static scanner-coverage label and unmapped_findings count.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Project, ScanHistory, File, Vulnerability, User
from backend.api.auth import get_current_user
from backend.utils.owasp_map import OWASP_CATEGORY_CONFIG, OWASP_VERSION

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["OWASP"])


@router.get("/{project_id}/owasp")
def get_owasp_coverage(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns OWASP Top 10:2021 coverage for the latest completed scan of the given project.
    """
    # Verify ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id,
    ).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    def _empty_categories():
        return [
            {
                "id": cfg["id"],
                "name": cfg["name"],
                "open": 0,
                "fixed": 0,
                "cwes": [],
                "coverage": cfg["coverage"],
                "coverage_note": cfg["note"],
            }
            for cfg in OWASP_CATEGORY_CONFIG
        ]

    # Get latest completed scan
    latest_scan = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.project_id == project_id,
            ScanHistory.status == "completed",
        )
        .order_by(ScanHistory.scan_time.desc())
        .first()
    )

    if not latest_scan:
        return {"version": OWASP_VERSION, "categories": _empty_categories(), "unmapped_findings": 0}

    # Get all files for this project
    file_ids = [f.id for f in db.query(File).filter(File.project_id == project_id).all()]
    if not file_ids:
        return {"version": OWASP_VERSION, "categories": _empty_categories(), "unmapped_findings": 0}

    # Fetch all vulnerabilities for this project
    vulns = db.query(Vulnerability).filter(Vulnerability.file_id.in_(file_ids)).all()

    # Build buckets per OWASP category id (A01..A10)
    bucket = {cfg["id"]: {"open": 0, "fixed": 0, "cwes": set()} for cfg in OWASP_CATEGORY_CONFIG}

    unmapped = 0
    for vuln in vulns:
        cat_id = None
        if vuln.owasp_category:
            part = vuln.owasp_category.split(":")[0].strip()
            if part in bucket:
                cat_id = part

        if cat_id:
            if vuln.fixed:
                bucket[cat_id]["fixed"] += 1
            else:
                bucket[cat_id]["open"] += 1
            if vuln.cwe_id:
                bucket[cat_id]["cwes"].add(vuln.cwe_id)
        else:
            unmapped += 1

    categories = [
        {
            "id": cfg["id"],
            "name": cfg["name"],
            "open": bucket[cfg["id"]]["open"],
            "fixed": bucket[cfg["id"]]["fixed"],
            "cwes": sorted(list(bucket[cfg["id"]]["cwes"])),
            "coverage": cfg["coverage"],
            "coverage_note": cfg["note"],
        }
        for cfg in OWASP_CATEGORY_CONFIG
    ]

    return {
        "version": OWASP_VERSION,
        "categories": categories,
        "unmapped_findings": unmapped,
    }
