from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Project, ScanHistory, Vulnerability, File, User
from backend.api.auth import get_current_user
from backend.reports.html_report import generate_html_report
from backend.reports.pdf_report import generate_pdf_report
from backend.reports.json_csv_report import generate_json_report, generate_csv_report

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/{project_id}")
def download_project_report(
    project_id: UUID,
    format: str = "html",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates and downloads a security report in HTML, PDF, JSON, or CSV formats.
    """
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
        
    # Get latest completed scan
    scan = db.query(ScanHistory).filter(
        ScanHistory.project_id == project_id,
        ScanHistory.status == "completed"
    ).order_by(ScanHistory.scan_time.desc()).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No completed scan found for this project. Please run a scan first."
        )
        
    # Get all vulnerabilities
    vulnerabilities = db.query(Vulnerability).join(File).filter(
        File.project_id == project_id
    ).order_by(Vulnerability.severity.desc(), Vulnerability.line_number.asc()).all()
    
    format = format.lower()
    
    if format == "html":
        html_content = generate_html_report(project, scan, vulnerabilities)
        return HTMLResponse(content=html_content)
        
    elif format == "pdf":
        html_content = generate_html_report(project, scan, vulnerabilities)
        pdf_bytes = generate_pdf_report(html_content)
        if pdf_bytes is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PDF generation failed. The host might be missing system library dependencies (Pango/Cairo) for WeasyPrint. Please try HTML or run in Docker."
            )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{project.project_name.replace(' ', '_')}_{project_id}.pdf"}
        )
        
    elif format == "json":
        json_str = generate_json_report(project, scan, vulnerabilities)
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{project.project_name.replace(' ', '_')}_{project_id}.json"}
        )
        
    elif format == "csv":
        csv_str = generate_csv_report(vulnerabilities)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{project.project_name.replace(' ', '_')}_{project_id}.csv"}
        )
        
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Supported formats: html, pdf, json, csv"
        )
