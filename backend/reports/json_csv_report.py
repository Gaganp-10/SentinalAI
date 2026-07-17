import json
import csv
import io
from typing import List
from backend.utils.severity import calculate_security_score

def generate_json_report(project, scan, vulnerabilities: List) -> str:
    """
    Generates a structured JSON string of the project scan report.
    """
    score = calculate_security_score(vulnerabilities)
    
    findings_data = []
    for vuln in vulnerabilities:
        findings_data.append({
            "id": str(vuln.id),
            "file": vuln.file.filepath,
            "filename": vuln.file.filename,
            "line_number": vuln.line_number,
            "type": vuln.type,
            "severity": vuln.severity,
            "description": vuln.description,
            "recommendation": vuln.recommendation,
            "cwe_id": vuln.cwe_id,
            "owasp_category": vuln.owasp_category,
            "confidence": vuln.confidence,
            "source_tool": vuln.source_tool,
            "fixed": vuln.fixed
        })
        
    report_dict = {
        "project": {
            "id": str(project.id),
            "project_name": project.project_name,
            "scan_date": project.scan_date.isoformat() if project.scan_date else None
        },
        "scan": {
            "id": str(scan.id),
            "scan_time": scan.scan_time.isoformat() if scan.scan_time else None,
            "total_issues": scan.total_issues,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "status": scan.status,
            "security_score": score
        },
        "vulnerabilities": findings_data
    }
    
    return json.dumps(report_dict, indent=2)


def generate_csv_report(vulnerabilities: List) -> str:
    """
    Generates a CSV formatted string of the scan vulnerabilities.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "Vulnerability ID",
        "File Path",
        "Line Number",
        "Vulnerability Type",
        "Severity",
        "CWE ID",
        "OWASP Category",
        "Confidence",
        "Tools Detected",
        "Fixed Status",
        "Description"
    ])
    
    for vuln in vulnerabilities:
        writer.writerow([
            str(vuln.id),
            vuln.file.filepath,
            vuln.line_number,
            vuln.type,
            vuln.severity,
            vuln.cwe_id or "N/A",
            vuln.owasp_category or "N/A",
            vuln.confidence,
            vuln.source_tool,
            "Yes" if vuln.fixed else "No",
            vuln.description
        ])
        
    return output.getvalue()
