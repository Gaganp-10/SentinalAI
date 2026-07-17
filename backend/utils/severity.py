from typing import List, Dict

def calculate_security_score(vulnerabilities: List) -> int:
    """
    Calculates a security score from 0 to 100.
    Deducts points for vulnerabilities based on severity.
    """
    score = 100
    
    # Weights for each severity level
    weights = {
        "critical": 15,
        "high": 10,
        "medium": 5,
        "low": 2,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        severity = getattr(vuln, "severity", "low").lower()
        score -= weights.get(severity, 2)
        
    return max(0, score)

def parse_severity_counts(vulnerabilities: List) -> Dict[str, int]:
    """
    Counts the number of vulnerabilities by severity level.
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    for vuln in vulnerabilities:
        severity = getattr(vuln, "severity", "low").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["low"] += 1
    return counts
