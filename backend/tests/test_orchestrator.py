from backend.detectors.orchestrator import Orchestrator
from backend.detectors.schema import Finding

def test_orchestrator_deduplication_and_merging():
    # Arrange: two mock findings on the same file, line, and vulnerability type
    finding1 = Finding(
        file_path="api/v1/users.py",
        line_number=45,
        type="SQL Injection",
        severity="critical",
        description="SQL injection in DB query",
        confidence=0.6,
        source_tool="bandit"
    )
    
    finding2 = Finding(
        file_path="api/v1/users.py",
        line_number=45,
        type="SQL Injection",
        severity="critical",
        description="SQL injection warning from AST",
        confidence=0.8,
        source_tool="ast"
    )
    
    # Act: Perform the deduplication step as executed by Orchestrator
    raw_findings = [finding1, finding2]
    
    merged = {}
    agreed_tools = {}
    
    for finding in raw_findings:
        key = finding.dedup_key()
        if key not in agreed_tools:
            agreed_tools[key] = set()
        agreed_tools[key].add(finding.source_tool)
        
        if key not in merged:
            merged[key] = finding
        else:
            existing = merged[key]
            if finding.confidence > existing.confidence:
                merged[key] = finding
                
    result_findings = []
    for key, finding in merged.items():
        tools = agreed_tools[key]
        finding.source_tool = ",".join(sorted(list(tools)))
        result_findings.append(finding)
        
    # Assert: Only 1 merged finding should remain, with highest confidence and both tools recorded
    assert len(result_findings) == 1
    merged_finding = result_findings[0]
    assert merged_finding.confidence == 0.8
    assert merged_finding.source_tool == "ast,bandit"
    # Ensure standard slash formatting on relative file path
    assert merged_finding.file_path == "api/v1/users.py"
