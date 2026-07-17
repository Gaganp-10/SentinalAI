import os
import logging
from typing import List, Dict, Set
from backend.detectors.schema import Finding
from backend.detectors.bandit_detector import BanditDetector
from backend.detectors.semgrep_detector import SemgrepDetector
from backend.detectors.ast_detector import ASTDetector
from backend.parser.language_detect import detect_language

logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self):
        self.bandit = BanditDetector()
        self.semgrep = SemgrepDetector()
        self.ast = ASTDetector()

    def scan_project(self, project_dir: str) -> List[Finding]:
        # 1. Detect languages present in the project
        languages: Set[str] = set()
        file_count = 0
        
        for root, _, files in os.walk(project_dir):
            for file in files:
                lang = detect_language(file)
                if lang != "unknown":
                    languages.add(lang)
                file_count += 1
                
        logger.info(f"Scanning directory {project_dir} with {file_count} total files. Languages found: {languages}")

        raw_findings: List[Finding] = []

        # 2. Run Bandit & AST linter if Python is present
        if "python" in languages:
            logger.info("Running Bandit linter...")
            raw_findings.extend(self.bandit.scan(project_dir))
            
            logger.info("Running Custom AST linter...")
            raw_findings.extend(self.ast.scan(project_dir))

        # 3. Run Semgrep linter if supported languages are present
        semgrep_languages = {"python", "javascript", "typescript", "java", "c", "php"}
        if languages.intersection(semgrep_languages):
            logger.info("Running Semgrep scanner...")
            raw_findings.extend(self.semgrep.scan(project_dir))

        # 4. Merge & Dedup findings
        # Key: (file_path, line_number, type_lower)
        merged: Dict[tuple, Finding] = {}
        # Keep track of which tools detected which key: key -> set of tool names
        agreed_tools: Dict[tuple, Set[str]] = {}

        for finding in raw_findings:
            key = finding.dedup_key()
            
            # Keep track of tools
            if key not in agreed_tools:
                agreed_tools[key] = set()
            agreed_tools[key].add(finding.source_tool)

            if key not in merged:
                merged[key] = finding
            else:
                # Keep the one with the highest confidence
                existing = merged[key]
                if finding.confidence > existing.confidence:
                    # Update fields, but preserve code snippet if it was set
                    code = existing.code_snippet or finding.code_snippet
                    cwe = existing.cwe_id or finding.cwe_id
                    owasp = existing.owasp_category or finding.owasp_category
                    
                    finding.code_snippet = code
                    finding.cwe_id = cwe
                    finding.owasp_category = owasp
                    merged[key] = finding

        # 5. Write the final merged tools list into source_tool
        result_findings: List[Finding] = []
        for key, finding in merged.items():
            tools = agreed_tools[key]
            # Store sorted comma-separated string, e.g. "bandit,semgrep"
            finding.source_tool = ",".join(sorted(list(tools)))
            result_findings.append(finding)

        logger.info(f"Scan complete. Found {len(result_findings)} unique vulnerabilities.")
        return result_findings
