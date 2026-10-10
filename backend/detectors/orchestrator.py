import os
import logging
from collections import defaultdict
from typing import List, Dict, Set
from backend.detectors.schema import Finding, DetectorError
from backend.detectors.bandit_detector import BanditDetector
from backend.detectors.semgrep_detector import SemgrepDetector
from backend.detectors.ast_detector import ASTDetector
from backend.detectors.issue_classes import get_issue_class, get_canonical_cwe
from backend.utils.owasp_map import get_owasp_category
from backend.parser.language_detect import detect_language

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def candidate_fix_score(f: Finding) -> tuple:
    """
    Scores a finding candidate within a merge cluster.
    Prefers candidates that:
    1. Are auto-fixable by local deterministic templates (fix != original).
    2. Have non-empty code snippets.
    3. Have compact (single-line or minimal context) snippets to ensure clean exact matching.
    4. Have higher confidence.
    """
    from backend.fixer.fix_generator import generate_template_fix
    fix, fixable = generate_template_fix(f)
    is_fixable = 1 if (fixable and fix != (f.code_snippet or "")) else 0
    has_snippet = 1 if (f.code_snippet and f.code_snippet.strip()) else 0
    # Prefer compact snippets (fewer lines = less susceptible to adjacent line interference)
    line_count = len((f.code_snippet or "").splitlines())
    compactness = -line_count if line_count > 0 else -999
    conf = f.confidence if f.confidence is not None else 0.0
    return (is_fixable, has_snippet, compactness, conf)


class Orchestrator:
    def __init__(self):
        self.bandit = BanditDetector()
        self.semgrep = SemgrepDetector()
        self.ast = ASTDetector()
        self.warnings: List[str] = []

    def scan_project(self, project_dir: str) -> List[Finding]:
        self.warnings = []
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
            try:
                raw_findings.extend(self.bandit.scan(project_dir))
            except Exception as e:
                warn_msg = f"Bandit scan failed: {e}"
                logger.warning(warn_msg)
                self.warnings.append(warn_msg)
            
            logger.info("Running Custom AST linter...")
            try:
                raw_findings.extend(self.ast.scan(project_dir))
            except Exception as e:
                warn_msg = f"AST scan failed: {e}"
                logger.warning(warn_msg)
                self.warnings.append(warn_msg)

        # 3. Run Semgrep linter if supported languages are present
        semgrep_languages = {"python", "javascript", "typescript", "java", "c", "php"}
        if languages.intersection(semgrep_languages):
            logger.info("Running Semgrep scanner...")
            try:
                raw_findings.extend(self.semgrep.scan(project_dir))
            except DetectorError as e:
                warn_msg = f"Semgrep scan failed: {e}"
                logger.warning(warn_msg)
                self.warnings.append(warn_msg)
            except Exception as e:
                warn_msg = f"Semgrep scan failed: {e}"
                logger.warning(warn_msg)
                self.warnings.append(warn_msg)

        # 4. Merge & Deduplicate findings
        result_findings = self.dedup_findings(raw_findings)
        logger.info(f"Scan complete. Found {len(result_findings)} unique vulnerabilities.")
        return result_findings

    def dedup_findings(self, raw_findings: List[Finding]) -> List[Finding]:
        """
        Deduplicates raw findings across linters (Bandit, Semgrep, AST).

        Rules:
        1. Issue-class clustering with 1-line tolerance:
           Findings in the same file with the same issue_class whose line numbers are
           within 1 line of each other (abs(line_a - line_b) <= 1) are merged into ONE record.
           - canonical CWE from backend.detectors.issue_classes is assigned.
           - owasp_category is derived from the canonical CWE.
           - source_tool lists all tools (comma-separated, sorted).
           - The surviving record retains the type, code_snippet, and description that
             best satisfy apply-fix (preferring template-fixable candidates with clean snippets).
           - Separate occurrences of the same issue_class at distant lines (> 1 line apart)
             remain distinct records.
        2. Unclassified findings (issue_class is None):
           Not merged by class; deduplicated strictly by (norm_path, line_number, cwe/type).
        """
        for f in raw_findings:
            f.file_path = os.path.normpath(f.file_path).replace("\\", "/")
            if not f.issue_class and f.rule_id:
                f.issue_class = get_issue_class(f.rule_id)

        # Separate classified vs unclassified findings
        classified_groups = defaultdict(list)  # (norm_path, issue_class) -> [Finding]
        unclassified = []

        for f in raw_findings:
            if f.issue_class:
                classified_groups[(f.file_path, f.issue_class)].append(f)
            else:
                unclassified.append(f)

        merged_findings: List[Finding] = []

        # 1. Process classified findings via 1-line tolerance clustering
        for (norm_path, issue_class), group in classified_groups.items():
            # Sort findings by line_number
            group.sort(key=lambda x: x.line_number)

            # Form clusters where adjacent findings are within 1 line of each other
            clusters: List[List[Finding]] = []
            current_cluster: List[Finding] = []

            for f in group:
                if not current_cluster:
                    current_cluster.append(f)
                else:
                    # Tolerance: if line is within 1 line of the current cluster's latest finding
                    if f.line_number - current_cluster[-1].line_number <= 1:
                        current_cluster.append(f)
                    else:
                        clusters.append(current_cluster)
                        current_cluster = [f]

            if current_cluster:
                clusters.append(current_cluster)

            # Merge each cluster into a single finding
            for cluster in clusters:
                winner = max(cluster, key=candidate_fix_score)

                # Merge source tools
                tools: Set[str] = set()
                for f in cluster:
                    for t in (f.source_tool or "").split(","):
                        if t.strip():
                            tools.add(t.strip())
                merged_tools = ",".join(sorted(list(tools)))

                # Canonical CWE and OWASP category
                canonical_cwe = get_canonical_cwe(issue_class) or winner.cwe_id
                owasp_cat = get_owasp_category(canonical_cwe)

                # Earliest line number in cluster
                earliest_line = min(f.line_number for f in cluster)

                # Highest severity in cluster
                highest_sev = max(
                    cluster,
                    key=lambda f: SEVERITY_ORDER.get((f.severity or "").lower(), 0)
                ).severity

                max_conf = max(f.confidence for f in cluster)

                surviving = Finding(
                    file_path=winner.file_path,
                    line_number=earliest_line,
                    type=winner.type,
                    severity=highest_sev,
                    description=winner.description,
                    recommendation=winner.recommendation,
                    code_snippet=winner.code_snippet,
                    suggested_fix=winner.suggested_fix,
                    cwe_id=canonical_cwe,
                    owasp_category=owasp_cat,
                    confidence=max_conf,
                    source_tool=merged_tools,
                    fixed=any(f.fixed for f in cluster),
                    auto_fixable=winner.auto_fixable,
                    rule_id=winner.rule_id,
                    issue_class=issue_class
                )
                merged_findings.append(surviving)

        # 2. Process unclassified findings (exact line & type/cwe deduplication)
        unclassified_by_path = defaultdict(list)
        for f in unclassified:
            unclassified_by_path[f.file_path].append(f)

        for path, u_list in unclassified_by_path.items():
            exact_map: Dict[tuple, Finding] = {}
            exact_tools: Dict[tuple, Set[str]] = {}

            for f in u_list:
                key = (f.line_number, (f.cwe_id or f.type.lower().strip()))
                if key not in exact_map:
                    exact_map[key] = f
                    exact_tools[key] = set((f.source_tool or "").split(","))
                else:
                    existing = exact_map[key]
                    exact_tools[key].update((f.source_tool or "").split(","))
                    if (f.confidence or 0.0) > (existing.confidence or 0.0):
                        f.code_snippet = f.code_snippet or existing.code_snippet
                        exact_map[key] = f
                    else:
                        existing.code_snippet = existing.code_snippet or f.code_snippet

            for key, f in exact_map.items():
                tools = set(t.strip() for t in exact_tools[key] if t.strip())
                f.source_tool = ",".join(sorted(list(tools)))
                f.owasp_category = get_owasp_category(f.cwe_id)
                merged_findings.append(f)

        # Sort all merged findings by file path and line number
        merged_findings.sort(key=lambda x: (x.file_path, x.line_number))
        return merged_findings
