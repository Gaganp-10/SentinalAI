import ast
import os
import re
import logging
from typing import List
from backend.detectors.schema import Finding

logger = logging.getLogger(__name__)

class ASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, file_content: str):
        self.file_path = file_path
        self.file_content = file_content
        self.lines = file_content.splitlines()
        self.findings: List[Finding] = []
        
        # Regex to detect credentials or secrets
        self.secret_keywords = re.compile(
            r".*(password|secret|token|api_key|apikey|jwt_secret|private_key|auth_token|db_pass|aws_key|passphrase|credentials).*",
            re.IGNORECASE
        )
        # Regex for common SQL keywords
        self.sql_keywords = re.compile(
            r"\b(select|insert|update|delete|drop|alter|create|replace|upsert)\b",
            re.IGNORECASE
        )

    def _get_snippet(self, line_number: int) -> str:
        """Return the source line at line_number with only trailing whitespace
        stripped.  Leading indentation is preserved so the snippet exactly
        matches the real file content, which is required for the apply-fix
        endpoint to locate the vulnerable line via an exact string search."""
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].rstrip()
        return ""

    def visit_Assign(self, node: ast.Assign):
        # Check assignments for hardcoded secrets
        for target in node.targets:
            target_names = []
            if isinstance(target, ast.Name):
                target_names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        target_names.append(elt.id)
            
            for name in target_names:
                if self.secret_keywords.match(name):
                    is_secret = False
                    val_str = ""
                    # Check if standard string constant
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val_str = node.value.value
                        if len(val_str) > 4 and not val_str.startswith("<") and not val_str.startswith("YOUR_"):
                            is_secret = True
                    elif isinstance(node.value, ast.Str):  # Python < 3.8 fallback
                        val_str = node.value.s
                        if len(val_str) > 4 and not val_str.startswith("<") and not val_str.startswith("YOUR_"):
                            is_secret = True
                            
                    if is_secret:
                        self.findings.append(Finding(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            type="Hardcoded Secret",
                            severity="high",
                            description=f"Potential hardcoded credential or secret detected in variable assignment: '{name}'.",
                            recommendation="Move sensitive credentials to environment variables or a secrets manager.",
                            code_snippet=self._get_snippet(node.lineno),
                            cwe_id="CWE-798",
                            owasp_category="A02:2021-Cryptographic Failures",
                            confidence=0.8,
                            source_tool="ast"
                        ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check for weak hashing algorithms: md5, sha1
        is_weak_hash = False
        hash_algo = ""
        
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in ["md5", "sha1"]:
                    is_weak_hash = True
                    hash_algo = node.func.attr
        elif isinstance(node.func, ast.Name):
            if node.func.id in ["md5", "sha1"]:
                is_weak_hash = True
                hash_algo = node.func.id
                
        if is_weak_hash:
            self.findings.append(Finding(
                file_path=self.file_path,
                line_number=node.lineno,
                type="Weak Hashing Algorithm",
                severity="medium",
                description=f"Use of weak cryptographic hashing algorithm '{hash_algo}' detected.",
                recommendation="Replace weak hashing algorithms (MD5/SHA-1) with secure alternatives such as SHA-256 or bcrypt.",
                code_snippet=self._get_snippet(node.lineno),
                cwe_id="CWE-328",
                owasp_category="A02:2021-Cryptographic Failures",
                confidence=0.9,
                source_tool="ast"
            ))

        # Check for dangerous eval or exec usage
        is_dangerous_eval = False
        eval_func = ""
        if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
            is_dangerous_eval = True
            eval_func = node.func.id
            
        if is_dangerous_eval:
            self.findings.append(Finding(
                file_path=self.file_path,
                line_number=node.lineno,
                type="Dangerous Function Execution",
                severity="high",
                description=f"Use of dangerous built-in function '{eval_func}' detected.",
                recommendation=f"Avoid using '{eval_func}' with dynamic inputs, as it executes arbitrary code. Refactor logic to avoid dynamic interpretation.",
                code_snippet=self._get_snippet(node.lineno),
                cwe_id="CWE-95",
                owasp_category="A03:2021-Injection",
                confidence=0.9,
                source_tool="ast"
            ))

        # Check for dynamic SQL statements passed to database cursor execution calls
        if isinstance(node.func, ast.Attribute) and node.func.attr in ["execute", "executemany"]:
            if len(node.args) > 0:
                arg = node.args[0]
                is_concat_or_formatted = False
                sql_found = False
                
                # Case 1: f-strings
                if isinstance(arg, ast.JoinedStr):
                    is_concat_or_formatted = True
                    for val in arg.values:
                        if isinstance(val, ast.Constant) and isinstance(val.value, str) and self.sql_keywords.search(val.value):
                            sql_found = True
                        elif isinstance(val, ast.Str) and self.sql_keywords.search(val.s):
                            sql_found = True
                            
                # Case 2: string addition (+) or modulo (%) string formatting
                elif isinstance(arg, ast.BinOp):
                    def check_binop(bin_node):
                        nonlocal sql_found, is_concat_or_formatted
                        if isinstance(bin_node.op, (ast.Add, ast.Mod)):
                            is_concat_or_formatted = True
                        
                        # Check left operand
                        if isinstance(bin_node.left, ast.Constant) and isinstance(bin_node.left.value, str):
                            if self.sql_keywords.search(bin_node.left.value):
                                sql_found = True
                        elif isinstance(bin_node.left, ast.Str) and self.sql_keywords.search(bin_node.left.s):
                            sql_found = True
                        elif isinstance(bin_node.left, ast.BinOp):
                            check_binop(bin_node.left)
                            
                        # Check right operand
                        if isinstance(bin_node.right, ast.Constant) and isinstance(bin_node.right.value, str):
                            if self.sql_keywords.search(bin_node.right.value):
                                sql_found = True
                        elif isinstance(bin_node.right, ast.Str) and self.sql_keywords.search(bin_node.right.s):
                            sql_found = True
                        elif isinstance(bin_node.right, ast.BinOp):
                            check_binop(bin_node.right)
                            
                    check_binop(arg)
                    
                # Case 3: ".format()" method calls
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    is_concat_or_formatted = True
                    format_str_node = arg.func.value
                    if isinstance(format_str_node, ast.Constant) and isinstance(format_str_node.value, str):
                        if self.sql_keywords.search(format_str_node.value):
                            sql_found = True
                    elif isinstance(format_str_node, ast.Str) and self.sql_keywords.search(format_str_node.s):
                        sql_found = True
                        
                if is_concat_or_formatted and sql_found:
                    self.findings.append(Finding(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        type="SQL Injection",
                        severity="critical",
                        description="SQL query constructed using dynamic string formatting or concatenation.",
                        recommendation="Use parameterized queries / prepared statements instead of dynamic string building (e.g. cursor.execute('SELECT * FROM users WHERE name = %s', (name,))).",
                        code_snippet=self._get_snippet(node.lineno),
                        cwe_id="CWE-89",
                        owasp_category="A03:2021-Injection",
                        confidence=0.8,
                        source_tool="ast"
                    ))
                    
        self.generic_visit(node)

class ASTDetector:
    def scan(self, project_dir: str) -> List[Finding]:
        findings = []
        for root, _, files in os.walk(project_dir):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, project_dir).replace("\\", "/")
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        
                        tree = ast.parse(content, filename=full_path)
                        visitor = ASTVisitor(rel_path, content)
                        visitor.visit(tree)
                        findings.extend(visitor.findings)
                    except SyntaxError as se:
                        logger.warning(f"Syntax error parsing {rel_path} with AST: {se}")
                    except Exception as e:
                        logger.error(f"Error checking AST for {rel_path}: {e}")
        return findings
