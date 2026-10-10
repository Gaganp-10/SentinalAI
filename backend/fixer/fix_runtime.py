"""
Runtime Correctness & Validation Utilities for Automated Code Fixes
===================================================================
Provides:
1. Database driver detection and SQL placeholder selection ('?' for sqlite3, '%s' for psycopg2/PyMySQL).
2. Missing import insertion (adds 'import os' etc. cleanly after docstrings and __future__ imports).
3. Undefined-name validation via pyflakes to prevent runtime NameErrors.
"""

import ast
import io
import re
import logging
from typing import Optional, Tuple, Set

logger = logging.getLogger(__name__)


def detect_sql_placeholder(source: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Analyzes Python source code to detect the imported database driver and choose
    the appropriate parameter placeholder style.
    
    Returns:
        (placeholder, driver_name)
        e.g. ("?", "sqlite3") or ("%s", "psycopg2")
        or (None, reason_description) if driver cannot be determined.
    """
    if not source:
        return None, "Empty source code"

    imported_modules: Set[str] = set()

    try:
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split('.')[0])
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split('.')[0])
                    imported_modules.add(node.module)
    except SyntaxError:
        # Fallback to regex line scan if partial code snippet
        for line in source.splitlines():
            m_imp = re.match(r'^\s*import\s+([a-zA-Z0-9_\.,\s]+)', line)
            m_from = re.match(r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import', line)
            if m_imp:
                for part in m_imp.group(1).split(','):
                    mod = part.strip().split()[0].split('.')[0]
                    imported_modules.add(mod)
            elif m_from:
                imported_modules.add(m_from.group(1).split('.')[0])

    qmark_drivers = {"sqlite3"}
    format_drivers = {"psycopg2", "psycopg", "pymysql", "mysql.connector", "MySQLdb", "mysql"}

    found_qmark = imported_modules.intersection(qmark_drivers)
    found_format = imported_modules.intersection(format_drivers)

    if found_qmark and not found_format:
        return "?", "sqlite3"
    elif found_format and not found_qmark:
        driver = sorted(list(found_format))[0]
        return "%s", driver
    elif found_qmark and found_format:
        return None, "Multiple conflicting database drivers imported"
    else:
        return None, "Database driver could not be determined from imports"


def has_module_import(source: str, module_name: str) -> bool:
    """
    Checks if source already imports module_name via 'import <module>' or 'from <module> import ...'.
    """
    try:
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == module_name or a.name.startswith(module_name + '.'):
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module == module_name or (node.module and node.module.startswith(module_name + '.')):
                    return True
        return False
    except SyntaxError:
        # Fallback regex
        pattern = rf'^\s*(import\s+{module_name}\b|from\s+{module_name}\b)'
        return bool(re.search(pattern, source, re.MULTILINE))


def add_import_if_missing(source: str, module_name: str, import_stmt: str = "import os") -> str:
    """
    Inserts import_stmt into source if module_name is not already imported.
    Inserts at the standard PEP 8 import location:
    1. After shebang (#!) or encoding comments
    2. After module docstring (if present)
    3. After any 'from __future__ import ...' statements
    """
    if has_module_import(source, module_name):
        return source

    lines = source.splitlines(keepends=True)
    if not lines:
        return import_stmt + "\n"

    # Find comments / shebang
    idx = 0
    while idx < len(lines):
        line_str = lines[idx].strip()
        if line_str.startswith("#!") or "coding:" in line_str or "coding=" in line_str:
            idx += 1
        else:
            break

    # Parse AST to find end of docstring or __future__ imports
    ast_limit_line = 0
    try:
        tree = ast.parse(source)
        first_stmt = True
        for node in tree.body:
            # Check module docstring
            if first_stmt and isinstance(node, ast.Expr) and isinstance(getattr(node, 'value', None), ast.Constant) and isinstance(node.value.value, str):
                end_lineno = getattr(node, 'end_lineno', node.lineno)
                if end_lineno > ast_limit_line:
                    ast_limit_line = end_lineno
                first_stmt = False
                continue
            first_stmt = False

            # Check from __future__ import
            if isinstance(node, ast.ImportFrom) and node.module == '__future__':
                end_lineno = getattr(node, 'end_lineno', node.lineno)
                if end_lineno > ast_limit_line:
                    ast_limit_line = end_lineno
            else:
                break
    except SyntaxError:
        pass

    insert_idx = max(idx, ast_limit_line)

    stmt_line = import_stmt + "\n"
    lines.insert(insert_idx, stmt_line)
    return "".join(lines)


def get_new_undefined_names(orig_code: str, patched_code: str) -> Set[str]:
    """
    Analyzes patched_code and returns any undefined variable/module names that
    were introduced by the patch and did not exist in orig_code.
    Uses pyflakes.checker.Checker.
    """
    try:
        from pyflakes.checker import Checker
        from pyflakes.messages import UndefinedName

        def _collect_undefined(code: str) -> Set[str]:
            try:
                tree = ast.parse(code)
            except SyntaxError:
                return set()
            checker = Checker(tree)
            names = set()
            for msg in checker.messages:
                if isinstance(msg, UndefinedName):
                    names.add(msg.message_args[0])
            return names

        orig_undefined = _collect_undefined(orig_code)
        patched_undefined = _collect_undefined(patched_code)
        return patched_undefined - orig_undefined

    except Exception as e:
        logger.warning(f"Error checking undefined names: {e}")
        return set()
