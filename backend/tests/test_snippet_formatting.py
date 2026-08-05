"""Tests for the code_snippet formatting fixes.

Covers:
1. Bandit: _strip_bandit_line_numbers correctly removes line-number prefixes
2. AST detector: _get_snippet preserves leading indentation (uses rstrip not strip)

These are critical for POST /vulnerabilities/{id}/apply-fix, which requires an
exact match between code_snippet and the real file content.
"""
import ast
import os
import tempfile

import pytest

from backend.detectors.bandit_detector import _strip_bandit_line_numbers
from backend.detectors.ast_detector import ASTVisitor


# ─── Bandit strip helper ───────────────────────────────────────────────────────

class TestStripBanditLineNumbers:

    def test_single_line_stripped(self):
        # Bandit format: "<lineno> <code_with_its_own_indent>"
        # Single line with no code indentation
        raw = "10 cursor.execute(query)\n"
        result = _strip_bandit_line_numbers(raw)
        assert result == "cursor.execute(query)\n"

    def test_multi_line_stripped(self):
        # Real Bandit output: '3     cursor = sqlite3...' means line 3, one sep space,
        # then '    cursor = ...' which is 4-space indented code.
        raw = (
            "3     cursor = conn.cursor()\n"
            "4     query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "5     cursor.execute(query)\n"
        )
        expected = (
            "    cursor = conn.cursor()\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
        )
        result = _strip_bandit_line_numbers(raw)
        assert result == expected

    def test_preserves_code_own_indentation(self):
        # Bandit format: "<lineno> <code_indent><code>"
        # '5 password = ...' has no code indent (top-level statement)
        raw = "5 password = \"secret123\"\n"
        result = _strip_bandit_line_numbers(raw)
        assert result == 'password = "secret123"\n'
        # Nested code: '7     password = ...' → 4 spaces are the code's own indent
        raw_indented = '7     password = "secret123"\n'
        result_indented = _strip_bandit_line_numbers(raw_indented)
        assert result_indented == '    password = "secret123"\n'
        assert result_indented.startswith("    ")

    def test_trailing_empty_line_unchanged(self):
        # Bandit snippets often end with a trailing empty line ("\n" → split gives "")
        raw = "1 import os\n2 import sys\n"
        result = _strip_bandit_line_numbers(raw)
        # Should cleanly strip both prefixes and not corrupt blank split artefact
        assert "import os" in result
        assert "import sys" in result
        # No stray digit prefixes remain
        import re
        for line in result.split("\n"):
            if line:  # skip empty splits
                assert not re.match(r"^\d+\s", line), f"Line still has prefix: {repr(line)}"

    def test_code_starting_with_digits_not_double_stripped(self):
        # Real code that starts with a digit literal should NOT be stripped
        # The prefix is only stripped once per line (the outermost match)
        raw = "7 x = 100 + 200\n"
        result = _strip_bandit_line_numbers(raw)
        # Bandit prefix "7 " is removed; "100 + 200" (which starts with a digit
        # but has NO leading whitespace as a prefix after the line-number group) stays
        assert result == "x = 100 + 200\n"

    def test_empty_string_unchanged(self):
        assert _strip_bandit_line_numbers("") == ""

    def test_no_prefix_unchanged(self):
        # A string that doesn't match the pattern at the start of any line
        raw = "    cursor.execute(query)"
        result = _strip_bandit_line_numbers(raw)
        assert result == "    cursor.execute(query)"

    def test_snippet_matches_file_content(self):
        """Simulate the exact apply-fix matching scenario.

        Write a temp file with vulnerable code, run the strip helper on a
        bandit-style code value, and assert the resulting snippet is found
        exactly once inside the real file content.
        """
        # Simulate what a real file looks like on disk (indented function body)
        file_content = (
            "import sqlite3\n"
            "\n"
            "def query_user(username):\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    cursor = conn.cursor()\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()\n"
        )

        # Real Bandit output: lineno + one sep space + code (which is 4-space indented)
        # Line 5 = '    cursor = conn.cursor()' in the file
        bandit_raw_code = (
            "5     cursor = conn.cursor()\n"
            "6     query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "7     cursor.execute(query)\n"
        )

        cleaned_snippet = _strip_bandit_line_numbers(bandit_raw_code)

        # The cleaned snippet must appear exactly once in the file
        snippet_to_find = cleaned_snippet.rstrip("\n")
        assert file_content.count(snippet_to_find) == 1, (
            f"Expected exactly one occurrence of snippet in file.\n"
            f"Snippet: {repr(snippet_to_find)}"
        )


# ─── AST detector _get_snippet indentation preservation ───────────────────────

class TestASTSnippetIndentation:

    def _make_visitor(self, code: str) -> ASTVisitor:
        visitor = ASTVisitor("test.py", code)
        tree = ast.parse(code)
        visitor.visit(tree)
        return visitor

    def test_indented_hardcoded_secret_preserves_indent(self):
        code = (
            "def configure():\n"
            "    db_password = \"supersecretpassword\"\n"
            "    return db_password\n"
        )
        visitor = self._make_visitor(code)
        assert len(visitor.findings) == 1
        snippet = visitor.findings[0].code_snippet
        # Must have leading 4-space indent — it's part of the real file content
        assert snippet.startswith("    "), (
            f"Leading indentation was stripped! Got: {repr(snippet)}"
        )
        assert "db_password" in snippet

    def test_indented_sql_injection_preserves_indent(self):
        code = (
            "def fetch(username):\n"
            "    cursor.execute(\"SELECT * FROM users WHERE name = '\" + username + \"'\")\n"
        )
        visitor = self._make_visitor(code)
        assert len(visitor.findings) == 1
        snippet = visitor.findings[0].code_snippet
        assert snippet.startswith("    "), (
            f"Leading indentation was stripped! Got: {repr(snippet)}"
        )

    def test_indented_eval_preserves_indent(self):
        code = (
            "def run():\n"
            "    eval(user_code)\n"
        )
        visitor = self._make_visitor(code)
        assert len(visitor.findings) == 1
        snippet = visitor.findings[0].code_snippet
        assert snippet.startswith("    ")

    def test_snippet_matches_real_file_content(self):
        """Core regression test: snippet from ASTVisitor must be findable
        inside the original file content via an exact string search."""
        code = (
            "def configure():\n"
            "    db_password = \"supersecretpassword\"\n"
            "    return db_password\n"
        )
        visitor = self._make_visitor(code)
        assert len(visitor.findings) >= 1
        snippet = visitor.findings[0].code_snippet
        # Exact match: strip the trailing whitespace we add via rstrip, but
        # the leading indentation must still be present in the source
        assert snippet in code, (
            f"Snippet {repr(snippet)} not found in file content. "
            "apply-fix would fail with 409."
        )

    def test_no_trailing_whitespace_in_snippet(self):
        """rstrip should remove trailing spaces/tabs but not affect other chars."""
        code = "db_password = \"mysecret\"  \n"
        visitor = self._make_visitor(code)
        if visitor.findings:
            snippet = visitor.findings[0].code_snippet
            assert not snippet.endswith(" "), (
                f"Snippet has trailing whitespace: {repr(snippet)}"
            )
