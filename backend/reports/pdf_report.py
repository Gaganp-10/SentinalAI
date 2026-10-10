"""
PDF report generator for SentinelAI using xhtml2pdf (pisa).

Design constraints (xhtml2pdf 0.2.x):
  - No flexbox / CSS grid  →  use tables and block elements
  - No JS / charting libs  →  draw bars with table cells
  - SVG unreliable         →  use PNG for the logo (base64 embedded for container/local portability)
  - <pre> does not wrap    →  word-wrap: break-word + manual wrap at 90 chars

CRITICAL GUARDRAILS:
  - Function signature `generate_pdf_report(html_content: str) -> Optional[bytes]`
    is strictly PRESERVED.
  - No heavy dependencies added. Pure HTML/CSS via xhtml2pdf.
"""

import os
import base64
import html as html_mod
import logging
import re
import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── xhtml2pdf availability ────────────────────────────────────────────────────

XHTML2PDF_AVAILABLE = False
try:
    from xhtml2pdf import pisa  # noqa: F401
    XHTML2PDF_AVAILABLE = True
except Exception as _e:  # pragma: no cover
    logger.warning("xhtml2pdf not available: %s", _e)

# ── Logo asset loading ────────────────────────────────────────────────────────

_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
_LOGO_PATH = os.path.join(_ASSETS_DIR, "logo.png")
_LOGO_B64: Optional[str] = None

try:
    with open(_LOGO_PATH, "rb") as _f:
        _LOGO_B64 = base64.b64encode(_f.read()).decode("ascii")
except FileNotFoundError:
    logger.warning("PDF logo not found at %s; header will show text shield icon.", _LOGO_PATH)


def _link_callback(uri: str, rel: str) -> str:
    """Resolve asset paths for xhtml2pdf whether running locally or in Docker."""
    if uri.startswith("data:"):
        return uri
    if not os.path.isabs(uri):
        candidate = os.path.join(_ASSETS_DIR, uri)
        if os.path.exists(candidate):
            return candidate
    return uri


def _logo_img(size: int = 28) -> str:
    """Return an img tag for the logo, or a text icon fallback."""
    if _LOGO_B64:
        return (
            f'<img src="data:image/png;base64,{_LOGO_B64}" '
            f'width="{size}" height="{size}" style="vertical-align:middle;"/>'
        )
    if os.path.exists(_LOGO_PATH):
        return (
            f'<img src="{_LOGO_PATH}" '
            f'width="{size}" height="{size}" style="vertical-align:middle;"/>'
        )
    return '<span style="font-size:12pt;font-weight:bold;color:#0f172a;">[S]</span>'


# ── Severity configuration & Colors ───────────────────────────────────────────

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_SEV_COLORS = {
    "critical": {"bg": "#fef2f2", "fg": "#991b1b", "border": "#fca5a5", "bar": "#dc2626"},
    "high":     {"bg": "#fff7ed", "fg": "#c2410c", "border": "#fed7aa", "bar": "#ea580c"},
    "medium":   {"bg": "#fefce8", "fg": "#854d0e", "border": "#fef08a", "bar": "#ca8a04"},
    "low":      {"bg": "#f0fdf4", "fg": "#166534", "border": "#bbf7d0", "bar": "#16a34a"},
    "info":     {"bg": "#f0f9ff", "fg": "#075985", "border": "#bae6fd", "bar": "#0284c7"},
}

_DEFAULT_SEV = {"bg": "#f1f5f9", "fg": "#334155", "border": "#cbd5e1", "bar": "#64748b"}


def _sev(s: str) -> dict:
    return _SEV_COLORS.get((s or "").lower(), _DEFAULT_SEV)


# ── Security score (mirrors frontend formula) ─────────────────────────────────
# TODO: consolidate into backend/utils/severity.py so all report types share it.

_SCORE_WEIGHTS = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}


def _calc_score(vulnerabilities: List) -> int:
    score = 100
    for v in vulnerabilities:
        score -= _SCORE_WEIGHTS.get((getattr(v, "severity", "") or "").lower(), 0)
    return max(0, score)


def _score_color(score: int) -> str:
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#ca8a04"
    if score >= 40:
        return "#ea580c"
    return "#dc2626"


# ── Markdown-lite renderer (no external dependency) ───────────────────────────

def _md_to_html(text: Optional[str]) -> str:
    """
    Convert a minimal subset of markdown to safe HTML for xhtml2pdf:
      ### Heading  →  <b>Heading</b>
      - item       →  &bull;&nbsp;item
      **bold**     →  <b>bold</b>
      `code`       →  <font face="Courier">code</font>
      blank line   →  <br/>
    All dynamic text is HTML-escaped.
    """
    if not text:
        return ""
    lines = str(text).splitlines()
    out: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out.append("<br/>")
            continue
        # Headings: #, ##, ###, ####
        m_head = re.match(r"^#{1,4}\s+(.*)", stripped)
        if m_head:
            safe_head = html_mod.escape(m_head.group(1))
            out.append(f'<div style="font-weight:bold; font-size:9pt; margin-top:4px; margin-bottom:2px; color:#0f172a;">{safe_head}</div>')
            continue
        # Bullet: - or *
        m_bullet = re.match(r"^[-*]\s+(.*)", stripped)
        if m_bullet:
            content = html_mod.escape(m_bullet.group(1))
            content = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", content)
            content = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", content)
            out.append(f'<div style="padding-left:12px; margin-bottom:2px;">&bull;&nbsp;{content}</div>')
            continue
        # Regular paragraph line
        content = html_mod.escape(stripped)
        content = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", content)
        content = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", content)
        out.append(f'<div style="margin-bottom:2px;">{content}</div>')
    return "".join(out)


# ── Code snippet sanitiser ────────────────────────────────────────────────────

_MAX_SNIPPET_LINES = 60
_WRAP_AT = 90


def _safe_snippet(code: Optional[str]) -> str:
    """HTML-escape + manual line-wrap at 90 chars + line cap at 60 lines."""
    if not code:
        return ""
    lines = str(code).splitlines()
    truncated = False
    if len(lines) > _MAX_SNIPPET_LINES:
        lines = lines[:_MAX_SNIPPET_LINES]
        truncated = True
    wrapped: List[str] = []
    for line in lines:
        if len(line) > _WRAP_AT:
            chunks = textwrap.wrap(
                line,
                _WRAP_AT,
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            wrapped.extend(chunks if chunks else [line])
        else:
            wrapped.append(line)
    if truncated:
        wrapped.append("... [truncated]")
    return html_mod.escape("\n".join(wrapped))


# ── HTML Builder for PDF Report ───────────────────────────────────────────────

def _build_pdf_html(project, scan, vulnerabilities: List) -> str:
    proj_name = html_mod.escape(str(getattr(project, "project_name", "Unknown Project") or "Unknown Project"))
    scan_time = (
        scan.scan_time.strftime("%Y-%m-%d %H:%M UTC")
        if scan and getattr(scan, "scan_time", None)
        else "N/A"
    )
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    files_count = len(getattr(project, "files", []) or [])
    total = len(vulnerabilities)

    score = _calc_score(vulnerabilities)
    score_clr = _score_color(score)

    # Severity counts
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for v in vulnerabilities:
        sev = (getattr(v, "severity", "") or "").lower()
        if sev in counts:
            counts[sev] += 1

    max_count = max(counts.values(), default=1) or 1

    # Sort: critical first, then line number
    sev_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            sev_rank.get((getattr(v, "severity", "") or "").lower(), 99),
            getattr(v, "line_number", 0) or 0,
        ),
    )

    # Group by file
    from collections import OrderedDict
    by_file: "OrderedDict[str, list]" = OrderedDict()
    for v in sorted_vulns:
        f_obj = getattr(v, "file", None)
        fp = getattr(f_obj, "filepath", None) or getattr(f_obj, "filename", "unknown")
        by_file.setdefault(fp, []).append(v)

    # ── CSS ───────────────────────────────────────────────────────────────────
    css = """
<style>
@page {
    size: A4;
    margin-top: 26mm;
    margin-bottom: 22mm;
    margin-left: 18mm;
    margin-right: 18mm;

    @frame header_frame {
        -pdf-frame-content: page-header;
        left: 18mm; right: 18mm;
        top: 8mm; height: 14mm;
    }
    @frame footer_frame {
        -pdf-frame-content: page-footer;
        left: 18mm; right: 18mm;
        bottom: 6mm; height: 10mm;
    }
}

body {
    font-family: Arial, Helvetica, sans-serif;
    color: #1e293b;
    font-size: 9pt;
    line-height: 1.45;
    margin: 0;
    padding: 0;
}

/* ── Header and Footer Frames ── */
#page-header {
    width: 100%;
    border-bottom: 0.75pt solid #cbd5e1;
    padding-bottom: 4px;
}
#page-header table { width: 100%; }
#page-header td { padding: 0; vertical-align: middle; }

#page-footer {
    width: 100%;
    border-top: 0.75pt solid #cbd5e1;
    padding-top: 4px;
}
#page-footer table { width: 100%; }
#page-footer td { padding: 0; vertical-align: middle; font-size: 7.5pt; color: #64748b; }

/* ── Section Headings ── */
h2 {
    font-size: 13pt;
    color: #0f172a;
    font-weight: bold;
    margin: 18px 0 8px 0;
    padding-bottom: 4px;
    border-bottom: 1.5pt solid #3b82f6;
    page-break-after: avoid;
}
h3 {
    font-size: 10.5pt;
    color: #0f172a;
    font-weight: bold;
    margin: 12px 0 4px 0;
    page-break-after: avoid;
}

/* ── Summary Meta Table ── */
.meta-table { width: 100%; margin-bottom: 16px; }
.meta-table td {
    padding: 6px 10px;
    border: 0.5pt solid #e2e8f0;
    font-size: 8.5pt;
}
.meta-table td.lbl {
    font-weight: bold;
    background-color: #f8fafc;
    color: #334155;
    width: 24%;
}

/* ── Score Box ── */
.score-box {
    border: 1pt solid #e2e8f0;
    background-color: #f8fafc;
    padding: 12px 14px;
    border-radius: 4px;
    text-align: center;
}
.score-title { font-size: 7.5pt; font-weight: bold; color: #64748b; letter-spacing: 0.5px; }
.score-num { font-size: 28pt; font-weight: bold; line-height: 1.1; margin: 4px 0; }
.score-sub { font-size: 8pt; color: #64748b; }

/* ── Severity Breakdown Table ── */
.bar-table { width: 100%; }
.bar-table td { padding: 3px 2px; vertical-align: middle; }

/* ── File Container ── */
.file-heading {
    background-color: #f1f5f9;
    border: 0.5pt solid #cbd5e1;
    border-radius: 3px;
    padding: 6px 10px;
    margin: 16px 0 8px 0;
    font-size: 8.5pt;
    font-family: Courier, monospace;
    font-weight: bold;
    color: #1e293b;
    word-wrap: break-word;
    page-break-after: avoid;
}

/* ── Finding Block ── */
.finding-block {
    border: 0.75pt solid #e2e8f0;
    border-radius: 4px;
    padding: 10px 12px;
    margin-bottom: 12px;
    page-break-inside: avoid;
    background-color: #ffffff;
}
.finding-loc {
    font-family: Courier, monospace;
    font-size: 8.5pt;
    color: #475569;
    margin-bottom: 5px;
}
.tags-row {
    font-size: 8pt;
    color: #475569;
    margin-bottom: 6px;
}

/* ── Chips ── */
.chip-fixed {
    color: #166534;
    background-color: #f0fdf4;
    border: 0.5pt solid #bbf7d0;
    font-size: 7.5pt;
    font-weight: bold;
    padding: 1px 6px;
}
.chip-open {
    color: #991b1b;
    background-color: #fef2f2;
    border: 0.5pt solid #fca5a5;
    font-size: 7.5pt;
    font-weight: bold;
    padding: 1px 6px;
}
.chip-auto {
    color: #075985;
    background-color: #f0f9ff;
    border: 0.5pt solid #bae6fd;
    font-size: 7.5pt;
    font-weight: bold;
    padding: 1px 6px;
}

/* ── Code Pre Boxes ── */
pre.code-box {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: Courier, monospace;
    font-size: 7.5pt;
    line-height: 1.35;
    padding: 8px 10px;
    margin: 4px 0 8px 0;
    border-radius: 3px;
    word-wrap: break-word;
    white-space: pre-wrap;
}
pre.fix-box {
    background-color: #052e16;
    color: #dcfce7;
    font-family: Courier, monospace;
    font-size: 7.5pt;
    line-height: 1.35;
    padding: 8px 10px;
    margin: 4px 0 8px 0;
    border-radius: 3px;
    border-left: 3pt solid #16a34a;
    word-wrap: break-word;
    white-space: pre-wrap;
}

/* ── Empty State ── */
.empty-state {
    border: 1pt solid #bbf7d0;
    background-color: #f0fdf4;
    color: #166534;
    padding: 20px;
    border-radius: 4px;
    text-align: center;
    margin: 24px 0;
}
</style>
"""

    # ── Page Header (all pages) ───────────────────────────────────────────────
    header_html = f"""
<div id="page-header">
  <table><tr>
    <td style="width:34px;">{_logo_img(26)}</td>
    <td style="padding-left:8px;">
      <span style="font-size:11pt; font-weight:bold; color:#0f172a;">SentinelAI</span>
    </td>
    <td style="text-align:right; font-size:9pt; font-weight:bold; color:#475569;">
      SentinelAI Security Report
    </td>
  </tr></table>
</div>
"""

    # ── Page Footer (all pages) ───────────────────────────────────────────────
    footer_html = f"""
<div id="page-footer">
  <table><tr>
    <td style="width:35%;">{proj_name}</td>
    <td style="width:35%; text-align:center;">Generated {gen_time}</td>
    <td style="width:30%; text-align:right;">
      Page <pdf:pagenumber/> of <pdf:pagecount/>
    </td>
  </tr></table>
</div>
"""

    # ── Summary Block (page 1) ────────────────────────────────────────────────
    raw_warnings = getattr(scan, "warnings", None)
    parsed_warnings = []
    if raw_warnings:
        if isinstance(raw_warnings, str):
            try:
                import json
                parsed_warnings = json.loads(raw_warnings)
            except Exception:
                parsed_warnings = [raw_warnings]
        elif isinstance(raw_warnings, list):
            parsed_warnings = raw_warnings

    has_warnings = bool(parsed_warnings)
    status_label = "Completed with Warnings" if has_warnings else "Completed"
    status_color = "#ca8a04" if has_warnings else "#16a34a"

    warnings_html = ""
    if parsed_warnings:
        warn_items = "".join(f'<div style="padding-left:8px; margin-bottom:2px;">&bull;&nbsp;{html_mod.escape(str(w))}</div>' for w in parsed_warnings)
        warnings_html = f"""
<div style="background-color:#fffbeb; border:1px solid #fef08a; border-radius:3px; padding:6px 10px; margin-bottom:12px; font-size:8pt; color:#92400e;">
  <div style="font-weight:bold; margin-bottom:3px;">Scan Warnings:</div>
  {warn_items}
</div>
"""

    summary_meta = f"""
<h2>Project Summary</h2>
<table class="meta-table">
  <tr>
    <td class="lbl">Project Name</td><td>{proj_name}</td>
    <td class="lbl">Scan Date</td><td>{html_mod.escape(scan_time)}</td>
  </tr>
  <tr>
    <td class="lbl">Files Scanned</td><td>{files_count}</td>
    <td class="lbl">Total Findings</td><td>{total}</td>
  </tr>
  <tr>
    <td class="lbl">Scan Status</td>
    <td><span style="color:{status_color}; font-weight:bold;">{status_label}</span></td>
    <td class="lbl">Report Date</td><td>{html_mod.escape(gen_time)}</td>
  </tr>
</table>
"""

    # Severity table rows: horizontal bar drawn directly as table cell
    total_bar_w = 210
    bar_rows = ""
    for sev in _SEVERITY_ORDER:
        cnt = counts[sev]
        c = _sev(sev)
        if total > 0 and cnt > 0:
            bar_w = max(6, int(total_bar_w * (cnt / max_count)))
            remain_w = total_bar_w - bar_w
            bar_cell = f'<td style="width:{bar_w}pt; background-color:{c["bar"]}; height:9pt; font-size:1pt; padding:0;">&nbsp;</td>'
            remain_cell = f'<td style="width:{remain_w}pt; background-color:#f1f5f9; height:9pt; font-size:1pt; padding:0;">&nbsp;</td>'
        else:
            bar_cell = ''
            remain_cell = f'<td style="width:{total_bar_w}pt; background-color:#f8fafc; height:9pt; font-size:1pt; padding:0;">&nbsp;</td>'

        bar_rows += f"""
<tr>
  <td style="width:50pt; font-weight:bold; font-size:8pt; text-transform:uppercase; color:{c['fg']}; padding:3px 2px;">{html_mod.escape(sev)}</td>
  <td style="width:25pt; text-align:right; font-weight:bold; font-size:8.5pt; color:#1e293b; padding:3px 8px 3px 2px;">{cnt}</td>
  <td style="width:6pt; padding:0;">&nbsp;</td>
  {bar_cell}
  {remain_cell}
</tr>"""

    score_and_breakdown = f"""
<table style="width: 100%; margin-bottom: 16px;">
  <tr>
    <td style="width: 120pt; vertical-align: top;">
      <div class="score-box">
        <div class="score-title">SECURITY SCORE</div>
        <div class="score-num" style="color: {score_clr};">{score}</div>
        <div class="score-sub">out of 100</div>
      </div>
    </td>
    <td style="padding-left: 14px; vertical-align: top;">
      <h3 style="margin-top: 0;">Severity Breakdown</h3>
      <table class="bar-table">
        {bar_rows}
      </table>
    </td>
  </tr>
</table>
"""

    # ── Findings Section ──────────────────────────────────────────────────────
    if not sorted_vulns:
        findings_html = """
<h2>Findings</h2>
<div class="empty-state">
  <div style="font-size:13pt; font-weight:bold; margin-bottom:4px;">No vulnerabilities found</div>
  <div style="font-size:9pt; color:#15803d;">All security checks passed. No vulnerabilities were detected in this scan.</div>
</div>
"""
    else:
        file_blocks: List[str] = []
        for fp, vulns in by_file.items():
            f_obj = vulns[0].file if hasattr(vulns[0], "file") else None
            lang = getattr(f_obj, "language", "") or ""
            lang_label = f" ({html_mod.escape(lang)})" if lang else ""
            safe_fp = html_mod.escape(str(fp))
            file_blocks.append(f'<div class="file-heading">File: {safe_fp}{lang_label}</div>')

            for v in vulns:
                sev_str = (getattr(v, "severity", "") or "").lower()
                c = _sev(sev_str)
                sev_label = html_mod.escape(sev_str.upper())
                vtype = html_mod.escape(str(getattr(v, "type", "") or "Security Issue"))
                lineno = getattr(v, "line_number", 0) or 0
                file_rel = html_mod.escape(str(getattr(f_obj, "filename", None) or fp))

                # Clean CWE / OWASP tags (omitted when null or "none")
                cwe_val = getattr(v, "cwe_id", None)
                cwe_str = str(cwe_val).strip() if (cwe_val and str(cwe_val).strip().lower() not in ("none", "null", "")) else ""
                owasp_val = getattr(v, "owasp_category", None)
                owasp_str = str(owasp_val).strip() if (owasp_val and str(owasp_val).strip().lower() not in ("none", "null", "")) else ""

                tags_parts = []
                if cwe_str:
                    tags_parts.append(f"<b>CWE:</b> {html_mod.escape(cwe_str)}")
                if owasp_str:
                    tags_parts.append(f"<b>OWASP:</b> {html_mod.escape(owasp_str)}")
                tags_html = "  &nbsp;&bull;&nbsp;  ".join(tags_parts)

                # Markdown conversion for description & recommendation
                description = _md_to_html(getattr(v, "description", None))
                recommendation = _md_to_html(getattr(v, "recommendation", None))

                # Safe snippets
                snippet = _safe_snippet(getattr(v, "code_snippet", None))
                fix = _safe_snippet(getattr(v, "suggested_fix", None))

                # Status chips
                is_fixed = bool(getattr(v, "fixed", False))
                auto_fixable = bool(getattr(v, "auto_fixable", False))

                if is_fixed:
                    status_chip = '<span class="chip-fixed">FIXED</span>'
                else:
                    status_chip = '<span class="chip-open">OPEN</span>'

                autofix_chip = ""
                if auto_fixable and not is_fixed:
                    autofix_chip = '&nbsp;<span class="chip-auto">Auto-fixable</span>'

                snippet_html = (
                    f'<div style="font-size:7.5pt; font-weight:bold; color:#475569; margin-top:6px; margin-bottom:2px;">Vulnerable Code</div>'
                    f'<pre class="code-box">{snippet}</pre>'
                    if snippet else ""
                )
                fix_html = (
                    f'<div style="font-size:7.5pt; font-weight:bold; color:#166534; margin-top:6px; margin-bottom:2px;">Suggested Fix</div>'
                    f'<pre class="fix-box">{fix}</pre>'
                    if fix else ""
                )
                rec_html = (
                    f'<div style="font-size:7.5pt; font-weight:bold; color:#334155; margin-top:6px; margin-bottom:2px;">Recommendation</div>'
                    f'<div style="font-size:8.5pt; color:#334155; margin-bottom:4px;">{recommendation}</div>'
                    if recommendation else ""
                )

                file_blocks.append(f"""
<div class="finding-block">
  <table style="width: 100%; margin-bottom: 5px;">
    <tr>
      <td style="width: 60pt; background-color: {c['bg']}; color: {c['fg']}; border: 1px solid {c['border']}; text-align: center; font-weight: bold; font-size: 7.5pt; padding: 2px 4px;">
        {sev_label}
      </td>
      <td style="padding-left: 8px; vertical-align: middle;">
        <span style="font-size: 9.5pt; font-weight: bold; color: #0f172a;">{vtype}</span>
      </td>
      <td style="text-align: right; vertical-align: middle;">
        {status_chip}{autofix_chip}
      </td>
    </tr>
  </table>
  <div class="finding-loc">{file_rel}:{lineno}</div>
  {f'<div class="tags-row">{tags_html}</div>' if tags_html else ""}
  {f'<div style="font-size:7.5pt; font-weight:bold; color:#334155; margin-top:5px; margin-bottom:2px;">Description</div><div style="font-size:8.5pt; color:#334155;">{description}</div>' if description else ""}
  {snippet_html}
  {fix_html}
  {rec_html}
</div>
""")

        findings_html = f"""
<h2>Findings
  <span style="font-size:8.5pt; font-weight:normal; color:#64748b;">
    ({total} finding{"s" if total != 1 else ""}, grouped by file, sorted by severity)
  </span>
</h2>
{"".join(file_blocks)}
"""

    # ── Assemble Full Document ────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>SentinelAI Security Report — {proj_name}</title>
  {css}
</head>
<body>
{header_html}
{footer_html}
{summary_meta}
{warnings_html}
{score_and_breakdown}
{findings_html}
</body>
</html>"""


# ── Public APIs ───────────────────────────────────────────────────────────────

def generate_pdf_html(project, scan, vulnerabilities: List) -> str:
    """Build the clean HTML string formatted for xhtml2pdf."""
    return _build_pdf_html(project, scan, vulnerabilities)


def generate_pdf_report(html_content: str) -> Optional[bytes]:
    """
    Renders HTML content into PDF bytes using xhtml2pdf (pisa).
    Returns PDF bytes on success, or None on failure or if xhtml2pdf is missing.
    """
    if not XHTML2PDF_AVAILABLE:
        logger.error("Cannot generate PDF: xhtml2pdf is not installed.")
        return None

    buf = BytesIO()
    try:
        from xhtml2pdf import pisa as _pisa
        result = _pisa.CreatePDF(html_content, dest=buf, link_callback=_link_callback)
    except Exception as exc:
        logger.error("xhtml2pdf raised an exception: %s", exc)
        return None

    if result.err:
        logger.error("xhtml2pdf reported %d error(s); not returning output.", result.err)
        return None

    pdf_bytes = buf.getvalue()
    if not pdf_bytes or len(pdf_bytes) < 200:
        logger.error("xhtml2pdf returned invalid or suspiciously small output (%d bytes).", len(pdf_bytes))
        return None

    return pdf_bytes


def generate_pdf_report_for_project(project, scan, vulnerabilities: List) -> Optional[bytes]:
    """
    Convenience method: builds the styled PDF HTML and returns PDF bytes.
    Returns None on failure.
    """
    html_content = generate_pdf_html(project, scan, vulnerabilities)
    return generate_pdf_report(html_content)
