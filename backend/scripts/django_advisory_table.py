"""
django_advisory_table.py
========================
Fetches ALL advisories for django==2.2.0 from OSV.dev and prints
a full per-advisory calculation table (all rows, no truncation).

Each row shows:
  # | advisory_id | cve | severity | fixed_versions_in_advisory |
  fixes_gt_installed | wb_min (2.2.x) | global_min

At the bottom a summary section prints:
  - Global recommended version (fixes everything)
  - Within-branch (2.2.x) recommendation
  - Counts of advisories fixed by each option

Run from the repo root:
  python -m backend.scripts.django_advisory_table
"""
import os
import sys
import time
import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from packaging.version import parse as parse_pypi_version, InvalidVersion
from backend.sca.findings import (
    extract_fixed_versions,
    is_strictly_greater,
    compute_minimum_covering_version,
    compute_within_branch_version,
    installed_major_minor,
    _is_valid_ecosystem_version,
)

ECOSYSTEM = "PyPI"
PKG = "django"
INSTALLED = "2.2.0"


def fetch_with_retry(url, method="GET", body=None, retries=3):
    for attempt in range(retries):
        try:
            with httpx.Client(timeout=20.0) as c:
                if method == "POST":
                    r = c.post(url, json=body)
                else:
                    r = c.get(url)
                if r.status_code == 200:
                    return r.json()
                elif r.status_code in (429, 500, 502, 503, 504):
                    time.sleep(1.0 * (2 ** attempt))
                else:
                    raise RuntimeError(f"HTTP {r.status_code} from {url}")
        except (httpx.RequestError, httpx.TimeoutException):
            if attempt == retries - 1:
                raise
            time.sleep(1.0 * (2 ** attempt))
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts")


def main():
    print(f"Fetching advisory IDs for {PKG}=={INSTALLED} from OSV.dev ...")
    resp = fetch_with_retry(
        "https://api.osv.dev/v1/query",
        method="POST",
        body={"package": {"name": PKG, "ecosystem": ECOSYSTEM}, "version": INSTALLED},
    )
    vuln_stubs = resp.get("vulns", [])
    advisory_ids = [v["id"] for v in vuln_stubs]
    total = len(advisory_ids)
    print(f"  -> {total} advisory IDs returned")

    # Fetch full advisory records
    print("Fetching full advisory records (one per advisory) ...")
    adv_records = {}
    for i, aid in enumerate(advisory_ids, 1):
        print(f"  [{i:>3}/{total}] {aid}", end="\r", flush=True)
        data = fetch_with_retry(f"https://api.osv.dev/v1/vulns/{aid}")
        adv_records[aid] = data
        # Polite rate-limiting
        if i % 10 == 0:
            time.sleep(0.3)
    print()  # newline after \r progress

    # ------------------------------------------------------------------ #
    # Per-advisory calculation
    # ------------------------------------------------------------------ #
    inst_mm = installed_major_minor(ECOSYSTEM, INSTALLED)  # (2, 2)

    rows = []           # list of dicts, one per advisory
    fixed_by_advisory = []  # parallel list of fix-version lists

    for aid in advisory_ids:
        rec = adv_records[aid]

        # Severity
        sev_raw = rec.get("database_specific", {}).get("severity", "")
        severity = sev_raw.strip().upper() if sev_raw else "NOT_PROVIDED"

        # CVE aliases
        aliases = rec.get("aliases", [])
        cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), None)

        # All fixed versions from this advisory (ECOSYSTEM ranges only)
        fixes = extract_fixed_versions(rec, ECOSYSTEM, PKG)
        fixed_by_advisory.append(fixes)

        # Valid fixes > installed
        fixes_gt = [
            v for v in fixes
            if _is_valid_ecosystem_version(ECOSYSTEM, v)
            and is_strictly_greater(ECOSYSTEM, v, INSTALLED)
        ]

        # Per-advisory global minimum (smallest fix > installed)
        if fixes_gt:
            per_adv_global_min = min(fixes_gt, key=lambda x: parse_pypi_version(x))
        else:
            per_adv_global_min = None

        # Per-advisory within-branch minimum (smallest fix in 2.2.x > installed)
        fixes_wb = [
            v for v in fixes_gt
            if (parse_pypi_version(v).major, parse_pypi_version(v).minor) == inst_mm
        ]
        if fixes_wb:
            per_adv_wb_min = min(fixes_wb, key=lambda x: parse_pypi_version(x))
        else:
            per_adv_wb_min = None

        rows.append({
            "id": aid,
            "cve": cve or "",
            "severity": severity,
            "all_fixes": fixes,
            "fixes_gt_installed": fixes_gt,
            "per_adv_global_min": per_adv_global_min,
            "per_adv_wb_min": per_adv_wb_min,
        })

    # ------------------------------------------------------------------ #
    # Compute global recommended version + within-branch recommendation
    # ------------------------------------------------------------------ #
    recommended_version = compute_minimum_covering_version(
        ECOSYSTEM, fixed_by_advisory, installed_version=INSTALLED
    )
    wb_version, wb_fixed_count = compute_within_branch_version(
        ECOSYSTEM, fixed_by_advisory, INSTALLED, inst_mm
    )

    # Count advisories that have NO applicable fix at all (global)
    no_fix_count = sum(1 for r in rows if r["per_adv_global_min"] is None)
    advisories_fixed_by_rec = total - no_fix_count  # those WITH a global fix

    # ------------------------------------------------------------------ #
    # Build output lines
    # ------------------------------------------------------------------ #
    lines = []

    RULE = "=" * 120
    DASH = "-" * 120

    lines.append(RULE)
    lines.append(f"Per-Advisory Calculation: {PKG}=={INSTALLED}  ({ECOSYSTEM})")
    lines.append(f"Total advisories fetched : {total}")
    lines.append(RULE)
    lines.append("")

    # Column widths
    COL_W = {
        "num":     4,
        "id":     20,
        "cve":    20,
        "sev":    14,
        "fixes":  34,
        "gt":     24,
        "wb":     14,
        "glb":    14,
    }
    hdr = (
        f"{'#':<{COL_W['num']}} "
        f"{'Advisory ID':<{COL_W['id']}} "
        f"{'CVE':<{COL_W['cve']}} "
        f"{'Severity':<{COL_W['sev']}} "
        f"{'Fixed versions (all)':<{COL_W['fixes']}} "
        f"{'Fixes > 2.2.0':<{COL_W['gt']}} "
        f"{'WB min (2.2.x)':<{COL_W['wb']}} "
        f"{'Global min':<{COL_W['glb']}}"
    )
    sep = "-" * len(hdr)
    lines.append(hdr)
    lines.append(sep)

    for idx, row in enumerate(rows, 1):
        all_fixes_str = ", ".join(row["all_fixes"]) if row["all_fixes"] else "(none)"
        gt_str        = ", ".join(row["fixes_gt_installed"]) if row["fixes_gt_installed"] else "(none)"
        wb_str        = row["per_adv_wb_min"] or "(none)"
        glb_str       = row["per_adv_global_min"] or "(none)"

        if len(all_fixes_str) > COL_W["fixes"]:
            all_fixes_str = all_fixes_str[:COL_W["fixes"] - 3] + "..."
        if len(gt_str) > COL_W["gt"]:
            gt_str = gt_str[:COL_W["gt"] - 3] + "..."

        lines.append(
            f"{idx:<{COL_W['num']}} "
            f"{row['id']:<{COL_W['id']}} "
            f"{row['cve']:<{COL_W['cve']}} "
            f"{row['severity']:<{COL_W['sev']}} "
            f"{all_fixes_str:<{COL_W['fixes']}} "
            f"{gt_str:<{COL_W['gt']}} "
            f"{wb_str:<{COL_W['wb']}} "
            f"{glb_str:<{COL_W['glb']}}"
        )

    lines.append(sep)
    lines.append("")

    # ------------------------------------------------------------------ #
    # Legend
    # ------------------------------------------------------------------ #
    lines.append("COLUMN LEGEND")
    lines.append("-" * 60)
    lines.append(f"  #              : row number (1-{total})")
    lines.append( "  Advisory ID    : OSV / GHSA identifier")
    lines.append( "  CVE            : CVE alias (if any)")
    lines.append( "  Severity       : database_specific.severity from OSV record")
    lines.append( "  Fixed versions : all ECOSYSTEM-range fixed versions in advisory")
    lines.append(f"  Fixes > {INSTALLED}  : subset that are strictly greater than installed")
    lines.append(f"  WB min (2.2.x) : smallest fix > {INSTALLED} that stays in the 2.2.x branch")
    lines.append( "                   '(none)' = no fix exists within the 2.2.x branch")
    lines.append(f"  Global min     : smallest fix > {INSTALLED} in any version")
    lines.append(f"                   '(none)' = advisory has no fix > {INSTALLED} at all")
    lines.append("")

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    lines.append(RULE)
    lines.append("SUMMARY - HOW THE TWO UPGRADE PATHS ARE DETERMINED")
    lines.append(RULE)
    lines.append("")
    lines.append(f"  Installed version          : {PKG}=={INSTALLED}  (branch 2.2.x)")
    lines.append(f"  Total advisories           : {total}")
    lines.append("")
    lines.append("  Rule for GLOBAL recommendation (Fixes everything)")
    lines.append("  " + "-" * 49)
    lines.append("    For each advisory, take the smallest fixed version > installed.")
    lines.append("    The global recommendation = MAX of those per-advisory minimums.")
    lines.append("    Any advisory with no fix > installed makes the result indeterminate (None).")
    lines.append("")
    if recommended_version:
        lines.append(f"  -> Global recommended version : {recommended_version}")
        lines.append(f"     Advisories resolved        : {advisories_fixed_by_rec} of {total}")
        lines.append(f"     (Advisories with no applicable fix: {no_fix_count})")
    else:
        lines.append( "  -> Global recommended version : None (indeterminate)")
        lines.append(f"     Reason: {no_fix_count} advisory(ies) have no fixed version > {INSTALLED}")

    lines.append("")
    lines.append("  Rule for WITHIN-BRANCH recommendation (Within your 2.2.x branch)")
    lines.append("  " + "-" * 66)
    lines.append(f"    For each advisory, take the smallest fixed version > {INSTALLED} AND in 2.2.x.")
    lines.append( "    Within-branch recommendation = MAX of those per-advisory within-branch minimums.")
    lines.append( "    Count = advisories that have a within-branch fix <= that recommendation.")
    lines.append("")
    if wb_version:
        lines.append(f"  -> Within-branch recommended  : {wb_version}  (branch 2.2.x)")
        lines.append(f"     Advisories resolved        : {wb_fixed_count} of {total}")
        no_wb_fix = total - wb_fixed_count
        lines.append(f"     (Advisories with no 2.2.x fix: {no_wb_fix} -- require a major upgrade)")
    else:
        lines.append( "  -> Within-branch recommended  : None (no advisory has a fix within 2.2.x)")

    lines.append("")
    lines.append("  HOW THE FINDING CARD DISPLAYS THESE (when is_major_jump=True)")
    lines.append("  " + "-" * 64)
    if wb_version and recommended_version:
        wb_col  = wb_version
        rec_col = recommended_version
        lines.append(f"  | {'Path':<29} | {'Version':<15} | {'Advisories resolved':<19} |")
        lines.append(f"  |-{'-'*29}-|-{'-'*15}-|-{'-'*19}-|")
        lines.append(f"  | {'Within your 2.2.x branch':<29} | {wb_col:<15} | {str(wb_fixed_count)+' of '+str(total):<19} |")
        lines.append(f"  | {'Fixes everything (major)':<29} | {rec_col:<15} | {'all '+str(total):<19} |")
    else:
        lines.append( "  (No within-branch option available; only the global recommendation is shown.)")

    lines.append("")
    lines.append(RULE)
    lines.append("END OF REPORT")
    lines.append(RULE)

    output = "\n".join(lines)

    # Write to file (UTF-8 so it survives any version of the text)
    out_path = os.path.join(
        os.path.dirname(__file__), "django_2_2_0_advisory_table.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

    # Print to console (errors=replace guards against cp1252 on Windows)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    print(output)
    print(f"\n[Saved to: {out_path}]")


if __name__ == "__main__":
    main()
