# Benchmark: Real 3 000-File Scan + Diff

## Purpose
`benchmark_real_3000.py` measures the wall-clock time of three operations on a
SentinelAI project that contains 3 000 Python source files:

| Operation | Metric |
|---|---|
| File generation + DB registration | seconds |
| Real background scan (Bandit + AST + Semgrep + OSV) | seconds |
| Snapshot write (3 000 `ScanFinding` rows) | milliseconds |
| Diff computation (Scan 2 vs Scan 1) | milliseconds |

## No persistent users or credentials

The benchmark runs against an **in-memory SQLite database** (`sqlite:///:memory:`).
Every `User`, `Project`, `File`, `ScanHistory` and `ScanFinding` row is
created inside that ephemeral session and is discarded when the process exits.

**It never touches:**
- The production PostgreSQL database (`secdetector`)
- The `uploads/` directory of any real project (it writes to `settings.UPLOAD_DIR/<uuid>/`)
- Any `.env` file, API key, or credential

The temporary upload directory is deleted with `shutil.rmtree` at the end of the run.

## How to run

From the repository root (activate your virtualenv first):

```bash
# Windows PowerShell
python backend/scripts/benchmarks/benchmark_real_3000.py

# Linux / macOS
python backend/scripts/benchmarks/benchmark_real_3000.py
```

No database connection required — the script bootstraps its own SQLite session.

## Expected output (approximate, hardware-dependent)

```
================================================================================
GENERATING 3,000 REAL FILES AND RUNNING SCAN + SNAPSHOT WRITE + DIFF
================================================================================
Generated 3,000 files and registered in DB in 1.23s
--- Executing Real Scan 1 (3,000 files) ---
Scan 1 Completed: 50 issues found across 3,000 files.
Real Scan 1 Total Time (detector execution + snapshot write): 38.57s
ScanFinding rows written for Scan 1: 50
--- Modifying files and executing Real Scan 2 (3,000 files) ---
Scan 2 Completed: 60 issues found across 3,000 files.
Real Scan 2 Total Time: 39.12s
ScanFinding rows written for Scan 2: 60
Total ScanFinding rows in DB for this project: 110

Real Scan Diff Computation Time: 12.34 ms (0.0123s)
Diff Summary: {
  "new": 10,
  "resolved": 0,
  "persisting": 50,
  "regressed": 0,
  "not_comparable": 0
}

Benchmark completed and clean up done.
```
