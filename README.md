# SentinelAI — Security Vulnerability Detector & Fixer

An AI-assisted application security scanner that detects vulnerabilities
in source code, explains them in plain language, maps them to industry
standards (CWE/OWASP), and — for well-understood vulnerability classes —
can safely generate and apply a real code fix directly to the file.

> Upload code → detect real vulnerabilities → understand why they matter
> → review a fix → apply it safely → verify the file is still valid.

<!--
  SCREENSHOT GUIDE — capture these and drop them in below,
  replacing this comment block:

  1. Login page (glass auth UI)
  2. Dashboard (project list, empty and populated states)
  3. Project detail page (file upload zone + scan trigger)
  4. Scan Results / vulnerability list (severity filters visible)
  5. Vulnerability Detail page (code viewer + diff view + Apply Fix)
  6. Security score gauge + severity chart + codebase map (dashboard viz)
  7. A "before" and "after" of a file that had a fix applied
-->

## Features

- **Multi-engine detection** — Bandit (Python-specific rules), Semgrep
  (multi-language: JS, Java, C/C++, PHP), and a custom Python AST
  analyzer for additional rules, with results deduplicated across engines
- **Software Composition Analysis (SCA)** — automated vulnerable dependency
  scanning powered by OSV.dev API across Python (`requirements.txt`), JavaScript
  (`package.json`, `package-lock.json`), and Java Maven (`pom.xml`) manifests,
  with lockfile precedence, defensive XML parsing (`defusedxml`) to prevent entity expansion,
  and deterministic covering-version upgrade guidance
- **Accurate CWE and OWASP mapping** — every finding carries a
  normalized CWE ID extracted from the detector's own metadata (with a
  comprehensive fallback map for Bandit), dependency findings mapped directly
  to OWASP A06:2021 (Vulnerable and Outdated Components), and the single-source
  OWASP Top 10:2021 category is always derived from `backend/utils/owasp_map.py`
  (never hardcoded per detector). Source: [owasp.org/Top10](https://owasp.org/Top10/)
- **Structured explanations** — every finding includes Issue / Reason /
  Impact / Severity / Fix, mapped to CWE and OWASP Top 10 categories
  where applicable
- **Safe automatic fixing** — for vulnerability types with a reliable,
  mechanical fix (SQL injection via string concatenation, hardcoded
  secrets, `shell=True` subprocess calls, weak hashing algorithms), the
  system generates real replacement code, shows a before/after diff, and
  can apply it directly to the file — with atomic import injection,
  database driver-aware SQL placeholders (`?` vs `%s`), and pre-write
  validation (`ast.parse()` syntax check and `pyflakes` undefined name analysis)
  that blocks writes introducing errors (HTTP 422) rather than risking a corrupted file.
  When an AI provider is configured, additional finding types (e.g. insecure
  deserialization) can receive an **AI-generated fix**. These fixes are labeled
  **"AI-generated · re-scan clean · behaviour not tested"** in the UI: the patch
  passed syntax validation and a post-apply re-scan confirmed the vulnerability
  pattern no longer appears, but functional regression testing with real application
  payloads is the developer's responsibility. Fixes that change the data format
  (e.g. `pickle` → `json`) display an amber **"Behaviour change"** warning — callers
  must send JSON-serialised payloads after the fix is applied.
- **Honest about limitations** — findings without a safe, unambiguous
  fix are clearly marked as requiring manual review rather than guessing
- **Google Sign-In** alongside standard email/password auth
- **Scan Comparison and Regression Detection** — historical snapshotting per scan (`ScanFinding`) with stable SHA-256 fingerprints across line shifts and whitespace. Compares any scan against its predecessor or specified baseline to report:
  - **New**: in the current scan, not in the base scan, and never seen in any retained earlier scan
  - **Regressed**: in the current scan, not in the base scan, but seen in an earlier retained scan (present, disappeared, and came back)
  - **Resolved**: in the base scan, not in the current scan, and comparable under honesty rules (attributed with "resolved via apply-fix" when fixed automatically)
  - **Persisting**: in both scans (tracks version changes for dependencies without breaking fingerprint continuity)
  - **Not Comparable**: findings that cannot honestly be claimed as resolved because a detector failed or did not run (e.g. Semgrep or OSV failure), or the target file was removed from the project
  - **Retention Window**: snapshots are maintained for the 20 most recent completed scans per project, pruning older ones automatically
  - **Fingerprint Limitation**: renaming a variable or altering the flagged line itself generates a new fingerprint, registering as 1 resolved and 1 new finding
- **Dashboard visualizations** — per-project security score, severity
  breakdown, scan history timeline, interactive "What changed" scan diff panel, and a codebase-wide vulnerability map
- **Report export** — PDF, HTML, JSON, and CSV

## Tech Stack

**Backend**
- Python 3.11+, FastAPI
- PostgreSQL via SQLAlchemy
- JWT auth (python-jose) + bcrypt, plus Google OAuth (ID token
  verification)
- Bandit, Semgrep, custom AST analyzer
- OSV.dev client (httpx) + defusedxml for Software Composition Analysis (SCA)
- OpenAI-compatible AI layer (swappable provider), with a safe
  template-based fallback when no AI key is configured
- xhtml2pdf for PDF report generation

**Frontend**
- React + TypeScript + Vite
- TanStack Router
- shadcn/ui + Tailwind CSS
- Recharts (via shadcn's chart wrapper) for dashboard visualizations

**Infrastructure**
- Docker + Docker Compose (backend, PostgreSQL, and frontend as separate
  services, with a multi-stage frontend build served via nginx)
- **Named Volumes & Storage**:
  - `postgres_data`: Persistent storage for PostgreSQL (mounted at `/var/lib/postgresql/data`).
  - `uploads_data`: High-performance named volume for scanned user code and extracted files (mounted inside the backend container at `/app/uploads`). Docker Compose namespaces this volume as `securityvulnerabilitydecoderandfixer_uploads_data`. *(Note: any references in legacy notes or documentation mentioning `uploads_data (backend_uploads:...)` refer strictly to this Compose volume `uploads_data` mounted at `/app/uploads`).*
- **Test Compose file (`docker-compose.test.yml`)** — a local-only override (gitignored, never auto-loaded by `docker compose up`) that exposes PostgreSQL on `127.0.0.1:5433` for host-side `pytest` runs:
  ```bash
  # Bring up the DB with test port exposed (host test runs only):
  docker compose -f docker-compose.yml -f docker-compose.test.yml up -d db
  ```
  Tests connect to the separate database `security_scanner_test` (not `security_scanner`).
  Plain `docker compose config` and `docker compose up` ignore this file entirely —
  it is never included in production.

## Architecture

```
                    User
                     │
                     ▼
          React + TypeScript Frontend
                     │
                     ▼
             FastAPI Backend
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
  Detection      AI Layer     PostgreSQL
   Engine      (explain/fix)
  (Bandit +
   Semgrep +
   custom AST)
```

Detection results are normalized into a common schema regardless of
which engine found them, **deduplicated** by `(file, line, CWE-ID)` when
a CWE exists (otherwise by `(file, line, normalised-type)`) — the
highest-confidence finding is kept and any non-null CWE is propagated.
Results are then persisted with severity, CWE/OWASP mapping, and an
AI-or-template-generated explanation and suggested fix.

## Getting Started

### Quick start with Docker (recommended)

```bash
git clone https://github.com/Gaganp-10/SentinalAI.git
cd SentinalAI
docker-compose up --build
```

Once running:
- Frontend: http://localhost:3000
- Backend API docs (Swagger): http://localhost:8000/docs

### Manual setup (without Docker)

**Backend:**
```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt
```

Create `backend/.env`:
```
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5433/secdetector
SECRET_KEY=your-secret-key
ALLOWED_ORIGINS=["http://localhost:3000"]
GOOGLE_CLIENT_ID=your-google-oauth-client-id
```

Run:
```bash
cd ..
uvicorn backend.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## API Overview

Full interactive documentation is available at `/docs` once the backend
is running. Core endpoints:

```
POST   /auth/signup            /auth/login            /auth/google
GET    /auth/me

POST   /projects                GET /projects
POST   /projects/{id}/files     GET /projects/{id}/files
POST   /projects/{id}/scan      GET /scans/{id}

GET    /vulnerabilities?project_id=
PATCH  /vulnerabilities/{id}
POST   /vulnerabilities/{id}/regenerate-fix
POST   /vulnerabilities/{id}/apply-fix
GET    /files/{id}/download

GET    /projects/{id}/owasp    # OWASP Top 10:2021 coverage (per-category open/fixed/CWEs)

GET    /reports/{id}?format=pdf|html|json|csv
```

## Project Structure

```
├── backend/
│   ├── api/            # route handlers (incl. owasp.py)
│   ├── detectors/       # Bandit/Semgrep/AST wrappers + orchestrator
│   ├── sca/             # Software Composition Analysis (OSV.dev client, parsers, findings)
│   ├── utils/
│   │   └── owasp_map.py  # single-source CWE→OWASP Top 10:2021 table
│   ├── ai/               # AI provider interface + fallback templates
│   ├── fixer/             # fix application + safety validation
│   ├── models/             # SQLAlchemy models
│   ├── database/            # session/engine setup
│   ├── tests/               # pytest suite (test_step6.py)
│   └── main.py
├── frontend/
│   └── src/
│       ├── routes/       # TanStack Router pages
│       ├── components/    # UI components (incl. OwaspCoveragePanel)
│       └── api/             # backend API client (incl. owasp.ts)
├── docker-compose.yml
└── uploads/              # scanned files (gitignored)
```

## Recommended-Version Rule (SCA)

The canonical rule — implemented in `backend/sca/findings.py::compute_minimum_covering_version`,
stated in every finding's explanation text, and tested in `backend/tests/test_step7.py`:

> **For each advisory:** collect all fixed versions listed.  
> Discard any that are **≤ the installed version** (they pre-date the installed release).  
> Take the **smallest** of the remaining versions as that advisory's minimum covering version.  
> If any advisory has no remaining fixed version, return `None` (no safe recommendation).  
> Otherwise the overall recommendation is the **maximum** (highest) of all per-advisory minimums,  
> because upgrading to that one version satisfies every advisory simultaneously.

### Worked example — Django `2.2.0` (installed)

| Advisory | Severity | Fixed versions in OSV | Fixes ≤ 2.2.0 ignored | Per-advisory min > 2.2.0 |
|---|---|---|---|---|
| GHSA-2gwj-7jmv-h26r | CRITICAL | 2.2.28, 3.2.13, 4.0.4 | — | **2.2.28** |
| GHSA-2m34-jcjv-45xf | MODERATE | 2.2.13, 3.0.7 | — | **2.2.13** |
| GHSA-3gh2-xw74-jmcw | HIGH | 1.11.29, 2.2.11, 3.0.4 | 1.11.29 | **2.2.11** |
| GHSA-3h9f-r86x-qvjx | LOW | 5.2.16, 6.0.7 | — | **5.2.16** |
| GHSA-53qw-q765-4fww | HIGH | 2.2.26, 3.2.11, 4.0.1 | — | **2.2.26** |
| GHSA-68w8-qjq3-2gfm | MODERATE | 2.2.24, 3.1.12, 3.2.4 | — | **2.2.24** |
| GHSA-6c3j-c64m-qhgq | MODERATE | 2.1.9, 2.2.2 | 2.1.9 | **2.2.2** |
| GHSA-6c7v-2f49-8h26 | MODERATE | 2.1.10, 2.2.3, 1.11.22 | 2.1.10, 1.11.22 | **2.2.3** |
| GHSA-6cw3-g6wv-c2xv | HIGH | 2.2.27, 3.2.12, 4.0.2 | — | **2.2.27** |
| GHSA-6r97-cj55-9hrq | CRITICAL | 1.11.23, 2.1.11, 2.2.4 | 1.11.23, 2.1.11 | **2.2.4** |
| GHSA-6w2r-r2m5-xq5w | HIGH | 4.2.24, 5.1.12, 5.2.6 | — | **4.2.24** |
| GHSA-7rp2-fm2h-wchj | MODERATE | 1.11.21, 2.1.9, 2.2.2 | 1.11.21, 2.1.9 | **2.2.2** |
| *(63 more)* | | | | |

**Overall recommendation = max of per-advisory minimums = `5.2.16`**  
(driven by GHSA-3h9f-r86x-qvjx which only has fixes on the 5.x/6.x branch)

> Django 2.2.0 has **75** total advisories from OSV. Every advisory in the
> sample above has at least one fix strictly greater than 2.2.0, so a
> covering version *can* be computed. The result is `5.2.16` because that
> advisory only provides fixes on the 5.x and 6.x branches.

### Express 4.17.1 — severity source

Express 4.17.1 has **2 OSV advisories**:

| Advisory | `database_specific.severity` from OSV | Summary |
|---|---|---|
| GHSA-qw6h-vgh9-j6wx | `LOW` (source-provided) | XSS via response.redirect() |
| GHSA-rv95-896h-c2vc | `MODERATE` (source-provided) | Open Redirect in malformed URLs |

The `medium` severity shown in SentinelAI for Express 4.17.1 is **not a
default** — it comes directly from `database_specific.severity = "MODERATE"`
in GHSA-rv95-896h-c2vc, which normalizes to `medium` via `normalize_severity()`.
`npm audit` may report these differently because it uses the npm advisory
database (npmjs.com/advisories), not the OSV database; severity labels can
differ between registries for the same vulnerability.


### General
- Automatic fixing currently covers a fixed set of well-understood
  vulnerability types; broader AI-driven fix generation for arbitrary
  findings is planned once a funded AI provider is in place
- The AST detector cannot track SQL queries assigned to a variable
  before being passed to `execute()` — only direct string-concatenation
  in the call site is flagged. This is a known limitation of static
  analysis without data-flow tracking.
- Semgrep detector failure is logged to backend logs but not surfaced in
  the UI as a user-facing warning; scans proceed with Bandit and AST results.
- `semgrep --test` is subject to an upstream path-normalization bug on Windows
  (`IndexError` in `semgrep.test:relatively_eq`); rule correctness is verified
  directly via `semgrep scan` on the fixture files.
- Apple Sign-In is present in the UI but not yet functional (requires a
  paid Apple Developer account)
- Not yet deployed to a public host — currently designed to run locally
  or via Docker

### Software Composition Analysis (SCA) — Limitations

| Limitation | Detail |
|---|---|
| **Internet required** | Dependency scanning queries `https://api.osv.dev` at scan time. Scans will partially or fully fail if the host has no outbound internet access. Findings from any batches that succeeded are always preserved. |
| **Versions sent to OSV** | Package name, ecosystem string (`PyPI`, `npm`, `Maven`), and exact version are transmitted to `api.osv.dev` in compliance with the [OSV Query API](https://google.github.io/osv.dev/post-v1-query/). No file content is sent. |
| **Pinned / resolved versions only** | Only dependencies with an exact pinned version are queried. Unpinned ranges (e.g., `flask>=2.0`, `express: ^4.18.0`) are reported as `not_checked` in the dependency summary and listed in scan warnings. |
| **No automatic fix** | Dependency vulnerabilities are never auto-patched. The UI shows a disabled *"Update this dependency manually (>= X)"* button. Upgrades must be applied by the developer in their package manager (`pip`, `npm`, `mvn`). |
| **Supported ecosystems** | Only `PyPI` (`requirements.txt`, `requirements-*.txt`), `npm` (`package.json` / `package-lock.json`), and `Maven` (`pom.xml`) are scanned. Go, Rust, Ruby, PHP, and other ecosystems are not yet supported. |
| **Transitive dependencies** | Transitive dependencies are resolved from `package-lock.json` (npm) when present; for `requirements.txt` and `pom.xml` only directly listed packages are checked. |
| **OSV data freshness** | Advisory data is fetched live at scan time (6-hour in-memory cache per process). OSV may not yet have published advisories for newly disclosed CVEs. |


## Validation

This project was validated against real vulnerable code samples covering
SQL injection, hardcoded credentials, insecure deserialization, weak
cryptographic hashing, and command injection. Detection accuracy,
explanation correctness, and — for auto-fixable findings — the safety and
correctness of applied fixes were verified, including automated pre-write
validation confirming patched files are free of syntax errors (`ast.parse`)
and newly introduced undefined names (`pyflakes`). These guarantees, along with
driver-specific SQL parameterization, atomic import injection (`os`, `hashlib`, `subprocess`),
and rollback safeguards, are comprehensively covered by automated unit and
integration tests (`backend/tests/test_runtime_fix_correctness.py`,
`backend/tests/test_step6.py`, `backend/tests/test_issue_classes_dedup.py`,
and `backend/tests/test_step7.py` for SCA/dependency scanning).

## Test Database Isolation

All automated tests run against a **separate** PostgreSQL database
(`security_scanner_test`) — never against the application database
(`security_scanner`). Isolation is enforced at session startup:
`backend/database/session.py` detects whether `pytest` is active (via
`sys.modules`, the `TESTING=1` env var, or `PYTEST_CURRENT_TEST`) and
appends `_test` to the database name automatically. A session-scoped autouse
fixture in `backend/tests/conftest.py` asserts the engine URL contains
`security_scanner_test` before any test runs.

The redacted connection string used by the test suite inside Docker:
```
postgresql://sentinel:***@db:5432/security_scanner_test
```

The app database is never touched by the test suite. Row counts in
`users`, `projects`, and `vulnerabilities` are unchanged after a full
test run.

## Performance Benchmarking

To benchmark scan snapshotting and diff computation performance across a large project (3,000 files):

```bash
python backend/scripts/benchmarks/benchmark_real_3000.py
```

*Note: The benchmark uses an isolated, ephemeral in-memory SQLite database (`sqlite:///:memory:`). It does not create or persist any users, database credentials, or disk artifacts in your application database.*
