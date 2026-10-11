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
  that blocks writes introducing errors (HTTP 422) rather than risking a corrupted file
- **Honest about limitations** — findings without a safe, unambiguous
  fix are clearly marked as requiring manual review rather than guessing
- **Google Sign-In** alongside standard email/password auth
- **Dashboard visualizations** — per-project security score, severity
  breakdown, scan history timeline, and a codebase-wide vulnerability map
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

## Known Limitations / Roadmap

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
`backend/tests/test_step6.py`, and `backend/tests/test_issue_classes_dedup.py`).
