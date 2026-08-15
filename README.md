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
- **Structured explanations** — every finding includes Issue / Reason /
  Impact / Severity / Fix, mapped to CWE and OWASP Top 10 categories
  where applicable
- **Safe automatic fixing** — for vulnerability types with a reliable,
  mechanical fix (SQL injection via string concatenation, hardcoded
  secrets, `shell=True` subprocess calls, weak hashing algorithms), the
  system generates real replacement code, shows a before/after diff, and
  can apply it directly to the file — with an exact-match safety check
  and a pre-write syntax validation (`ast.parse()`) that blocks the write
  entirely rather than risking a corrupted file
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
which engine found them, deduplicated by (file, line, vulnerability
type), then persisted with severity, CWE/OWASP mapping, and an
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

GET    /reports/{id}?format=pdf|html|json|csv
```

## Project Structure

```
├── backend/
│   ├── api/            # route handlers
│   ├── detectors/       # Bandit/Semgrep/AST wrappers + orchestrator
│   ├── ai/               # AI provider interface + fallback templates
│   ├── fixer/             # fix application + safety validation
│   ├── models/             # SQLAlchemy models
│   ├── database/            # session/engine setup
│   └── main.py
├── frontend/
│   └── src/
│       ├── routes/       # TanStack Router pages
│       ├── components/    # UI components, charts, code/diff viewer
│       └── api/             # backend API client
├── docker-compose.yml
└── uploads/              # scanned files (gitignored)
```

## Known Limitations / Roadmap

- Automatic fixing currently covers a fixed set of well-understood
  vulnerability types; broader AI-driven fix generation for arbitrary
  findings is planned once a funded AI provider is in place
- Apple Sign-In is present in the UI but not yet functional (requires a
  paid Apple Developer account)
- Not yet deployed to a public host — currently designed to run locally
  or via Docker

## Validation

This project was validated against real vulnerable code samples covering
SQL injection, hardcoded credentials, insecure deserialization, weak
cryptographic hashing, and command injection. Detection accuracy,
explanation correctness, and — for auto-fixable findings — the safety and
correctness of applied fixes were manually verified, including
mechanically re-compiling patched files to confirm they remain valid,
runnable code.
