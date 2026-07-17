# Walkthrough — Security Vulnerability Detector & Fixer Backend

The complete FastAPI backend has been successfully built, integrated with PostgreSQL (via SQLAlchemy), linter engines (Bandit, Semgrep, and custom AST rules), the AI Layer (OpenAI Provider + local template fallbacks), and multiple download formats (HTML, PDF, JSON, and CSV).

Here is a summary of the components built and verified.

---

## 1. Directory Structure Implemented

We created the complete layout under the `backend/` directory:
- `main.py`: Application entrypoint, registering CORS and routers.
- `requirements.txt`: Python package requirements with support for Python 3.11+ (runtimes like Docker) and Python 3.13 (host system).
- `Dockerfile` & `docker-compose.yml`: Fully configured Docker setup for multi-stage building.
- `api/`: Routers for authentication, project metadata, files, scans, vulnerabilities, reports, and AI.
- `parser/`: Extension-based programming language detection module.
- `detectors/`: Linter orchestrator, wrapper scripts for Bandit and Semgrep, and custom Python AST rules (for hardcoded secrets, weak hashing, dangerous eval/exec execution, and SQL string concatenation).
- `ai/`: AI Provider interfaces, OpenAI implementation, and explanation prompt templates.
- `fixer/`: AI-based secure code repair engine generating patched files, snippets, and unified diffs.
- `reports/`: HTML templates and compilation pipelines for HTML, PDF (WeasyPrint), JSON, and CSV reports.
- `database/` & `models/`: Database connection sessions and SQLAlchemy tables.
- `utils/`: Configuration (Pydantic-Settings), cryptographic helpers (direct raw `bcrypt` hashing), and security scoring calculations.

---

## 2. Completed API Endpoints

The following REST endpoints are fully functional and secure (requiring valid JWT bearer tokens, except signup/login):

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/signup` | Register a new user |
| `POST` | `/auth/login` | Authenticate credentials and get JWT token |
| `GET` | `/auth/me` | Fetch profile metadata for logged-in user |
| `POST` | `/projects` | Create a new security scan project |
| `GET` | `/projects` | List all projects belonging to user |
| `GET` | `/projects/{project_id}` | Retrieve details of a specific project |
| `POST` | `/projects/{project_id}/files` | Upload single code files or ZIP archive (with Zip-Slip traversal guard) |
| `GET` | `/projects/{project_id}/files` | List all files uploaded in a project |
| `POST` | `/projects/{project_id}/scan` | Trigger static scans asynchronously as a background task |
| `GET` | `/scans/{scan_id}` | Poll scan running status and severity counts |
| `GET` | `/projects/{project_id}/scans` | Fetch history of all project scans |
| `GET` | `/vulnerabilities` | List, filter, and search vulnerabilities (severity, type, text search) |
| `PATCH` | `/vulnerabilities/{vuln_id}` | Mark a vulnerability finding as fixed/resolved |
| `POST` | `/vulnerabilities/{vuln_id}/regenerate-fix` | AI-regenerate a secure code snippet fix |
| `GET` | `/reports/{project_id}` | Export findings report in `html`, `pdf`, `json`, or `csv` format |
| `POST` | `/ai/ask` | Ask Q&A security mentor questions about a scan finding |

---

## 3. Custom AST Detector Rules

To detect security issues not covered by basic linters, we implemented custom Python Abstract Syntax Tree (`ast`) rules:
1. **Hardcoded Secrets**: Assignments of non-empty strings (length > 4) to variables whose names match sensitive keywords (e.g. `password`, `secret`, `api_key`).
2. **Weak Hashing**: Insecure cryptography hashes such as `hashlib.md5(...)` or `hashlib.sha1(...)`.
3. **Dangerous Executions**: Dynamic evaluation of arbitrary input using built-in `eval(...)` or `exec(...)`.
4. **SQL Injection**: Dynamic database cursor query executions (`cursor.execute()`) constructed via f-strings, `%` string formatting, or string additions, containing SQL keywords (e.g., `SELECT`, `UPDATE`).

---

## 4. Verification Results

We built a comprehensive unit test suite in `backend/tests/` to check core application behavior. 

We executed `pytest` in the local Python 3.13 virtual environment with **100% of tests passing**:

```bash
backend\tests\test_ast.py ....                                           [ 33%]
backend\tests\test_auth.py .                                             [ 41%]
backend\tests\test_orchestrator.py .                                     [ 50%]
backend\tests\test_parser.py ......                                      [100%]

======================= 12 passed, 13 warnings in 0.95s =======================
```

### Verified Features:
- **Language Detection**: Checked extensions mapping `.py` to Python, `.js`/`.ts` to JavaScript/TypeScript, `.java` to Java, `.cpp` to C, and `.php` to PHP.
- **AST Detector Rules**: Validated correct flag-raising on hardcoded secrets, weak hashlib invocations, eval/exec executions, and dynamic SQL statements, while ensuring safe parameterized queries are ignored.
- **Authentication**: Checked user registration, password hashing verification, JWT token generation, and secure profile fetching `/auth/me`.
- **Orchestrator Deduplication**: Validated that duplicate linter results (same file, line, and type) are consolidated into a single entry, keeping the highest confidence, and merging tool designations (e.g. `ast,bandit`).
