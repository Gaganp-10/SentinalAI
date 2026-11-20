# Security Architecture & Accepted Risks Policy

## 1. Semgrep Environment Isolation & Upstream Transitive Dependencies

### Architecture & Isolation
Semgrep is installed inside an isolated virtualenv (`/opt/semgrep/bin/semgrep`) within the backend container, completely outside the application runtime environment (`/app` and system Python).
- **Semgrep Pin**: `semgrep==1.183.0`
- **Application Environment (`/app`)**: Decoupled from Semgrep. Direct and transitive dependency audits via `pip-audit -r backend/requirements.txt` reveal **0 vulnerabilities**.
- **Execution Path**: The backend detector (`backend/detectors/semgrep_detector.py`) executes Semgrep exclusively via absolute path `/opt/semgrep/bin/semgrep` in isolated subprocess process groups with `--metrics=off` and `--disable-version-check`.
- **Filesystem Permissions**: The `/opt/semgrep` virtualenv is strictly root-owned (no `chown` to `appuser`), preventing non-root `appuser` from modifying or poisoning installed libraries at runtime.

### Version Jump Explanation (1.169.0 -> 1.183.0)
Semgrep was updated from `1.169.0` to `1.183.0` to incorporate critical upstream security patches and parser enhancements:
- In `1.169.0`, Semgrep pinned vulnerable dependencies in older `mcp` versions and vulnerable `opentelemetry-api` packages.
- Upgrading to `1.183.0` upgraded Semgrep core engine performance and AST parser accuracy across Python, JS, Java, C, and PHP.
- All 14 custom security rule fixtures (`backend/tests/fixtures/semgrep`) were re-verified against `1.183.0`, achieving **14 of 14 detections with 0 false positives**.

### Dependency Conflict / Resolver Incompatibility
Attempting to upgrade `mcp` and `opentelemetry-api` to unpinned latest versions inside `/opt/semgrep` produces hard dependency resolver conflicts because `semgrep==1.183.0` strictly pins `mcp==1.29.0` and `opentelemetry-api~=1.37.0`:
```text
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
opentelemetry-sdk 1.37.0 requires opentelemetry-api==1.37.0, but you have opentelemetry-api 1.45.2 which is incompatible.
opentelemetry-semantic-conventions 0.58b0 requires opentelemetry-api==1.37.0, but you have opentelemetry-api 1.45.2 which is incompatible.
semgrep 1.183.0 requires mcp==1.29.0, but you have mcp 2.3.0 which is incompatible.
semgrep 1.183.0 requires opentelemetry-api~=1.37.0, but you have opentelemetry-api 1.45.2 which is incompatible.
```

### Accepted Residual Transitive Risks in `/opt/semgrep`

The residual vulnerabilities in `/opt/semgrep` are recorded below with reachability reasoning and expiry date:

| Package | Vulnerability | Severity | Advisory Link | Reachability Reasoning | Review Expiry |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `mcp` | CVE-2026-59951 | CRITICAL | [https://osv.dev/vulnerability/CVE-2026-59951](https://osv.dev/vulnerability/CVE-2026-59951) | Unreachable. Semgrep CLI does not expose an MCP network listener; all scans run offline against local directory trees. | 2026-12-31 |
| `mcp` | CVE-2026-116685 | HIGH | [https://osv.dev/vulnerability/CVE-2026-116685](https://osv.dev/vulnerability/CVE-2026-116685) | Unreachable. MCP transport layers are never initialized during static analysis parsing. | 2026-12-31 |
| `mcp` | CVE-2026-116684 | HIGH | [https://osv.dev/vulnerability/CVE-2026-116684](https://osv.dev/vulnerability/CVE-2026-116684) | Unreachable. No external MCP clients or untrusted JSON-RPC streams are connected. | 2026-12-31 |
| `mcp` | CVE-2026-116686 | HIGH | [https://osv.dev/vulnerability/CVE-2026-116686](https://osv.dev/vulnerability/CVE-2026-116686) | Unreachable. Remote MCP server negotiation is never invoked. | 2026-12-31 |
| `opentelemetry-api` | CVE-2026-114603 | CRITICAL | [https://osv.dev/vulnerability/CVE-2026-114603](https://osv.dev/vulnerability/CVE-2026-114603) | Unreachable. Telemetry is explicitly disabled via `--metrics=off` and `--disable-version-check`; telemetry network export logic is inactive. | 2026-12-31 |
| `opentelemetry-api` | CVE-2026-126360 | HIGH | [https://osv.dev/vulnerability/CVE-2026-126360](https://osv.dev/vulnerability/CVE-2026-126360) | Unreachable. Metric serialization and span propagation buffers are not executed during local offline scanning. | 2026-12-31 |

---

## 2. Container OS Packages & `--ignore-unfixed` Policy

### Policy Definition
In container vulnerability scanning (Trivy), OS base image packages (Debian 13 / Alpine Linux) are scanned with the **`--ignore-unfixed`** policy:
1. Vulnerabilities with an official security fix available in the upstream package distribution must be remediated by updating the package or base image.
2. Vulnerabilities without an upstream fix released by the distribution maintainers (unfixed/wontfix/open in Debian/Alpine security trackers) are accepted as residual infrastructure risk, provided:
   - The affected library is not exposed to untrusted network inputs (e.g., read-only root filesystems, non-root user execution, dropped capabilities `ALL`, `no-new-privileges: true`).
   - The container does not run compilers, debuggers, or package managers in production.

---

## 3. Content Security Policy (CSP) Staging & Enforcing Rollout Policy

### Current State: `Content-Security-Policy-Report-Only`
To prevent breaking third-party authentication flows (Google Identity Services / One Tap popups and redirect tokens) during initial staging and pre-production domain validation, Caddy serves the CSP in **Report-Only** mode:
```caddy
Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' https://accounts.google.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.googleusercontent.com; font-src 'self'; connect-src 'self' https://accounts.google.com; frame-src https://accounts.google.com; frame-ancestors 'none'; report-uri /api/csp-report;"
```

### Self-Hosted Typography
All typography (`Space Grotesk`, `IBM Plex Sans`, `IBM Plex Mono`, and `Inter`) is packaged via `@fontsource/*` npm dependencies and bundled directly into static hashed `.woff2` files under `/assets/` by Vite at build time. No requests are made to external font providers (`fonts.googleapis.com`, `fonts.gstatic.com`).

### Enforcing Policy (Production Activation)
Once Google OAuth sign-in and callback redirection are verified on the target production domain, switch the header in `Caddyfile` from `Content-Security-Policy-Report-Only` to `Content-Security-Policy`:
```caddy
Content-Security-Policy "default-src 'self'; script-src 'self' https://accounts.google.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.googleusercontent.com; font-src 'self'; connect-src 'self' https://accounts.google.com; frame-src https://accounts.google.com; frame-ancestors 'none'; report-uri /api/csp-report;"
```
Violation reports continue to be logged to the `/api/csp-report` telemetry endpoint.
