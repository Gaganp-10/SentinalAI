from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import json
import time
import threading

from backend.utils.config import settings
from backend.database.session import engine, Base, SessionLocal

# Import all routers to mount them
from backend.api import auth, projects, files, scans, vulnerabilities, reports, ai, owasp

from contextlib import asynccontextmanager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sweep_orphaned_scans(db_session=None):
    """
    Startup sweep: marks any scans left in 'pending' or 'running' state as failed
    due to server restart, preventing them from hanging permanently.
    Accepts an optional db_session (useful for testing); defaults to a new SessionLocal().
    """
    from backend.models.models import ScanHistory
    session = db_session if db_session is not None else SessionLocal()
    try:
        stale_scans = session.query(ScanHistory).filter(ScanHistory.status.in_(["pending", "running"])).all()
        if stale_scans:
            logger.info("Startup sweep: marking %d orphaned scans as failed", len(stale_scans))
            for scan in stale_scans:
                scan.status = "failed"
                warnings = json.loads(scan.warnings) if scan.warnings else []
                warnings.append("Scan interrupted by server restart.")
                scan.warnings = json.dumps(warnings)
            session.commit()
    except Exception as e:
        logger.error("Failed to execute startup scan sweep: %s", e)
        session.rollback()
    finally:
        if db_session is None:
            session.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager: executes database schema initialization,
    required migrations under PostgreSQL advisory lock, and orphaned scan sweeps on startup.
    Preserves fail-fast behavior by raising RuntimeError if initialization or migrations fail.
    """
    try:
        from backend.database.migration import init_db_schema_and_migrations
        init_db_schema_and_migrations(engine, base=Base)
        sweep_orphaned_scans()
    except Exception as e:
        logger.critical("FATAL: Failed to initialize database schema or migrations: %s", e)
        raise RuntimeError(f"Backend startup aborted due to schema/migration initialization failure: {e}") from e
    yield

# Initialize FastAPI application
is_production = (settings.ENV or "").strip().lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
    lifespan=lifespan,
    redirect_slashes=False,
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under /api namespace for proxy isolation and prevention of SPA route collisions
all_routers = [auth.router, projects.router, files.router, scans.router, vulnerabilities.router, reports.router, ai.router, owasp.router]

for r in all_routers:
    app.include_router(r, prefix="/api")
    # Maintain root mounts for backward compatibility with direct backend callers/tests
    app.include_router(r)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "docs": "/docs"
    }

@app.get("/api")
def api_root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": "v1"
    }

@app.get("/api/health")
def health_check():
    """
    Lightweight liveness/readiness probe used by Docker Compose healthcheck
    and nginx upstream checks. Returns 200 when the process is up.
    """
    return {"status": "ok"}

@app.get("/api/proxy-test")
def proxy_test(request: Request):
    """
    Diagnostic endpoint to verify client IP and HTTPS scheme propagation through reverse proxy.
    Available only in development environments; disabled in production and other environments.
    """
    env = (settings.ENV or "").strip().lower()
    if env != "development":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not found."
        )
    client_ip = request.client.host if request.client else "unknown"
    return {
        "client_ip": client_ip,
        "scheme": request.url.scheme,
        "is_secure": request.url.is_secure,
        "headers": {
            "x-forwarded-for": request.headers.get("x-forwarded-for"),
            "x-forwarded-proto": request.headers.get("x-forwarded-proto"),
            "host": request.headers.get("host"),
        }
    }

_csp_rate_limit_lock = threading.Lock()
_csp_rate_limit_records: dict[str, list[float]] = {}
_last_csp_cleanup: float = 0.0
MAX_CSP_RECORDS: int = 10000

def reset_csp_rate_limits():
    """Helper for unit tests to reset CSP rate limit records."""
    global _last_csp_cleanup
    with _csp_rate_limit_lock:
        _csp_rate_limit_records.clear()
        _last_csp_cleanup = 0.0

@app.post("/api/csp-report", status_code=204)
async def csp_report(request: Request):
    """
    Receives and logs CSP violation reports submitted by user-agents.
    Enforces:
      - 16 KB payload size limit (HTTP 413)
      - Content-Type check (application/csp-report, application/json, or application/reports+json) (HTTP 415)
      - Per-IP rate limiting (60/min) (HTTP 429)
      - Bounded memory storage (automatic expiration pruning & capacity ceiling rejection)
      - Sanitized, JSON-escaped single-line log output
    """
    # 1. Content-Type check
    content_type = request.headers.get("content-type", "").lower()
    allowed_types = ("application/csp-report", "application/json", "application/reports+json")
    if not any(content_type.startswith(t) for t in allowed_types):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Content-Type for CSP report. Expected application/csp-report or application/json."
        )

    # 2. Rate limiting (60 requests per minute per IP)
    from backend.api.auth import _get_client_ip
    client_ip = _get_client_ip(request)

    now = time.time()
    cutoff = now - 60.0
    global _last_csp_cleanup
    with _csp_rate_limit_lock:
        # Periodic pruning of expired entries (every 60s or when table reaches MAX_CSP_RECORDS)
        if now - _last_csp_cleanup > 60.0 or len(_csp_rate_limit_records) >= MAX_CSP_RECORDS:
            stale_ips = [
                ip for ip, timestamps in _csp_rate_limit_records.items()
                if not timestamps or timestamps[-1] <= cutoff
            ]
            for ip in stale_ips:
                del _csp_rate_limit_records[ip]
            _last_csp_cleanup = now

        # Reject untracked IPs when table is at capacity after cleanup (do not evict unexpired records)
        if client_ip not in _csp_rate_limit_records and len(_csp_rate_limit_records) >= MAX_CSP_RECORDS:
            logger.warning(
                "CSP report rate limiter capacity reached with unexpired records; rejecting untracked IP %s",
                client_ip
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many CSP violation reports. Service busy or rate limit reached."
            )

        hits = [ts for ts in _csp_rate_limit_records.get(client_ip, []) if ts > cutoff]
        if len(hits) >= 60:
            _csp_rate_limit_records[client_ip] = hits
            logger.warning("CSP report rate limit exceeded for IP %s", client_ip)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many CSP violation reports from this IP. Please try again later."
            )
        hits.append(now)
        _csp_rate_limit_records[client_ip] = hits

    # 3. 16 KB size limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 16384:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="CSP report payload exceeds 16KB limit."
                )
        except ValueError:
            pass

    raw_chunks = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > 16384:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="CSP report payload exceeds 16KB limit."
            )
        raw_chunks.append(chunk)

    raw_body = b"".join(raw_chunks)
    if not raw_body:
        return

    # 4. JSON-escaped logging
    try:
        parsed = json.loads(raw_body.decode("utf-8", errors="replace"))
        log_line = json.dumps(parsed, separators=(",", ":"))
    except Exception:
        log_line = json.dumps({"raw_report": raw_body.decode("utf-8", errors="replace")[:2048]})

    logger.warning("CSP Violation: %s", log_line)
    return

@app.get("/api/redirect-test")
def redirect_test(request: Request):
    """
    Diagnostic endpoint to demonstrate FastAPI redirects preserving HTTPS scheme.
    """
    target = request.url_for("api_root")
    return RedirectResponse(url=str(target), status_code=307)
