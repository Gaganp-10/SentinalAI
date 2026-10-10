from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from backend.utils.config import settings
from backend.database.session import engine, Base

# Import all routers to mount them
from backend.api import auth, projects, files, scans, vulnerabilities, reports, ai, owasp

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database tables on startup
try:
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    from backend.database.migration import run_db_migrations
    run_db_migrations(engine)
    logger.info("Database tables initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize database tables: {e}")

# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    docs_url="/docs",
    redoc_url="/redoc"
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
