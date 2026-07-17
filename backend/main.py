from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from backend.utils.config import settings
from backend.database.session import engine, Base
# Import all routers to mount them
from backend.api import auth, projects, files, scans, vulnerabilities, reports, ai

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database tables on startup
try:
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)
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

# Register routers at the root to match specification URLs exactly
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(files.router)
app.include_router(scans.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)
app.include_router(ai.router)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "docs": "/docs"
    }
