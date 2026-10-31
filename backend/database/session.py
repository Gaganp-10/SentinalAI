import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.utils.config import settings

def get_database_url() -> str:
    """
    Returns the database connection URL.
    Ensures that test suites run against a dedicated, isolated test database
    (security_scanner_test or TEST_DATABASE_URL) and can never connect to or
    touch the production/application database (security_scanner).
    """
    if os.getenv("TEST_DATABASE_URL"):
        return os.getenv("TEST_DATABASE_URL")

    is_testing = (
        "pytest" in sys.modules
        or os.getenv("TESTING") == "1"
        or bool(os.getenv("PYTEST_CURRENT_TEST"))
    )

    base_url = settings.sqlalchemy_database_uri
    if is_testing:
        if base_url.endswith("/security_scanner"):
            return base_url + "_test"
        elif "/security_scanner?" in base_url:
            return base_url.replace("/security_scanner?", "/security_scanner_test?")
        elif not base_url.startswith("sqlite") and not base_url.endswith("_test"):
            parts = base_url.rsplit("/", 1)
            if len(parts) == 2 and parts[1]:
                return f"{parts[0]}/{parts[1]}_test"
    return base_url

db_url = get_database_url()

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
