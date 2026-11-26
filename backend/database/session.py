import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.utils.config import settings

def get_database_url() -> str:
    """
    Returns the database connection URL.
    Ensures that test suites run strictly and exclusively against an isolated,
    in-memory SQLite database ('sqlite://') using StaticPool and check_same_thread=False.
    The application database can NEVER be connected to or touched during tests.
    """
    is_testing = (
        "pytest" in sys.modules
        or os.getenv("TESTING") == "1"
        or bool(os.getenv("PYTEST_CURRENT_TEST"))
    )

    if is_testing:
        test_url = (os.getenv("TEST_DATABASE_URL") or "").strip()
        if not test_url:
            # Default test database: pure in-memory SQLite
            return "sqlite://"

        from sqlalchemy.engine.url import make_url
        parsed_test = make_url(test_url)

        # Enforce in-memory SQLite exclusively: reject file-based SQLite URLs
        if parsed_test.drivername == "sqlite":
            raw_url = test_url.split("?")[0].strip()
            db_path = parsed_test.database
            if db_path not in (None, "", ":memory:") or raw_url not in ("sqlite://", "sqlite:///", "sqlite:///:memory:"):
                raise RuntimeError(
                    f"CRITICAL: Non-in-memory SQLite database '{test_url}' is rejected in test mode! "
                    "Automated tests must run strictly and exclusively against in-memory SQLite ('sqlite://')."
                )
            return test_url

        # Reject all non-SQLite databases unconditionally (including PostgreSQL)
        raise RuntimeError(
            f"CRITICAL: Database '{test_url}' is rejected in test mode! "
            "Automated tests must run strictly and exclusively against in-memory SQLite ('sqlite://')."
        )

    return settings.sqlalchemy_database_uri

db_url = get_database_url()

connect_args = {}
engine_kwargs = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    from sqlalchemy.pool import StaticPool
    engine_kwargs["poolclass"] = StaticPool

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    connect_args=connect_args,
    **engine_kwargs
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
