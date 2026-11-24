import pytest
from fastapi.testclient import TestClient
import sys
import os

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# Enforce test database isolation before ANY application or database modules are imported
if not os.environ.get("TEST_DATABASE_URL"):
    os.environ["TEST_DATABASE_URL"] = "sqlite://"

from backend.main import app
from backend.database.session import Base, get_db, SessionLocal, engine as session_engine
import backend.models.models

@pytest.fixture(scope="session", autouse=True)
def ensure_test_database_isolation():
    """
    Guarantees that test execution NEVER touches the application database.
    Enforces that the active test engine is exclusively in-memory SQLite with StaticPool.
    """
    from sqlalchemy.pool import StaticPool

    db_url = session_engine.url
    db_driver = db_url.drivername

    assert db_driver == "sqlite", (
        f"CRITICAL: Non-SQLite driver '{db_driver}' detected in test mode! Only in-memory SQLite is allowed."
    )
    raw_url = str(db_url).split("?")[0].strip()
    assert db_url.database in (None, "", ":memory:") and raw_url in ("sqlite://", "sqlite:///", "sqlite:///:memory:"), (
        f"CRITICAL: File-based SQLite engine '{db_url}' is rejected! Tests must use in-memory SQLite."
    )
    assert isinstance(session_engine.pool, StaticPool), (
        f"CRITICAL: In-memory SQLite test engine must use StaticPool, but got {type(session_engine.pool)}."
    )

    # Base metadata schema creation for tests that interact directly with SessionLocal
    Base.metadata.create_all(bind=session_engine)


# Bind test session fixtures directly to the unified session_engine, avoiding duplicate engines
engine = session_engine
TestingSessionLocal = SessionLocal


@pytest.fixture(scope="function")
def db():
    # Setup test tables
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        # Clean teardown of test tables and recreate empty schema for subsequent tests
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    prior_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as c:
            yield c
    finally:
        if prior_override is not None:
            app.dependency_overrides[get_db] = prior_override
        else:
            app.dependency_overrides.pop(get_db, None)
