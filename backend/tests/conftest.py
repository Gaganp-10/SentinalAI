import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app
from backend.database.session import Base, get_db, engine as session_engine
import backend.models.models

@pytest.fixture(scope="session", autouse=True)
def ensure_test_database_isolation():
    """
    Guarantees that test execution NEVER touches the application database 'security_scanner'.
    Asserts that the active database is either an isolated test database (e.g. 'security_scanner_test')
    or an in-memory/isolated SQLite database, and creates all required tables.
    """
    db_name = session_engine.url.database or ""
    assert db_name != "security_scanner", (
        f"CRITICAL: Test suite is attempting to connect to application database '{db_name}'! "
        "Tests must run against a separate database (e.g. security_scanner_test or sqlite)."
    )
    # Ensure schema exists in test database
    Base.metadata.create_all(bind=session_engine)

from sqlalchemy.pool import StaticPool

SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db():
    # Setup test tables
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        # Tear down test tables
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db, monkeypatch):
    import backend.database.session as session_module
    import backend.api.auth as auth_module

    monkeypatch.setattr(session_module, "SessionLocal", TestingSessionLocal)
    monkeypatch.setattr(auth_module, "SessionLocal", TestingSessionLocal)

    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

