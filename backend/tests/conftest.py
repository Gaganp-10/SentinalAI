import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app
from backend.database.session import Base, get_db

# Create a test SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
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
        if os.path.exists("./test.db"):
            try:
                os.remove("./test.db")
            except Exception:
                pass

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

