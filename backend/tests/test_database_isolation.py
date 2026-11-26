import os
import pytest
from uuid import uuid4
from sqlalchemy.engine.url import make_url
from sqlalchemy.pool import StaticPool

from backend.database.session import engine, SessionLocal, get_database_url
from backend.models.models import User
from backend.utils.config import settings


def test_database_is_separate_from_app_db():
    """
    Verifies that the test suite runs against an isolated, in-memory SQLite test database
    and that its configuration cannot connect to or touch the configured application database,
    regardless of whether the application database is named 'secdetector' or 'security_scanner'.
    """
    db_url = engine.url
    db_driver = db_url.drivername

    # 1. Proves isolation through the test engine's driver and precise in-memory SQLite configuration
    assert db_driver == "sqlite", f"Active test engine '{db_url}' is not SQLite!"

    raw_url = str(db_url).split("?")[0].strip()
    assert db_url.database in (None, "", ":memory:") and raw_url in ("sqlite://", "sqlite:///", "sqlite:///:memory:"), (
        f"SQLite test engine '{db_url}' is not an in-memory database!"
    )
    assert isinstance(engine.pool, StaticPool), (
        "In-memory SQLite test engine must use StaticPool to preserve state across connections."
    )

    # 2. Assert the active test engine does NOT point to the application database
    app_url = make_url(settings.sqlalchemy_database_uri)
    assert not (
        db_driver == app_url.drivername
        and db_url.host == app_url.host
        and db_url.port == app_url.port
        and db_url.database == app_url.database
    ), f"CRITICAL: Active test engine connects to application database '{db_url.database}'!"


def test_test_database_rejects_file_based_sqlite(monkeypatch):
    """
    Verifies that file-based SQLite database URLs are strictly rejected in test mode.
    Only genuinely in-memory SQLite URLs ('sqlite://') are permitted.
    """
    file_sqlite_urls = [
        "sqlite:///./some_existing_database.db",
        "sqlite:///app.db",
        "sqlite:///./test_runner.db",
        "sqlite:////tmp/test.db",
        "sqlite:///C:/path/to/db.sqlite",
    ]
    for url in file_sqlite_urls:
        monkeypatch.setenv("TEST_DATABASE_URL", url)
        with pytest.raises(RuntimeError, match="Non-in-memory SQLite database.*rejected"):
            get_database_url()


def test_test_database_rejects_all_non_sqlite_databases(monkeypatch):
    """
    Verifies that get_database_url() strictly and unconditionally rejects non-SQLite databases:
    - Application database URLs (secdetector, security_scanner, or settings.DATABASE_URL)
    - Any PostgreSQL database URL (with or without ALLOW_POSTGRES_TEST_DB)
    - Any other external database engines (MySQL, Oracle, etc.)
    """
    non_sqlite_urls = [
        "postgresql://postgres:pass@localhost:5433/secdetector",
        "postgresql://postgres:pass@localhost:5432/security_scanner",
        settings.sqlalchemy_database_uri,
        "postgresql://postgres:pass@localhost:5432/security_scanner_test",
        "postgresql://postgres:pass@localhost:5432/test_db",
        "mysql://root:pass@localhost:3306/testdb",
    ]
    # Even if an environment attempts an opt-in, non-SQLite databases must be rejected unconditionally
    monkeypatch.setenv("ALLOW_POSTGRES_TEST_DB", "1")

    for url in non_sqlite_urls:
        monkeypatch.setenv("TEST_DATABASE_URL", url)
        with pytest.raises(RuntimeError, match="rejected in test mode"):
            get_database_url()


def test_test_database_defaults_to_in_memory_sqlite_when_unset(monkeypatch):
    """
    Verifies that when TEST_DATABASE_URL is unset, get_database_url() deterministically
    defaults to in-memory SQLite ('sqlite://').
    """
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    assert get_database_url() == "sqlite://"


def test_test_engine_operates_in_memory_without_application_connection():
    """
    Verifies that test operations strictly execute within the isolated in-memory test database:
    - Writes, reads, and rolls back records via SessionLocal without contacting the application database.
    - Does not generate persistent database files on disk.
    - Tests prove isolation through configuration and local verification rather than contacting the real database.
    """
    db = SessionLocal()
    canary_username = f"canary_isolated_{uuid4().hex[:8]}"
    canary_email = f"{canary_username}@test.local"

    try:
        user = User(
            username=canary_username,
            email=canary_email,
            hashed_password="test_hashed_password"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Record exists and is retrievable within isolated test database
        queried = db.query(User).filter(User.username == canary_username).first()
        assert queried is not None
        assert queried.email == canary_email

        # Engine is confirmed in-memory SQLite
        assert engine.url.drivername == "sqlite"
        assert engine.url.database in (None, "", ":memory:")

        # Confirm no persistent test database file was created on disk
        assert not os.path.exists("test_runner.db")
    finally:
        user_in_db = db.query(User).filter(User.username == canary_username).first()
        if user_in_db:
            db.delete(user_in_db)
            db.commit()
        db.close()
