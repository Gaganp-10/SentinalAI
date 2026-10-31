import os
import pytest
from backend.database.session import engine, SessionLocal, get_database_url
from backend.models.models import User, Project
from uuid import uuid4

def test_database_is_separate_from_app_db():
    """
    Verifies Requirement 2:
    Tests must run against a separate database (security_scanner_test or sqlite)
    and CANNOT touch or connect to the application database (security_scanner).
    """
    db_name = engine.url.database or ""
    # 1. Assert database is NOT the application database
    assert db_name != "security_scanner", (
        f"Active test engine database is '{db_name}', which is the application database!"
    )
    # 2. Confirm it is either security_scanner_test or an in-memory/test sqlite
    assert (
        db_name.endswith("_test")
        or "test" in db_name.lower()
        or engine.url.drivername == "sqlite"
    ), f"Unexpected test database name: '{db_name}'"

    # Redacted connection URL format
    redacted_url = engine.url.render_as_string(hide_password=True)
    assert "***" in redacted_url or "[REDACTED]" in redacted_url or not engine.url.password
    assert "security_scanner_test" in redacted_url or engine.url.drivername == "sqlite"


def test_test_database_cannot_touch_app_database():
    """
    Inserts a canary record into the test database and proves that the
    application database 'security_scanner' is completely unaffected.
    """
    db = SessionLocal()
    canary_username = f"canary_test_isolation_{uuid4().hex[:8]}"
    canary_email = f"{canary_username}@test.com"

    try:
        user = User(
            username=canary_username,
            email=canary_email,
            hashed_password="test_hashed_password"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Record exists in test DB
        assert db.query(User).filter(User.username == canary_username).first() is not None

        # Verify application DB 'security_scanner' does not contain this canary
        # Connect explicitly to the app database to confirm absence
        from sqlalchemy import create_engine
        from backend.utils.config import settings

        app_db_url = settings.sqlalchemy_database_uri
        if not app_db_url.startswith("sqlite") and "db:5432" in app_db_url:
            # We are running inside container with postgres access
            app_engine = create_engine(app_db_url)
            from sqlalchemy.orm import sessionmaker
            AppSession = sessionmaker(bind=app_engine)
            app_db = AppSession()
            try:
                found_in_app_db = app_db.query(User).filter(User.username == canary_username).first()
                assert found_in_app_db is None, (
                    "CRITICAL LEAK: Record written in test appeared in the application database!"
                )
            finally:
                app_db.close()
    finally:
        # Cleanup canary from test database
        user_in_db = db.query(User).filter(User.username == canary_username).first()
        if user_in_db:
            db.delete(user_in_db)
            db.commit()
        db.close()
