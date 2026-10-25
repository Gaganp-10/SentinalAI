import pytest
from pydantic import ValidationError
from backend.utils.config import Settings

def test_config_allows_defaults_in_development():
    """In development mode, default development credentials and keys are permitted."""
    cfg = Settings(
        ENV="development",
        SECRET_KEY="dev-secret-key-change-later",
        POSTGRES_PASSWORD="postgres",
    )
    assert cfg.ENV == "development"
    assert cfg.POSTGRES_PASSWORD == "postgres"

def test_config_fails_in_production_if_secret_key_is_default():
    """In production mode, default placeholder SECRET_KEY values must fail validation."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            ENV="production",
            SECRET_KEY="SUPER_SECRET_KEY_CHANGE_ME_IN_PRODUCTION_1234567890",
            POSTGRES_PASSWORD="strong_custom_password_123!",
        )
    assert "SECRET_KEY" in str(excinfo.value)

def test_config_fails_in_production_if_secret_key_too_short():
    """In production mode, SECRET_KEY shorter than 32 characters must fail validation."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            ENV="production",
            SECRET_KEY="short-secret-key-too-small",
            POSTGRES_PASSWORD="strong_custom_password_123!",
        )
    assert "at least 32 characters" in str(excinfo.value)

def test_config_fails_in_production_if_postgres_password_is_default():
    """In production mode, default 'postgres' database password must fail validation."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            ENV="production",
            SECRET_KEY="valid_production_secret_key_at_least_32_characters_long",
            POSTGRES_PASSWORD="postgres",
        )
    assert "POSTGRES_PASSWORD" in str(excinfo.value)

def test_config_fails_in_production_if_postgres_password_is_empty():
    """In production mode, empty database password must fail validation."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            ENV="production",
            SECRET_KEY="valid_production_secret_key_at_least_32_characters_long",
            POSTGRES_PASSWORD="",
        )
    assert "POSTGRES_PASSWORD" in str(excinfo.value)

def test_config_fails_in_production_if_database_url_has_postgres_default():
    """In production mode, DATABASE_URL containing default 'postgres' password must fail."""
    with pytest.raises(ValidationError) as excinfo:
        Settings(
            ENV="production",
            SECRET_KEY="valid_production_secret_key_at_least_32_characters_long",
            POSTGRES_PASSWORD="custom_password_123",
            DATABASE_URL="postgresql://postgres:postgres@db:5432/secdetector",
        )
    assert "DATABASE_URL" in str(excinfo.value)

def test_config_succeeds_in_production_with_valid_secure_values():
    """In production mode, strong SECRET_KEY and non-default password succeed."""
    cfg = Settings(
        ENV="production",
        SECRET_KEY="a_strong_and_cryptographically_secure_random_key_production_32chars",
        POSTGRES_PASSWORD="super_secure_pg_password_987#",
        DATABASE_URL="postgresql://postgres:super_secure_pg_password_987#@db:5432/secdetector",
    )
    assert cfg.ENV == "production"
    assert cfg.POSTGRES_PASSWORD == "super_secure_pg_password_987#"
