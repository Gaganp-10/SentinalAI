import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
from sqlalchemy import create_engine, text, inspect
from starlette.requests import Request
from backend.utils.config import settings
from backend.api.auth import _get_client_ip, get_trusted_proxy_networks
from backend.database.migration import run_db_migrations, SENTINEL_MIGRATION_LOCK_ID


def _create_mock_request(client_host: str = None, headers: dict = None):
    """Creates a mock FastAPI/Starlette Request object."""
    req = MagicMock()
    if client_host is not None:
        client_mock = MagicMock()
        client_mock.host = client_host
        req.client = client_mock
    else:
        req.client = None
    req.headers = headers or {}
    return req


# =============================================================================
# 1. Trusted Proxy & Client IP Identification Tests
# =============================================================================

def test_original_socket_peer_preserved_without_uvicorn_proxy_middleware():
    """
    Requirement 1 & 7:
    Verify that in standard ASGI request processing without Uvicorn's ProxyHeadersMiddleware,
    the direct socket peer in scope['client'] is preserved as request.client.host,
    allowing _get_client_ip() to reliably verify the connecting peer.
    """
    scope = {
        "type": "http",
        "client": ("172.28.0.2", 45122),  # Caddy socket peer
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195"),
            (b"x-forwarded-proto", b"https"),
        ],
    }
    req = Request(scope)
    # Confirm request.client reflects the original socket peer, not rewritten by middleware
    assert req.client.host == "172.28.0.2"

    with pytest.MonkeyPatch().context() as m:
        m.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])
        client_ip = _get_client_ip(req)
        assert client_ip == "203.0.113.195"


def test_trusted_caddy_peer_parses_single_forwarded_header(monkeypatch):
    """
    Requirement 3 & 4:
    When Caddy (static IP 172.28.0.2) forwards the client IP in X-Forwarded-For,
    the validated client IP must be returned.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": "203.0.113.195"}
    )
    client_ip = _get_client_ip(req)
    assert client_ip == "203.0.113.195"


def test_untrusted_peer_ignores_forwarded_headers(monkeypatch):
    """
    Requirement 7:
    When an untrusted client connects directly to the backend,
    X-Forwarded-For must be completely ignored. The direct peer IP must be returned.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    # 198.51.100.50 is public/external — not in TRUSTED_PROXIES
    req = _create_mock_request(
        client_host="198.51.100.50",
        headers={"x-forwarded-for": "1.2.3.4"}
    )
    client_ip = _get_client_ip(req)
    assert client_ip == "198.51.100.50", (
        f"Expected peer IP 198.51.100.50, but got {client_ip}. "
        "Forwarded headers must be ignored for untrusted peers."
    )


def test_production_trust_configuration_narrows_to_caddy_exact_ip(monkeypatch):
    """
    Requirement 4:
    In production, TRUSTED_PROXIES trusts Caddy's exact IP (172.28.0.2/32).
    Another container on the same subnet (e.g. 172.28.0.3) is untrusted and
    cannot spoof X-Forwarded-For.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    # Subnet neighbor 172.28.0.3 connects attempting to spoof X-Forwarded-For
    req = _create_mock_request(
        client_host="172.28.0.3",
        headers={"x-forwarded-for": "10.99.99.99"}
    )
    client_ip = _get_client_ip(req)
    # Must be 172.28.0.3 because 172.28.0.3 is NOT in 172.28.0.2/32
    assert client_ip == "172.28.0.3"


# =============================================================================
# Strict Single-IP X-Forwarded-For Parsing Tests (Requirement 4)
# =============================================================================

def test_forwarded_for_valid_single_ip_accepted(monkeypatch):
    """
    Valid single IPv4, IPv6, and IPv4-mapped IPv6 addresses must be accepted
    and properly parsed/normalized.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    # Standard IPv4
    req_v4 = _create_mock_request(client_host="172.28.0.2", headers={"x-forwarded-for": "203.0.113.195"})
    assert _get_client_ip(req_v4) == "203.0.113.195"

    # Standard IPv6
    req_v6 = _create_mock_request(client_host="172.28.0.2", headers={"x-forwarded-for": "2001:db8::1"})
    assert _get_client_ip(req_v6) == "2001:db8::1"

    # IPv4-mapped IPv6
    req_mapped = _create_mock_request(client_host="172.28.0.2", headers={"x-forwarded-for": "::ffff:203.0.113.195"})
    assert _get_client_ip(req_mapped) == "203.0.113.195"


def test_forwarded_for_trailing_comma_falls_back_to_peer_ip(monkeypatch):
    """
    A trailing comma (e.g. '203.0.113.195,') must NOT be silently normalized
    into a valid single IP; it must fall back safely to the proxy's peer IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": "203.0.113.195,"}
    )
    assert _get_client_ip(req) == "172.28.0.2"


def test_forwarded_for_multiple_empty_segments_falls_back_to_peer_ip(monkeypatch):
    """
    Multiple empty segments (e.g. '203.0.113.195,,,' or ',,,') must NOT be
    silently normalized into a valid single IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req1 = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": "203.0.113.195,,,"}
    )
    assert _get_client_ip(req1) == "172.28.0.2"

    req2 = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": ",,,"}
    )
    assert _get_client_ip(req2) == "172.28.0.2"


def test_forwarded_for_leading_comma_falls_back_to_peer_ip(monkeypatch):
    """
    A leading comma (e.g. ',203.0.113.195') must NOT be silently normalized;
    it must fall back safely to the proxy's peer IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": ",203.0.113.195"}
    )
    assert _get_client_ip(req) == "172.28.0.2"


def test_forwarded_for_multiple_actual_ips_falls_back_to_peer_ip(monkeypatch):
    """
    Multiple actual IP values (e.g. '203.0.113.195, 198.51.100.1') must NOT
    arbitrarily select an entry; it must safely fall back to the proxy's peer IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req = _create_mock_request(
        client_host="172.28.0.2",
        headers={"x-forwarded-for": "203.0.113.195, 198.51.100.1"}
    )
    assert _get_client_ip(req) == "172.28.0.2"


def test_forwarded_for_malformed_ip_falls_back_to_peer_ip(monkeypatch):
    """
    Malformed IP addresses must fall back to the verified proxy peer IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    for malformed in ["invalid-ip", "999.999.999.999", "203.0.113.195 extra"]:
        req = _create_mock_request(
            client_host="172.28.0.2",
            headers={"x-forwarded-for": malformed}
        )
        assert _get_client_ip(req) == "172.28.0.2"


def test_trusted_peer_missing_forwarded_header(monkeypatch):
    """
    When a trusted proxy forwards without X-Forwarded-For, use the proxy's IP.
    """
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["127.0.0.1/32", "::1/128", "172.28.0.2/32"])

    req = _create_mock_request(
        client_host="172.28.0.2",
        headers={}
    )
    client_ip = _get_client_ip(req)
    assert client_ip == "172.28.0.2"


def test_trusted_proxies_empty_json_array():
    """
    Successfully parsed empty JSON array (string '[]' or list [])
    must be accepted as an empty list, not fall back to comma-separated parsing
    or reject '[]' as a malformed IP.
    """
    from backend.utils.config import Settings

    cfg_str = Settings(
        SECRET_KEY="a" * 32,
        TRUSTED_PROXIES="[]",
    )
    assert cfg_str.TRUSTED_PROXIES == []

    cfg_list = Settings(
        SECRET_KEY="a" * 32,
        TRUSTED_PROXIES=[],
    )
    assert cfg_list.TRUSTED_PROXIES == []


def test_trusted_proxies_normal_json_array():
    """
    Standard JSON array string must parse properly into list of validated CIDRs.
    """
    from backend.utils.config import Settings

    cfg = Settings(
        SECRET_KEY="a" * 32,
        TRUSTED_PROXIES='["127.0.0.1/32", "172.28.0.2/32"]',
    )
    assert cfg.TRUSTED_PROXIES == ["127.0.0.1/32", "172.28.0.2/32"]


def test_trusted_proxies_comma_separated_values():
    """
    Comma-separated string must parse properly into list of validated CIDRs.
    """
    from backend.utils.config import Settings

    cfg = Settings(
        SECRET_KEY="a" * 32,
        TRUSTED_PROXIES="127.0.0.1/32, 172.28.0.2/32",
    )
    assert cfg.TRUSTED_PROXIES == ["127.0.0.1/32", "172.28.0.2/32"]


def test_trusted_proxies_compose_prod_default_format():
    """
    Confirms the exact default TRUSTED_PROXIES format used in docker-compose.prod.yml
    ('127.0.0.1/32,::1/128,172.28.0.2/32') parses correctly into the expected three CIDRs.
    """
    from backend.utils.config import Settings

    cfg = Settings(
        SECRET_KEY="a" * 32,
        TRUSTED_PROXIES="127.0.0.1/32,::1/128,172.28.0.2/32",
    )
    assert cfg.TRUSTED_PROXIES == ["127.0.0.1/32", "::1/128", "172.28.0.2/32"]


def test_trusted_proxies_invalid_entry_fails_validation():
    """
    Requirement 5:
    Invalid TRUSTED_PROXIES configuration entries must NOT be silently ignored.
    Settings validation must fail fast for list, JSON string, or comma-separated string.
    """
    from pydantic import ValidationError
    from backend.utils.config import Settings

    # List of invalid entries
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            SECRET_KEY="a" * 32,
            TRUSTED_PROXIES=["127.0.0.1/32", "not-a-valid-ip-or-cidr"],
        )
    assert "Invalid trusted proxy CIDR or IP" in str(exc_info.value)

    # JSON array with invalid entry
    with pytest.raises(ValidationError) as exc_info2:
        Settings(
            SECRET_KEY="a" * 32,
            TRUSTED_PROXIES='["not-a-valid-ip-or-cidr"]',
        )
    assert "Invalid trusted proxy CIDR or IP" in str(exc_info2.value)

    # Comma-separated string with invalid entry
    with pytest.raises(ValidationError) as exc_info3:
        Settings(
            SECRET_KEY="a" * 32,
            TRUSTED_PROXIES="127.0.0.1/32, not-a-valid-ip-or-cidr",
        )
    assert "Invalid trusted proxy CIDR or IP" in str(exc_info3.value)


def test_development_behavior_default_configuration():
    """
    Requirement 4 & 7:
    In development/standalone mode, default TRUSTED_PROXIES is loopback only.
    """
    nets = get_trusted_proxy_networks()
    net_strs = [str(n) for n in nets]
    assert "127.0.0.1/32" in net_strs
    assert "::1/128" in net_strs
    # Broad ranges must not be present by default
    assert "172.16.0.0/12" not in net_strs
    assert "10.0.0.0/8" not in net_strs


def test_testclient_in_production_rejected(monkeypatch):
    """
    Requirement 7:
    FastAPI TestClient must NOT be treated as a trusted production proxy.
    In ENV=production, host='testclient' must be rejected with HTTP 400.
    """
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    req = _create_mock_request(client_host="testclient")
    with pytest.raises(HTTPException) as exc_info:
        _get_client_ip(req)
    assert exc_info.value.status_code == 400


def test_testclient_in_development_supported():
    """
    In development and test environments, TestClient is supported for test compatibility.
    """
    req_forwarded = _create_mock_request(
        client_host="testclient",
        headers={"x-forwarded-for": "198.51.100.88"}
    )
    assert _get_client_ip(req_forwarded) == "198.51.100.88"

    # Multi-value in testclient falls back safely to 127.0.0.1
    req_multi = _create_mock_request(
        client_host="testclient",
        headers={"x-forwarded-for": "198.51.100.88, 198.51.100.89"}
    )
    assert _get_client_ip(req_multi) == "127.0.0.1"

    req_empty = _create_mock_request(client_host="testclient", headers={})
    assert _get_client_ip(req_empty) == "127.0.0.1"


# =============================================================================
# 2. Database Migration Reliability Tests
# =============================================================================

def test_migration_failure_propagates():
    """
    Requirement 6:
    Required migration failures must propagate and not be swallowed.
    """
    failing_engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "sqlite"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    failing_engine.begin.return_value = cm

    with pytest.MonkeyPatch().context() as m:
        m.setattr("backend.database.migration.inspect", MagicMock(side_effect=Exception("Database lock acquisition failed")))
        with pytest.raises(Exception, match="Database lock acquisition failed"):
            run_db_migrations(failing_engine)


def test_migration_failure_during_alter_table_propagates():
    """
    Verifies that if an error occurs during an ALTER TABLE operation (e.g. on users table),
    the exception is NOT swallowed or caught without transaction recovery; it propagates directly.
    """
    engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "postgresql"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    engine.begin.return_value = cm

    def mock_execute(statement, *args, **kwargs):
        stmt_str = str(statement)
        if "ALTER TABLE users ADD COLUMN token_version" in stmt_str:
            raise RuntimeError("PostgreSQL relation locked or syntax error")
        return MagicMock()

    conn_mock.execute = mock_execute

    with pytest.MonkeyPatch().context() as m:
        inspector_mock = MagicMock()
        inspector_mock.get_table_names.return_value = ["users"]
        inspector_mock.get_columns.return_value = [{"name": "id"}]
        m.setattr("backend.database.migration.inspect", MagicMock(return_value=inspector_mock))

        with pytest.raises(RuntimeError, match="PostgreSQL relation locked or syntax error"):
            run_db_migrations(engine)


def test_migration_acquires_advisory_lock_on_postgres():
    """
    Requirement 6:
    When running against PostgreSQL, run_db_migrations must acquire
    pg_advisory_xact_lock with the designated migration lock ID within the transaction.
    """
    pg_engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "postgresql"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    pg_engine.begin.return_value = cm

    executed_sqls = []

    def mock_execute(statement, *args, **kwargs):
        executed_sqls.append(str(statement))
        return MagicMock()

    conn_mock.execute = mock_execute

    with pytest.MonkeyPatch().context() as m:
        inspector_mock = MagicMock()
        inspector_mock.get_table_names.return_value = []
        m.setattr("backend.database.migration.inspect", MagicMock(return_value=inspector_mock))

        run_db_migrations(pg_engine)

    assert any(f"pg_advisory_xact_lock({SENTINEL_MIGRATION_LOCK_ID})" in s for s in executed_sqls), (
        f"Expected pg_advisory_xact_lock({SENTINEL_MIGRATION_LOCK_ID}) to be executed, but got: {executed_sqls}"
    )


def test_migration_skips_advisory_lock_on_sqlite():
    """
    Requirement 6:
    SQLite does not support pg_advisory_xact_lock; it must be skipped safely.
    """
    sqlite_engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "sqlite"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    sqlite_engine.begin.return_value = cm

    executed_sqls = []

    def mock_execute(statement, *args, **kwargs):
        executed_sqls.append(str(statement))
        return MagicMock()

    conn_mock.execute = mock_execute

    with pytest.MonkeyPatch().context() as m:
        inspector_mock = MagicMock()
        inspector_mock.get_table_names.return_value = []
        m.setattr("backend.database.migration.inspect", MagicMock(return_value=inspector_mock))

        run_db_migrations(sqlite_engine)

    assert not any("pg_advisory_xact_lock" in s for s in executed_sqls), (
        "pg_advisory_xact_lock must NOT be executed on SQLite"
    )


def test_migration_idempotent_and_preserves_existing_data():
    """
    Requirement 6:
    Verifies on a real SQLite database that run_db_migrations:
    - Successfully adds missing columns to existing tables
    - Preserves existing rows and values intact
    - Is idempotent when run multiple times consecutively
    """
    test_engine = create_engine("sqlite:///:memory:")

    with test_engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users (id VARCHAR PRIMARY KEY, username VARCHAR, email VARCHAR)"
        ))
        conn.execute(text(
            "INSERT INTO users (id, username, email) VALUES ('u1', 'alice', 'alice@example.com')"
        ))

    # First migration run
    run_db_migrations(test_engine)

    with test_engine.connect() as conn:
        cols = inspect(test_engine).get_columns("users")
        tv_col = next(c for c in cols if c["name"] == "token_version")
        assert tv_col["nullable"] is False

        user = conn.execute(text("SELECT id, username, token_version FROM users WHERE id = 'u1'")).fetchone()
        assert user[0] == "u1"
        assert user[1] == "alice"
        assert user[2] == 1  # Verified default populated for legacy user

    # Second migration run (idempotency check)
    run_db_migrations(test_engine)

    with test_engine.connect() as conn:
        cols2 = inspect(test_engine).get_columns("users")
        tv_col2 = next(c for c in cols2 if c["name"] == "token_version")
        assert tv_col2["nullable"] is False
        user2 = conn.execute(text("SELECT id, username, token_version FROM users WHERE id = 'u1'")).fetchone()
        assert user2[1] == "alice"
        assert user2[2] == 1


def test_init_db_schema_and_migrations_protects_create_all_with_advisory_lock():
    """
    Finding 1:
    Verifies that init_db_schema_and_migrations acquires the PostgreSQL advisory
    transaction lock BEFORE executing Base.metadata.create_all(bind=conn),
    preventing race conditions during concurrent container startup.
    """
    from backend.database.migration import init_db_schema_and_migrations

    pg_engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "postgresql"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    pg_engine.begin.return_value = cm

    operation_order = []

    def mock_execute(statement, *args, **kwargs):
        stmt = str(statement)
        if "pg_advisory_xact_lock" in stmt:
            operation_order.append("advisory_lock")
        return MagicMock()

    conn_mock.execute = mock_execute

    base_mock = MagicMock()
    def mock_create_all(bind=None):
        operation_order.append("create_all")
    base_mock.metadata.create_all = mock_create_all

    with pytest.MonkeyPatch().context() as m:
        inspector_mock = MagicMock()
        inspector_mock.get_table_names.return_value = []
        m.setattr("backend.database.migration.inspect", MagicMock(return_value=inspector_mock))

        init_db_schema_and_migrations(pg_engine, base=base_mock)

    assert operation_order[:2] == ["advisory_lock", "create_all"], (
        f"Expected advisory_lock BEFORE create_all, got: {operation_order}"
    )


def test_production_startup_fails_on_migration_failure():
    """
    Verifies that FastAPI lifespan startup aborts and raises RuntimeError
    if database schema initialization or migrations fail, preserving
    production fail-fast behavior.
    """
    import anyio
    from backend.main import lifespan, app

    async def _run():
        with pytest.MonkeyPatch().context() as m:
            m.setattr(
                "backend.database.migration.init_db_schema_and_migrations",
                MagicMock(side_effect=RuntimeError("Simulated migration lock acquisition failure"))
            )
            with pytest.raises(RuntimeError, match="Backend startup aborted due to schema/migration initialization failure"):
                async with lifespan(app):
                    pass

    anyio.run(_run)


def test_token_version_migration_enforces_not_null_on_postgres():
    """
    Finding 4:
    Verifies that on PostgreSQL, if a legacy token_version column exists as nullable,
    the migration backfills NULLs and alters the column to SET NOT NULL and SET DEFAULT 1.
    """
    pg_engine = MagicMock()
    conn_mock = MagicMock()
    conn_mock.dialect.name = "postgresql"
    cm = MagicMock()
    cm.__enter__.return_value = conn_mock
    cm.__exit__.return_value = None
    pg_engine.begin.return_value = cm

    executed_sqls = []

    def mock_execute(statement, *args, **kwargs):
        executed_sqls.append(str(statement))
        return MagicMock()

    conn_mock.execute = mock_execute

    with pytest.MonkeyPatch().context() as m:
        inspector_mock = MagicMock()
        inspector_mock.get_table_names.return_value = ["users"]
        # Simulate legacy nullable column
        inspector_mock.get_columns.return_value = [
            {"name": "id", "nullable": False},
            {"name": "token_version", "nullable": True},
        ]
        m.setattr("backend.database.migration.inspect", MagicMock(return_value=inspector_mock))

        run_db_migrations(pg_engine)

    assert any("UPDATE users SET token_version = 1 WHERE token_version IS NULL" in s for s in executed_sqls)
    assert any("ALTER TABLE users ALTER COLUMN token_version SET NOT NULL" in s for s in executed_sqls)
    assert any("ALTER TABLE users ALTER COLUMN token_version SET DEFAULT 1" in s for s in executed_sqls)


def test_proxy_test_environment_normalization(monkeypatch):
    """
    Finding 2 / Review Finding:
    /api/proxy-test diagnostic endpoint must be accessible ONLY in normalized
    development environments ((settings.ENV or '').strip().lower() == 'development').
    All other values (production, staging, unknown, empty, case variations) must return 404.
    """
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)

    # Allowed in development (including whitespace and case variations)
    for allowed_env in ["development", "Development", "development ", " DEVELOPMENT\t"]:
        monkeypatch.setattr(settings, "ENV", allowed_env)
        res = client.get("/api/proxy-test")
        assert res.status_code == 200, f"Expected 200 for ENV={allowed_env!r}, got {res.status_code}"
        assert "client_ip" in res.json()

    # Blocked in all non-development environments -> 404 Not Found
    for blocked_env in ["production", "Production", "PRODUCTION", "staging", "test", "", "   ", "unknown", None]:
        monkeypatch.setattr(settings, "ENV", blocked_env)
        res = client.get("/api/proxy-test")
        assert res.status_code == 404, f"Expected 404 for ENV={blocked_env!r}, got {res.status_code}"
        assert res.json()["detail"] == "Endpoint not found."


def test_csp_rate_limit_bounded_cleanup_and_rejection_at_capacity():
    """
    Verifies that _csp_rate_limit_records maintains bounded memory:
    - Expired entries are automatically pruned during cleanup.
    - Untracked IPs are rejected (HTTP 429) when table is at MAX_CSP_RECORDS of unexpired records.
    - Capacity is strictly bounded by MAX_CSP_RECORDS.
    """
    import time
    from fastapi.testclient import TestClient
    from backend.main import app, _csp_rate_limit_records, reset_csp_rate_limits, MAX_CSP_RECORDS

    client = TestClient(app)
    reset_csp_rate_limits()

    # Pre-populate with expired IP records (> 60s ago)
    now = time.time()
    for i in range(50):
        _csp_rate_limit_records[f"10.0.0.{i}"] = [now - 120.0]

    # Verify stale records are present
    assert len(_csp_rate_limit_records) == 50

    # Submit a CSP report from an active IP (triggering cleanup)
    res = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "203.0.113.88"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res.status_code == 204

    # All 50 expired IPs must have been purged
    assert "203.0.113.88" in _csp_rate_limit_records
    for i in range(50):
        assert f"10.0.0.{i}" not in _csp_rate_limit_records

    # Fill table up to MAX_CSP_RECORDS with unexpired timestamps
    reset_csp_rate_limits()
    for i in range(MAX_CSP_RECORDS):
        _csp_rate_limit_records[f"10.1.{i // 256}.{i % 256}"] = [now - 10.0]

    assert len(_csp_rate_limit_records) == MAX_CSP_RECORDS

    # Making a new request from an untracked IP at capacity rejects with 429 (no unexpired eviction)
    res2 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "198.51.100.99"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res2.status_code == 429
    assert "Service busy or rate limit reached" in res2.json()["detail"]
    assert len(_csp_rate_limit_records) <= MAX_CSP_RECORDS
    assert "198.51.100.99" not in _csp_rate_limit_records

    reset_csp_rate_limits()


def test_csp_rate_limit_unexpired_records_never_evicted_and_tracked_ips_processed(monkeypatch):
    """
    Verifies that unexpired records (1, 59, and 60 requests) are NEVER evicted:
    1. Active records with 1, 59, and 60 hits survive when untracked IPs arrive at capacity.
    2. Untracked IPs fail closed (HTTP 429) when table is at capacity of unexpired records.
    3. Existing tracked IPs continue normal processing even when capacity is reached.
    4. Expired records are pruned, freeing capacity for untracked IPs.
    5. Storage never exceeds MAX_CSP_RECORDS.
    6. The 60 requests/minute rate-limit policy remains strictly enforced.
    """
    import time
    from fastapi.testclient import TestClient
    import backend.main as main_mod

    # Constrain capacity to 3 records for exact state inspection
    monkeypatch.setattr(main_mod, "MAX_CSP_RECORDS", 3)
    client = TestClient(main_mod.app)
    main_mod.reset_csp_rate_limits()

    now = time.time()
    # IP 1: Active with 1 request (low activity)
    main_mod._csp_rate_limit_records["192.0.2.1"] = [now - 5.0]
    # IP 2: Active with 59 requests (approaching rate limit)
    main_mod._csp_rate_limit_records["192.0.2.2"] = [now - (59 - i) * 0.5 for i in range(59)]
    # IP 3: Active with 60 requests (at rate limit / blocked)
    main_mod._csp_rate_limit_records["192.0.2.3"] = [now - (60 - i) * 0.5 for i in range(60)]

    assert len(main_mod._csp_rate_limit_records) == 3

    # 1. Untracked IP 4 arrives under capacity pressure (len == 3 >= MAX_CSP_RECORDS).
    # NONE of the unexpired records (1, 59, 60 hits) must be evicted.
    # Untracked IP 4 must be rejected with HTTP 429.
    res_untracked = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.4"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_untracked.status_code == 429
    assert "Service busy or rate limit reached" in res_untracked.json()["detail"]

    # All unexpired records survive intact
    assert len(main_mod._csp_rate_limit_records) == 3
    assert "192.0.2.1" in main_mod._csp_rate_limit_records
    assert len(main_mod._csp_rate_limit_records["192.0.2.1"]) == 1
    assert "192.0.2.2" in main_mod._csp_rate_limit_records
    assert len(main_mod._csp_rate_limit_records["192.0.2.2"]) == 59
    assert "192.0.2.3" in main_mod._csp_rate_limit_records
    assert len(main_mod._csp_rate_limit_records["192.0.2.3"]) == 60
    assert "192.0.2.4" not in main_mod._csp_rate_limit_records

    # 2. Existing tracked IPs must continue through normal rate-limit processing:
    # IP 1 (1 hit) sends another request -> accepted (204 OK), count becomes 2
    res_ip1 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.1"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_ip1.status_code == 204
    assert len(main_mod._csp_rate_limit_records["192.0.2.1"]) == 2

    # IP 2 (59 hits) sends 60th request -> accepted (204 OK), count becomes 60
    res_ip2_60 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.2"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_ip2_60.status_code == 204
    assert len(main_mod._csp_rate_limit_records["192.0.2.2"]) == 60

    # IP 2 sends 61st request -> rejected (429 per-IP rate limit)
    res_ip2_61 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.2"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_ip2_61.status_code == 429
    assert "Too many CSP violation reports from this IP" in res_ip2_61.json()["detail"]

    # IP 3 (60 hits) sends request -> rejected (429 per-IP rate limit)
    res_ip3 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.3"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_ip3.status_code == 429
    assert "Too many CSP violation reports from this IP" in res_ip3.json()["detail"]

    # Table size is still strictly bounded
    assert len(main_mod._csp_rate_limit_records) == 3

    # 3. Expired records are removed and capacity becomes available:
    # Expire IP 1 and IP 3 (> 60s ago)
    main_mod._csp_rate_limit_records["192.0.2.1"] = [now - 120.0]
    main_mod._csp_rate_limit_records["192.0.2.3"] = [now - 120.0]

    # Now untracked IP 5 arrives -> expired records pruned -> IP 5 accepted
    res_ip5 = client.post(
        "/api/csp-report",
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "192.0.2.5"},
        json={"csp-report": {"document-uri": "https://example.com"}},
    )
    assert res_ip5.status_code == 204
    assert "192.0.2.1" not in main_mod._csp_rate_limit_records
    assert "192.0.2.3" not in main_mod._csp_rate_limit_records
    assert "192.0.2.5" in main_mod._csp_rate_limit_records
    assert "192.0.2.2" in main_mod._csp_rate_limit_records
    assert len(main_mod._csp_rate_limit_records) == 2

    main_mod.reset_csp_rate_limits()
