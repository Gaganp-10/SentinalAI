import logging
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

# Advisory lock constant ID for SentinelAI migrations (64-bit bigint)
SENTINEL_MIGRATION_LOCK_ID = 74928174

def _apply_migrations(conn):
    """
    Applies custom column migrations inside an active database connection/transaction.
    """
    is_postgres = conn.dialect.name == "postgresql"
    inspector = inspect(conn)
    tables = inspector.get_table_names()

    if "users" in tables:
        user_cols = {col["name"]: col for col in inspector.get_columns("users")}
        if "token_version" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1"))
            conn.execute(text("UPDATE users SET token_version = 1 WHERE token_version IS NULL"))
        else:
            # If column exists but is nullable, enforce NOT NULL and backfill on PostgreSQL
            tv_col = user_cols.get("token_version")
            if tv_col and tv_col.get("nullable", True):
                conn.execute(text("UPDATE users SET token_version = 1 WHERE token_version IS NULL"))
                if is_postgres:
                    conn.execute(text("ALTER TABLE users ALTER COLUMN token_version SET NOT NULL"))
                    conn.execute(text("ALTER TABLE users ALTER COLUMN token_version SET DEFAULT 1"))

    if "vulnerabilities" in tables:
        vuln_cols = [col["name"] for col in inspector.get_columns("vulnerabilities")]
        if "auto_fixable" not in vuln_cols:
            auto_fixable_sql = (
                "ALTER TABLE vulnerabilities ADD COLUMN auto_fixable BOOLEAN DEFAULT 1"
                if conn.dialect.name == "sqlite"
                else "ALTER TABLE vulnerabilities ADD COLUMN auto_fixable BOOLEAN DEFAULT TRUE"
            )
            conn.execute(text(auto_fixable_sql))
        if "fix_source" not in vuln_cols:
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN fix_source VARCHAR"))

    if "scan_history" in tables:
        scan_cols = [col["name"] for col in inspector.get_columns("scan_history")]
        if "warnings" not in scan_cols:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN warnings TEXT"))
        if "dependency_summary" not in scan_cols:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN dependency_summary TEXT"))
        if "engines_run" not in scan_cols:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN engines_run TEXT"))
        if "scanned_files" not in scan_cols:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN scanned_files TEXT"))

    if "scan_findings" in tables:
        sf_cols = [col["name"] for col in inspector.get_columns("scan_findings")]
        if "fixed_by_apply_fix" not in sf_cols:
            conn.execute(text("ALTER TABLE scan_findings ADD COLUMN fixed_by_apply_fix BOOLEAN DEFAULT FALSE"))


def init_db_schema_and_migrations(engine, base=None):
    """
    Initializes database tables and executes migrations within a single atomic operation.
    Protected by PostgreSQL transaction-level advisory lock when running on Postgres
    to prevent concurrent startup race conditions (e.g. duplicate table/index creation).
    """
    try:
        with engine.begin() as conn:
            is_postgres = conn.dialect.name == "postgresql"
            if is_postgres:
                logger.info("Acquiring PostgreSQL advisory migration lock (%d)...", SENTINEL_MIGRATION_LOCK_ID)
                conn.execute(text(f"SELECT pg_advisory_xact_lock({SENTINEL_MIGRATION_LOCK_ID})"))

            if base is not None:
                logger.info("Initializing database tables...")
                base.metadata.create_all(bind=conn)

            _apply_migrations(conn)

        logger.info("Database schema and migrations initialized successfully.")
    except Exception as e:
        logger.critical("FATAL: Database initialization failed: %s", e)
        raise


def run_db_migrations(engine):
    """
    Idempotent database migration helper.
    Backwards-compatible migration entrypoint for tests and standalone scripts.
    """
    init_db_schema_and_migrations(engine, base=None)
