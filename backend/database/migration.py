import logging
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

def run_db_migrations(engine):
    """
    Idempotent database migration helper using SQLAlchemy inspector.
    Works consistently across both SQLite and PostgreSQL without relying on
    non-standard syntax like 'ADD COLUMN IF NOT EXISTS'.
    """
    try:
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = inspector.get_table_names()

            if "vulnerabilities" in tables:
                vuln_cols = [col["name"] for col in inspector.get_columns("vulnerabilities")]
                if "auto_fixable" not in vuln_cols:
                    conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN auto_fixable BOOLEAN DEFAULT 1"))
                    conn.commit()
                if "fix_source" not in vuln_cols:
                    conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN fix_source VARCHAR"))
                    conn.commit()

            if "scan_history" in tables:
                scan_cols = [col["name"] for col in inspector.get_columns("scan_history")]
                if "warnings" not in scan_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN warnings TEXT"))
                    conn.commit()
                if "dependency_summary" not in scan_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN dependency_summary TEXT"))
                    conn.commit()
                if "engines_run" not in scan_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN engines_run TEXT"))
                    conn.commit()
                if "scanned_files" not in scan_cols:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN scanned_files TEXT"))
                    conn.commit()

            if "scan_findings" in tables:
                sf_cols = [col["name"] for col in inspector.get_columns("scan_findings")]
                if "fixed_by_apply_fix" not in sf_cols:
                    conn.execute(text("ALTER TABLE scan_findings ADD COLUMN fixed_by_apply_fix BOOLEAN DEFAULT FALSE"))
                    conn.commit()
        logger.info("Database migrations executed successfully.")
    except Exception as e:
        logger.error(f"Error executing database migrations: {e}")
