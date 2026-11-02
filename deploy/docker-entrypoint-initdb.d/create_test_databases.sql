-- PostgreSQL init script for the test database container.
-- Creates both the application database and the isolated test database so that:
--   1. Tests run against 'security_scanner_test' (POSTGRES_DB env override).
--   2. test_test_database_cannot_touch_app_database can connect to 'security_scanner'
--      and query the users table to confirm no test data leaked into it.

SELECT 'CREATE DATABASE security_scanner'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'security_scanner'
)\gexec

SELECT 'CREATE DATABASE security_scanner_test'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'security_scanner_test'
)\gexec

-- Connect to the app DB and create the minimal schema so the isolation
-- canary query (SELECT FROM users WHERE username = ...) succeeds and
-- correctly returns zero rows, proving isolation.
\connect security_scanner

CREATE TABLE IF NOT EXISTS users (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR     NOT NULL UNIQUE,
    email       VARCHAR     NOT NULL UNIQUE,
    hashed_password VARCHAR NOT NULL,
    created_at  TIMESTAMP   NOT NULL DEFAULT now(),
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE
);
