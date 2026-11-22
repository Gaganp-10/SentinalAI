#!/usr/bin/env bash
# =============================================================================
# SentinelAI Database & Uploads Restore Script
#
# Usage:
#   # 1. Scratch test mode: Verify backup integrity in an isolated temporary database
#   ./deploy/restore.sh --scratch-test /path/to/db_TIMESTAMP.dump
#
#   # 2. Production restore: Restores database & uploads volume
#   ./deploy/restore.sh [--allow-errors] /path/to/db_TIMESTAMP.dump [/path/to/uploads_TIMESTAMP.tar.gz]
#
# Flags:
#   --scratch-test   Restore to a temporary database, then drop it. Does not touch production.
#   --allow-errors   Continue even if pg_restore reports non-fatal errors (use only for known issues).
# =============================================================================

set -euo pipefail
umask 077
export MSYS_NO_PATHCONV=1

SCRATCH_MODE=0
ALLOW_ERRORS=0
POSITIONAL=()

for arg in "$@"; do
    case "${arg}" in
        --scratch-test) SCRATCH_MODE=1 ;;
        --allow-errors) ALLOW_ERRORS=1 ;;
        *)              POSITIONAL+=("${arg}") ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

DB_DUMP_FILE="${1:-}"
UPLOADS_TAR_FILE="${2:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-./docker.env}"
BACKUP_DIR="$(dirname "${DB_DUMP_FILE:-/dev/null}")"

if [[ -z "${DB_DUMP_FILE}" ]]; then
    echo "Usage: $0 [--scratch-test] [--allow-errors] <db_dump_file> [uploads_tar_file]" >&2
    exit 1
fi

if [[ ! -f "${DB_DUMP_FILE}" ]]; then
    echo "ERROR: Database dump file not found: ${DB_DUMP_FILE}" >&2
    exit 1
fi

# Load database credentials if env file exists
COMPOSE_ENV_ARG=()
if [[ -f "./docker.env.prod.local" ]]; then
    ENV_FILE="./docker.env.prod.local"
    COMPOSE_ENV_ARG=(--env-file "${ENV_FILE}")
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' "${ENV_FILE}" | xargs)
elif [[ -f "${ENV_FILE}" ]]; then
    COMPOSE_ENV_ARG=(--env-file "${ENV_FILE}")
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' "${ENV_FILE}" | xargs)
elif [[ -f "/home/deploy/sentinel-ai/docker.env" ]]; then
    COMPOSE_ENV_ARG=(--env-file "/home/deploy/sentinel-ai/docker.env")
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' /home/deploy/sentinel-ai/docker.env | xargs)
fi

POSTGRES_USER="${POSTGRES_USER:-sentinel}"
POSTGRES_DB="${POSTGRES_DB:-security_scanner}"

# Identify container IDs via Docker Compose ps -q
DB_CONTAINER="$(docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" ps -q db 2>/dev/null || true)"
if [[ -z "${DB_CONTAINER}" ]]; then
    echo "ERROR: PostgreSQL database container is not running." >&2
    exit 1
fi

# Verify SHA-256 checksum file belonging to this specific dump
DUMP_DIR="$(dirname "${DB_DUMP_FILE}")"
DUMP_BASE="$(basename "${DB_DUMP_FILE}")"
TIMESTAMP="${DUMP_BASE#db_}"
TIMESTAMP="${TIMESTAMP%.dump}"
CHECKSUM_FILE="${DUMP_DIR}/checksums_${TIMESTAMP}.sha256"

if [[ ! -f "${CHECKSUM_FILE}" ]]; then
    echo "ERROR: Required checksum file '${CHECKSUM_FILE}' not found for dump '${DB_DUMP_FILE}'." >&2
    exit 1
fi

echo "=== Verifying cryptographic SHA-256 checksums (${CHECKSUM_FILE}) ==="
(
    cd "${DUMP_DIR}"
    sha256sum --check --ignore-missing "$(basename "${CHECKSUM_FILE}")"
)
echo "Checksum verification passed."

# Validate dump file size and format before restoring
if [[ ! -s "${DB_DUMP_FILE}" ]]; then
    echo "ERROR: Database dump file is empty." >&2
    exit 1
fi

if ! docker exec -i "${DB_CONTAINER}" pg_restore -l < "${DB_DUMP_FILE}" > /dev/null 2>&1; then
    echo "ERROR: Database dump validation failed (pg_restore -l rejected file)." >&2
    exit 1
fi

# Validate uploads tarball (before touching anything) if provided
if [[ -n "${UPLOADS_TAR_FILE}" ]]; then
    if [[ ! -s "${UPLOADS_TAR_FILE}" ]]; then
        echo "ERROR: Uploads archive file empty or not found: ${UPLOADS_TAR_FILE}" >&2
        exit 1
    fi
    echo "=== Validating uploads tarball (tar -tzf) ==="
    if ! tar -tzf "${UPLOADS_TAR_FILE}" > /dev/null 2>&1; then
        echo "ERROR: Uploads tarball failed integrity check (tar -tzf)." >&2
        exit 1
    fi
    echo "Uploads tarball integrity OK."
fi

# =============================================================================
# Scratch Test Mode: Verify backup in an isolated temporary database
# =============================================================================
if [[ "${SCRATCH_MODE}" -eq 1 ]]; then
    SCRATCH_DB="scratch_restore_verify_$(date +%s)"
    echo "=== Running Scratch Verification in temporary database '${SCRATCH_DB}' ==="

    trap 'docker exec -i "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d postgres -c "DROP DATABASE IF EXISTS ${SCRATCH_DB};" > /dev/null 2>&1 || true' EXIT INT TERM

    echo "1. Creating scratch database..."
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d postgres -c "CREATE DATABASE ${SCRATCH_DB};"

    echo "2. Restoring dump into scratch database..."
    RESTORE_LOG="$(mktemp)"
    if ! docker exec -i "${DB_CONTAINER}" pg_restore -U "${POSTGRES_USER}" -d "${SCRATCH_DB}" --no-owner --role="${POSTGRES_USER}" < "${DB_DUMP_FILE}" > "${RESTORE_LOG}" 2>&1; then
        FATAL_COUNT="$(grep -c -i "fatal" "${RESTORE_LOG}" || true)"
        if [[ "${FATAL_COUNT}" -gt 0 ]]; then
            echo "ERROR: Fatal errors detected during scratch pg_restore:" >&2
            cat "${RESTORE_LOG}" >&2
            rm -f "${RESTORE_LOG}"
            exit 1
        fi
    fi
    TOTAL_ERRORS="$(grep -c -i "ERROR:" "${RESTORE_LOG}" || true)"
    echo "Scratch pg_restore completed with error count: ${TOTAL_ERRORS}"
    if [[ "${TOTAL_ERRORS}" -gt 0 && "${ALLOW_ERRORS}" -eq 0 ]]; then
        echo "ERROR: pg_restore reported ${TOTAL_ERRORS} error(s). Pass --allow-errors to override." >&2
        cat "${RESTORE_LOG}" >&2
        rm -f "${RESTORE_LOG}"
        exit 1
    fi
    rm -f "${RESTORE_LOG}"

    echo "3. Verifying restored tables and record counts..."
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${SCRATCH_DB}" -c "
        SELECT 'users' AS table_name, count(*) AS count FROM users
        UNION ALL
        SELECT 'projects', count(*) FROM projects
        UNION ALL
        SELECT 'files', count(*) FROM files
        UNION ALL
        SELECT 'vulnerabilities', count(*) FROM vulnerabilities;
    "

    echo "SUCCESS: Backup '${DB_DUMP_FILE}' verified completely intact."
    exit 0
fi

# =============================================================================
# Production Restore Mode
# =============================================================================
echo "WARNING: This operation will OVERWRITE data in '${POSTGRES_DB}'."
read -r -p "Are you sure you want to proceed? [y/N] " response
if [[ ! "${response}" =~ ^[yY]([eE][sS])?$ ]]; then
    echo "Restore aborted by user."
    exit 0
fi

echo "=== [1/4] Stopping backend to prevent live writes during restore ==="
docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" stop backend || true

echo "=== [2/4] Pre-restore safety dump (backups/pre_restore_${TIMESTAMP}.dump) ==="
PRE_RESTORE_DUMP="${BACKUP_DIR}/pre_restore_${TIMESTAMP}.dump"
if ! docker exec "${DB_CONTAINER}" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -Fc > "${PRE_RESTORE_DUMP}" 2>/dev/null; then
    echo "WARNING: Pre-restore dump failed (database may be empty). Continuing." >&2
    rm -f "${PRE_RESTORE_DUMP}"
else
    echo "Pre-restore dump saved: ${PRE_RESTORE_DUMP} ($(du -h "${PRE_RESTORE_DUMP}" | cut -f1))"
fi

echo "=== [3/4] Restoring PostgreSQL database '${POSTGRES_DB}' ==="
RESTORE_LOG="$(mktemp)"
if ! docker exec -i "${DB_CONTAINER}" pg_restore \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    --clean \
    --if-exists \
    --no-owner \
    --role="${POSTGRES_USER}" < "${DB_DUMP_FILE}" > "${RESTORE_LOG}" 2>&1; then
    FATAL_COUNT="$(grep -c -i "fatal" "${RESTORE_LOG}" || true)"
    if [[ "${FATAL_COUNT}" -gt 0 ]]; then
        echo "ERROR: Fatal error encountered during pg_restore:" >&2
        cat "${RESTORE_LOG}" >&2
        rm -f "${RESTORE_LOG}"
        docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" start backend || true
        exit 1
    fi
fi
TOTAL_ERRORS="$(grep -c -i "ERROR:" "${RESTORE_LOG}" || true)"
echo "Database restore complete (pg_restore errors: ${TOTAL_ERRORS})."
if [[ "${TOTAL_ERRORS}" -gt 0 && "${ALLOW_ERRORS}" -eq 0 ]]; then
    echo "ERROR: pg_restore reported ${TOTAL_ERRORS} error(s). Pass --allow-errors to override." >&2
    cat "${RESTORE_LOG}" >&2
    rm -f "${RESTORE_LOG}"
    docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" start backend || true
    exit 1
fi
rm -f "${RESTORE_LOG}"

if [[ -n "${UPLOADS_TAR_FILE}" ]]; then
    UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | grep "sentinel_prod" | head -n 1 || true)"
    if [[ -z "${UPLOADS_VOLUME}" ]]; then
        UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | head -n 1 || true)"
    fi
    if [[ -z "${UPLOADS_VOLUME}" ]]; then
        echo "ERROR: Uploads volume 'uploads_data' not found." >&2
        docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" start backend || true
        exit 1
    fi

    echo "Restoring uploads volume '${UPLOADS_VOLUME}'..."
    docker run --rm -i \
        -v "${UPLOADS_VOLUME}:/uploads" \
        alpine:3.20 sh -c "rm -rf /uploads/* && tar -xzf - -C /uploads" < "${UPLOADS_TAR_FILE}"
    echo "Uploads volume restore complete."
fi

echo "=== [4/4] Starting backend container ==="
docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" start backend

echo "Production restore completed successfully."
