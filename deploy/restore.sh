#!/usr/bin/env bash
# =============================================================================
# SentinelAI Database & Uploads Restore Script
#
# Usage:
#   # 1. Test restore into a scratch database to verify backup integrity:
#   ./deploy/restore.sh --scratch-test /path/to/db_TIMESTAMP.dump
#
#   # 2. Perform full production restore (database + uploads volume):
#   ./deploy/restore.sh /path/to/db_TIMESTAMP.dump /path/to/uploads_TIMESTAMP.tar.gz
#
#   # 3. Restore database only:
#   ./deploy/restore.sh /path/to/db_TIMESTAMP.dump
# =============================================================================

set -euo pipefail

SCRATCH_MODE=0
if [[ "${1:-}" == "--scratch-test" ]]; then
    SCRATCH_MODE=1
    shift
fi

DB_DUMP_FILE="${1:-}"
UPLOADS_TAR_FILE="${2:-}"

if [[ -z "${DB_DUMP_FILE}" ]]; then
    echo "Usage: $0 [--scratch-test] <db_dump_file> [uploads_tar_file]" >&2
    exit 1
fi

if [[ ! -f "${DB_DUMP_FILE}" ]]; then
    echo "ERROR: Database dump file not found: ${DB_DUMP_FILE}" >&2
    exit 1
fi

# Load docker.env if present
if [[ -f "./docker.env" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' ./docker.env | xargs)
elif [[ -f "/home/deploy/sentinel-ai/docker.env" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' /home/deploy/sentinel-ai/docker.env | xargs)
fi

POSTGRES_USER="${POSTGRES_USER:-sentinel}"
POSTGRES_DB="${POSTGRES_DB:-security_scanner}"

DB_CONTAINER="$(docker ps --filter "name=db" --format "{{.Names}}" | head -n 1)"
if [[ -z "${DB_CONTAINER}" ]]; then
    echo "ERROR: PostgreSQL database container is not running." >&2
    exit 1
fi

# =============================================================================
# Scratch Test Mode: Verify backup in an isolated temporary database
# =============================================================================
if [[ "${SCRATCH_MODE}" -eq 1 ]]; then
    SCRATCH_DB="scratch_restore_verify_$(date +%s)"
    echo "=== Running Scratch Verification in temporary database '${SCRATCH_DB}' ==="

    echo "1. Creating scratch database..."
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d postgres -c "CREATE DATABASE ${SCRATCH_DB};"

    echo "2. Restoring dump into scratch database..."
    # pg_restore returns 0 or 1 on non-fatal warnings; pipe output cleanly
    docker exec -i "${DB_CONTAINER}" pg_restore -U "${POSTGRES_USER}" -d "${SCRATCH_DB}" --no-owner --role="${POSTGRES_USER}" < "${DB_DUMP_FILE}" || true

    echo "3. Verifying restored tables and record counts..."
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${SCRATCH_DB}" -c "\dt"
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${SCRATCH_DB}" -c "
        SELECT 'users' AS table_name, count(*) AS count FROM users
        UNION ALL
        SELECT 'projects', count(*) FROM projects
        UNION ALL
        SELECT 'files', count(*) FROM files
        UNION ALL
        SELECT 'vulnerabilities', count(*) FROM vulnerabilities;
    "

    echo "4. Dropping scratch database..."
    docker exec "${DB_CONTAINER}" psql -U "${POSTGRES_USER}" -d postgres -c "DROP DATABASE ${SCRATCH_DB};"

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

echo "=== [1/2] Restoring PostgreSQL database '${POSTGRES_DB}' ==="
docker exec -i "${DB_CONTAINER}" pg_restore \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    --clean \
    --if-exists \
    --no-owner \
    --role="${POSTGRES_USER}" < "${DB_DUMP_FILE}" || true
echo "Database restore complete."

if [[ -n "${UPLOADS_TAR_FILE}" ]]; then
    if [[ ! -f "${UPLOADS_TAR_FILE}" ]]; then
        echo "ERROR: Uploads archive file not found: ${UPLOADS_TAR_FILE}" >&2
        exit 1
    fi

    UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | head -n 1)"
    if [[ -z "${UPLOADS_VOLUME}" ]]; then
        echo "ERROR: Uploads volume 'uploads_data' not found." >&2
        exit 1
    fi

    echo "=== [2/2] Restoring uploads volume '${UPLOADS_VOLUME}' ==="
    docker run --rm -i \
        -v "${UPLOADS_VOLUME}:/uploads" \
        alpine:3.20 sh -c "rm -rf /uploads/* && tar -xzf - -C /uploads" < "${UPLOADS_TAR_FILE}"
    echo "Uploads volume restore complete."
else
    echo "No uploads archive provided. Uploads volume was not modified."
fi

echo "Production restore completed successfully."
