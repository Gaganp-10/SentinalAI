#!/usr/bin/env bash
# =============================================================================
# SentinelAI Automated Backup Script (PostgreSQL + Uploads Volume)
#
# Creates:
#   1. PostgreSQL custom-format compressed dump (-Fc), validated with pg_restore -l
#   2. Gzip-compressed tarball of the uploads volume
#   3. SHA-256 checksums file for atomic verification on restore
# =============================================================================

set -euo pipefail
umask 077
export MSYS_NO_PATHCONV=1

BACKUP_DIR="${BACKUP_DIR:-$(pwd)/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
S3_BUCKET="${S3_BUCKET:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-./docker.env}"

COMPOSE_ENV_ARG=()
if [[ -f "${ENV_FILE}" ]]; then
    COMPOSE_ENV_ARG=(--env-file "${ENV_FILE}")
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' "${ENV_FILE}" | xargs)
elif [[ -f "/home/deploy/sentinel-ai/docker.env" ]]; then
    COMPOSE_ENV_ARG=(--env-file "/home/deploy/sentinel-ai/docker.env")
    # shellcheck disable=SC2046
    export $(grep -E '^(POSTGRES_USER|POSTGRES_DB)=' /home/deploy/sentinel-ai/docker.env | xargs)
fi

# Load S3_BUCKET from backup.env if present
if [[ -f "/home/deploy/sentinel-ai/backup.env" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^S3_BUCKET=' /home/deploy/sentinel-ai/backup.env | xargs)
elif [[ -f "./backup.env" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^S3_BUCKET=' ./backup.env | xargs)
fi

POSTGRES_USER="${POSTGRES_USER:-sentinel}"
POSTGRES_DB="${POSTGRES_DB:-security_scanner}"

# Identify container IDs via Docker Compose ps -q
DB_CONTAINER="$(docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" ps -q db 2>/dev/null || true)"
if [[ -z "${DB_CONTAINER}" ]]; then
    echo "ERROR: PostgreSQL database container is not running." >&2
    exit 1
fi

UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | grep "sentinel_prod" | head -n 1 || true)"
if [[ -z "${UPLOADS_VOLUME}" ]]; then
    UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | head -n 1 || true)"
fi
if [[ -z "${UPLOADS_VOLUME}" ]]; then
    echo "ERROR: Uploads volume 'uploads_data' not found." >&2
    exit 1
fi

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

TIMESTAMP="$(date -u +'%Y%m%d_%H%M%SZ')"
DB_BACKUP_FILE="${BACKUP_DIR}/db_${TIMESTAMP}.dump"
UPLOADS_BACKUP_FILE="${BACKUP_DIR}/uploads_${TIMESTAMP}.tar.gz"
CHECKSUM_FILE="${BACKUP_DIR}/checksums_${TIMESTAMP}.sha256"

DB_TMP="${DB_BACKUP_FILE}.tmp.$$"
UPLOADS_TMP="${UPLOADS_BACKUP_FILE}.tmp.$$"

cleanup() {
    rm -f "${DB_TMP}" "${UPLOADS_TMP}"
}
trap cleanup EXIT INT TERM

echo "=== [1/4] Dumping PostgreSQL database '${POSTGRES_DB}' ==="
docker exec "${DB_CONTAINER}" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -Fc > "${DB_TMP}"

# Validate dump: size > 0 and inspectable via pg_restore -l
if [[ ! -s "${DB_TMP}" ]]; then
    echo "ERROR: Database dump produced an empty file." >&2
    exit 1
fi

if ! docker exec -i "${DB_CONTAINER}" pg_restore -l < "${DB_TMP}" > /dev/null 2>&1; then
    echo "ERROR: Database dump validation failed (pg_restore -l rejected file)." >&2
    exit 1
fi

mv "${DB_TMP}" "${DB_BACKUP_FILE}"
echo "Database dump verified and saved: ${DB_BACKUP_FILE} ($(du -h "${DB_BACKUP_FILE}" | cut -f1))"

echo "=== [2/4] Archiving uploads volume '${UPLOADS_VOLUME}' ==="
docker run --rm \
    -v "${UPLOADS_VOLUME}:/uploads:ro" \
    alpine:3.20 tar -czf - -C /uploads . > "${UPLOADS_TMP}"

if [[ ! -s "${UPLOADS_TMP}" ]]; then
    echo "ERROR: Uploads archive produced an empty file." >&2
    exit 1
fi

mv "${UPLOADS_TMP}" "${UPLOADS_BACKUP_FILE}"
echo "Uploads archive verified and saved: ${UPLOADS_BACKUP_FILE} ($(du -h "${UPLOADS_BACKUP_FILE}" | cut -f1))"

echo "=== [3/4] Generating cryptographic SHA-256 checksums ==="
(
    cd "${BACKUP_DIR}"
    sha256sum "db_${TIMESTAMP}.dump" "uploads_${TIMESTAMP}.tar.gz" > "${CHECKSUM_FILE}"
)
echo "Checksums saved to ${CHECKSUM_FILE}"

echo "=== [4/4] Enforcing retention policy (keep ${RETENTION_DAYS} days) ==="
find "${BACKUP_DIR}" -maxdepth 1 -type f \( -name "db_*.dump" -o -name "uploads_*.tar.gz" -o -name "checksums_*.sha256" \) -mtime "+${RETENTION_DAYS}" -exec rm -f {} +
echo "Local backups older than ${RETENTION_DAYS} days purged."

if [[ -n "${S3_BUCKET}" ]]; then
    if command -v aws >/dev/null 2>&1; then
        echo "Uploading backups to s3://${S3_BUCKET}/sentinel-backups/..."
        aws s3 cp "${DB_BACKUP_FILE}" "s3://${S3_BUCKET}/sentinel-backups/db_${TIMESTAMP}.dump" --sse AES256
        aws s3 cp "${UPLOADS_BACKUP_FILE}" "s3://${S3_BUCKET}/sentinel-backups/uploads_${TIMESTAMP}.tar.gz" --sse AES256
        aws s3 cp "${CHECKSUM_FILE}" "s3://${S3_BUCKET}/sentinel-backups/checksums_${TIMESTAMP}.sha256" --sse AES256
        echo "S3 sync complete."
    else
        echo "WARNING: S3_BUCKET is set but AWS CLI ('aws') is not installed. S3 upload skipped." >&2
    fi
fi

echo "Backup successful: db_${TIMESTAMP}.dump and uploads_${TIMESTAMP}.tar.gz"
