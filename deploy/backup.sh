#!/usr/bin/env bash
# =============================================================================
# SentinelAI Automated Backup Script (PostgreSQL + Uploads Volume)
#
# Creates:
#   1. PostgreSQL custom-format compressed dump (-Fc)
#   2. Gzip-compressed tarball of the uploads volume
#
# Features:
#   - Automatic pruning: Keeps the latest 7 days of backups locally.
#   - Optional private S3 sync (if S3_BUCKET environment variable is set).
#   - Suitable for nightly cron execution (0 2 * * * /home/deploy/sentinel-ai/deploy/backup.sh)
# =============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-$(pwd)/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
S3_BUCKET="${S3_BUCKET:-}"

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

# Identify container and volume names
DB_CONTAINER="$(docker ps --filter "name=db" --format "{{.Names}}" | head -n 1)"
if [[ -z "${DB_CONTAINER}" ]]; then
    echo "ERROR: PostgreSQL database container is not running." >&2
    exit 1
fi

UPLOADS_VOLUME="$(docker volume ls --filter "name=uploads_data" --format "{{.Name}}" | head -n 1)"
if [[ -z "${UPLOADS_VOLUME}" ]]; then
    echo "ERROR: Uploads volume 'uploads_data' not found." >&2
    exit 1
fi

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

TIMESTAMP="$(date -u +'%Y%m%d_%H%M%SZ')"
DB_BACKUP_FILE="${BACKUP_DIR}/db_${TIMESTAMP}.dump"
UPLOADS_BACKUP_FILE="${BACKUP_DIR}/uploads_${TIMESTAMP}.tar.gz"

echo "=== [1/4] Dumping PostgreSQL database '${POSTGRES_DB}' ==="
docker exec "${DB_CONTAINER}" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -Fc > "${DB_BACKUP_FILE}"
chmod 600 "${DB_BACKUP_FILE}"
echo "Database dump created: ${DB_BACKUP_FILE} ($(du -h "${DB_BACKUP_FILE}" | cut -f1))"

echo "=== [2/4] Archiving uploads volume '${UPLOADS_VOLUME}' ==="
docker run --rm \
    -v "${UPLOADS_VOLUME}:/uploads:ro" \
    alpine:3.20 tar -czf - -C /uploads . > "${UPLOADS_BACKUP_FILE}"
chmod 600 "${UPLOADS_BACKUP_FILE}"
echo "Uploads archive created: ${UPLOADS_BACKUP_FILE} ($(du -h "${UPLOADS_BACKUP_FILE}" | cut -f1))"

echo "=== [3/4] Enforcing local retention policy (keep ${RETENTION_DAYS} days) ==="
find "${BACKUP_DIR}" -maxdepth 1 -type f \( -name "db_*.dump" -o -name "uploads_*.tar.gz" \) -mtime "+${RETENTION_DAYS}" -exec rm -f {} +
echo "Local backups older than ${RETENTION_DAYS} days purged."

echo "=== [4/4] S3 Bucket Upload ==="
if [[ -n "${S3_BUCKET}" ]]; then
    if command -v aws >/dev/null 2>&1; then
        echo "Uploading backups to s3://${S3_BUCKET}/sentinel-backups/..."
        aws s3 cp "${DB_BACKUP_FILE}" "s3://${S3_BUCKET}/sentinel-backups/db_${TIMESTAMP}.dump" --sse AES256
        aws s3 cp "${UPLOADS_BACKUP_FILE}" "s3://${S3_BUCKET}/sentinel-backups/uploads_${TIMESTAMP}.tar.gz" --sse AES256
        echo "S3 sync complete."
    else
        echo "WARNING: S3_BUCKET is set but AWS CLI ('aws') is not installed. S3 upload skipped." >&2
    fi
else
    echo "S3_BUCKET not configured. Backups stored locally in ${BACKUP_DIR}."
fi

echo "Backup successful: db_${TIMESTAMP}.dump and uploads_${TIMESTAMP}.tar.gz"
