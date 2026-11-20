#!/usr/bin/env bash
# =============================================================================
# SentinelAI Admin CLI Wrapper: Create User Account in Docker
#
# Usage:
#   ./deploy/create-user.sh
#   ./deploy/create-user.sh --username admin --email admin@example.com
# =============================================================================

set -euo pipefail
umask 077

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-./docker.env}"

COMPOSE_ENV_ARG=()
if [[ -f "${ENV_FILE}" ]]; then
    COMPOSE_ENV_ARG=(--env-file "${ENV_FILE}")
elif [[ -f "/home/deploy/sentinel-ai/docker.env" ]]; then
    COMPOSE_ENV_ARG=(--env-file "/home/deploy/sentinel-ai/docker.env")
fi

# Determine whether running interactively (TTY available)
INTERACTIVE_FLAG=""
if [ -t 0 ] && [ -t 1 ]; then
    INTERACTIVE_FLAG="-it"
else
    INTERACTIVE_FLAG="-T"
fi

# shellcheck disable=SC2086
docker compose "${COMPOSE_ENV_ARG[@]}" -f "${COMPOSE_FILE}" exec ${INTERACTIVE_FLAG} backend python -m backend.scripts.create_user "$@"
