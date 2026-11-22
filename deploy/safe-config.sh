#!/usr/bin/env bash
# =============================================================================
# SentinelAI Safe Production Configuration Viewer
#
# Inspects Docker Compose configuration while strictly redacting all secret
# material (passwords, cryptographic keys, tokens, and database credentials).
#
# Usage:
#   ./deploy/safe-config.sh
#   ./deploy/safe-config.sh /path/to/docker.env
# =============================================================================

set -euo pipefail

ENV_FILE="${1:-deploy/.env.prod.example}"

if [[ ! -f "${ENV_FILE}" ]]; then
    if [[ -f "docker.env" ]]; then
        ENV_FILE="docker.env"
    else
        echo "ERROR: Environment file '${ENV_FILE}' not found." >&2
        exit 1
    fi
fi

echo "=== SentinelAI Production Stack Configuration (Sanitized) ==="
echo "Loaded Environment Template: ${ENV_FILE}"
echo "------------------------------------------------------------"

# Generate docker compose config in JSON and sanitize with python
docker compose --env-file "${ENV_FILE}" -f docker-compose.prod.yml config --format json | python3 -c '
import sys, json, re

try:
    cfg = json.load(sys.stdin)
except Exception as e:
    sys.exit(f"Failed to parse compose configuration: {e}")

SENSITIVE_KEYS = {
    "SECRET_KEY", "POSTGRES_PASSWORD", "DATABASE_URL",
    "SMTP_PASSWORD", "GROQ_API_KEY", "OPENAI_API_KEY"
}

services = cfg.get("services", {})
for svc_name, svc in services.items():
    env = svc.get("environment", {})
    if isinstance(env, dict):
        for k in env:
            if any(s in k.upper() for s in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
                env[k] = "[REDACTED]"
            elif k.upper() == "DATABASE_URL":
                # Redact password part of database url
                env[k] = re.sub(r"://([^:]+):([^@]+)@", r"://\1:[REDACTED]@", str(env[k]))

print(json.dumps(cfg, indent=2))
'

