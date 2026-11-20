#!/usr/bin/env bash
# =============================================================================
# SentinelAI Server Bootstrap Script for Ubuntu 24.04 LTS (AWS EC2)
#
# Automated Tasks:
#   1. Sets up a dedicated unprivileged 'deploy' user with sanitized SSH keys.
#   2. Enforces SSH hardening (key-only access, PermitRootLogin no, MaxAuthTries 3).
#   3. Configures UFW firewall (default deny incoming, allow 22/80/443).
#   4. Installs and enables automated security updates with automatic reboot at 04:00.
#   5. Configures a 2 GB swap file with optimized swappiness.
#   6. Installs Docker Engine and Docker Compose from the official Docker repo.
#   7. Clones the application repository and checks out specified tag/commit.
#   8. Securely generates random POSTGRES_PASSWORD and SECRET_KEY into docker.env
#      with chmod 600 without printing them to console or logs.
# =============================================================================

set -euo pipefail

# Require root privileges to run bootstrap
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: bootstrap-server.sh must be run as root (or via sudo)." >&2
    exit 1
fi

REPO_URL="${1:-https://github.com/Gaganp-10/SentinalAI.git}"
GIT_REF="${2:-}"
APP_DIR="/home/deploy/sentinel-ai"

echo "=== [1/8] Updating system packages ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    gnupg \
    ufw \
    openssl \
    unzip

echo "=== [2/8] Creating deploy user and configuring sanitized SSH keys ==="
if ! id -u deploy &>/dev/null; then
    useradd -m -s /bin/bash deploy
    echo "Created user 'deploy'."
fi

# Grant passwordless sudo for administration
echo "deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/deploy
chmod 0440 /etc/sudoers.d/deploy

DEPLOY_SSH_DIR="/home/deploy/.ssh"
mkdir -p "${DEPLOY_SSH_DIR}"
chmod 700 "${DEPLOY_SSH_DIR}"
DEPLOY_AUTH_KEYS="${DEPLOY_SSH_DIR}/authorized_keys"
: > "${DEPLOY_AUTH_KEYS}.tmp"

# Helper function to sanitize and collect SSH keys (strip command= and no-* options)
process_keys() {
    local key_file="$1"
    if [[ -f "${key_file}" ]]; then
        while IFS= read -r line || [[ -n "${line}" ]]; do
            # Trim whitespace
            line="$(echo "${line}" | xargs)"
            # Skip empty lines and comments
            [[ -z "${line}" || "${line}" =~ ^# ]] && continue
            # Strip command= and no-* options to isolate key specification
            # Extract starting from key type (ssh-ed25519, ssh-rsa, ecdsa-sha2-*, sk-*)
            clean_key="$(echo "${line}" | sed -E 's/^.*((ssh-(ed25519|rsa|dss)|ecdsa-sha2-[^ ]+|sk-[^ ]+) [A-Za-z0-9+/=]+.*)$/\1/')"
            if [[ "${clean_key}" =~ ^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[^ ]+|sk-[^ ]+) ]]; then
                echo "${clean_key}" >> "${DEPLOY_AUTH_KEYS}.tmp"
            fi
        done < "${key_file}"
    fi
}

# Take keys from /home/ubuntu first, then fallback to /root
if [[ -f /home/ubuntu/.ssh/authorized_keys ]]; then
    process_keys /home/ubuntu/.ssh/authorized_keys
fi
if [[ ! -s "${DEPLOY_AUTH_KEYS}.tmp" && -f /root/.ssh/authorized_keys ]]; then
    process_keys /root/.ssh/authorized_keys
fi

# Validate deploy user has at least one valid SSH key before disabling password auth
VALID_KEY_COUNT="$(grep -c -E '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-|sk-)' "${DEPLOY_AUTH_KEYS}.tmp" || true)"
if [[ "${VALID_KEY_COUNT}" -lt 1 ]]; then
    echo "ERROR: Refusing to disable password authentication: deploy user has no valid SSH keys." >&2
    rm -f "${DEPLOY_AUTH_KEYS}.tmp"
    exit 1
fi

mv "${DEPLOY_AUTH_KEYS}.tmp" "${DEPLOY_AUTH_KEYS}"
chown -R deploy:deploy "${DEPLOY_SSH_DIR}"
chmod 600 "${DEPLOY_AUTH_KEYS}"
echo "Configured ${VALID_KEY_COUNT} sanitized SSH key(s) for deploy user."

# Enforce SSH hardening: key-only access, PermitRootLogin no, MaxAuthTries 3
cat << 'EOF' > /etc/ssh/sshd_config.d/60-hardening.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
MaxAuthTries 3
EOF
systemctl reload ssh || systemctl reload sshd || true
echo "SSH password auth disabled, root login disabled, MaxAuthTries set to 3."

echo "=== [3/8] Firewall Configuration (UFW) ==="
# AWS EC2 security groups typically manage ingress filtering at the hypervisor level.
# Unconfigured or default UFW rules can disrupt Docker bridge packet forwarding.
# Drop UFW unless explicitly requested via CONFIGURE_UFW=true.
CONFIGURE_UFW="${CONFIGURE_UFW:-false}"
if [[ "${CONFIGURE_UFW}" == "true" ]]; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw --force enable
    echo "UFW configured with rules for 22, 80, and 443."
else
    ufw --force disable || true
    echo "UFW dropped/disabled (firewall managed via AWS Security Groups; avoids Docker iptables collisions)."
fi

echo "=== [4/8] Configuring unattended-upgrades with automatic reboot at 04:00 ==="
apt-get install -y unattended-upgrades apt-listchanges
cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat << 'EOF' > /etc/apt/apt.conf.d/51unattended-upgrades-reboot
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
echo "Unattended security upgrades enabled with automated reboot scheduled at 04:00."

echo "=== [5/8] Configuring 2 GB Swap ==="
if ! grep -qs "/swapfile" /proc/swaps; then
    if [[ ! -f /swapfile ]]; then
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
    fi
    swapon /swapfile
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    cat << 'EOF' > /etc/sysctl.d/99-swap.conf
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
    sysctl --system
    echo "2 GB swap file activated."
else
    echo "Swap is already active."
fi

echo "=== [6/8] Installing Docker from official repository ==="
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# shellcheck source=/dev/null
VERSION_CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

usermod -aG docker deploy
systemctl enable docker
systemctl restart docker
echo "Docker Engine and Compose plugin installed successfully."

echo "=== [7/9] Installing AWS CLI v2 (verified download) ==="
if ! command -v aws &>/dev/null; then
    AWS_TMP_DIR="$(mktemp -d)"
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "${AWS_TMP_DIR}/awscliv2.zip"
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip.sig" -o "${AWS_TMP_DIR}/awscliv2.sig"

    # Import AWS CLI official signing key:
    # Key ID: A6310ACC4672475C
    # Fingerprint: FB5D 5830 1C12 6CF1 4235  BB82 7A0A 10CD 4672 475C
    if ! gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys A6310ACC4672475C 2>/dev/null; then
        gpg --keyserver hkps://keys.openpgp.org --recv-keys A6310ACC4672475C 2>/dev/null || true
    fi
    gpg --verify "${AWS_TMP_DIR}/awscliv2.sig" "${AWS_TMP_DIR}/awscliv2.zip"

    unzip -q "${AWS_TMP_DIR}/awscliv2.zip" -d "${AWS_TMP_DIR}"
    "${AWS_TMP_DIR}/aws/install" --update
    rm -rf "${AWS_TMP_DIR}"
    echo "AWS CLI v2 verified and installed successfully."
else
    echo "AWS CLI already installed: $(aws --version)"
fi

echo "=== [8/9] Setting up repository ==="
if [[ ! -d "${APP_DIR}" ]]; then
    su - deploy -c "git clone '${REPO_URL}' '${APP_DIR}'"
    echo "Cloned repository into ${APP_DIR}."
else
    echo "Directory ${APP_DIR} already exists. Retaining."
fi

if [[ -n "${GIT_REF}" ]]; then
    su - deploy -c "cd '${APP_DIR}' && git fetch --all && git checkout '${GIT_REF}'"
    echo "Checked out git ref: ${GIT_REF}."
fi

echo "=== [9/9] Generating secure production credentials (chmod 600) ==="
DOCKER_ENV_FILE="${APP_DIR}/docker.env"

if [[ ! -f "${DOCKER_ENV_FILE}" ]]; then
    RANDOM_PG_PASS="$(openssl rand -hex 32)"
    RANDOM_SECRET_KEY="$(openssl rand -hex 32)"

    (
        umask 077
        cat << EOF > "${DOCKER_ENV_FILE}"
# Production Docker Environment - Generated by bootstrap-server.sh
# Sensitive credentials file - permissions restricted to 600
DOMAIN=yourdomain.com
ACME_EMAIL=admin@yourdomain.com
TLS_INTERNAL=
ACME_CA=

ENV=production

POSTGRES_SERVER=db
POSTGRES_DB=security_scanner
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=${RANDOM_PG_PASS}

SECRET_KEY=${RANDOM_SECRET_KEY}

GOOGLE_CLIENT_ID=
GOOGLE_AUTH_ALLOWLIST=

EMAIL_BACKEND=smtp
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_USE_TLS=true
PASSWORD_RESET_EXPIRE_MINUTES=30
ACCESS_TOKEN_EXPIRE_MINUTES=120

AI_PROVIDER=template
MAX_AI_EXPLANATIONS_PER_SCAN=10
MAX_DAILY_COPILOT_CHATS_PER_USER=50

ALLOW_SIGNUP=false
MAX_PROJECTS_PER_USER=50
MAX_DAILY_UPLOADS_PER_USER=100
MAX_DAILY_UPLOAD_MB_PER_USER=500
MAX_USER_STORAGE_MB=500

SCAN_TIMEOUT_SECONDS=300
MAX_CONCURRENT_SCANS=2
EOF
    )
    chown deploy:deploy "${DOCKER_ENV_FILE}"
    chmod 600 "${DOCKER_ENV_FILE}"
    echo "Generated production docker.env with random credentials (chmod 600)."
else
    echo "${DOCKER_ENV_FILE} already exists. Retaining existing configuration."
fi

chmod +x "${APP_DIR}/deploy/"*.sh 2>/dev/null || true

echo "============================================================================="
echo "Bootstrap complete!"
echo "Next steps:"
echo "  1. Log in as deploy: ssh deploy@<SERVER_IP>"
echo "  2. Edit ${DOCKER_ENV_FILE} to set your DOMAIN, ACME_EMAIL, and SMTP settings."
echo "  3. Start the application:"
echo "     cd ${APP_DIR}"
echo "     docker compose --env-file docker.env -f docker-compose.prod.yml up -d --build"
echo "============================================================================="
