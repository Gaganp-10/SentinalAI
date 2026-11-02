#!/usr/bin/env bash
# =============================================================================
# SentinelAI Server Bootstrap Script for Ubuntu 24.04 LTS (AWS EC2)
#
# Automated Tasks:
#   1. Sets up a dedicated unprivileged 'deploy' user with SSH key authentication.
#   2. Enforces SSH key-only authentication (disables password logins).
#   3. Installs and enables automated security updates (unattended-upgrades).
#   4. Configures a 2 GB swap file with optimized swappiness.
#   5. Installs Docker Engine and Docker Compose from the official Docker repo.
#   6. Clones the application repository into /home/deploy/sentinel-ai.
#   7. Securely generates random POSTGRES_PASSWORD and SECRET_KEY into docker.env
#      with chmod 600 without printing them to console or logs.
# =============================================================================

set -euo pipefail

# Require root privileges to run bootstrap
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: bootstrap-server.sh must be run as root (or via sudo)." >&2
    exit 1
fi

REPO_URL="${1:-https://github.com/Gaganp-10/security-vulnerability-decoder-and-fixer.git}"
APP_DIR="/home/deploy/sentinel-ai"

echo "=== [1/7] Updating system packages ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    gnupg \
    ufw \
    openssl

echo "=== [2/7] Creating deploy user and configuring SSH key authentication ==="
if ! id -u deploy &>/dev/null; then
    useradd -m -s /bin/bash deploy
    echo "Created user 'deploy'."
fi

# Grant passwordless sudo for administration
echo "deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/deploy
chmod 0440 /etc/sudoers.d/deploy

# Configure SSH key for deploy user
mkdir -p /home/deploy/.ssh
if [[ -f /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
    echo "Copied root authorized_keys to /home/deploy/.ssh/authorized_keys."
elif [[ -f /home/ubuntu/.ssh/authorized_keys ]]; then
    cp /home/ubuntu/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
    echo "Copied ubuntu authorized_keys to /home/deploy/.ssh/authorized_keys."
fi
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
if [[ -f /home/deploy/.ssh/authorized_keys ]]; then
    chmod 600 /home/deploy/.ssh/authorized_keys
fi

# Enforce SSH key-only authentication
cat << 'EOF' > /etc/ssh/sshd_config.d/60-hardening.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
EOF
systemctl reload ssh || systemctl reload sshd || true
echo "SSH password authentication disabled; key-only access enforced."

echo "=== [3/7] Configuring unattended-upgrades (Automatic Security Patches) ==="
apt-get install -y unattended-upgrades apt-listchanges
cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
echo "Unattended security upgrades enabled."

echo "=== [4/7] Configuring 2 GB Swap ==="
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
    # Set swappiness to 10 for server workload
    cat << 'EOF' > /etc/sysctl.d/99-swap.conf
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
    sysctl --system
    echo "2 GB swap file activated."
else
    echo "Swap is already active."
fi

echo "=== [5/7] Installing Docker from official repository ==="
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

echo "=== [6/7] Setting up repository ==="
if [[ ! -d "${APP_DIR}" ]]; then
    su - deploy -c "git clone '${REPO_URL}' '${APP_DIR}'"
    echo "Cloned repository into ${APP_DIR}."
else
    echo "Directory ${APP_DIR} already exists. Skipping clone."
fi

echo "=== [7/7] Generating secure production credentials (chmod 600) ==="
DOCKER_ENV_FILE="${APP_DIR}/docker.env"

if [[ ! -f "${DOCKER_ENV_FILE}" ]]; then
    # Generate cryptographic random values without printing them (64-char hex strings)
    RANDOM_PG_PASS="$(openssl rand -hex 32)"
    RANDOM_SECRET_KEY="$(openssl rand -hex 32)"

    # Write directly with strict umask to prevent race condition
    (
        umask 077
        cat << EOF > "${DOCKER_ENV_FILE}"
# Production Docker Environment - Generated by bootstrap-server.sh
# Sensitive credentials file - permissions restricted to 600
# NOTE: Set DOMAIN and ACME_EMAIL to your actual production domain and email.
DOMAIN=yourdomain.com
ACME_EMAIL=admin@yourdomain.com
TLS_INTERNAL=

ENV=production
FRONTEND_URL=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com

POSTGRES_SERVER=db
POSTGRES_DB=security_scanner
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=${RANDOM_PG_PASS}
DATABASE_URL=postgresql://sentinel:${RANDOM_PG_PASS}@db:5432/security_scanner

SECRET_KEY=${RANDOM_SECRET_KEY}

EMAIL_BACKEND=smtp
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_USE_TLS=true
PASSWORD_RESET_EXPIRE_MINUTES=30

AI_PROVIDER=template

ALLOW_SIGNUP=true
MAX_PROJECTS_PER_USER=50
MAX_DAILY_UPLOADS_PER_USER=100
MAX_DAILY_UPLOAD_MB_PER_USER=500
EOF
    )
    chown deploy:deploy "${DOCKER_ENV_FILE}"
    chmod 600 "${DOCKER_ENV_FILE}"
    echo "Generated production docker.env with random credentials (chmod 600)."
else
    echo "${DOCKER_ENV_FILE} already exists. Retaining existing configuration."
fi

# Ensure backup and restore scripts have execute permissions
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
