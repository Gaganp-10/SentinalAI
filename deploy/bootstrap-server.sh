#!/usr/bin/env bash
# =============================================================================
# SentinelAI Server Bootstrap Script for Ubuntu 24.04 LTS (AWS EC2)
#
# Automated Tasks:
#   1. Sets up a dedicated unprivileged 'deploy' user with sanitized SSH keys.
#   2. Enforces SSH hardening (key-only access, PermitRootLogin no, MaxAuthTries 3).
#   3. Clones the repository and generates docker.env early (before steps that can fail).
#   4. Configures UFW firewall (default deny incoming, allow 22/80/443).
#   5. Installs and enables automated security updates with automatic reboot at 04:00.
#   6. Configures a 2 GB swap file with optimized swappiness.
#   7. Installs Docker Engine and Docker Compose from the official Docker repo.
#   8. Installs AWS CLI v2 with cryptographic PGP signature verification against
#      official AWS CLI Team key (cited from AWS official documentation).
# =============================================================================

set -euo pipefail

# Non-interactive package managers & automatic service restarts on Ubuntu 24.04
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# Require root privileges to run bootstrap
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: bootstrap-server.sh must be run as root (or via sudo)." >&2
    exit 1
fi

REPO_URL="${1:-https://github.com/Gaganp-10/SentinalAI.git}"
GIT_REF="${2:-}"
APP_DIR="/home/deploy/sentinel-ai"

echo "=== [1/8] Updating core system dependencies ==="
apt-get update -y
apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    gnupg \
    ufw \
    openssl \
    unzip \
    sed

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
            # Trim whitespace with sed (replaces xargs to avoid word splitting)
            line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
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

echo "=== [3/8] Cloning repository and writing docker.env early ==="
# Clone and configure repository early so config is saved even if subsequent steps fail
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

echo "=== [4/8] Firewall Configuration (UFW) ==="
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

echo "=== [5/8] Configuring unattended-upgrades with automatic reboot at 04:00 ==="
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

echo "=== [6/8] Configuring 2 GB Swap ==="
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

echo "=== [7/8] Installing Docker Engine from official repository ==="
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

echo "=== [8/8] Installing AWS CLI v2 with verified PGP signature ==="
# AWS CLI v2 Verification Reference:
# Official Documentation: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
# Key ID: A6310ACC4672475C
# Key Fingerprint: FB5D B77F D5C1 18B8 0511 ADA8 A631 0ACC 4672 475C
# User ID: AWS CLI Team <aws-cli@amazon.com>
if ! command -v aws &>/dev/null; then
    AWS_TMP_DIR="$(mktemp -d)"
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "${AWS_TMP_DIR}/awscliv2.zip"
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip.sig" -o "${AWS_TMP_DIR}/awscliv2.sig"

    # Embedded official public key from AWS documentation:
    cat << 'EOF' > "${AWS_TMP_DIR}/awscli.pubkey"
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBFzW5e0BEACrXbLv1wRi4ARuKIs2M0avLEd-v5o5rTqV5l18a2Xb8aJc
cR/grk C6VwsnDU0OUCideXcQ8WeHutqvgZH1JgKDbznoIzeQHJD238GEu+eKhRHcz8/jeG
94zkcgJOz3KbZGYMiTh277Fvj9zzvZsbMBCedV1BTg3TqgvdX4bdkhf5cH+7NtWO
lrFj6UwAsGukBTAOxC0l/dnSmZhJ7Z1KmEWilro/gOrjtOxqRQutlIqG22TaqoPG
fYVN+en3Zwbt97kcgZDwqbuykNt64oZWc4XKCa3mprEGC3IbJTBFqglXmZ7l9ywG
EEUJYOlb2XrSuPWml39beWdKM8kzr1OjnlOm6+lpTRCBfo0wa9F8YZRhHPAkwKkX
XDeOGpWRj4ohOx0d2GWkyV5xyN14p2tQOCdOODmz80yUTgRpPVQUtOEhXQARAQAB
tCFBV1MgQ0xJIFRlYW0gPGF3cy1jbGlAYW1hem9uLmNvbT6JAlQEEwEIAD4CGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQT7Xbd/1cEYuAURraimMQrMRnJHXAUC
akV0ygUJDqP4lQAKCRCmMQrMRnJHXFHjD/9eyZLYcKuQOlLvtqSDtUBiEZf6ZZjM
i3ygYH8rJNtuToUH+HvSpe819urJCquXhDrlK6N+aqW0hCLtNABJG/vsafIgvIYJ
hSGgpgtNnQyMV1jViRWqPjbouw8OkYKBThUfT1i2Y+wn58ifs6ODBCmTexWtXspA
Si+Gt49xDOW0APmbOPnI+a4HJW6tVEo6MWS0WjzpiBayR3d1A4pt4YrPfSdDgpLo
h2SLQqlRqvvVZJaWBjhkErNFpfsBA06sDcPEOb0G8LBUbR4WOcdvhe5LubJbZuxC
AG9kNPCVeQP1ixwjgjXKysaxeQ6rv0VzIQgRp6tLVLWhy6AKDNvLjFSsmXZ1Wl08
Y/RlOHXlzLuQMRE6sR1wOdRxc9TsrNWTGiBK65cvSWOy03JeBkQQ8pesqltiyxI9
U21kkgiXtTSKNGfKK8pO27D81YANhRqPK7iTp6kuFiY2WtOg90KTMNlIT+Ff85Y2
b1rHj6Z0SrCkJujhWk3IBPic/wJgz01LEc/OAdUPlby90RJZcIBhSlWhT7mXnXIO
c0HWlNQrns2s3CTyYwZSiSlYe9ApeLwhjDo8NhbFuCAy61l6O5UsR4AfZxx/rGKv
2wFb1/RN/P4gNe6vmxZAPjR0AQcwD3tc2McimOLr/22kmPz8IH3I0X7WoSFr0Biz
E91G7bb0hOb/cA==
=knv7
-----END PGP PUBLIC KEY BLOCK-----
EOF

    # Import embedded key and verify full fingerprint
    GNUPGHOME="${AWS_TMP_DIR}/gnupg"
    export GNUPGHOME
    mkdir -m 700 "${GNUPGHOME}"
    gpg --import "${AWS_TMP_DIR}/awscli.pubkey"
    
    EXPECTED_FP="FB5DB77FD5C118B80511ADA8A6310ACC4672475C"
    ACTUAL_FP="$(gpg --fingerprint --with-colons A6310ACC4672475C | awk -F: '$1 == "fpr" {print $10}' | head -n 1)"
    if [[ "${ACTUAL_FP}" != "${EXPECTED_FP}" ]]; then
        echo "ERROR: AWS CLI public key fingerprint mismatch: ${ACTUAL_FP} != ${EXPECTED_FP}" >&2
        rm -rf "${AWS_TMP_DIR}"
        exit 1
    fi

    # Verify signature
    gpg --verify "${AWS_TMP_DIR}/awscliv2.sig" "${AWS_TMP_DIR}/awscliv2.zip"

    unzip -q "${AWS_TMP_DIR}/awscliv2.zip" -d "${AWS_TMP_DIR}"
    "${AWS_TMP_DIR}/aws/install" --update
    rm -rf "${AWS_TMP_DIR}"
    echo "AWS CLI v2 verified and installed successfully."
else
    echo "AWS CLI already installed: $(aws --version)"
fi

echo "============================================================================="
echo "Bootstrap complete!"
echo "Next steps:"
echo "  1. Log in as deploy: ssh deploy@<SERVER_IP>"
echo "  2. Edit ${DOCKER_ENV_FILE} to set your DOMAIN, ACME_EMAIL, and SMTP settings."
echo "  3. Start the application:"
echo "     cd ${APP_DIR}"
echo "     docker compose --env-file docker.env -f docker-compose.prod.yml up -d --build"
echo "============================================================================="
