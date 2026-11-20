# SentinelAI Production Deployment & Operations Runbook

**Target Platform:** Single AWS EC2 Instance (`t3.medium`, 2 vCPU, 4 GiB RAM, 30 GiB gp3 EBS) running Ubuntu 24.04 LTS.
**Architecture:** Caddy Reverse Proxy (HTTPS 443 / HTTP 80) $\rightarrow$ Internal Frontend (Nginx SPA) $\rightarrow$ Internal Backend (FastAPI) $\rightarrow$ Internal Database (PostgreSQL 15).

---

## Architecture & Security Boundary

```
  Internet
     │
     ▼ [Ports 80, 443 only]
┌────────────────────────────────────────────────────────────────────────┐
│ Caddy 2.8 Reverse Proxy & TLS (Automatic ACME / Let's Encrypt)        │
│   - HSTS, X-Content-Type-Options: nosniff, Referrer-Policy             │
│   - Frame-Ancestors CSP (anti-clickjacking)                            │
│   - 55 MB Request Body Limit                                           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Internal Docker Network (isolated)
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
┌───────────────────────────────┐               ┌───────────────────────┐
│ Frontend (Nginx SPA)          │               │ Backend (FastAPI)     │
│   - Internal port 80 only     │ ──/api/───►   │   - Internal port 8000│
│   - React 19 Client Assets    │               │   - Read-only root fs │
│   - cap_drop: ALL             │               │   - tmpfs /tmp        │
│   - no-new-privileges: true   │               │   - Writable uploads  │
└───────────────────────────────┘               │   - cap_drop: ALL     │
                                                └───────────┬───────────┘
                                                            │ Internal port 5432
                                                            ▼
                                                ┌───────────────────────┐
                                                │ Database (PostgreSQL) │
                                                │   - Internal port 5432│
                                                │   - Named volume data │
                                                │   - cap_drop: ALL     │
                                                │   - no-new-privileges │
                                                └───────────────────────┘
```

---

## 1. First-Time Server Deployment

### Step 1.1: Launch AWS EC2 Instance (NOT RUN - AWS Console / CLI)
1. Launch an EC2 instance:
   - **AMI:** Ubuntu Server 24.04 LTS (HVM), SSD Volume Type (64-bit x86).
   - **Instance Type:** `t3.medium` (2 vCPU, 4 GiB Memory).
   - **Storage:** 30 GiB gp3 SSD (encrypted with AWS KMS default key).
2. **Security Group Inbound Rules:**
   - `TCP 22` — SSH (restrict to your office/admin IP).
   - `TCP 80` — HTTP (0.0.0.0/0).
   - `TCP 443` — HTTPS (0.0.0.0/0).
   - *All other inbound ports blocked (PostgreSQL 5432 and Backend 8000 are never exposed).*
3. **Elastic IP:** Allocate an Elastic IP and associate it with the instance to prevent IP changes on reboot.

### Step 1.2: Configure DNS
Create a DNS **A record** pointing your domain (e.g., `sentinel.yourdomain.com`) to the Elastic IP.

### Step 1.3: Run the Server Bootstrap Script
SSH into the server as `ubuntu`:
```bash
ssh -i /path/to/your-key.pem ubuntu@<SERVER_ELASTIC_IP>
```

Run the automated bootstrap script as `root`:
```bash
curl -fsSL https://raw.githubusercontent.com/Gaganp-10/security-vulnerability-decoder-and-fixer/main/deploy/bootstrap-server.sh -o bootstrap-server.sh
sudo bash bootstrap-server.sh
```

**What the bootstrap script automates:**
- Creates a dedicated `deploy` system user with passwordless `sudo` and copies SSH keys.
- Disables SSH password authentication (`PasswordAuthentication no`).
- Configures automated daily security updates via `unattended-upgrades`.
- Allocates and activates a `2 GB swap file` (`/swapfile`, `vm.swappiness=10`).
- Installs Docker Engine and Docker Compose from the official Docker repository.
- Clones the repository to `/home/deploy/sentinel-ai`.
- Generates cryptographically secure, non-default `POSTGRES_PASSWORD` and `SECRET_KEY` into `docker.env` with `chmod 600` permissions.

### Step 1.4: Configure Environment Variables
Log in as the `deploy` user:
```bash
ssh deploy@<SERVER_ELASTIC_IP>
cd /home/deploy/sentinel-ai
nano docker.env
```
Ensure the following variables are configured:
```ini
DOMAIN=sentinel.yourdomain.com
ACME_EMAIL=admin@yourdomain.com
TLS_INTERNAL=

ENV=production
FRONTEND_URL=https://sentinel.yourdomain.com
ALLOWED_ORIGINS=https://sentinel.yourdomain.com

EMAIL_BACKEND=smtp
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@sentinel.yourdomain.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=noreply@sentinel.yourdomain.com
SMTP_USE_TLS=true
ACCESS_TOKEN_EXPIRE_MINUTES=120

# Production Access & Abuse Controls
ALLOW_SIGNUP=false
GOOGLE_AUTH_ALLOWLIST=
MAX_PROJECTS_PER_USER=50
MAX_DAILY_UPLOADS_PER_USER=100
MAX_DAILY_UPLOAD_MB_PER_USER=500
MAX_USER_STORAGE_MB=500
```

### Step 1.5: Start the Production Stack
```bash
docker compose --env-file docker.env -f docker-compose.prod.yml up -d --build
```

Verify service health:
```bash
docker compose --env-file docker.env -f docker-compose.prod.yml ps
```
All four services (`caddy`, `frontend`, `backend`, `db`) should report `healthy` or `running`.

### Step 1.6: Create Initial Admin User
Because `ALLOW_SIGNUP=false` is enforced in production, create the initial administrative account using the CLI script (which prompts securely for the password without echoing):
```bash
./deploy/create-user.sh --username admin --email admin@yourdomain.com
```

### Database Architecture & Schema Migrations
Database schema creation and column migrations run automatically and idempotently on backend startup via `backend/database/migration.py` using SQLAlchemy reflection and direct SQL. No external migration framework (such as Alembic) is used.

---

## 2. Updating & Deploying New Versions

To deploy code updates with zero data loss:
```bash
cd /home/deploy/sentinel-ai

# 1. Fetch latest changes
git pull origin main

# 2. Build updated images
docker compose -f docker-compose.prod.yml build

# 3. Apply updates (Compose replaces changed containers seamlessly)
docker compose -f docker-compose.prod.yml up -d

# 4. Verify health
docker compose -f docker-compose.prod.yml ps
curl -fsSL https://${DOMAIN}/api/health
```

---

## 3. Rollback Procedures

### Code Rollback
If a newly deployed release introduces issues:
```bash
# 1. Check git log to find the previous stable commit tag or SHA
git log --oneline -n 5

# 2. Revert working tree to the stable release
git checkout <PREVIOUS_COMMIT_SHA>

# 3. Rebuild and restart containers
docker compose -f docker-compose.prod.yml up -d --build
```

### Database & Data Rollback
To restore from a backup:
```bash
# 1. Always verify backup integrity first using the scratch-test mode:
./deploy/restore.sh --scratch-test /home/deploy/backups/db_YYYYMMDD_HHMMSSZ.dump

# 2. Perform production restore:
./deploy/restore.sh \
    /home/deploy/backups/db_YYYYMMDD_HHMMSSZ.dump \
    /home/deploy/backups/uploads_YYYYMMDD_HHMMSSZ.tar.gz
```

---

## 4. Monitoring, Health Checks & Logs

### Health Check Endpoints
- **Application Health:** `https://${DOMAIN}/api/health`
  - Returns `{"status":"ok"}` with HTTP 200.
  - Used by AWS Route53 or external uptime monitors (UptimeRobot, BetterUptime).

### Container Logs
Inspect logs with timestamped log rotation:
```bash
# Stream all logs
docker compose -f docker-compose.prod.yml logs -f --tail=100

# Stream specific service
docker compose -f docker-compose.prod.yml logs -f caddy
docker compose -f docker-compose.prod.yml logs -f backend
docker compose -f docker-compose.prod.yml logs -f db
```

### Resource Utilization
```bash
docker stats --no-stream
```

---

## 5. Automated Backups, systemd Timer & S3 Offsite Sync

### Automated Backups via systemd Timer

SentinelAI uses a native `systemd` service and timer for reliable, randomized, and hardened backup execution.

#### Step 5.1: Install and Enable the systemd Timer
As root (or with `sudo`):
```bash
# 1. Copy unit and timer definitions to systemd directory
sudo cp /home/deploy/sentinel-ai/deploy/sentinel-backup.service /etc/systemd/system/
sudo cp /home/deploy/sentinel-ai/deploy/sentinel-backup.timer /etc/systemd/system/

# 2. Reload systemd daemon
sudo systemctl daemon-reload

# 3. Enable and start the backup timer
sudo systemctl enable --now sentinel-backup.timer

# 4. Verify timer is active and scheduled
sudo systemctl list-timers --all | grep sentinel-backup
```

The output will confirm next execution at `02:00 UTC` with a randomized jitter of up to 30 minutes (`RandomizedDelaySec=1800`) to avoid load spikes.

#### Step 5.2: Configure Optional S3 Offsite Sync
To sync backups to AWS S3, create `/home/deploy/sentinel-ai/backup.env` (owned by `deploy:deploy`, `chmod 600`):
```bash
cat << 'EOF' > /home/deploy/sentinel-ai/backup.env
S3_BUCKET=your-private-sentinel-backup-bucket
EOF
chown deploy:deploy /home/deploy/sentinel-ai/backup.env
chmod 600 /home/deploy/sentinel-ai/backup.env
```

### AWS S3 & IAM Least-Privilege Architecture

#### 1. EC2 Instance Profile (Write-Only Append Policy)
Attach an IAM role to the EC2 instance using the restricted policy defined in `deploy/s3-backup-policy.json`.
- **Allowed Actions:** `s3:PutObject` and `s3:ListBucket` (prefix-scoped).
- **Prohibited Actions:** `s3:GetObject` and `s3:DeleteObject` are explicitly excluded from the instance profile. This ensures that even in the event of an EC2 compromise or ransomware attack, the attacker cannot delete, alter, or exfiltrate historic offsite backups.

#### 2. Separate Admin Disaster Recovery Policy
The `deploy/s3-restore-policy.json` contains `s3:GetObject` and `s3:DeleteObject` permissions and is attached only to administrative IAM roles or temporary recovery credentials when executing an offsite restore.

#### 3. S3 Bucket Hardening Checklist
Configure your AWS S3 backup bucket with the following baseline protections:
1. **Block Public Access:** Enable all four Amazon S3 Block Public Access settings at both the bucket and account level.
2. **Bucket Versioning:** Enable Versioning on the bucket. If an object is overwritten or marked deleted, previous versions remain immutable.
3. **Lifecycle Rule (30-day retention):** Create an S3 Lifecycle Rule targeting the `sentinel-backups/` prefix:
   - Expire current versions after 30 days.
   - Permanently delete noncurrent versions after 30 days.
   - Delete expired object delete markers and abort incomplete multipart uploads after 7 days.
4. **Server-Side Encryption (SSE):** Enforce default encryption using SSE-S3 (`AES256`) or AWS KMS (`aws:kms`). `backup.sh` automatically passes `--sse AES256` during `aws s3 cp`.

---

## 6. Stopping the Instance to Save Cost

When the instance is not in active use (e.g., weekends, non-work hours):

### Step 6.1: Gracefully Stop Containers
```bash
cd /home/deploy/sentinel-ai
docker compose -f docker-compose.prod.yml stop
```

### Step 6.2: Stop the EC2 Instance (NOT RUN - AWS Console / CLI)
From your local terminal:
```bash
aws ec2 stop-instances --instance-ids <YOUR_INSTANCE_ID>
```
- **Data Persistence:** All PostgreSQL databases, files, and configurations reside on the persistent EBS root/data volume and survive instance stops.
- **Cost Reduction:** Compute (vCPU and RAM) charges drop to \$0 while stopped.
- **Elastic IP Note:** AWS charges \$0.005/hr (\$3.60/month) for an unattached or stopped-instance Elastic IP. If stopping for extended durations, consider disassociating and releasing the Elastic IP.

### Step 6.3: Starting Up Again
```bash
aws ec2 start-instances --instance-ids <YOUR_INSTANCE_ID>
```
Because every service is configured with `restart: unless-stopped`, Docker will automatically boot Caddy, Frontend, Backend, and Database on instance startup.

---

## 7. Complete Teardown & Decommissioning

To permanently remove the application and purge all data:

```bash
# 1. Stop and delete containers AND volumes (wipes PostgreSQL and Uploads)
docker compose -f docker-compose.prod.yml down -v

# 2. Terminate EC2 instance and release Elastic IP (AWS Console / CLI)
aws ec2 terminate-instances --instance-ids <YOUR_INSTANCE_ID>
aws ec2 release-address --allocation-id <YOUR_ALLOCATION_ID>
```
