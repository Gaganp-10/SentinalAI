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

## 1. First-Deploy Checklist for AWS EC2 (t3.medium)

Follow this step-by-step checklist to provision and launch SentinelAI on AWS from scratch:

### Checklist Overview

- [ ] **1. Provision EC2 Instance** (`t3.medium`, Ubuntu 24.04 LTS, gp3 30 GiB, IMDSv2 Required, Hop Limit 1)
- [ ] **2. Security Group Hardening** (Port 80 & 443 open to `0.0.0.0/0`, Port 22 open **only** to `<ADMIN_IP>/32`)
- [ ] **3. Elastic IP Allocation & Association**
- [ ] **4. DNS A Record** (`sentinel.yourdomain.com` pointing to Elastic IP)
- [ ] **5. Bootstrap Server Execution** (`bootstrap-server.sh` as root)
- [ ] **6. TLS Staging Validation** (ACME Staging endpoint first to avoid Let's Encrypt rate limits)
- [ ] **7. Switch to Production TLS & Docker Compose Up**
- [ ] **8. Initial Administrative User Creation** (`create-user.sh`)
- [ ] **9. Install & Enable Automated Backup Timer** (`sentinel-backup.timer` + failure handler)
- [ ] **10. Trigger Backup & Check Journal** (`systemctl start sentinel-backup.service`)
- [ ] **11. Test Scratch Restore Drill** (`restore.sh --scratch-test`)
- [ ] **12. Rollback Verification** (Pre-restore dump & disaster recovery procedure)

---

### Step 1.1: Provision AWS EC2 Instance (`t3.medium`)

Launch using AWS CLI (or AWS Console):
```bash
aws ec2 run-instances \
    --image-id resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --instance-type t3.medium \
    --key-name your-ssh-key \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3","Encrypted":true}}]' \
    --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=sentinel-ai-prod}]'
```

> [!IMPORTANT]
> **IMDSv2 Enforced (`HttpTokens=required,HttpPutResponseHopLimit=1`):** Restricting the IMDS response hop limit to `1` ensures that even if an attacker executes an SSRF exploit within a container on the host, the metadata service packet cannot traverse the Docker bridge network, preventing IAM credential exfiltration.

### Step 1.2: Configure Security Group (Strict Inbound Filtering)
```bash
# Allow SSH strictly from your office/admin IP (replace with your IP)
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr <ADMIN_IP>/32

# Allow public inbound HTTP and HTTPS for Caddy TLS termination
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr 0.0.0.0/0
```
*(All other inbound ports blocked; database 5432 and backend 8000 are purely internal).*

### Step 1.3: Elastic IP Allocation & DNS A Record
1. Allocate and associate an Elastic IP:
   ```bash
   ALLOC_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
   aws ec2 associate-address --instance-id <INSTANCE_ID> --allocation-id "${ALLOC_ID}"
   ```
2. In Route53 or your DNS registrar, create an **A record**:
   - **Host:** `sentinel.yourdomain.com`
   - **Target / Value:** `<ELASTIC_IP>`
   - **TTL:** 300 seconds

### Step 1.4: Run Server Bootstrap Script
SSH into the server as `ubuntu`:
```bash
ssh -i /path/to/your-key.pem ubuntu@<ELASTIC_IP>
```
Run `bootstrap-server.sh` as root:
```bash
curl -fsSL https://raw.githubusercontent.com/Gaganp-10/SentinalAI/main/deploy/bootstrap-server.sh -o bootstrap-server.sh
sudo bash bootstrap-server.sh
```

### Step 1.5: Configure TLS ACME Staging First
Log in as `deploy`:
```bash
ssh deploy@<ELASTIC_IP>
cd /home/deploy/sentinel-ai
nano docker.env
```
Set your domain, email, and activate ACME staging first to prevent Let's Encrypt rate limits:
```ini
DOMAIN=sentinel.yourdomain.com
ACME_EMAIL=admin@yourdomain.com
# Test against Let's Encrypt staging first:
ACME_CA=acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

Start the stack:
```bash
docker compose --env-file docker.env -f docker-compose.prod.yml up -d --build
```

Check Caddy logs to confirm successful staging certificate validation:
```bash
docker compose --env-file docker.env -f docker-compose.prod.yml logs -f caddy
```

### Step 1.6: Switch to Production TLS & Docker Compose Up
Once staging certificate negotiation succeeds, remove the staging CA:
```bash
# In docker.env, comment out or blank ACME_CA:
ACME_CA=
```
Restart Caddy to obtain production Let's Encrypt certificates:
```bash
docker compose --env-file docker.env -f docker-compose.prod.yml restart caddy
docker compose --env-file docker.env -f docker-compose.prod.yml logs -f caddy
```

### Step 1.7: Create Initial Admin User
Because `ALLOW_SIGNUP=false` is enforced in production, create the initial administrative account:
```bash
./deploy/create-user.sh --username admin --email admin@yourdomain.com
```

### Step 1.8: Install Systemd Backup Units & Verify
```bash
# 1. Copy units to systemd
sudo cp deploy/sentinel-backup.service deploy/sentinel-backup.timer deploy/sentinel-backup-failure@.service /etc/systemd/system/

# 2. Configure backup environment (S3 bucket and optional healthcheck ping)
install -m 600 /dev/null /home/deploy/sentinel-ai/backup.env
cat << 'EOF' > /home/deploy/sentinel-ai/backup.env
S3_BUCKET=your-sentinel-backups-bucket
HC_PING_URL=https://hc-ping.com/your-uuid
EOF

# 3. Reload systemd and enable timer
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-backup.timer
systemctl list-timers sentinel-backup.timer

# 4. Trigger manual test run and inspect journal logs
sudo systemctl start sentinel-backup.service
journalctl -u sentinel-backup.service -n 50 --no-pager
```

### Step 1.9: Test Restore Procedure (Scratch Test)
Verify backup integrity in an isolated temporary database without touching live data:
```bash
./deploy/restore.sh --scratch-test $(ls -t /home/deploy/sentinel-ai/backups/db_*.dump | head -n 1)
```

### Step 1.10: Rollback & Disaster Recovery
If an update or schema migration introduces breaking errors:
1. Stop backend: `docker compose -f docker-compose.prod.yml stop backend`
2. Restore the pre-restore dump taken automatically before the operation:
   ```bash
   ./deploy/restore.sh /home/deploy/sentinel-ai/backups/pre_restore_<TIMESTAMP>.dump
   ```
3. Restart backend: `docker compose -f docker-compose.prod.yml start backend`

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
