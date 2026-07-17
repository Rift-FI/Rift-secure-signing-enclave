#!/usr/bin/env bash
# ec2-bootstrap.sh — installs everything the Rift signer enclave needs
# on a fresh Amazon Linux 2023 EC2 with Nitro Enclaves enabled, clones
# the signer at a PINNED version, builds the EIF, and prints the PCR0
# for you to pin into your KMS key policy.
#
# For self-hosting integrators (banks/fintechs).
#
# Idempotent: safe to re-run. Won't wipe anything.
#
# Runs as ec2-user via SSM Session Manager. Requires a Nitro-Enclave-
# capable instance type launched with EnclaveOptions.Enabled=true.
#
# ENV OVERRIDES:
#   ENV_TAG              sandbox|prod (labels only, default sandbox)
#   ENCLAVE_REPO         default: Rift's public repo
#   ENCLAVE_REF          REQUIRED for reproducibility; default main
#                        (dev-only; prod = pinned tag like v1.0.0)
#   ENCLAVE_CPUS         default: 1
#   ENCLAVE_MEMORY_MIB   default: 1024
#   BEARER_FROM_SECRETS  1 to fetch/store bearer in AWS Secrets Manager
#                        instead of only /etc/rift-nginx-bearer.
#                        Requires the IAM permissions attached by
#                        aws-provision.sh when BEARER_TO_SECRETS_MGR=1.
#   SKIP_CW_AGENT        1 to skip CloudWatch Agent install (metrics/logs).
#                        Default: install (needed for the disk alarm).
#   JOURNAL_MAX_MB       cap for journald ring buffer. Default 500.

set -Eeuo pipefail
IFS=$'\n\t'

ENV_TAG="${ENV_TAG:-sandbox}"
ENCLAVE_REPO="${ENCLAVE_REPO:-https://github.com/Rift-FI/Rift-secure-signing-enclave.git}"
ENCLAVE_REF="${ENCLAVE_REF:-main}"
ENCLAVE_CPUS="${ENCLAVE_CPUS:-1}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-1024}"
BEARER_FROM_SECRETS="${BEARER_FROM_SECRETS:-0}"
SKIP_CW_AGENT="${SKIP_CW_AGENT:-0}"
JOURNAL_MAX_MB="${JOURNAL_MAX_MB:-500}"
WORKROOT="$HOME/rift"

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

trap 'die "step failed on line $LINENO: $BASH_COMMAND"' ERR

# ─────────────────────────────────────────────────────────────────
step "0 · sanity checks (env=$ENV_TAG)"
[[ $EUID -eq 0 ]] && die "run as ec2-user, not root. sudo is used inline where needed."
uname -m | grep -qE 'aarch64|x86_64' || die "unsupported arch: $(uname -m)"
if ! { [[ -r /etc/os-release ]] && grep -qi 'amazon linux' /etc/os-release; }; then
  warn "not Amazon Linux — proceeding but untested"
fi

# Ensure at least 20 GB free before we start. Rust + Docker + EIF need
# room; running out mid-build leaves half-finished state that a
# subsequent rerun has to clean up.
FREE_GB=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
if (( FREE_GB < 20 )); then
  die "root disk has only ${FREE_GB} GB free; need at least 20 GB. Grow the EBS volume or clean up."
fi
log "root disk: ${FREE_GB} GB free"

# ─────────────────────────────────────────────────────────────────
step "1 · system packages"
sudo dnf install -y \
  git jq curl tar make gcc gcc-c++ pkgconf-pkg-config \
  openssl openssl-devel \
  aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
  docker nginx logrotate

# ─────────────────────────────────────────────────────────────────
step "2 · docker + user groups"
sudo systemctl enable --now docker
if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  warn "added $USER to docker group. sudo is used below so this shell continues; new SSM sessions won't need sudo for docker."
fi
if ! id -nG "$USER" | grep -qw ne; then
  sudo usermod -aG ne "$USER"
fi

# ─────────────────────────────────────────────────────────────────
step "3 · nitro enclave allocator (${ENCLAVE_CPUS} vCPU, ${ENCLAVE_MEMORY_MIB} MiB)"
ALLOC=/etc/nitro_enclaves/allocator.yaml
sudo test -f "$ALLOC" || die "$ALLOC missing — nitro-cli install broken"
sudo cp "$ALLOC" "$ALLOC.bak.$(date +%s)"
sudo sed -i "s/^memory_mib:.*/memory_mib: ${ENCLAVE_MEMORY_MIB}/" "$ALLOC"
sudo sed -i "s/^cpu_count:.*/cpu_count: ${ENCLAVE_CPUS}/" "$ALLOC"
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl restart nitro-enclaves-allocator.service
sleep 3
sudo systemctl is-active nitro-enclaves-allocator.service >/dev/null \
  || die "allocator failed to start. journalctl -u nitro-enclaves-allocator"

[[ -e /dev/nitro_enclaves ]] \
  || die "/dev/nitro_enclaves missing — is this instance Nitro-Enclave-capable AND launched with --enclave-options Enabled=true?"

# ─────────────────────────────────────────────────────────────────
step "4 · journald size cap + log rotation"
# journald grows without a cap by default. Set a hard ceiling so it
# can't fill the disk. logrotate handles nginx access/error logs.
sudo mkdir -p /etc/systemd/journald.conf.d
sudo tee /etc/systemd/journald.conf.d/rift-caps.conf >/dev/null <<CONF
[Journal]
SystemMaxUse=${JOURNAL_MAX_MB}M
SystemKeepFree=1G
SystemMaxFileSize=100M
MaxRetentionSec=30day
Compress=yes
CONF
sudo systemctl restart systemd-journald
log "journald capped at ${JOURNAL_MAX_MB} MB, 30-day max retention"

# nginx logrotate — daily, 14 rotations, compressed. Amazon Linux ships
# a default; override with our tighter policy.
sudo tee /etc/logrotate.d/rift-nginx >/dev/null <<'ROTATE'
/var/log/nginx/*.log {
  daily
  rotate 14
  compress
  delaycompress
  missingok
  notifempty
  create 0640 nginx nginx
  sharedscripts
  postrotate
    /usr/bin/systemctl reload nginx.service >/dev/null 2>&1 || true
  endscript
}
ROTATE
log "nginx logrotate: daily, 14 rotations, compressed"

# ─────────────────────────────────────────────────────────────────
step "5 · CloudWatch Agent (for disk / memory metrics)"
if [[ "$SKIP_CW_AGENT" == "1" ]]; then
  warn "SKIP_CW_AGENT=1 — no CW metrics/alarms. Disk alarm from aws-provision.sh will never fire."
elif command -v amazon-cloudwatch-agent-ctl >/dev/null 2>&1; then
  log "CloudWatch Agent already installed"
else
  # arch-aware download
  ARCH_TAG="amd64"
  [[ "$(uname -m)" == "aarch64" ]] && ARCH_TAG="arm64"
  CWA_URL="https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/${ARCH_TAG}/latest/amazon-cloudwatch-agent.rpm"
  TMP_RPM="/tmp/amazon-cloudwatch-agent.rpm"
  curl -fsSL "$CWA_URL" -o "$TMP_RPM"
  sudo dnf install -y "$TMP_RPM"
  rm -f "$TMP_RPM"

  # Minimal config — disk + memory metrics + systemd logs for the
  # rift-parent-proxy and nginx units.
  sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
  sudo tee /opt/aws/amazon-cloudwatch-agent/etc/rift-cwa.json >/dev/null <<'CWA'
{
  "agent": { "metrics_collection_interval": 60, "run_as_user": "cwagent" },
  "metrics": {
    "namespace": "CWAgent",
    "append_dimensions": { "InstanceId": "${aws:InstanceId}" },
    "metrics_collected": {
      "disk": {
        "measurement": ["used_percent"],
        "resources": ["/"],
        "metrics_collection_interval": 60
      },
      "mem": {
        "measurement": ["mem_used_percent"],
        "metrics_collection_interval": 60
      }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/nginx/error.log",
            "log_group_name": "/rift/signer/nginx-error",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 14
          },
          {
            "file_path": "/var/log/nginx/access.log",
            "log_group_name": "/rift/signer/nginx-access",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 14
          }
        ]
      }
    }
  }
}
CWA
  sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/rift-cwa.json >/dev/null
  log "CloudWatch Agent installed and started"
fi

# ─────────────────────────────────────────────────────────────────
step "6 · rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"
cargo --version

# ─────────────────────────────────────────────────────────────────
step "7 · clone signer enclave @ $ENCLAVE_REF"
mkdir -p "$WORKROOT"
cd "$WORKROOT"
if [[ -d Rift-secure-signing-enclave/.git ]]; then
  log "repo present — fetching + checking out $ENCLAVE_REF"
  git -C Rift-secure-signing-enclave fetch --tags --prune
  git -C Rift-secure-signing-enclave checkout "$ENCLAVE_REF"
  # If ENCLAVE_REF is a branch, pull; if a tag/SHA, checkout above is enough.
  git -C Rift-secure-signing-enclave symbolic-ref -q HEAD >/dev/null && \
    git -C Rift-secure-signing-enclave pull --ff-only || true
else
  git clone "$ENCLAVE_REPO" Rift-secure-signing-enclave
  git -C Rift-secure-signing-enclave fetch --tags
  git -C Rift-secure-signing-enclave checkout "$ENCLAVE_REF"
fi
cd Rift-secure-signing-enclave
BUILT_SHA=$(git rev-parse HEAD)
log "building from $ENCLAVE_REF ($BUILT_SHA)"
if [[ "$ENCLAVE_REF" == "main" || "$ENCLAVE_REF" == "master" ]]; then
  warn "you are building from a moving branch. PCR0 will not be reproducible."
  warn "for production, pin ENCLAVE_REF to a released tag (e.g. v1.0.0)."
fi

# ─────────────────────────────────────────────────────────────────
step "8 · build EIF"
# docker + nitro-cli need sudo since docker-group membership requires
# a new login session; safe because Makefile targets are self-contained.
sudo -E env PATH="$PATH" make eif

# ─────────────────────────────────────────────────────────────────
step "9 · capture PCR0"
PCR0=$(sudo -E env PATH="$PATH" make pcr0 | tr -d '[:space:]')
[[ ${#PCR0} -eq 96 ]] || die "PCR0 looks wrong (len ${#PCR0}, want 96): $PCR0"

# ─────────────────────────────────────────────────────────────────
step "10 · install parent-proxy as systemd unit"
# NOT under sudo — the target's cargo build must run as ec2-user so it
# can find the rustup toolchain in $HOME/.rustup. The Makefile uses
# `sudo` per-line inside install-parent-proxy for the cp + systemctl.
make install-parent-proxy
sudo systemctl status rift-parent-proxy --no-pager | head -6 || true

# ─────────────────────────────────────────────────────────────────
step "11 · nginx sidecar (public /sign + /generate-wallet with bearer auth)"
# Idempotent bearer sourcing. Three modes:
#   1. BEARER_FROM_SECRETS=1 → pull from Secrets Manager; if empty,
#      generate + push back so both sides stay in sync.
#   2. else if /etc/rift-nginx-bearer exists → reuse.
#   3. else → generate fresh, write to file, chmod 600.

BEARER_SECRET_NAME="rift-signer-${ENV_TAG}-nginx-bearer"

if [[ "$BEARER_FROM_SECRETS" == "1" ]]; then
  command -v aws >/dev/null 2>&1 || die "AWS CLI required for BEARER_FROM_SECRETS=1"
  REGION_META=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/placement/region || true)
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-$REGION_META}"

  if aws secretsmanager describe-secret --secret-id "$BEARER_SECRET_NAME" >/dev/null 2>&1; then
    BEARER=$(aws secretsmanager get-secret-value --secret-id "$BEARER_SECRET_NAME" \
      --query SecretString --output text 2>/dev/null || true)
    if [[ -z "$BEARER" || "$BEARER" == "None" ]]; then
      BEARER=$(openssl rand -hex 32)
      aws secretsmanager put-secret-value --secret-id "$BEARER_SECRET_NAME" \
        --secret-string "$BEARER" >/dev/null
      log "populated empty Secrets Manager entry with fresh bearer"
    else
      log "reused bearer from Secrets Manager"
    fi
  else
    die "BEARER_FROM_SECRETS=1 but secret $BEARER_SECRET_NAME missing. Re-run aws-provision.sh with BEARER_TO_SECRETS_MGR=1."
  fi
  # Also write local file as a cache; nginx reads from here.
  sudo tee /etc/rift-nginx-bearer >/dev/null <<< "$BEARER"
  sudo chmod 600 /etc/rift-nginx-bearer
else
  if [[ ! -f /etc/rift-nginx-bearer ]]; then
    BEARER=$(openssl rand -hex 32)
    sudo tee /etc/rift-nginx-bearer >/dev/null <<< "$BEARER"
    sudo chmod 600 /etc/rift-nginx-bearer
    log "generated fresh bearer at /etc/rift-nginx-bearer"
  else
    BEARER=$(sudo cat /etc/rift-nginx-bearer)
    log "reusing existing bearer from /etc/rift-nginx-bearer"
  fi
fi

# nginx sits in front of the parent-proxy: verifies Bearer, forwards to
# 127.0.0.1:7777. ALB terminates TLS on the way in.
sudo tee /etc/nginx/conf.d/rift-parent-proxy.conf >/dev/null <<NGINX
map \$http_authorization \$rift_authorized {
    default 0;
    "Bearer $BEARER" 1;
}

# Auth'd surface on :8080. ALB HTTPS listener forwards here.
server {
    listen 8080;
    server_name _;
    client_max_body_size 32k;

    if (\$rift_authorized = 0) {
        return 401;
    }

    location = /health {
        proxy_pass http://127.0.0.1:7777/health;
        proxy_set_header Host \$host;
    }
    location = /sign {
        proxy_pass http://127.0.0.1:7777/sign;
        proxy_set_header Host \$host;
        proxy_read_timeout 35s;
    }
    location = /generate-wallet {
        proxy_pass http://127.0.0.1:7777/generate-wallet;
        proxy_set_header Host \$host;
        proxy_read_timeout 35s;
    }
    location / { return 404; }
}

# Unauth'd health-only on :8081 — ALB target-group health checks hit
# this directly. Kept off :8080 so a working health check can't be
# used as an oracle for whether the auth is up.
server {
    listen 8081;
    server_name _;
    location = /health {
        proxy_pass http://127.0.0.1:7777/health;
    }
    location / { return 404; }
}
NGINX

sudo nginx -t || die "nginx config test failed"
sudo systemctl enable --now nginx
sudo systemctl restart nginx
sudo systemctl status nginx --no-pager | head -4 || true

# ─────────────────────────────────────────────────────────────────
step "12 · self-verify (health, bearer round-trip, systemd units)"

# Give services 3s to settle before probing.
sleep 3

FAIL=0

# parent-proxy alive
if sudo systemctl is-active --quiet rift-parent-proxy; then
  log "✓ rift-parent-proxy: active"
else
  warn "✗ rift-parent-proxy: NOT active"
  FAIL=1
fi

# nginx alive
if sudo systemctl is-active --quiet nginx; then
  log "✓ nginx: active"
else
  warn "✗ nginx: NOT active"
  FAIL=1
fi

# unauth'd health path returns ok
if curl -sf --max-time 5 http://127.0.0.1:8081/health >/dev/null; then
  log "✓ nginx :8081/health returns 2xx"
else
  # The enclave isn't running yet at bootstrap time — the parent-proxy
  # returns 5xx on /health until you `make run`. So this is expected on
  # first bootstrap, warn-only.
  warn "△ nginx :8081/health non-2xx (expected until `sudo make run`)"
fi

# authed path with correct bearer → not-401
CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "authorization: Bearer $BEARER" http://127.0.0.1:8080/health || echo 000)
if [[ "$CODE" == "401" ]]; then
  warn "✗ nginx bearer check REJECTED the correct bearer. Config broken."
  FAIL=1
else
  log "✓ nginx bearer check accepts the correct token (got HTTP $CODE)"
fi

# authed path with wrong bearer → 401
CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "authorization: Bearer nope" http://127.0.0.1:8080/health || echo 000)
if [[ "$CODE" == "401" ]]; then
  log "✓ nginx bearer check rejects wrong token"
else
  warn "✗ nginx bearer check DID NOT reject wrong token (got HTTP $CODE). SEVERE."
  FAIL=1
fi

# no auth header → 401
CODE=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health || echo 000)
if [[ "$CODE" == "401" ]]; then
  log "✓ nginx bearer check rejects missing header"
else
  warn "✗ nginx bearer check DID NOT require a header (got HTTP $CODE). SEVERE."
  FAIL=1
fi

if (( FAIL )); then
  warn "self-verify found $FAIL failure(s). Review the log lines above before proceeding."
else
  log "self-verify passed"
fi

# ─────────────────────────────────────────────────────────────────
step "13 · save state for the runbook"
STATE="$WORKROOT/state.json"
INSTANCE_ID=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id || echo unknown)
REGION=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/placement/region || echo unknown)
cat > "$STATE" <<JSON
{
  "env_tag": "$ENV_TAG",
  "instance_id": "$INSTANCE_ID",
  "region": "$REGION",
  "enclave_repo": "$ENCLAVE_REPO",
  "enclave_ref": "$ENCLAVE_REF",
  "enclave_sha": "$BUILT_SHA",
  "pcr0": "$PCR0",
  "bearer_file": "/etc/rift-nginx-bearer",
  "bearer_from_secrets": $BEARER_FROM_SECRETS,
  "enclave_cpus": $ENCLAVE_CPUS,
  "enclave_memory_mib": $ENCLAVE_MEMORY_MIB,
  "self_verify_failures": $FAIL,
  "captured_at": "$(date -u +%FT%TZ)"
}
JSON
log "wrote $STATE"

echo
echo "════════════════════════════════════════════════════════════════"
echo " enclave bootstrap complete — env=$ENV_TAG"
echo "════════════════════════════════════════════════════════════════"
echo
echo "  instance    : $INSTANCE_ID  ($REGION)"
echo "  ref         : $ENCLAVE_REF"
echo "  built sha   : $BUILT_SHA"
echo "  PCR0        : $PCR0"
echo "  bearer file : /etc/rift-nginx-bearer  (600, root)"
[[ "$BEARER_FROM_SECRETS" == "1" ]] && echo "  bearer secret: $BEARER_SECRET_NAME"
echo "  self-verify : $((FAIL == 0 ? 1 : 0))/1 passed ($FAIL failures)"
echo
echo "▶ VERIFY the PCR0 matches Rift's canonical published value:"
echo "    ./verify-pcr0.sh"
echo
echo "▶ NEXT MANUAL STEPS (see INTEGRATOR-SETUP.md):"
echo "  1. verify PCR0 (above)"
echo "  2. paste PCR0 into your KMS key policy's"
echo "     kms:RecipientAttestation:ImageSha384 condition"
echo "  3. cd ~/rift/Rift-secure-signing-enclave && sudo make run"
echo "  4. curl http://127.0.0.1:8081/health  → 'ok' means the enclave"
echo "     path is fully wired end-to-end"
echo "  5. paste bearer + parent-proxy URL + KMS ARN into Rift's"
echo "     dashboard Enclave tab. Then Rift routes your projects'"
echo "     users to your enclave automatically."
echo
echo "  Bearer to paste into the dashboard:"
echo "    sudo cat /etc/rift-nginx-bearer"
echo
