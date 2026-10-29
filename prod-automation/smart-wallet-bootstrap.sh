#!/usr/bin/env bash
# smart-wallet-bootstrap.sh — deploys the smart-wallet Node process
# on the SAME EC2 the enclave is running on. This is the parent-side
# service that receives HTTPS from your backend, builds UserOps, asks
# the enclave (via parent-proxy) to sign, and submits to the bundler.
#
# For self-hosting integrators (banks / fintechs).
#
# Preconditions:
#   * ec2-bootstrap.sh has run
#   * `systemctl is-active rift-parent-proxy` = active
#   * `curl http://127.0.0.1:7777/health` = ok
#
# Idempotent — safe to re-run.
#
# ─── ENV VARS YOU (integrator) MUST provide ─────────────────────────
#   KMS_KEY_ARN          the SYMMETRIC KMS CMK the enclave will Decrypt
#                        against. Created by aws-provision.sh.
#   ENV_FILE_EXTRA       path to a file whose lines get appended to
#                        /etc/rift-smartwallet.env verbatim. This is
#                        where your operator-specific secrets go:
#                          PIMLICO_URL_BASE, PIMLICO_URL_ARB, …
#                          ALCHEMY_RPC_URL_BASE, …
#                          JWT_SIGNING_SECRET
#                          RIFT_BACKEND_URL             (given to you
#                                                        by Rift on
#                                                        registration)
#                          RIFT_BACKEND_SHARED_SECRET   (given to you
#                                                        by Rift on
#                                                        registration)
#                          ENCRYPTION_KEY               (Phase-0 legacy
#                                                        fallback; drop
#                                                        once your users
#                                                        are all on v3)
#
# ─── ENV VARS the script sets for you ────────────────────────────────
#   NODE_ENV=production
#   SIGNING_MODE=enclave
#   PARENT_PROXY_URL=http://127.0.0.1:7777
#   PORT (default 443)
#   RIFT_ENV=$ENV_TAG
#   KMS_KEY_ARN (from arg above)
#
# ─── Optional overrides ─────────────────────────────────────────────
#   ENV_TAG              sandbox|prod (default sandbox)
#   SMART_WALLET_REPO    git URL (default: Rift-published)
#   SMART_WALLET_REF     REQUIRED: git commit SHA (preferred) or release
#                        tag, paired with your ENCLAVE_REF. Branches are
#                        refused unless ALLOW_UNPINNED_REF=1 (dev only).
#   ALLOW_UNPINNED_REF   set to 1 to allow a branch name (dev only)
#   PORT                 default 443

set -Eeuo pipefail

ENV_TAG="${ENV_TAG:-sandbox}"
: "${KMS_KEY_ARN:?set KMS_KEY_ARN=arn:aws:kms:...}"
SMART_WALLET_REPO="${SMART_WALLET_REPO:-https://github.com/Rift-FI/smart-wallet.git}"
SMART_WALLET_REF="${SMART_WALLET_REF:-${SMART_WALLET_BRANCH:-}}"
[[ -n "$SMART_WALLET_REF" ]] || { echo "[fatal] set SMART_WALLET_REF to a commit SHA or release tag" >&2; exit 1; }
PORT="${PORT:-443}"
ENV_FILE_EXTRA="${ENV_FILE_EXTRA:-}"
WORKROOT="$HOME/rift"

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

trap 'die "step failed on line $LINENO: $BASH_COMMAND"' ERR

step "0 · preflight — enclave + parent-proxy must be live"
sudo systemctl is-active rift-parent-proxy >/dev/null \
  || die "rift-parent-proxy is not running. Fix that first."
curl -fsS --max-time 3 http://127.0.0.1:7777/health >/dev/null \
  || die "parent-proxy /health failed. Enclave probably isn't running."
log "parent-proxy healthy"

step "1 · node.js 20"
# NodeSource's signed package repository, configured explicitly instead
# of piping their setup script into a root shell. dnf verifies every
# package against the repo key (gpgcheck=1, repo_gpgcheck=0 matches
# NodeSource's own setup). Equivalent to their documented manual
# "signed repo" install.
if ! command -v node >/dev/null || [[ "$(node -v | cut -d. -f1)" != "v20" ]]; then
  NODESOURCE_KEY_URL="https://rpm.nodesource.com/gpgkey/ns-operations-public.key"
  sudo rpm --import "$NODESOURCE_KEY_URL"
  sudo tee /etc/yum.repos.d/nodesource-nodejs.repo >/dev/null <<'REPO'
[nodesource-nodejs]
name=Node.js Packages for $basearch
baseurl=https://rpm.nodesource.com/pub_20.x/nodistro/nodejs/$basearch
priority=9
enabled=1
gpgcheck=1
gpgkey=https://rpm.nodesource.com/gpgkey/ns-operations-public.key
module_hotfixes=1
REPO
  sudo dnf install -y nodejs
fi
node -v

step "2 · clone smart-wallet"
mkdir -p "$WORKROOT"
cd "$WORKROOT"
if [[ -d smart-wallet/.git ]]; then
  log "repo present — fetching"
  git -C smart-wallet fetch --all --prune
else
  git clone "$SMART_WALLET_REPO"
fi
cd smart-wallet
git fetch --tags --prune origin
if git show-ref --verify --quiet "refs/remotes/origin/$SMART_WALLET_REF"; then
  # A branch name: moving target, not reproducible.
  [[ "${ALLOW_UNPINNED_REF:-0}" == "1" ]] \
    || die "SMART_WALLET_REF=$SMART_WALLET_REF is a branch; pin a commit SHA or tag (or ALLOW_UNPINNED_REF=1 for dev)"
  warn "building from branch $SMART_WALLET_REF (ALLOW_UNPINNED_REF=1)"
  git checkout --detach "origin/$SMART_WALLET_REF"
else
  git -c advice.detachedHead=false checkout --detach "$SMART_WALLET_REF"
fi
log "smart-wallet at $(git rev-parse HEAD)"
npm ci

step "3 · env file at /etc/rift-smartwallet.env"
if [[ -f /etc/rift-smartwallet.env ]]; then
  sudo cp /etc/rift-smartwallet.env "/etc/rift-smartwallet.env.bak.$(date +%s)"
fi
sudo tee /etc/rift-smartwallet.env >/dev/null <<EOF
NODE_ENV=production
PORT=$PORT
SIGNING_MODE=enclave
PARENT_PROXY_URL=http://127.0.0.1:7777
KMS_KEY_ARN=$KMS_KEY_ARN
RIFT_ENV=$ENV_TAG
EOF
# The parent-proxy requires its bearer token (fail closed); hand the same
# value to smart-wallet so its enclave calls authenticate.
PROXY_TOKEN="$(sudo sed -n 's/^PARENT_PROXY_AUTH_TOKEN=//p' /etc/rift-parent-proxy.env 2>/dev/null | tail -1)"
if [[ -n "$PROXY_TOKEN" ]]; then
  echo "PARENT_PROXY_AUTH_TOKEN=$PROXY_TOKEN" | sudo tee -a /etc/rift-smartwallet.env >/dev/null
else
  warn "no PARENT_PROXY_AUTH_TOKEN in /etc/rift-parent-proxy.env — smart-wallet calls to the proxy will be rejected"
fi
unset PROXY_TOKEN
if [[ -n "$ENV_FILE_EXTRA" && -f "$ENV_FILE_EXTRA" ]]; then
  sudo tee -a /etc/rift-smartwallet.env >/dev/null < "$ENV_FILE_EXTRA"
  log "appended $(wc -l < "$ENV_FILE_EXTRA") lines from $ENV_FILE_EXTRA"
else
  warn "no ENV_FILE_EXTRA set. You still need to append:"
  warn "  ENCRYPTION_KEY, PIMLICO_* URLs, RPC URLs, JWT secrets"
  warn "  Edit /etc/rift-smartwallet.env manually now."
fi
sudo chmod 640 /etc/rift-smartwallet.env
sudo chown root:root /etc/rift-smartwallet.env

step "4 · systemd unit"
sudo tee /etc/systemd/system/rift-smartwallet.service >/dev/null <<UNIT
[Unit]
Description=Rift smart-wallet (enclave mode)
After=network-online.target rift-parent-proxy.service
Wants=network-online.target
Requires=rift-parent-proxy.service

[Service]
Type=simple
WorkingDirectory=$WORKROOT/smart-wallet
EnvironmentFile=/etc/rift-smartwallet.env
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=3
# Bind to :443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
User=ec2-user
Group=ec2-user

[Install]
WantedBy=multi-user.target
UNIT

step "5 · build + enable"
npm run build || die "smart-wallet build failed"
sudo systemctl daemon-reload
sudo systemctl enable rift-smartwallet.service
sudo systemctl restart rift-smartwallet.service
sleep 2
sudo systemctl status rift-smartwallet.service --no-pager | head -12 || true

step "6 · smoke test"
if curl -fsS --max-time 3 "https://127.0.0.1:$PORT/health" -k >/dev/null; then
  log "smart-wallet responding on :$PORT"
else
  warn "smart-wallet not answering on :$PORT — check journalctl -u rift-smartwallet -f"
fi

cat <<DONE

════════════════════════════════════════════════════════════════
 smart-wallet installed — env=$ENV_TAG
════════════════════════════════════════════════════════════════

next manual steps:
  1. put ALB or nginx (with ACM cert) in front of :$PORT
  2. point smartwallet-${ENV_TAG}.riftfi.xyz DNS at the ALB
  3. update backend env to use the new URL for ${ENV_TAG} traffic
     (PROD-SETUP.md step 8)
  4. run one real end-to-end transaction and verify it settles

DONE
