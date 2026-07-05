#!/usr/bin/env bash
# ec2-bootstrap.sh — installs everything the Rift signer enclave needs
# on a fresh Amazon Linux 2023 EC2 with Nitro Enclaves enabled, clones
# the signer at a PINNED version, builds the EIF, and prints the PCR0
# for you to pin into your KMS key policy.
#
# For self-hosting integrators (banks/fintechs) deploying Rift's
# infrastructure into their own AWS account.
#
# Idempotent: safe to re-run. Won't wipe anything.
#
# Runs as ec2-user via SSM Session Manager. Requires a Nitro-Enclave-
# capable instance type (c5.xlarge+, m5.xlarge+, c6g.large+, etc.)
# launched with EnclaveOptions.Enabled=true.
#
# ENV OVERRIDES (defaults are Rift-canonical — override to fork):
#   ENV_TAG            sandbox|prod (labels only, default sandbox)
#   ENCLAVE_REPO       git URL of signer enclave
#                      default: https://github.com/Rift-FI/Rift-secure-signing-enclave.git
#   ENCLAVE_REF        git tag / branch / SHA to build. REQUIRED for
#                      reproducibility. Recommended: a released tag
#                      like v1.0.0. Default: main (NOT reproducible;
#                      only use for dev). Rift publishes canonical
#                      PCR0 values per tag — see verify-pcr0.sh.
#   ENCLAVE_CPUS       default: 1
#   ENCLAVE_MEMORY_MIB default: 1024
#
# NOT set here:
#   * KMS policy (that's the manual security checkpoint — step 5 of
#     the runbook)
#   * DNS or ALB (integrator-specific — step 8 of the runbook)
#   * Rift backend registration (last step of the runbook)

set -Eeuo pipefail

ENV_TAG="${ENV_TAG:-sandbox}"
ENCLAVE_REPO="${ENCLAVE_REPO:-https://github.com/Rift-FI/Rift-secure-signing-enclave.git}"
ENCLAVE_REF="${ENCLAVE_REF:-main}"
ENCLAVE_CPUS="${ENCLAVE_CPUS:-1}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-1024}"
WORKROOT="$HOME/rift"

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

trap 'die "step failed on line $LINENO: $BASH_COMMAND"' ERR

step "0 · sanity checks (env=$ENV_TAG)"
[[ $EUID -eq 0 ]] && die "run as ec2-user, not root. sudo is used inline where needed."
uname -m | grep -qE 'aarch64|x86_64' || die "unsupported arch: $(uname -m)"
[[ -r /etc/os-release ]] && grep -qi 'amazon linux' /etc/os-release || warn "not Amazon Linux — proceeding but untested"

step "1 · system packages"
sudo dnf install -y \
  git jq curl tar make gcc gcc-c++ pkgconf-pkg-config \
  openssl openssl-devel \
  aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
  docker

step "2 · docker + user groups"
sudo systemctl enable --now docker
if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  warn "added $USER to docker group. sudo is used below so this shell continues; new SSM sessions won't need sudo for docker."
fi
if ! id -nG "$USER" | grep -qw ne; then
  sudo usermod -aG ne "$USER"
fi

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

step "4 · rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"
cargo --version

step "5 · clone signer enclave @ $ENCLAVE_REF"
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

step "6 · build EIF (this compiles the enclave binary + packs it)"
# Use sudo for docker/nitro-cli since group membership requires a new
# login session to take effect.
sudo -E env PATH="$PATH" make eif

step "7 · capture PCR0"
PCR0=$(sudo -E env PATH="$PATH" make pcr0 | tr -d '[:space:]')
[[ ${#PCR0} -eq 96 ]] || die "PCR0 looks wrong (len ${#PCR0}, want 96): $PCR0"

step "8 · install parent-proxy as systemd unit"
# NOT under sudo — the target's cargo build must run as ec2-user so it
# can find the rustup toolchain in $HOME/.rustup. The Makefile uses
# `sudo` per-line inside install-parent-proxy for the cp + systemctl.
make install-parent-proxy
sudo systemctl status rift-parent-proxy --no-pager | head -6 || true

step "9 · save state for the runbook"
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
  "enclave_cpus": $ENCLAVE_CPUS,
  "enclave_memory_mib": $ENCLAVE_MEMORY_MIB,
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
echo
echo "▶ VERIFY the PCR0 matches Rift's canonical published value"
echo "  before pinning it into your KMS policy:"
echo
echo "    ENCLAVE_REF=$ENCLAVE_REF PCR0=$PCR0 ./verify-pcr0.sh"
echo
echo "▶ NEXT MANUAL STEPS (see INTEGRATOR-SETUP.md):"
echo "  1. verify PCR0 (above)"
echo "  2. paste PCR0 into your KMS key policy's"
echo "     kms:RecipientAttestation:ImageSha384 condition"
echo "  3. cd ~/rift/Rift-secure-signing-enclave && sudo make run-debug"
echo "  4. curl http://127.0.0.1:7777/health"
echo "  5. run smart-wallet-bootstrap.sh once step 4 is green"
echo
