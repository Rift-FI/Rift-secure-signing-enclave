#!/usr/bin/env bash
# Build the enclave EIF for rotation and report its PCR0. Two modes:
#
#   --approved-commit <40-hex-sha>   (BUILD mode — what the rotation
#       Lambda runs on the EC2). Checks out EXACTLY that commit
#       (detached), refuses a dirty tracked tree, does NOT fetch JWKS or
#       touch any source file, builds the EIF and prints its PCR0. The
#       Lambda then compares that PCR0 with the independently approved
#       value in SSM and only touches KMS policies on an exact match.
#       Nothing fetched at build time can influence the measured image.
#
#   --refresh-jwks   (PREPARE mode — run by CI or a release engineer on
#       a workstation/CI runner with nitro-cli + docker, NOT by the
#       Lambda). Fetches fresh Google + Apple JWKS, patches
#       enclave/src/pinned_jwks.rs, builds the EIF and prints its PCR0.
#       The JWKS change must then be reviewed and committed, and the
#       commit SHA + PCR0 published to SSM (see prod-automation/README.md
#       "Enclave release approval"). The EC2 never decides on its own
#       which JWKS get baked into a key-releasing enclave.
#
# Why: previously this script ran on the EC2, pulled origin/main HEAD,
# fetched JWKS over the network and the Lambda added whatever PCR0
# came out to the KMS key policies. Anyone able to push to main, tamper
# with the EC2 checkout, or MITM the JWKS fetch could get an arbitrary
# enclave image trusted by KMS. Now the trusted value is set out of band.
#
# Environment:
#   ENCLAVE_SRC   path to the enclave repo (default: $HOME/rift/Rift-secure-signing-enclave)
#   GIT_REMOTE    remote to fetch the approved commit from (default: origin)
#
# Output (parsed by rotate-jwks-lambda.py — keep the formats):
#   "new PCR0: <96 hex>"
#   "built commit: <40 hex>"

set -euo pipefail

ENCLAVE_SRC="${ENCLAVE_SRC:-${HOME:-/home/ec2-user}/rift/Rift-secure-signing-enclave}"
GIT_REMOTE="${GIT_REMOTE:-origin}"

log() { printf "[%s] %s\n" "$(date -Is)" "$*"; }
die() { printf "\n[FATAL] %s\n" "$*" >&2; exit 1; }

usage() {
    cat >&2 <<USAGE
Usage:
  $0 --approved-commit <40-hex-sha>   # build mode (rotation Lambda)
  $0 --refresh-jwks                   # prepare mode (CI / release engineer)
USAGE
    exit 1
}

MODE="${1:-}"
APPROVED_COMMIT="${2:-}"
case "$MODE" in
    --approved-commit)
        [[ "$APPROVED_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
            || die "approved commit must be a full 40-char lowercase hex SHA, got '$APPROVED_COMMIT'"
        ;;
    --refresh-jwks) ;;
    *) usage ;;
esac

cd "$ENCLAVE_SRC" 2>/dev/null || die "enclave repo not at $ENCLAVE_SRC"
command -v jq >/dev/null 2>&1 || die "jq required"

build_and_report() {
    log "── build EIF ──"
    if ! sudo make eif 2>&1 | tail -6; then
        die "make eif failed"
    fi

    log "── capture PCR0 ──"
    NEW_PCR0="$(sudo make pcr0 | tr -d '[:space:]' | tr 'A-F' 'a-f')"
    [[ "$NEW_PCR0" =~ ^[0-9a-f]{96}$ ]] || die "PCR0 wrong shape (${#NEW_PCR0} chars, want 96 hex): $NEW_PCR0"
    BUILT_COMMIT="$(git rev-parse HEAD)"
    # Unprefixed lines for the Lambda's regexes.
    echo "new PCR0: $NEW_PCR0"
    echo "built commit: $BUILT_COMMIT"

    OLD_PCR0="$(sudo nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].Measurements.PCR0 // empty' || true)"
    log "currently-running PCR0: ${OLD_PCR0:-<no enclave running>}"
}

if [[ "$MODE" == "--approved-commit" ]]; then
    log "── BUILD mode: approved commit $APPROVED_COMMIT ──"
    # Tracked files must be pristine: a local edit would be measured
    # into the EIF and (correctly) fail the PCR0 comparison, but fail
    # here first with a clear message.
    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        git status --short --untracked-files=no | sed 's/^/  /'
        die "tracked files modified in $ENCLAVE_SRC — refusing to build (clean the checkout manually)"
    fi
    git fetch --quiet "$GIT_REMOTE" "$APPROVED_COMMIT" 2>/dev/null \
        || git fetch --quiet --tags "$GIT_REMOTE" \
        || die "git fetch failed — check remote + credentials"
    git cat-file -e "${APPROVED_COMMIT}^{commit}" 2>/dev/null \
        || die "approved commit $APPROVED_COMMIT not found after fetch"
    git -c advice.detachedHead=false checkout --quiet --detach "$APPROVED_COMMIT" \
        || die "git checkout $APPROVED_COMMIT failed"
    HEAD_SHA="$(git rev-parse HEAD)"
    [[ "$HEAD_SHA" == "$APPROVED_COMMIT" ]] || die "HEAD is $HEAD_SHA, expected $APPROVED_COMMIT"
    log "checked out $(git log -1 --oneline)"
    build_and_report
    exit 0
fi

# ── PREPARE mode ─────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || die "node required (for tools/fetch-jwks.mjs)"
[[ -f tools/fetch-jwks.mjs ]] || die "tools/fetch-jwks.mjs missing"
[[ -f enclave/src/pinned_jwks.rs ]] || die "enclave/src/pinned_jwks.rs missing"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rift-jwks.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
JWKS_SNIPPET="$WORKDIR/jwks-snippet.rs"

log "── PREPARE mode: fetch fresh JWKS from Google + Apple ──"
node tools/fetch-jwks.mjs > "$JWKS_SNIPPET" || die "fetch-jwks failed"
log "fetched snippet ($(wc -l < "$JWKS_SNIPPET") lines)"
grep -q "google_jwks" "$JWKS_SNIPPET" || die "snippet missing google_jwks fn"
grep -q "apple_jwks"  "$JWKS_SNIPPET" || die "snippet missing apple_jwks fn"

# Normalise pub/private visibility to match the existing file's style.
sed -i 's/^pub fn google_jwks/fn google_jwks/; s/^pub fn apple_jwks/fn apple_jwks/' "$JWKS_SNIPPET"

JWKS_SNIPPET="$JWKS_SNIPPET" python3 - <<'PYEOF'
import datetime, os, re, sys
src_path = "enclave/src/pinned_jwks.rs"
with open(src_path) as f:
    src = f.read()
with open(os.environ["JWKS_SNIPPET"]) as f:
    snippet = f.read()
# Replace from first "fn google_jwks" to EOF. current_jwks() and the
# module docs above stay untouched.
m = re.search(r'^fn google_jwks', src, re.M)
if not m:
    sys.exit("could not locate 'fn google_jwks' in pinned_jwks.rs")
head = src[:m.start()]
today = datetime.date.today().isoformat()
head = re.sub(r'^//! Last refreshed:.*$',
              f'//! Last refreshed: {today}. Schedule next refresh for ~+7 days.',
              head, count=1, flags=re.M)
with open(src_path, "w") as f:
    f.write(head + snippet.rstrip() + "\n")
print(f"patched {src_path}")
PYEOF

git --no-pager diff --stat -- enclave/src/pinned_jwks.rs || true
build_and_report

cat <<NEXT

════════════════════════════════════════════════════
 JWKS REFRESH PREPARED (nothing deployed, no KMS change)
════════════════════════════════════════════════════
  Candidate PCR0 : $NEW_PCR0   (built from a DIRTY tree: $BUILT_COMMIT + JWKS patch)

Next (see prod-automation/README.md "Enclave release approval"):
  1. Review + commit enclave/src/pinned_jwks.rs, push, get it merged.
  2. From a clean checkout of the merged commit, rebuild and confirm the
     PCR0 (two independent builds must agree).
  3. An approver publishes BOTH values to SSM:
       aws ssm put-parameter --overwrite --type String \\
         --name /rift/enclave/approved-commit --value <40-hex-sha>
       aws ssm put-parameter --overwrite --type String \\
         --name /rift/enclave/approved-pcr0   --value <96-hex-pcr0>
  4. Invoke the rotation Lambda (or wait for its schedule).
NEXT
