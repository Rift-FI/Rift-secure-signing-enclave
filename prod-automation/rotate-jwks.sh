#!/usr/bin/env bash
# Refresh Google + Apple JWKS in the enclave, rebuild EIF, capture the
# new PCR0. Runs on the EC2 host.
#
# Google rotates JWKS ~weekly. This should be on a weekly cron (or
# systemd timer). After capturing the new PCR0, run update-kms-pcr0.sh
# from CloudShell to add it to both KMS keys with an overlap window.
# Once verified the new enclave signs correctly, graduate the old
# PCR0 out with `update-kms-pcr0.sh --remove <old-pcr0>`.
#
# What it does, in order:
#   1. Runs tools/fetch-jwks.mjs to fetch fresh Google + Apple keys.
#   2. Sanity-checks the emitted snippet.
#   3. Backs up the current pinned_jwks.rs.
#   4. Patches pinned_jwks.rs — replaces everything from `fn google_jwks`
#      to EOF with the fresh snippet (the two functions live at the tail
#      of the file, in that order).
#   5. Rebuilds the Docker image + EIF via `make eif`.
#   6. Captures the new PCR0 via `make pcr0` and validates length.
#   7. Reports what to do next (KMS policy add + enclave restart).
#
# Environment:
#   ENCLAVE_SRC   — path to enclave repo (default: $HOME/rift/Rift-secure-signing-enclave)
#
# Usage:
#   ./rotate-jwks.sh 2>&1 | tee /var/log/rift-jwks-rotation.log

set -euo pipefail

ENCLAVE_SRC="${ENCLAVE_SRC:-$HOME/rift/Rift-secure-signing-enclave}"
JWKS_SNIPPET="/tmp/jwks-snippet-$(date +%s).rs"
BACKUP_STAMP="$(date +%Y%m%d-%H%M%S)"

log() { printf "[%s] %s\n" "$(date -Is)" "$*"; }
die() { printf "\n[FATAL] %s\n" "$*" >&2; exit 1; }

cd "$ENCLAVE_SRC" 2>/dev/null || die "enclave repo not at $ENCLAVE_SRC"

command -v node >/dev/null 2>&1 || die "node required (for tools/fetch-jwks.mjs)"
command -v jq   >/dev/null 2>&1 || die "jq required"
[[ -f tools/fetch-jwks.mjs ]] || die "tools/fetch-jwks.mjs missing"
[[ -f enclave/src/pinned_jwks.rs ]] || die "enclave/src/pinned_jwks.rs missing"

log "── STEP 1: fetch fresh JWKS from Google + Apple ──"
node tools/fetch-jwks.mjs > "$JWKS_SNIPPET" || die "fetch-jwks failed"
log "wrote $JWKS_SNIPPET ($(wc -l < "$JWKS_SNIPPET") lines)"

grep -q "google_jwks" "$JWKS_SNIPPET" || die "snippet missing google_jwks fn"
grep -q "apple_jwks"  "$JWKS_SNIPPET" || die "snippet missing apple_jwks fn"

log "── STEP 2: back up + patch pinned_jwks.rs ──"
cp enclave/src/pinned_jwks.rs "enclave/src/pinned_jwks.rs.bak-$BACKUP_STAMP"
log "backup: enclave/src/pinned_jwks.rs.bak-$BACKUP_STAMP"

# Normalise pub/private visibility to match the existing file's style
# (google_jwks and apple_jwks are file-private in pinned_jwks.rs; the
# public entry point is current_jwks() which stays put).
sed -i 's/^pub fn google_jwks/fn google_jwks/; s/^pub fn apple_jwks/fn apple_jwks/' "$JWKS_SNIPPET"

python3 - <<PYEOF
import re, sys
src_path = "enclave/src/pinned_jwks.rs"
snippet_path = "$JWKS_SNIPPET"
with open(src_path) as f:
    src = f.read()
with open(snippet_path) as f:
    snippet = f.read()
# Replace from first "fn google_jwks" to EOF. current_jwks() and the
# module docs above stay untouched.
m = re.search(r'^fn google_jwks', src, re.M)
if not m:
    sys.exit("could not locate 'fn google_jwks' in pinned_jwks.rs")
head = src[:m.start()]
# Also refresh the "Last refreshed:" comment line above (if present)
import datetime
today = datetime.date.today().isoformat()
head = re.sub(
    r'^//! Last refreshed:.*$',
    f'//! Last refreshed: {today}. Schedule next refresh for ~+7 days.',
    head, count=1, flags=re.M
)
new = head + snippet.rstrip() + "\n"
with open(src_path, "w") as f:
    f.write(new)
print(f"patched {src_path}: {len(head)} bytes preserved, {len(snippet)} bytes replaced tail")
PYEOF

log "── STEP 3: rebuild EIF ──"
sudo make eif 2>&1 | tail -6

log "── STEP 4: capture new PCR0 ──"
NEW_PCR0="$(sudo make pcr0 | tr -d '[:space:]')"
[[ ${#NEW_PCR0} -eq 96 ]] || die "PCR0 wrong length (${#NEW_PCR0}, want 96): $NEW_PCR0"
log "new PCR0: $NEW_PCR0"

OLD_PCR0="$(sudo nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].Measurements.PCR0 // empty')"
log "currently-running PCR0: ${OLD_PCR0:-<no enclave running>}"

# Persist for follow-up scripts
STATE_FILE="$HOME/rift/jwks-rotation-state.json"
mkdir -p "$(dirname "$STATE_FILE")"
cat > "$STATE_FILE" <<JSON
{
  "rotated_at": "$(date -Is)",
  "new_pcr0": "$NEW_PCR0",
  "old_pcr0": "${OLD_PCR0:-null}",
  "backup_file": "enclave/src/pinned_jwks.rs.bak-$BACKUP_STAMP"
}
JSON
log "state: $STATE_FILE"

echo
echo "════════════════════════════════════════════════════"
echo " JWKS ROTATION READY"
echo "════════════════════════════════════════════════════"
echo "  Old PCR0 : ${OLD_PCR0:-<none>}"
echo "  New PCR0 : $NEW_PCR0"
echo
echo "── NEXT: in CloudShell (has admin KMS perms), run: ──"
echo
echo "    ./update-kms-pcr0.sh --add $NEW_PCR0"
echo
echo "That adds the new PCR0 to BOTH KMS keys' policies (keeping the"
echo "old one for an overlap window)."
echo
echo "── THEN: back on this EC2, restart the enclave: ──"
echo
echo "    cd $ENCLAVE_SRC && sudo make kill && sudo make run"
echo "    # If the new enclave-cid differs, bump ENCLAVE_CID in"
echo "    # /etc/rift-parent-proxy.env and 'sudo systemctl restart rift-parent-proxy'"
echo
echo "── LATER (after ~24h overlap window): graduate old PCR0 out ──"
echo
if [[ -n "$OLD_PCR0" ]]; then
    echo "    ./update-kms-pcr0.sh --remove $OLD_PCR0"
fi
