#!/usr/bin/env bash
# Add or remove a PCR0 from BOTH prod KMS keys' hardened policies.
#
# The enclave-attested Decrypt statement's ImageSha384 condition can
# hold either a single string or an array. This script converts to
# array form as needed so you can run an overlap window:
#
#   1. rotate-jwks.sh (on EC2)   → produces NEW_PCR0
#   2. update-kms-pcr0.sh --add NEW_PCR0   (this script, CloudShell)
#      → both PCR0s valid for Decrypt
#   3. restart enclave on EC2 → now signing under NEW_PCR0
#   4. observe for ~24h; if healthy →
#   5. update-kms-pcr0.sh --remove OLD_PCR0
#      → only NEW_PCR0 valid; old one gracefully retired
#
# The overlap window is important: any in-flight sign / decrypt during
# the enclave restart doesn't 401 out.
#
# Environment (overridable):
#   OLD_KMS_KEY_ID  — 3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd (alias/Rift-prod-user-keys)
#   NEW_KMS_KEY_ID  — 4534fc26-ba5d-4f69-92d9-7aa96d8668ea (alias/rift-prod-user-keys)
#   REGION          — us-east-1
#
# Usage:
#   ./update-kms-pcr0.sh --add <96-hex-PCR0>
#   ./update-kms-pcr0.sh --remove <96-hex-PCR0>
#   ./update-kms-pcr0.sh --list

set -euo pipefail
export AWS_PAGER=""

OLD_KMS_KEY_ID="${OLD_KMS_KEY_ID:-3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd}"
NEW_KMS_KEY_ID="${NEW_KMS_KEY_ID:-4534fc26-ba5d-4f69-92d9-7aa96d8668ea}"
REGION="${REGION:-us-east-1}"

# Each key's hardened attested-Decrypt statement uses a slightly different
# Sid — we identify by prefix to be resilient to Sid tweaks.
NEW_KEY_SID_PREFIX="AllowAttestedDecryptFromSignerEnclave"
OLD_KEY_SID_PREFIX="AllowAttestedDecryptFromNewProdEnclave"

usage() {
    cat >&2 <<USAGE
Usage:
  $0 --add    <96-hex-PCR0>
  $0 --remove <96-hex-PCR0>
  $0 --list

Env overrides: OLD_KMS_KEY_ID, NEW_KMS_KEY_ID, REGION
USAGE
    exit 1
}

MODE="${1:-}"
PCR0="${2:-}"

case "$MODE" in
    --add|--remove)
        if [[ ${#PCR0} -ne 96 || ! "$PCR0" =~ ^[0-9a-fA-F]+$ ]]; then
            echo "FATAL: PCR0 must be 96 hex chars, got: '$PCR0'" >&2
            exit 1
        fi
        ;;
    --list) ;;
    *) usage ;;
esac

command -v jq  >/dev/null 2>&1 || { echo "jq required" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "aws cli required" >&2; exit 1; }

fetch_current_pcr0s() {
    local KEY_ID="$1"
    local SID_PREFIX="$2"
    aws kms get-key-policy --region "$REGION" --key-id "$KEY_ID" --policy-name default \
        | jq -r '.Policy' \
        | jq --arg prefix "$SID_PREFIX" '
            .Statement[] | select(.Sid | startswith($prefix))
            | .Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"]
            | if type == "array" then . else [.] end
            | .[]
          '
}

list_all() {
    echo "── $NEW_KMS_KEY_ID (alias/rift-prod-user-keys) ──"
    fetch_current_pcr0s "$NEW_KMS_KEY_ID" "$NEW_KEY_SID_PREFIX" | sed 's/^/  /'
    echo
    echo "── $OLD_KMS_KEY_ID (alias/Rift-prod-user-keys) ──"
    fetch_current_pcr0s "$OLD_KMS_KEY_ID" "$OLD_KEY_SID_PREFIX" | sed 's/^/  /'
}

if [[ "$MODE" == "--list" ]]; then
    list_all
    exit 0
fi

update_key() {
    local KEY_ID="$1"
    local SID_PREFIX="$2"

    echo "── $KEY_ID ──"
    local CUR="/tmp/kms-cur-${KEY_ID}.json"
    local NEW="/tmp/kms-new-${KEY_ID}.json"
    local BACKUP="/tmp/kms-BACKUP-${KEY_ID}-$(date +%s).json"

    aws kms get-key-policy --region "$REGION" --key-id "$KEY_ID" --policy-name default \
        | jq -r '.Policy' > "$CUR"
    cp "$CUR" "$BACKUP"
    echo "  backup: $BACKUP"

    jq --arg pcr0 "$PCR0" --arg prefix "$SID_PREFIX" --arg mode "$MODE" '
        .Statement |= map(
            if (.Sid | startswith($prefix)) then
                (.Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"]) as $existing
                | (
                    if ($existing | type) == "string" then [$existing]
                    elif ($existing | type) == "array" then $existing
                    else []
                    end
                ) as $arr
                | (
                    if $mode == "--add"    then ($arr + [$pcr0] | unique)
                    else                        ($arr - [$pcr0])
                    end
                ) as $updated
                | if ($updated | length) == 0 then
                    error("would leave zero PCR0s on \(.Sid) — refusing")
                  else
                    .Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"] =
                        (if ($updated | length) == 1 then $updated[0] else $updated end)
                  end
            else . end
        )
    ' "$CUR" > "$NEW"

    echo "  target statement after edit:"
    jq --arg prefix "$SID_PREFIX" '.Statement[] | select(.Sid | startswith($prefix))' "$NEW" \
        | sed 's/^/    /'

    aws kms put-key-policy --region "$REGION" --key-id "$KEY_ID" \
        --policy-name default --policy "file://$NEW"
    echo "  ✓ applied"
}

echo "mode: $MODE  pcr0: $PCR0"
echo

update_key "$NEW_KMS_KEY_ID" "$NEW_KEY_SID_PREFIX"
echo
update_key "$OLD_KMS_KEY_ID" "$OLD_KEY_SID_PREFIX"

echo
echo "── verify: currently allowed PCR0s ──"
list_all
echo
echo "✓ done."
