#!/usr/bin/env bash
# teardown-provision.sh — remove everything aws-provision.sh created,
# in dependency-safe order, for a given ENV_TAG.
#
# DESTRUCTIVE. Requires an explicit `--yes` OR `TEARDOWN_YES=1` env.
# In prod, requires typing `yes-prod-teardown` at the prompt.
#
# Resources touched (all filtered by tags):
#   * EC2 instance         (rift-env, rift-role)
#   * DLM lifecycle policy (by description)
#   * CloudWatch alarms    (rift-signer-{env}-*)
#   * Security group       (rift-signer-{env}-sg)
#   * Instance profile     (rift-signer-enclave-{env}-instance-profile)
#   * IAM role             (rift-signer-enclave-{env}-role)
#   * Secrets Manager entry (optional)
#   * KMS CMK              → SCHEDULED FOR DELETION (7-day reversible)
#
# What we DON'T touch:
#   * EBS snapshots older than the DLM policy's retention window
#     (they'll expire naturally). Pass DELETE_SNAPSHOTS=1 to wipe them.
#   * Any resource not tagged `rift-env=<env> rift-role=signer-enclave`.
#
# USAGE:
#   ENV_TAG=sandbox AWS_REGION=us-east-1 ./teardown-provision.sh --yes
#   ENV_TAG=prod    AWS_REGION=us-east-1 ./teardown-provision.sh --yes
#   ENV_TAG=sandbox AWS_REGION=us-east-1 DRY_RUN=1 ./teardown-provision.sh

set -Eeuo pipefail
IFS=$'\n\t'

: "${ENV_TAG:?set ENV_TAG=sandbox or prod}"
: "${AWS_REGION:?set AWS_REGION}"
DRY_RUN="${DRY_RUN:-0}"
DELETE_SNAPSHOTS="${DELETE_SNAPSHOTS:-0}"
DELETE_BEARER_SECRET="${DELETE_BEARER_SECRET:-0}"
YES_FLAG="${TEARDOWN_YES:-0}"
[[ "${1:-}" == "--yes" ]] && YES_FLAG=1

case "$ENV_TAG" in
  sandbox|prod) ;;
  *) echo "ENV_TAG must be sandbox or prod" >&2; exit 1 ;;
esac

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

awsx() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '\033[33m[dry-run]\033[0m aws %s\n' "$*" >&2
    return 0
  fi
  aws "$@"
}

export AWS_PAGER=""
command -v aws >/dev/null || die "aws cli not installed"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

if [[ "$DRY_RUN" != "1" ]]; then
  if [[ "$ENV_TAG" == "prod" ]]; then
    warn "─── PROD TEARDOWN ───"
    warn "This will destroy the prod signer enclave stack in account $ACCOUNT_ID region $AWS_REGION."
    read -rp "Type 'yes-prod-teardown' to continue: " confirm
    [[ "$confirm" == "yes-prod-teardown" ]] || die "aborted"
  elif [[ "$YES_FLAG" != "1" ]]; then
    die "Not confirmed. Pass --yes or set TEARDOWN_YES=1."
  fi
fi

ROLE_NAME="rift-signer-enclave-${ENV_TAG}-role"
IP_NAME="rift-signer-enclave-${ENV_TAG}-instance-profile"
KEY_ALIAS="alias/rift-${ENV_TAG}-user-keys"
SG_NAME="rift-signer-${ENV_TAG}-sg"
BEARER_SECRET_NAME="rift-signer-${ENV_TAG}-nginx-bearer"

# ─────────────────────────────────────────────────────────────────
step "1 · terminate EC2 instance(s)"
INSTANCES=$(aws ec2 describe-instances \
  --filters "Name=tag:rift-env,Values=$ENV_TAG" \
            "Name=tag:rift-role,Values=signer-enclave" \
            "Name=instance-state-name,Values=running,pending,stopped,stopping" \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)

if [[ -n "$INSTANCES" ]]; then
  for iid in $INSTANCES; do
    # Prod has termination-protection on — turn it off first, then kill.
    awsx ec2 modify-instance-attribute --instance-id "$iid" \
      --no-disable-api-termination >/dev/null 2>&1 || true
    awsx ec2 modify-instance-attribute --instance-id "$iid" \
      --attribute disableApiStop --value false >/dev/null 2>&1 || true
    log "terminating $iid"
    awsx ec2 terminate-instances --instance-ids "$iid" >/dev/null
  done
  if [[ "$DRY_RUN" != "1" ]]; then
    # shellcheck disable=SC2086  # $INSTANCES is intentionally word-split into separate args
    aws ec2 wait instance-terminated --instance-ids $INSTANCES
  fi
  log "instance(s) terminated"
else
  log "no instances to terminate"
fi

# ─────────────────────────────────────────────────────────────────
step "2 · orphaned EBS volumes (DeleteOnTermination=false leaves these)"
VOLS=$(aws ec2 describe-volumes \
  --filters "Name=tag:rift-env,Values=$ENV_TAG" \
            "Name=tag:rift-role,Values=signer-enclave" \
            "Name=status,Values=available" \
  --query 'Volumes[].VolumeId' --output text 2>/dev/null || true)
if [[ -n "$VOLS" ]]; then
  for v in $VOLS; do
    log "deleting available volume $v"
    awsx ec2 delete-volume --volume-id "$v" >/dev/null || true
  done
else
  log "no orphan volumes"
fi

# ─────────────────────────────────────────────────────────────────
step "3 · EBS snapshots"
if [[ "$DELETE_SNAPSHOTS" == "1" ]]; then
  SNAPS=$(aws ec2 describe-snapshots --owner-ids self \
    --filters "Name=tag:rift-env,Values=$ENV_TAG" \
              "Name=tag:rift-role,Values=signer-enclave" \
    --query 'Snapshots[].SnapshotId' --output text 2>/dev/null || true)
  if [[ -n "$SNAPS" ]]; then
    for s in $SNAPS; do
      log "deleting snapshot $s"
      awsx ec2 delete-snapshot --snapshot-id "$s" >/dev/null || true
    done
  else
    log "no snapshots"
  fi
else
  warn "DELETE_SNAPSHOTS=0 (default). Snapshots stay; they'll age out naturally."
fi

# ─────────────────────────────────────────────────────────────────
step "4 · DLM lifecycle policy"
DLM_DESC="rift-signer-${ENV_TAG}-daily-snapshots"
DLM_IDS=$(aws dlm get-lifecycle-policies \
  --query "Policies[?Description=='$DLM_DESC'].PolicyId" \
  --output text 2>/dev/null || true)
for pid in $DLM_IDS; do
  [[ -z "$pid" || "$pid" == "None" ]] && continue
  log "deleting DLM policy $pid"
  awsx dlm delete-lifecycle-policy --policy-id "$pid" >/dev/null || true
done

# ─────────────────────────────────────────────────────────────────
step "5 · CloudWatch alarms"
for ALARM in \
  "rift-signer-${ENV_TAG}-status-check-failed" \
  "rift-signer-${ENV_TAG}-cpu-high" \
  "rift-signer-${ENV_TAG}-disk-high"; do
  if aws cloudwatch describe-alarms --alarm-names "$ALARM" \
    --query 'MetricAlarms[0].AlarmName' --output text 2>/dev/null | grep -q "$ALARM"; then
    log "deleting alarm $ALARM"
    awsx cloudwatch delete-alarms --alarm-names "$ALARM" >/dev/null || true
  fi
done

# ─────────────────────────────────────────────────────────────────
step "6 · security group"
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
if [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
  # ENIs sometimes take a beat to release the SG after instance term.
  for _ in 1 2 3 4 5; do
    if awsx ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1; then
      log "deleted SG $SG_ID"
      SG_ID=""
      break
    fi
    [[ "$DRY_RUN" == "1" ]] && break
    warn "SG $SG_ID still in use, retrying in 6s"
    sleep 6
  done
  [[ -n "$SG_ID" && "$DRY_RUN" != "1" ]] && warn "could not delete SG $SG_ID — clean up manually"
else
  log "no SG to delete"
fi

# ─────────────────────────────────────────────────────────────────
step "7 · IAM instance profile + role"
if aws iam get-instance-profile --instance-profile-name "$IP_NAME" >/dev/null 2>&1; then
  awsx iam remove-role-from-instance-profile \
    --instance-profile-name "$IP_NAME" --role-name "$ROLE_NAME" >/dev/null 2>&1 || true
  awsx iam delete-instance-profile --instance-profile-name "$IP_NAME" >/dev/null || true
  log "deleted instance profile $IP_NAME"
fi

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  # Detach managed policies + delete inline policies before role delete.
  MANAGED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
    --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)
  for arn in $MANAGED; do
    awsx iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$arn" >/dev/null || true
  done
  INLINE=$(aws iam list-role-policies --role-name "$ROLE_NAME" \
    --query 'PolicyNames' --output text 2>/dev/null || true)
  for name in $INLINE; do
    awsx iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$name" >/dev/null || true
  done
  awsx iam delete-role --role-name "$ROLE_NAME" >/dev/null || true
  log "deleted role $ROLE_NAME"
fi

# ─────────────────────────────────────────────────────────────────
step "8 · Secrets Manager bearer entry"
if [[ "$DELETE_BEARER_SECRET" == "1" ]]; then
  if aws secretsmanager describe-secret --secret-id "$BEARER_SECRET_NAME" >/dev/null 2>&1; then
    # Force-delete with no recovery window since it's a rotatable secret.
    awsx secretsmanager delete-secret --secret-id "$BEARER_SECRET_NAME" \
      --force-delete-without-recovery >/dev/null || true
    log "deleted bearer secret $BEARER_SECRET_NAME"
  fi
else
  warn "DELETE_BEARER_SECRET=0 (default). Bearer secret preserved. Rerun with =1 to wipe."
fi

# ─────────────────────────────────────────────────────────────────
step "9 · KMS CMK — SCHEDULE for deletion (7-day reversible)"
KEY_ID=$(aws kms list-aliases --query "Aliases[?AliasName=='$KEY_ALIAS'].TargetKeyId" \
  --output text 2>/dev/null || true)
if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
  # First delete the alias — otherwise a re-provision can't recreate it.
  awsx kms delete-alias --alias-name "$KEY_ALIAS" >/dev/null || true
  # Then schedule the key for deletion. 7 days is the minimum window,
  # gives ops a chance to cancel if this was a mistake.
  awsx kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 >/dev/null || true
  log "KMS key $KEY_ID scheduled for deletion in 7 days"
  log "  cancel with: aws kms cancel-key-deletion --key-id $KEY_ID"
else
  log "no KMS key to schedule"
fi

# ─────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo " teardown complete — env=$ENV_TAG${DRY_RUN:+ (dry-run)}"
echo "════════════════════════════════════════════════════════════════"
[[ -f "./.aws-provision-${ENV_TAG}.state" && "$DRY_RUN" != "1" ]] && \
  rm -f "./.aws-provision-${ENV_TAG}.state"
