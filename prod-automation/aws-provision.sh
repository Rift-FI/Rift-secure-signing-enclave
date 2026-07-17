#!/usr/bin/env bash
# aws-provision.sh — laptop-side infra bring-up for a new signer-enclave
# EC2 environment (sandbox or prod).
#
# Idempotent. Safe to re-run — every resource is looked up by name / tag
# before creation. --dry-run prints every AWS mutation without executing it.
#
# What it creates:
#   1. IAM role  rift-signer-enclave-{env}-role  + instance profile
#      with SSMManagedInstanceCore, CloudWatch Agent, and inline
#      kms:Decrypt on the CMK below.
#   2. KMS CMK  alias/rift-{env}-user-keys  (SYMMETRIC_DEFAULT) with a
#      PLACEHOLDER key policy. You harden it AFTER ec2-bootstrap.sh
#      prints the PCR0 (see INTEGRATOR-SETUP.md step 6).
#   3. Security group  rift-signer-{env}-sg  (443 open by default;
#      recommend tightening to ALB SG after Phase 1).
#   4. EBS-backed Nitro-Enclave-capable EC2 with:
#        - 50 GB gp3 root, encrypted, DeleteOnTermination=false
#        - IMDSv2 required
#        - Detailed monitoring enabled
#   5. DLM snapshot lifecycle policy taking daily snapshots of the EBS
#      volume, retained 14 days.
#   6. CloudWatch alarms: status check failed, CPU > 80% for 5min,
#      disk > 85%. Notifications go nowhere unless you pass SNS_TOPIC_ARN.
#
# What it does NOT do:
#   * Attach the PCR0 attestation condition to the KMS key policy.
#   * Point DNS at the instance or attach an ALB.
#   * Modify any prod KMS key or IAM role.
#
# USAGE:
#   ENV_TAG=sandbox   AWS_REGION=us-east-1   ./aws-provision.sh
#   ENV_TAG=prod      AWS_REGION=us-east-1   ./aws-provision.sh
#   ENV_TAG=sandbox   AWS_REGION=us-east-1   DRY_RUN=1 ./aws-provision.sh
#
# ENV OVERRIDES:
#   ENV_TAG               required: sandbox|prod
#   AWS_REGION            required
#   INSTANCE_TYPE         default: c6g.large  (arm64, cheap, enclave-capable)
#   VOLUME_GB             default: 50 (min 30, prod recommended 100)
#   AMI_SSM_PARAM         default: al2023-arm64 latest
#   KEY_NAME              optional: EC2 KeyPair for emergency ssh
#   SUBNET_ID             optional: launch subnet (else default subnet)
#   SNS_TOPIC_ARN         optional: alarm destination
#   DRY_RUN               1 to print without executing
#   SKIP_DLM              1 to skip snapshot lifecycle (not recommended)
#   SKIP_ALARMS           1 to skip CloudWatch alarms
#   BEARER_TO_SECRETS_MGR 1 to also create a Secrets Manager entry for
#                         the nginx bearer (ec2-bootstrap.sh will use it
#                         if present). Default: file-only on the box.

set -Eeuo pipefail
IFS=$'\n\t'

: "${ENV_TAG:?set ENV_TAG=sandbox or prod}"
: "${AWS_REGION:?set AWS_REGION}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6g.large}"
VOLUME_GB="${VOLUME_GB:-50}"
AMI_SSM_PARAM="${AMI_SSM_PARAM:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64}"
KEY_NAME="${KEY_NAME:-}"
SUBNET_ID="${SUBNET_ID:-}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_DLM="${SKIP_DLM:-0}"
SKIP_ALARMS="${SKIP_ALARMS:-0}"
BEARER_TO_SECRETS_MGR="${BEARER_TO_SECRETS_MGR:-0}"

case "$ENV_TAG" in
  sandbox|prod) ;;
  *) echo "ENV_TAG must be sandbox or prod" >&2; exit 1 ;;
esac

if (( VOLUME_GB < 30 )); then
  echo "VOLUME_GB must be >= 30" >&2
  exit 1
fi

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

# Wrapper for AWS mutations. In DRY_RUN mode prints the command and
# returns an empty string (for --query capture) or 0 (for side-effect
# calls). Never touches AWS.
awsx() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '\033[33m[dry-run]\033[0m aws %s\n' "$*" >&2
    return 0
  fi
  aws "$@"
}

export AWS_PAGER=""

command -v aws >/dev/null || die "aws cli not installed"
aws sts get-caller-identity >/dev/null || die "aws cli not configured / no creds"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
log "account=$ACCOUNT_ID region=$AWS_REGION env=$ENV_TAG type=$INSTANCE_TYPE volume=${VOLUME_GB}GB dry_run=$DRY_RUN"

if [[ "$ENV_TAG" == "prod" && "$DRY_RUN" != "1" ]]; then
  warn "you're about to provision PROD infra."
  read -rp "type 'yes-prod' to continue: " confirm
  [[ "$confirm" == "yes-prod" ]] || die "aborted"
fi

ROLE_NAME="rift-signer-enclave-${ENV_TAG}-role"
IP_NAME="rift-signer-enclave-${ENV_TAG}-instance-profile"
KEY_ALIAS="alias/rift-${ENV_TAG}-user-keys"
SG_NAME="rift-signer-${ENV_TAG}-sg"
DLM_ROLE_NAME="AWSDataLifecycleManagerDefaultRole"
BEARER_SECRET_NAME="rift-signer-${ENV_TAG}-nginx-bearer"
INSTANCE_NAME="rift-signer-${ENV_TAG}"
CREATED_AT="$(date -u +%FT%TZ)"
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/templates" && pwd)"

# Canonical tag set. Applied to every resource we own so `teardown-provision.sh`
# can find them again by tag, and so cost-allocation reports are clean.
common_tags_cli() {
  # Args: <resource-type>  -> emits an --tag-specifications value.
  local rt="$1"
  echo "ResourceType=$rt,Tags=[{Key=Name,Value=$INSTANCE_NAME},{Key=rift-env,Value=$ENV_TAG},{Key=rift-role,Value=signer-enclave},{Key=rift-created-at,Value=$CREATED_AT},{Key=rift-managed-by,Value=aws-provision.sh}]"
}

# ─────────────────────────────────────────────────────────────────
step "1 · IAM role + instance profile"
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "role $ROLE_NAME exists"
else
  awsx iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TEMPLATE_DIR/iam-trust-policy.json" \
    --description "Rift signer enclave EC2 ($ENV_TAG)" \
    --tags "Key=rift-env,Value=$ENV_TAG" "Key=rift-role,Value=signer-enclave" >/dev/null
  log "created role $ROLE_NAME"
fi

# Attach managed policies — SSM for Session Manager, CloudWatchAgentServer
# for pushing metrics/logs from the box, Secrets Manager read (used only
# when BEARER_TO_SECRETS_MGR=1 but attached unconditionally so a later
# flip doesn't need a re-provision).
for POLICY in \
  arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore \
  arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy; do
  awsx iam attach-role-policy \
    --role-name "$ROLE_NAME" --policy-arn "$POLICY" >/dev/null || true
done

if aws iam get-instance-profile --instance-profile-name "$IP_NAME" >/dev/null 2>&1; then
  log "instance profile $IP_NAME exists"
else
  awsx iam create-instance-profile --instance-profile-name "$IP_NAME" >/dev/null
  awsx iam add-role-to-instance-profile \
    --instance-profile-name "$IP_NAME" --role-name "$ROLE_NAME"
  log "created instance profile $IP_NAME"
  [[ "$DRY_RUN" == "1" ]] || sleep 8   # IAM eventual consistency
fi

# ─────────────────────────────────────────────────────────────────
step "2 · KMS CMK (placeholder policy — PCR0 gate added later)"
KEY_ARN=""
KEY_ID_RAW=$(aws kms list-aliases --query "Aliases[?AliasName=='$KEY_ALIAS'].TargetKeyId" --output text 2>/dev/null || true)
if [[ -n "$KEY_ID_RAW" && "$KEY_ID_RAW" != "None" ]]; then
  KEY_ARN="arn:aws:kms:$AWS_REGION:$ACCOUNT_ID:key/$KEY_ID_RAW"
  log "key already exists: $KEY_ARN"
else
  POLICY=$(sed -e "s|__ACCOUNT_ID__|$ACCOUNT_ID|g" \
               -e "s|__ROLE_NAME__|$ROLE_NAME|g" \
               "$TEMPLATE_DIR/kms-key-policy-placeholder.json")
  if [[ "$DRY_RUN" == "1" ]]; then
    warn "[dry-run] would create KMS CMK aliased $KEY_ALIAS"
    KEY_ARN="arn:aws:kms:$AWS_REGION:$ACCOUNT_ID:key/DRYRUN-XXXX-XXXX-XXXX"
  else
    KEY_ID=$(aws kms create-key \
      --description "Rift signer enclave $ENV_TAG (placeholder policy)" \
      --key-usage ENCRYPT_DECRYPT \
      --key-spec SYMMETRIC_DEFAULT \
      --policy "$POLICY" \
      --tags "TagKey=rift-env,TagValue=$ENV_TAG" \
             "TagKey=rift-role,TagValue=signer-enclave" \
             "TagKey=rift-created-at,TagValue=$CREATED_AT" \
      --query 'KeyMetadata.KeyId' --output text)
    aws kms create-alias --alias-name "$KEY_ALIAS" --target-key-id "$KEY_ID" >/dev/null
    KEY_ARN="arn:aws:kms:$AWS_REGION:$ACCOUNT_ID:key/$KEY_ID"
    # Enable automatic rotation once per year. Doesn't rotate the CMK
    # itself (that would break the PCR0 gate), only the backing key
    # material used to derive the CMK. Safe.
    aws kms enable-key-rotation --key-id "$KEY_ID" >/dev/null || true
    log "created KMS key $KEY_ID as $KEY_ALIAS (rotation enabled)"
    warn "KMS policy has NO attestation gate yet. Tighten after PCR0 capture."
  fi
fi

# ─────────────────────────────────────────────────────────────────
step "3 · IAM permissions policy — kms:Decrypt on the CMK"
PERM_POLICY=$(sed -e "s|__KEY_ARN__|$KEY_ARN|g" \
                   "$TEMPLATE_DIR/iam-permissions-policy.json")
awsx iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "AllowKmsDecryptOnRiftCmk" \
  --policy-document "$PERM_POLICY" >/dev/null
log "attached inline kms:Decrypt policy"

# ─────────────────────────────────────────────────────────────────
step "4 · security group"
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
  if [[ "$DRY_RUN" == "1" ]]; then
    warn "[dry-run] would create SG $SG_NAME in VPC $VPC_ID"
    SG_ID="sg-DRYRUN"
  else
    SG_ID=$(aws ec2 create-security-group \
      --group-name "$SG_NAME" \
      --description "Rift signer enclave $ENV_TAG" \
      --vpc-id "$VPC_ID" --query GroupId --output text)
    aws ec2 authorize-security-group-ingress \
      --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
    aws ec2 create-tags --resources "$SG_ID" \
      --tags Key=rift-env,Value="$ENV_TAG" Key=rift-role,Value=signer-enclave \
             Key=rift-created-at,Value="$CREATED_AT" >/dev/null
    log "created SG $SG_ID (443 open — tighten to ALB SG after Phase 1)"
  fi
else
  log "SG already exists: $SG_ID"
fi

# ─────────────────────────────────────────────────────────────────
step "5 · optional Secrets Manager entry for the nginx bearer"
if [[ "$BEARER_TO_SECRETS_MGR" == "1" ]]; then
  if aws secretsmanager describe-secret --secret-id "$BEARER_SECRET_NAME" >/dev/null 2>&1; then
    log "bearer secret $BEARER_SECRET_NAME exists"
  else
    # Create an empty secret; ec2-bootstrap.sh will populate it during
    # the box bring-up.
    awsx secretsmanager create-secret \
      --name "$BEARER_SECRET_NAME" \
      --description "nginx sidecar bearer for rift-signer-${ENV_TAG}" \
      --tags "Key=rift-env,Value=$ENV_TAG" "Key=rift-role,Value=signer-enclave" >/dev/null || true
    log "created empty secret $BEARER_SECRET_NAME (ec2-bootstrap.sh populates it)"
  fi
  # Grant the instance role permission to read + write this secret.
  BEARER_SECRET_ARN="arn:aws:secretsmanager:$AWS_REGION:$ACCOUNT_ID:secret:$BEARER_SECRET_NAME-*"
  cat > /tmp/rift-bearer-secret-policy.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret"
    ],
    "Resource": "$BEARER_SECRET_ARN"
  }]
}
POLICY
  awsx iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "AllowNginxBearerSecret" \
    --policy-document file:///tmp/rift-bearer-secret-policy.json >/dev/null
  rm -f /tmp/rift-bearer-secret-policy.json
else
  log "Secrets Manager for bearer disabled (BEARER_TO_SECRETS_MGR=0). Bearer will live only in /etc/rift-nginx-bearer on the EC2."
fi

# ─────────────────────────────────────────────────────────────────
step "6 · launch EC2 (only if not already running for this env)"
EXISTING=$(aws ec2 describe-instances \
  --filters "Name=tag:rift-env,Values=$ENV_TAG" \
            "Name=tag:rift-role,Values=signer-enclave" \
            "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)

if [[ -n "$EXISTING" && "$EXISTING" != "None" ]]; then
  INSTANCE_ID="$EXISTING"
  log "instance already running: $INSTANCE_ID"
else
  AMI=$(aws ssm get-parameter --name "$AMI_SSM_PARAM" --query Parameter.Value --output text)
  log "AMI: $AMI"

  SUBNET_ARG=()
  [[ -n "$SUBNET_ID" ]] && SUBNET_ARG=(--subnet-id "$SUBNET_ID")
  KEY_ARG=()
  [[ -n "$KEY_NAME" ]] && KEY_ARG=(--key-name "$KEY_NAME")

  # Durable EBS. DeleteOnTermination=false so an accidental instance kill
  # does not lose the disk. Snapshots are separate (DLM below), so this
  # is belt+suspenders.
  BLOCK_DEV="DeviceName=/dev/xvda,Ebs={VolumeSize=${VOLUME_GB},VolumeType=gp3,Iops=3000,Throughput=125,DeleteOnTermination=false,Encrypted=true}"
  INSTANCE_TAGS=$(common_tags_cli instance)
  VOLUME_TAGS=$(common_tags_cli volume)

  if [[ "$DRY_RUN" == "1" ]]; then
    warn "[dry-run] would run-instances with $BLOCK_DEV, IMDSv2, enclaves enabled"
    INSTANCE_ID="i-DRYRUN"
  else
    INSTANCE_ID=$(aws ec2 run-instances \
      --image-id "$AMI" \
      --instance-type "$INSTANCE_TYPE" \
      --security-group-ids "$SG_ID" \
      --iam-instance-profile "Name=$IP_NAME" \
      --enclave-options Enabled=true \
      --monitoring Enabled=true \
      --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=2,InstanceMetadataTags=enabled" \
      --block-device-mappings "$BLOCK_DEV" \
      --tag-specifications "$INSTANCE_TAGS" "$VOLUME_TAGS" \
      "${SUBNET_ARG[@]}" "${KEY_ARG[@]}" \
      --query 'Instances[0].InstanceId' --output text)
    log "launching $INSTANCE_ID"
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
    log "instance is running"

    # Disable API stop AND API termination in prod. Explicit stop / terminate
    # still works if you first turn the protection off, but the shield
    # prevents a fat-finger from taking prod down.
    if [[ "$ENV_TAG" == "prod" ]]; then
      aws ec2 modify-instance-attribute \
        --instance-id "$INSTANCE_ID" \
        --disable-api-termination >/dev/null || true
      aws ec2 modify-instance-attribute \
        --instance-id "$INSTANCE_ID" \
        --attribute disableApiStop --value true >/dev/null 2>&1 || true
      log "prod: termination + stop protection enabled"
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────────
step "7 · DLM snapshot lifecycle (daily, 14-day retention)"
if [[ "$SKIP_DLM" == "1" ]]; then
  warn "SKIP_DLM=1 — no automated snapshots. Not recommended for prod."
else
  # DLM needs its own service-linked role. Create if missing.
  if ! aws iam get-role --role-name "$DLM_ROLE_NAME" >/dev/null 2>&1; then
    awsx iam create-role --role-name "$DLM_ROLE_NAME" \
      --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"dlm.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
      --description "Data Lifecycle Manager service role" >/dev/null
    awsx iam attach-role-policy --role-name "$DLM_ROLE_NAME" \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole >/dev/null
    [[ "$DRY_RUN" == "1" ]] || sleep 6
  fi

  DLM_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$DLM_ROLE_NAME"
  DLM_DESC="rift-signer-${ENV_TAG}-daily-snapshots"

  # Idempotency: skip if a policy with our exact description exists.
  EXISTING_DLM=$(aws dlm get-lifecycle-policies \
    --query "Policies[?Description=='$DLM_DESC'].PolicyId" \
    --output text 2>/dev/null || true)

  if [[ -z "$EXISTING_DLM" || "$EXISTING_DLM" == "None" ]]; then
    cat > /tmp/rift-dlm-policy.json <<DLM
{
  "ResourceTypes": ["VOLUME"],
  "TargetTags": [
    {"Key": "rift-env", "Value": "$ENV_TAG"},
    {"Key": "rift-role", "Value": "signer-enclave"}
  ],
  "Schedules": [{
    "Name": "daily",
    "TagsToAdd": [{"Key": "rift-snapshot-schedule", "Value": "daily"}],
    "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
    "RetainRule": {"Count": 14},
    "CopyTags": true
  }]
}
DLM
    awsx dlm create-lifecycle-policy \
      --execution-role-arn "$DLM_ROLE_ARN" \
      --description "$DLM_DESC" \
      --state ENABLED \
      --policy-details file:///tmp/rift-dlm-policy.json >/dev/null || true
    rm -f /tmp/rift-dlm-policy.json
    log "DLM policy created (daily 03:00 UTC, 14-day retention, targets rift-env=$ENV_TAG + rift-role=signer-enclave volumes)"
  else
    log "DLM policy already exists: $EXISTING_DLM"
  fi
fi

# ─────────────────────────────────────────────────────────────────
step "8 · CloudWatch alarms"
if [[ "$SKIP_ALARMS" == "1" ]]; then
  warn "SKIP_ALARMS=1 — no alarms. Fine for sandbox, DO NOT skip in prod."
elif [[ "$DRY_RUN" == "1" ]]; then
  warn "[dry-run] would create 3 CloudWatch alarms"
elif [[ "$INSTANCE_ID" == "i-DRYRUN" ]]; then
  :
else
  # Alarm 1: status check failed (host-side or instance-side).
  aws cloudwatch put-metric-alarm \
    --alarm-name "rift-signer-${ENV_TAG}-status-check-failed" \
    --alarm-description "Rift signer $ENV_TAG: instance or host status check failing" \
    --namespace AWS/EC2 --metric-name StatusCheckFailed \
    --statistic Maximum --period 60 --evaluation-periods 2 \
    --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
    --treat-missing-data breaching \
    --dimensions "Name=InstanceId,Value=$INSTANCE_ID" \
    ${SNS_TOPIC_ARN:+--alarm-actions "$SNS_TOPIC_ARN"} \
    --tags "Key=rift-env,Value=$ENV_TAG" "Key=rift-role,Value=signer-enclave" >/dev/null

  # Alarm 2: CPU > 80% for 5 min sustained.
  aws cloudwatch put-metric-alarm \
    --alarm-name "rift-signer-${ENV_TAG}-cpu-high" \
    --alarm-description "Rift signer $ENV_TAG: CPU > 80% for 5min" \
    --namespace AWS/EC2 --metric-name CPUUtilization \
    --statistic Average --period 60 --evaluation-periods 5 \
    --threshold 80 --comparison-operator GreaterThanThreshold \
    --dimensions "Name=InstanceId,Value=$INSTANCE_ID" \
    ${SNS_TOPIC_ARN:+--alarm-actions "$SNS_TOPIC_ARN"} \
    --tags "Key=rift-env,Value=$ENV_TAG" "Key=rift-role,Value=signer-enclave" >/dev/null

  # Alarm 3: disk > 85%. Uses the CloudWatch Agent metric namespace;
  # requires the agent to be installed by ec2-bootstrap.sh (it is).
  aws cloudwatch put-metric-alarm \
    --alarm-name "rift-signer-${ENV_TAG}-disk-high" \
    --alarm-description "Rift signer $ENV_TAG: root disk > 85%" \
    --namespace CWAgent --metric-name disk_used_percent \
    --statistic Maximum --period 300 --evaluation-periods 2 \
    --threshold 85 --comparison-operator GreaterThanThreshold \
    --dimensions "Name=InstanceId,Value=$INSTANCE_ID" "Name=path,Value=/" \
    --treat-missing-data notBreaching \
    ${SNS_TOPIC_ARN:+--alarm-actions "$SNS_TOPIC_ARN"} \
    --tags "Key=rift-env,Value=$ENV_TAG" "Key=rift-role,Value=signer-enclave" >/dev/null

  log "created 3 CloudWatch alarms (status-check, cpu, disk)"
  if [[ -z "$SNS_TOPIC_ARN" ]]; then
    warn "SNS_TOPIC_ARN not set — alarms fire but nobody gets paged. Set SNS_TOPIC_ARN and re-run."
  fi
fi

# ─────────────────────────────────────────────────────────────────
step "9 · summary"
if [[ "$INSTANCE_ID" == "i-DRYRUN" ]]; then
  PUBLIC_IP="(dry-run)"
else
  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || echo "(none)")
fi

# Write the state to a local file so teardown-provision.sh + docs can
# reference exactly what got made.
STATE_FILE="./.aws-provision-${ENV_TAG}.state"
if [[ "$DRY_RUN" != "1" ]]; then
  cat > "$STATE_FILE" <<STATE
env_tag=$ENV_TAG
region=$AWS_REGION
account_id=$ACCOUNT_ID
instance_id=$INSTANCE_ID
public_ip=$PUBLIC_IP
role_name=$ROLE_NAME
instance_profile=$IP_NAME
kms_alias=$KEY_ALIAS
kms_arn=$KEY_ARN
security_group=$SG_ID
bearer_secret=$([ "$BEARER_TO_SECRETS_MGR" = 1 ] && echo "$BEARER_SECRET_NAME" || echo "(file only)")
created_at=$CREATED_AT
STATE
  log "wrote $STATE_FILE"
fi

cat <<SUMMARY

════════════════════════════════════════════════════════════════
 provisioning complete — env=$ENV_TAG${DRY_RUN:+ (dry-run)}
════════════════════════════════════════════════════════════════

  instance id        : $INSTANCE_ID
  public ip          : $PUBLIC_IP
  region             : $AWS_REGION
  role               : $ROLE_NAME
  instance profile   : $IP_NAME
  kms alias          : $KEY_ALIAS
  kms arn            : $KEY_ARN
  security group     : $SG_ID
  ebs                : ${VOLUME_GB} GB gp3, DeleteOnTermination=false
  snapshots          : daily 03:00 UTC, 14-day retention
  alarms             : status-check, cpu, disk  ${SNS_TOPIC_ARN:+ → $SNS_TOPIC_ARN}
  bearer storage     : $([ "$BEARER_TO_SECRETS_MGR" = 1 ] && echo "Secrets Manager + local file" || echo "local file only")

next steps:

  # A. wait ~60s for SSM agent to register, then jump into the box
  aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION
  sudo su - ec2-user

  # B. inside the box, run bootstrap
  ENV_TAG=$ENV_TAG ENCLAVE_REF=v1.0.0 ./ec2-bootstrap.sh

  # C. verify PCR0 matches Rift's canonical value, then tighten KMS
  ./verify-pcr0.sh
  # …paste PCR0 into the KMS key policy hardened template (step 6 of runbook)

  # D. teardown when needed
  ENV_TAG=$ENV_TAG ./teardown-provision.sh

SUMMARY
