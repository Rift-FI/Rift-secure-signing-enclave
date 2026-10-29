#!/usr/bin/env bash
# aws-provision.sh — laptop-side infra bring-up for a new signer-enclave
# EC2 environment (sandbox or prod).
#
# Idempotent. Safe to re-run — every resource is looked up by name
# before creation.
#
# What it does:
#   1. IAM role  rift-signer-enclave-{env}-role  + instance profile
#   2. Attaches AmazonSSMManagedInstanceCore  (session manager access)
#   3. Attaches a small custom policy allowing kms:Decrypt on the CMK
#   4. Creates a KMS CMK  rift-{env}-user-keys  with a PLACEHOLDER key
#      policy — you MUST edit it to add the PCR0 attestation gate
#      AFTER ec2-bootstrap.sh prints the PCR0. This script deliberately
#      leaves the attestation gate open until you fill it in.
#   5. Creates security group  rift-signer-{env}-sg  (443 from 0/0)
#   6. Launches a Nitro-Enclave-capable EC2 instance and enables
#      enclaves at launch.
#
# What it does NOT do:
#   * Attach the PCR0 attestation condition to the KMS key policy.
#     That happens AFTER ec2-bootstrap.sh runs and prints PCR0.
#   * Point DNS at the instance.
#   * Modify any prod KMS key or IAM role.
#
# USAGE:
#   ENV_TAG=sandbox   AWS_REGION=us-east-1   ./aws-provision.sh
#   ENV_TAG=prod      AWS_REGION=us-east-1   ./aws-provision.sh
#
# ENV OVERRIDES:
#   ENV_TAG            required: sandbox|prod
#   AWS_REGION         required
#   INSTANCE_TYPE      default: c6g.large  (arm64, cheap, enclave-capable)
#   AMI_SSM_PARAM      default: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
#   KEY_NAME           optional: EC2 KeyPair for emergency ssh. Not needed
#                      if you only ever use SSM Session Manager.
#   SUBNET_ID          optional: launch subnet. Default: default subnet.
#   ENCLAVE_REF        git commit SHA (preferred) or release tag of the
#                      signer repo whose ec2-bootstrap.sh the printed
#                      next-steps fetch and build. Required: the bootstrap
#                      is no longer fetched from a moving branch.
#   ENCLAVE_RAW_BASE   raw-content base URL of the signer repo
#                      (default: https://raw.githubusercontent.com/Rift-FI/Rift-secure-signing-enclave)

set -Eeuo pipefail

: "${ENV_TAG:?set ENV_TAG=sandbox or prod}"
: "${AWS_REGION:?set AWS_REGION}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c6g.large}"
AMI_SSM_PARAM="${AMI_SSM_PARAM:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64}"
KEY_NAME="${KEY_NAME:-}"
SUBNET_ID="${SUBNET_ID:-}"
ENCLAVE_REF="${ENCLAVE_REF:-}"
ENCLAVE_RAW_BASE="${ENCLAVE_RAW_BASE:-https://raw.githubusercontent.com/Rift-FI/Rift-secure-signing-enclave}"

case "$ENV_TAG" in
  sandbox|prod) ;;
  *) echo "ENV_TAG must be sandbox or prod" >&2; exit 1 ;;
esac

log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[fatal]\033[0m %s\n' "$*" >&2; exit 1; }
step() { echo; printf '\033[35m━━━ %s ━━━\033[0m\n' "$*"; }

export AWS_PAGER=""

# Fail early (before creating anything) if the bootstrap ref is unpinned.
[[ -n "$ENCLAVE_REF" ]] || die "set ENCLAVE_REF to the signer commit SHA (or release tag) to bootstrap — never a branch"
case "$ENCLAVE_REF" in
  main|master|HEAD) die "ENCLAVE_REF=$ENCLAVE_REF is a moving ref; pin a commit SHA or release tag" ;;
esac

command -v aws >/dev/null || die "aws cli not installed"
aws sts get-caller-identity >/dev/null || die "aws cli not configured / no creds"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
log "account=$ACCOUNT_ID region=$AWS_REGION env=$ENV_TAG type=$INSTANCE_TYPE"

if [[ "$ENV_TAG" == "prod" ]]; then
  warn "you're about to provision PROD infra."
  read -rp "type 'yes-prod' to continue: " confirm
  [[ "$confirm" == "yes-prod" ]] || die "aborted"
fi

ROLE_NAME="rift-signer-enclave-${ENV_TAG}-role"
IP_NAME="rift-signer-enclave-${ENV_TAG}-instance-profile"
KEY_ALIAS="alias/rift-${ENV_TAG}-user-keys"
SG_NAME="rift-signer-${ENV_TAG}-sg"
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/templates" && pwd)"

step "1 · IAM role + instance profile"
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  log "role $ROLE_NAME exists"
else
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TEMPLATE_DIR/iam-trust-policy.json" \
    --description "Rift signer enclave EC2 ($ENV_TAG)" >/dev/null
  log "created role $ROLE_NAME"
fi
aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore >/dev/null || true

if aws iam get-instance-profile --instance-profile-name "$IP_NAME" >/dev/null 2>&1; then
  log "instance profile $IP_NAME exists"
else
  aws iam create-instance-profile --instance-profile-name "$IP_NAME" >/dev/null
  aws iam add-role-to-instance-profile \
    --instance-profile-name "$IP_NAME" --role-name "$ROLE_NAME"
  log "created instance profile $IP_NAME"
  sleep 8   # IAM propagation
fi

step "2 · KMS CMK (placeholder policy — PCR0 gate added later)"
KEY_ARN=$(aws kms list-aliases --query "Aliases[?AliasName=='$KEY_ALIAS'].TargetKeyId" --output text || true)
if [[ -z "$KEY_ARN" || "$KEY_ARN" == "None" ]]; then
  # Placeholder policy: root has admin; role can Decrypt with NO
  # attestation gate yet. This is deliberately loose so bootstrap can
  # complete; you'll tighten it once PCR0 is captured.
  POLICY=$(sed -e "s|__ACCOUNT_ID__|$ACCOUNT_ID|g" \
               -e "s|__ROLE_NAME__|$ROLE_NAME|g" \
               "$TEMPLATE_DIR/kms-key-policy-placeholder.json")
  KEY_ID=$(aws kms create-key \
    --description "Rift signer enclave $ENV_TAG (placeholder policy)" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT \
    --policy "$POLICY" \
    --tags "TagKey=rift-env,TagValue=$ENV_TAG" \
    --query 'KeyMetadata.KeyId' --output text)
  aws kms create-alias --alias-name "$KEY_ALIAS" --target-key-id "$KEY_ID" >/dev/null
  log "created KMS key $KEY_ID as $KEY_ALIAS"
  KEY_ARN="arn:aws:kms:$AWS_REGION:$ACCOUNT_ID:key/$KEY_ID"
  warn "KMS policy has NO attestation gate yet. This is expected."
  warn "You MUST tighten it after PCR0 capture — see PROD-SETUP.md step 5."
else
  KEY_ARN="arn:aws:kms:$AWS_REGION:$ACCOUNT_ID:key/$KEY_ARN"
  log "key already exists: $KEY_ARN"
fi

step "3 · IAM permissions policy — allow kms:Decrypt on the CMK"
PERM_POLICY=$(sed -e "s|__KEY_ARN__|$KEY_ARN|g" \
                   "$TEMPLATE_DIR/iam-permissions-policy.json")
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "AllowKmsDecryptOnRiftCmk" \
  --policy-document "$PERM_POLICY" >/dev/null
log "attached inline kms:Decrypt policy"

step "4 · security group"
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text)
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "Rift signer enclave $ENV_TAG" \
    --vpc-id "$VPC_ID" --query GroupId --output text)
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
  log "created SG $SG_ID (443 open)"
else
  log "SG already exists: $SG_ID"
fi

step "5 · launch EC2 (only if not already running for this env)"
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

  INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI" \
    --instance-type "$INSTANCE_TYPE" \
    --security-group-ids "$SG_ID" \
    --iam-instance-profile "Name=$IP_NAME" \
    --enclave-options Enabled=true \
    --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=2" \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3,DeleteOnTermination=true,Encrypted=true}' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rift-signer-$ENV_TAG},{Key=rift-env,Value=$ENV_TAG},{Key=rift-role,Value=signer-enclave}]" \
    "${SUBNET_ARG[@]}" "${KEY_ARG[@]}" \
    --query 'Instances[0].InstanceId' --output text)
  log "launching $INSTANCE_ID"
  aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
  log "instance is running"
fi

step "6 · summary"
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<SUMMARY

════════════════════════════════════════════════════════════════
 provisioning complete — env=$ENV_TAG
════════════════════════════════════════════════════════════════

  instance id        : $INSTANCE_ID
  public ip          : $PUBLIC_IP
  region             : $AWS_REGION
  role               : $ROLE_NAME
  instance profile   : $IP_NAME
  kms alias          : $KEY_ALIAS
  kms arn            : $KEY_ARN
  security group     : $SG_ID

next steps:

  # A. wait ~60s for SSM agent to register, then jump into the box
  aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION

  # B. once inside, fetch the bootstrap AT THE PINNED REF, review it,
  #    then run it with the same ref (it builds exactly that commit).
  BOOT=\$(mktemp -d)/ec2-bootstrap.sh
  curl -sSf --proto '=https' "$ENCLAVE_RAW_BASE/$ENCLAVE_REF/prod-automation/ec2-bootstrap.sh" -o "\$BOOT"
  less "\$BOOT"     # review before running
  ENV_TAG=$ENV_TAG ENCLAVE_REF=$ENCLAVE_REF bash "\$BOOT"
  # (or copy the file over via SSM if you don't want to publish it yet)

  # C. copy the PCR0 it prints, then tighten the KMS key policy
  #    (PROD-SETUP.md step 5).

SUMMARY
