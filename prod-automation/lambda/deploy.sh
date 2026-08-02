#!/usr/bin/env bash
# One-shot deploy of the rift-jwks-rotator Lambda + all its supporting
# resources. Idempotent — re-run to update.
#
# What it creates / updates:
#   1. SNS topic:      rift-jwks-rotation
#   2. IAM policy:     rift-jwks-rotator-policy  (KMS put/get on 2 keys,
#                                                 SSM SendCommand + Get,
#                                                 SNS Publish, CW Logs)
#   3. IAM role:       rift-jwks-rotator-role    (trusted by lambda.amazonaws.com)
#   4. Lambda:         rift-jwks-rotator (python3.11, 5min timeout, 256MB)
#   5. EventBridge:    rift-jwks-rotator-weekly  (Monday 03:00 UTC cron)
#   6. Subscribes YOUR_EMAIL to the SNS topic (unless SKIP_SNS_SUB=1)
#
# Prereqs:
#   - CloudShell (or any workstation with admin AWS creds)
#   - The Python source file rotate-jwks-lambda.py in the SAME directory
#   - Env: EMAIL (your notification email), REGION (default us-east-1)
#
# Usage:
#   EMAIL=you@riftfi.xyz ./deploy.sh
#
#   # Skip email confirmation prompt (won't send SNS-confirm email):
#   SKIP_SNS_SUB=1 ./deploy.sh
#
#   # Fire a test invocation right after deploy:
#   INVOKE_AFTER_DEPLOY=1 EMAIL=... ./deploy.sh

set -euo pipefail
export AWS_PAGER=""

: "${EMAIL:?EMAIL env var required (for SNS subscription)}"
REGION="${REGION:-us-east-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

# ── constants (tuned for the current prod setup) ───────────────────
FUNCTION_NAME="rift-jwks-rotator"
ROLE_NAME="rift-jwks-rotator-role"
POLICY_NAME="rift-jwks-rotator-policy"
SNS_TOPIC_NAME="rift-jwks-rotation"
EVENT_RULE="rift-jwks-rotator-weekly"
LAMBDA_HANDLER="rotate-jwks-lambda.handler"
LAMBDA_RUNTIME="python3.11"
LAMBDA_TIMEOUT=300      # 5 minutes — SSM commands take a while
LAMBDA_MEMORY=256

EC2_INSTANCE_ID="${EC2_INSTANCE_ID:-i-0fa3850b5f3543e16}"
OLD_KMS_KEY_ID="${OLD_KMS_KEY_ID:-3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd}"
NEW_KMS_KEY_ID="${NEW_KMS_KEY_ID:-4534fc26-ba5d-4f69-92d9-7aa96d8668ea}"
ENCLAVE_SRC_DIR="${ENCLAVE_SRC_DIR:-/home/ec2-user/rift/Rift-secure-signing-enclave}"

# Weekly cron: Monday 03:00 UTC
SCHEDULE_EXPR="cron(0 3 ? * MON *)"

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$WORKDIR/rotate-jwks-lambda.py" ]] || {
    echo "FATAL: rotate-jwks-lambda.py missing next to deploy.sh" >&2; exit 1
}

log() { printf "\n[%s] %s\n" "$(date -Is)" "$*"; }

# ── 1. SNS topic ───────────────────────────────────────────────────
log "1/6 SNS topic $SNS_TOPIC_NAME"
SNS_ARN="$(aws sns create-topic --region "$REGION" --name "$SNS_TOPIC_NAME" \
    --query TopicArn --output text)"
echo "   $SNS_ARN"

if [[ "${SKIP_SNS_SUB:-0}" != "1" ]]; then
    # AWS treats identical subscribe calls as idempotent (returns
    # SubscriptionArn = "PendingConfirmation" the first time).
    aws sns subscribe --region "$REGION" \
        --topic-arn "$SNS_ARN" --protocol email --notification-endpoint "$EMAIL" \
        --query SubscriptionArn --output text > /dev/null
    echo "   subscribed $EMAIL — check inbox for confirmation email"
fi

# ── 2. IAM policy ──────────────────────────────────────────────────
log "2/6 IAM policy $POLICY_NAME"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

cat > /tmp/lambda-policy.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KmsAdminScopedToTwoKeys",
      "Effect": "Allow",
      "Action": [
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy"
      ],
      "Resource": [
        "arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/${OLD_KMS_KEY_ID}",
        "arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/${NEW_KMS_KEY_ID}"
      ]
    },
    {
      "Sid": "SsmRunOnEc2",
      "Effect": "Allow",
      "Action": ["ssm:SendCommand"],
      "Resource": [
        "arn:aws:ec2:${REGION}:${ACCOUNT_ID}:instance/${EC2_INSTANCE_ID}",
        "arn:aws:ssm:${REGION}::document/AWS-RunShellScript"
      ]
    },
    {
      "Sid": "SsmReadResults",
      "Effect": "Allow",
      "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      "Resource": "*"
    },
    {
      "Sid": "NotifyViaSns",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "${SNS_ARN}"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:*"
    }
  ]
}
POLICY

if aws iam get-policy --policy-arn "$POLICY_ARN" >/dev/null 2>&1; then
    # Create a new version (max 5; keep only current + one prior)
    aws iam create-policy-version --policy-arn "$POLICY_ARN" \
        --policy-document file:///tmp/lambda-policy.json --set-as-default >/dev/null
    echo "   updated existing policy"
else
    aws iam create-policy --policy-name "$POLICY_NAME" \
        --policy-document file:///tmp/lambda-policy.json >/dev/null
    echo "   created"
fi

# ── 3. IAM role for Lambda ─────────────────────────────────────────
log "3/6 IAM role $ROLE_NAME"

cat > /tmp/trust-policy.json <<TRUST
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
TRUST

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
    echo "   role exists"
else
    aws iam create-role --role-name "$ROLE_NAME" \
        --assume-role-policy-document file:///tmp/trust-policy.json >/dev/null
    echo "   created role"
fi
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo "   $ROLE_ARN"

# IAM needs a moment after role creation before Lambda can assume it.
sleep 8

# ── 4. Lambda function ─────────────────────────────────────────────
log "4/6 Lambda $FUNCTION_NAME"

# Package: single Python file, no dependencies beyond boto3 (built-in).
cd "$WORKDIR"
rm -f /tmp/lambda-pkg.zip
zip -q /tmp/lambda-pkg.zip rotate-jwks-lambda.py

ENV_VARS="Variables={"\
"EC2_INSTANCE_ID=${EC2_INSTANCE_ID},"\
"OLD_KMS_KEY_ID=${OLD_KMS_KEY_ID},"\
"NEW_KMS_KEY_ID=${NEW_KMS_KEY_ID},"\
"ENCLAVE_SRC_DIR=${ENCLAVE_SRC_DIR},"\
"SNS_TOPIC_ARN=${SNS_ARN},"\
"REGION=${REGION}"\
"}"

if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
    aws lambda update-function-code --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --zip-file fileb:///tmp/lambda-pkg.zip >/dev/null
    aws lambda wait function-updated --region "$REGION" --function-name "$FUNCTION_NAME"
    aws lambda update-function-configuration --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --runtime "$LAMBDA_RUNTIME" \
        --handler "$LAMBDA_HANDLER" \
        --timeout "$LAMBDA_TIMEOUT" \
        --memory-size "$LAMBDA_MEMORY" \
        --environment "$ENV_VARS" >/dev/null
    echo "   updated"
else
    aws lambda create-function --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --runtime "$LAMBDA_RUNTIME" \
        --role "$ROLE_ARN" \
        --handler "$LAMBDA_HANDLER" \
        --zip-file fileb:///tmp/lambda-pkg.zip \
        --timeout "$LAMBDA_TIMEOUT" \
        --memory-size "$LAMBDA_MEMORY" \
        --environment "$ENV_VARS" >/dev/null
    aws lambda wait function-active --region "$REGION" --function-name "$FUNCTION_NAME"
    echo "   created"
fi

LAMBDA_ARN="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

# ── 5. EventBridge schedule ────────────────────────────────────────
log "5/6 EventBridge rule $EVENT_RULE ($SCHEDULE_EXPR)"

aws events put-rule --region "$REGION" \
    --name "$EVENT_RULE" \
    --schedule-expression "$SCHEDULE_EXPR" \
    --state ENABLED >/dev/null

# Grant EventBridge permission to invoke Lambda (idempotent).
aws lambda add-permission --region "$REGION" \
    --function-name "$FUNCTION_NAME" \
    --statement-id "AllowEventBridgeInvoke" \
    --action "lambda:InvokeFunction" \
    --principal events.amazonaws.com \
    --source-arn "arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${EVENT_RULE}" \
    2>/dev/null || echo "   invoke permission already set"

aws events put-targets --region "$REGION" \
    --rule "$EVENT_RULE" \
    --targets "Id=1,Arn=${LAMBDA_ARN}" >/dev/null

# ── 6. summary ─────────────────────────────────────────────────────
log "6/6 DONE"
cat <<SUMMARY

════════════════════════════════════════════════════
  rift-jwks-rotator deployed
════════════════════════════════════════════════════
  Lambda      : $LAMBDA_ARN
  Role        : $ROLE_ARN
  SNS         : $SNS_ARN
  Schedule    : $SCHEDULE_EXPR (weekly)
  Rule        : arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${EVENT_RULE}
  Logs        : /aws/lambda/${FUNCTION_NAME}

Next:
  1. Confirm the SNS subscription (email in your inbox from AWS).
  2. Fire a test invocation:

       aws lambda invoke --region ${REGION} \\
         --function-name ${FUNCTION_NAME} \\
         --cli-binary-format raw-in-base64-out \\
         --payload '{}' /tmp/out.json && cat /tmp/out.json

     Watch logs live:
       aws logs tail /aws/lambda/${FUNCTION_NAME} --follow --region ${REGION}

  3. First scheduled run: next Monday 03:00 UTC.
SUMMARY

if [[ "${INVOKE_AFTER_DEPLOY:-0}" == "1" ]]; then
    log "firing test invocation"
    aws lambda invoke --region "$REGION" \
        --function-name "$FUNCTION_NAME" \
        --cli-binary-format raw-in-base64-out \
        --payload '{}' /tmp/lambda-out.json
    echo "── lambda output ──"
    cat /tmp/lambda-out.json
    echo
fi
