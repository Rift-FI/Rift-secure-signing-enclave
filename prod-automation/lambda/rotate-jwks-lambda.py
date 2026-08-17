"""
Weekly JWKS rotator for the Rift signing enclave.

Runs on a Monday-03:00-UTC EventBridge schedule. End-to-end:
  1. SSM-run rotate-jwks.sh on the EC2, extract new PCR0 from output.
  2. Add the new PCR0 to both KMS keys' hardened attested-Decrypt policies
     (keeping the old one for now — overlap window).
  3. SSM-run: kill old enclave, start new one, bump parent-proxy's
     ENCLAVE_CID, restart parent-proxy.
  4. SSM-run: curl the parent-proxy /health through nginx with the bearer
     — proves the new enclave signs.
  5. If verified: remove old PCR0 from both KMS policies (graduate).
     If not: SNS-alert and leave the overlap window intact for a human
     to sort out.
  6. Publish success / failure to SNS regardless.

Environment (Lambda config vars):
  EC2_INSTANCE_ID      — i-0fa3850b5f3543e16
  ENCLAVE_SRC_DIR      — /home/ec2-user/rift/Rift-secure-signing-enclave
  OLD_KMS_KEY_ID       — 3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd
  NEW_KMS_KEY_ID       — 4534fc26-ba5d-4f69-92d9-7aa96d8668ea
  SNS_TOPIC_ARN        — arn:aws:sns:us-east-1:957814222213:rift-jwks-rotation
  NEW_KEY_SID_PREFIX   — AllowAttestedDecryptFromSignerEnclave
  OLD_KEY_SID_PREFIX   — AllowAttestedDecryptFromNewProdEnclave
  REGION               — us-east-1
"""

import json
import os
import re
import time
import logging
import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

REGION = os.environ.get("REGION", "us-east-1")
INSTANCE_ID = os.environ["EC2_INSTANCE_ID"]
ENCLAVE_DIR = os.environ.get(
    "ENCLAVE_SRC_DIR", "/home/ec2-user/rift/Rift-secure-signing-enclave"
)
OLD_KEY = os.environ["OLD_KMS_KEY_ID"]
NEW_KEY = os.environ["NEW_KMS_KEY_ID"]
SNS_ARN = os.environ["SNS_TOPIC_ARN"]
NEW_KEY_SID = os.environ.get(
    "NEW_KEY_SID_PREFIX", "AllowAttestedDecryptFromSignerEnclave"
)
OLD_KEY_SID = os.environ.get(
    "OLD_KEY_SID_PREFIX", "AllowAttestedDecryptFromNewProdEnclave"
)

ssm = boto3.client("ssm", region_name=REGION)
kms = boto3.client("kms", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)


def ssm_run(commands: list[str], timeout: int = 900) -> tuple[str, str]:
    """
    Fire a shell command batch on the EC2 via SSM Run Command, wait for
    completion, return (stdout, stderr). Raises RuntimeError on failure
    so the calling handler can catch + notify.
    """
    log.info("SSM SendCommand: %s", commands[0][:120])
    resp = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
        TimeoutSeconds=60,
    )
    cmd_id = resp["Command"]["CommandId"]

    # Poll — SSM's waiter is CommandExecuted but it caps at ~15 min.
    # We do our own with a longer horizon.
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(4)
        try:
            inv = ssm.get_command_invocation(
                CommandId=cmd_id, InstanceId=INSTANCE_ID
            )
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        status = inv["Status"]
        if status in ("Success",):
            return inv["StandardOutputContent"], inv["StandardErrorContent"]
        if status in ("Cancelled", "TimedOut", "Failed"):
            raise RuntimeError(
                f"SSM command {cmd_id} status={status}\n"
                f"stdout:\n{inv.get('StandardOutputContent', '')}\n"
                f"stderr:\n{inv.get('StandardErrorContent', '')}"
            )
        # Pending / InProgress / Delayed — keep waiting.
    raise RuntimeError(f"SSM command {cmd_id} timed out after {timeout}s")


def extract_pcr0(stdout: str) -> str:
    """Pull the 96-hex PCR0 out of rotate-jwks.sh stdout."""
    m = re.search(r"new PCR0:\s*([0-9a-fA-F]{96})", stdout)
    if not m:
        raise RuntimeError(
            f"could not find 'new PCR0: <96 hex>' in rotate-jwks.sh output\n"
            f"---stdout tail---\n{stdout[-2000:]}"
        )
    return m.group(1).lower()


def kms_update_pcr0(key_id: str, sid_prefix: str, add: str | None = None, remove: str | None = None):
    """
    Read the key policy, edit the ImageSha384 condition on the statement
    matching sid_prefix, put the new policy. Handles single-string OR
    array-shaped condition values, converts to array when adding a
    second value.
    """
    policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    policy = json.loads(policy_str)
    changed = False
    for stmt in policy["Statement"]:
        if not stmt.get("Sid", "").startswith(sid_prefix):
            continue
        cond = stmt.setdefault("Condition", {}).setdefault(
            "StringEqualsIgnoreCase", {}
        )
        existing = cond.get("kms:RecipientAttestation:ImageSha384", [])
        if isinstance(existing, str):
            existing = [existing]
        current = set(v.lower() for v in existing)
        if add:
            current.add(add.lower())
        if remove:
            current.discard(remove.lower())
        if not current:
            raise RuntimeError(
                f"refusing to leave zero PCR0s on {key_id} statement {stmt['Sid']}"
            )
        # Single value: emit as string (matches AWS console shape).
        # Multiple: emit as array.
        updated = sorted(current)
        cond["kms:RecipientAttestation:ImageSha384"] = (
            updated[0] if len(updated) == 1 else updated
        )
        changed = True
        log.info("KMS %s: %s -> %s", key_id, sorted(v.lower() for v in existing), updated)
    if not changed:
        raise RuntimeError(f"no statement in {key_id} matched Sid prefix {sid_prefix}")
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(policy, indent=2),
    )


def notify(subject: str, body: str):
    try:
        sns.publish(TopicArn=SNS_ARN, Subject=subject[:100], Message=body)
    except Exception as e:
        log.error("SNS publish failed: %s", e)


def handler(event, context):
    log.info("event: %s", json.dumps(event))
    started = time.time()
    try:
        # ── 1. rebuild EIF on EC2, capture new PCR0 ──
        # SSM Run Command runs with a stripped env (HOME is unset) so we
        # export what rotate-jwks.sh and the makefile expect. ENCLAVE_SRC
        # explicitly wins over the $HOME-derived default inside the
        # script. PATH is set so nitro-cli / docker / node / jq resolve
        # even without a login shell.
        log.info("step 1: rotate-jwks.sh")
        # Invoke via `bash` (not `./`) so the run doesn't hard-depend on
        # the on-disk +x bit. Git's index tracks the executable mode, but
        # the mode is easy to lose on commits authored from Windows (that's
        # what caused the 2026-08-17 Monday rotation to fail with
        # "Permission denied"). With `bash SCRIPT` the shell reads the file
        # itself and mode doesn't matter — belt & braces for a script that
        # runs unattended on a cron.
        stdout, _stderr = ssm_run(
            [
                f"export HOME=/home/ec2-user "
                f"&& export ENCLAVE_SRC={ENCLAVE_DIR} "
                f"&& export PATH=/usr/local/bin:/usr/bin:/bin:$PATH "
                f"&& cd {ENCLAVE_DIR}/prod-automation "
                f"&& bash rotate-jwks.sh"
            ],
            timeout=900,
        )
        new_pcr0 = extract_pcr0(stdout)
        log.info("new PCR0: %s", new_pcr0)

        # ── 2. capture the currently-running PCR0 BEFORE we restart ──
        log.info("step 2a: read running PCR0")
        cur_out, _ = ssm_run(
            [
                "sudo nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0 // empty'"
            ],
            timeout=60,
        )
        old_pcr0 = cur_out.strip().lower()
        log.info("currently-running PCR0: %s", old_pcr0 or "<none>")
        if not re.fullmatch(r"[0-9a-f]{96}", old_pcr0 or ""):
            raise RuntimeError(f"unexpected running PCR0 shape: '{old_pcr0}'")

        # ── 3. KMS: add new PCR0 to BOTH keys (overlap window) ──
        log.info("step 3: KMS add new PCR0")
        kms_update_pcr0(NEW_KEY, NEW_KEY_SID, add=new_pcr0)
        kms_update_pcr0(OLD_KEY, OLD_KEY_SID, add=new_pcr0)

        # ── 4. Restart enclave, bump parent-proxy CID ──
        log.info("step 4: kill+run enclave + restart parent-proxy")
        restart_stdout, _ = ssm_run(
            [
                f"cd {ENCLAVE_DIR} && sudo make kill && sudo make run && "
                f"sleep 3 && "
                f"NEW_CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID') && "
                f'echo "NEW_CID=$NEW_CID" && '
                f'sudo sed -i "s/^ENCLAVE_CID=.*/ENCLAVE_CID=$NEW_CID/" /etc/rift-parent-proxy.env && '
                f"sudo systemctl restart rift-parent-proxy && "
                f"sleep 3 && "
                f"sudo systemctl is-active rift-parent-proxy && "
                f"echo restart_ok"
            ],
            timeout=180,
        )
        if "restart_ok" not in restart_stdout:
            raise RuntimeError(f"enclave restart didn't confirm ok:\n{restart_stdout}")

        # ── 5. Health check ──
        log.info("step 5: health check")
        health_stdout, _ = ssm_run(
            [
                f"BEARER=$(sudo cat /etc/rift-nginx-bearer) && "
                f'curl -sS -o /dev/null -w "%{{http_code}}" http://127.0.0.1:7777/health && echo && '
                f'curl -sS -o /dev/null -w "%{{http_code}}" -H "authorization: Bearer $BEARER" http://127.0.0.1:8080/health && echo'
            ],
            timeout=60,
        )
        codes = [ln.strip() for ln in health_stdout.split() if ln.strip().isdigit()]
        if codes[:2] != ["200", "200"]:
            raise RuntimeError(
                f"health check didn't return 200/200:\n{health_stdout}\n"
                f"NOT graduating old PCR0 — overlap window preserved for manual recovery"
            )

        # ── 6. Graduate old PCR0 ──
        log.info("step 6: graduate old PCR0 (%s)", old_pcr0)
        if old_pcr0 == new_pcr0:
            log.info("old == new (idempotent rerun?) — skipping remove")
        else:
            kms_update_pcr0(NEW_KEY, NEW_KEY_SID, remove=old_pcr0)
            kms_update_pcr0(OLD_KEY, OLD_KEY_SID, remove=old_pcr0)

        elapsed = int(time.time() - started)
        msg = (
            f"✓ JWKS rotation succeeded in {elapsed}s\n"
            f"  old PCR0: {old_pcr0}\n"
            f"  new PCR0: {new_pcr0}\n"
            f"Both KMS keys now allow only the new PCR0. Enclave restarted."
        )
        log.info(msg)
        notify("Rift JWKS rotation — SUCCESS", msg)
        return {"ok": True, "old_pcr0": old_pcr0, "new_pcr0": new_pcr0}

    except Exception as e:
        elapsed = int(time.time() - started)
        body = (
            f"✗ JWKS rotation FAILED after {elapsed}s\n\n"
            f"Error:\n{e}\n\n"
            f"Runbook:\n"
            f"  1. Check CloudWatch Logs for /aws/lambda/rift-jwks-rotator\n"
            f"  2. SSM into EC2, check enclave state:\n"
            f"       sudo nitro-cli describe-enclaves\n"
            f"       sudo systemctl status rift-parent-proxy\n"
            f"  3. If enclave died mid-rotation, restart manually:\n"
            f"       cd {ENCLAVE_DIR} && sudo make kill && sudo make run\n"
            f"  4. Verify KMS policies didn't get stuck with only the\n"
            f"     new PCR0 while the enclave is running the old one:\n"
            f"       aws kms get-key-policy --key-id {NEW_KEY} --policy-name default\n"
            f"       aws kms get-key-policy --key-id {OLD_KEY} --policy-name default\n"
        )
        log.error(body)
        notify("Rift JWKS rotation — FAILED", body)
        raise
