"""
Enclave rotation Lambda for the Rift signing enclave (approval-gated).

Runs on an EventBridge schedule (and on demand). It deploys ONLY an
enclave image that a human / CI approved out of band. End-to-end:

  0. Read the approved release from SSM Parameter Store:
       APPROVED_PCR0_PARAM   (default /rift/enclave/approved-pcr0)   96 hex
       APPROVED_COMMIT_PARAM (default /rift/enclave/approved-commit) 40 hex
     Both are written by an approver after reviewing the commit and
     reproducing its PCR0 independently (prod-automation/README.md,
     "Enclave release approval").
  1. Read the currently-running PCR0. If it already equals the approved
     PCR0 there is nothing to do: exit OK without touching anything.
  2. SSM-run `rotate-jwks.sh --approved-commit <sha>` on the EC2: checks
     out exactly that commit (no JWKS fetch, no origin/main), builds the
     EIF, reports its PCR0 and the commit it built.
  3. GATE: built PCR0 must equal the approved PCR0 (and built commit the
     approved commit). Mismatch => SNS alert, abort, NO KMS policy
     change, enclave left running untouched.
  4. Add the approved PCR0 to both KMS keys' attested-Decrypt statements
     (old PCR0 kept: overlap window).
  5. Restart: re-verify the on-disk EIF's PCR0, launch it WITHOUT a
     rebuild (`make run-eif`), point parent-proxy at the new CID.
  6. CANARY (real end-to-end, not /health): POST /health/enclave on the
     parent-proxy. That request crosses vsock into the new enclave,
     which reports its own PCR0 from the NSM and performs an attested
     KMS GenerateDataKey round trip against CANARY_KMS_KEY_ID. Required:
     HTTP 200, pcr0 == approved, kms_checked == true.
  7. Only if the canary passes: remove the old PCR0 from both KMS
     policies (graduate). Otherwise alert and leave the overlap window
     intact for a human.
  8. Publish success / failure to SNS.

Note: /health on the parent-proxy (and nginx) is a process-liveness
probe only and never reaches the enclave; it is NOT used as evidence
that the new enclave works.

Environment (Lambda config vars):
  EC2_INSTANCE_ID        i-0fa3850b5f3543e16
  ENCLAVE_SRC_DIR        /home/ec2-user/rift/Rift-secure-signing-enclave
  OLD_KMS_KEY_ID         3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd
  NEW_KMS_KEY_ID         4534fc26-ba5d-4f69-92d9-7aa96d8668ea
  SNS_TOPIC_ARN          arn:aws:sns:us-east-1:957814222213:rift-jwks-rotation
  NEW_KEY_SID_PREFIX     AllowAttestedDecryptFromSignerEnclave
  OLD_KEY_SID_PREFIX     AllowAttestedDecryptFromNewProdEnclave
  REGION                 us-east-1
  APPROVED_PCR0_PARAM    /rift/enclave/approved-pcr0
  APPROVED_COMMIT_PARAM  /rift/enclave/approved-commit
  CANARY_KMS_KEY_ID      key used for the canary's attested GenerateDataKey
                         (default: NEW_KMS_KEY_ID; set to "none" to skip
                         the KMS half of the canary — not recommended)
  PARENT_PROXY_URL       http://127.0.0.1:7777 (as seen from the EC2)
"""

import json
import logging
import os
import re
import time

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
APPROVED_PCR0_PARAM = os.environ.get("APPROVED_PCR0_PARAM", "/rift/enclave/approved-pcr0")
APPROVED_COMMIT_PARAM = os.environ.get(
    "APPROVED_COMMIT_PARAM", "/rift/enclave/approved-commit"
)
CANARY_KMS_KEY_ID = os.environ.get("CANARY_KMS_KEY_ID", NEW_KEY)
PARENT_PROXY_URL = os.environ.get("PARENT_PROXY_URL", "http://127.0.0.1:7777")

PCR0_RE = re.compile(r"[0-9a-f]{96}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# Key id / ARN / alias characters only — the value is interpolated into
# a shell command on the EC2.
KEY_ID_RE = re.compile(r"[A-Za-z0-9:/_\-]{1,256}")
URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?")

# Time budget (seconds). Lambda's hard cap is 900 s; the build gets
# whatever is left after reserving enough for restart + canary, and KMS
# is only touched while that reserve is still available.
RESTART_TIMEOUT = 120
CANARY_TIMEOUT = 180
POST_BUILD_RESERVE = RESTART_TIMEOUT + CANARY_TIMEOUT + 60

ssm = boto3.client("ssm", region_name=REGION)
kms = boto3.client("kms", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)


class GateFailure(RuntimeError):
    """Approval gate refused the build. Nothing was changed."""


def ssm_run(commands: list[str], timeout: int = 900) -> tuple[str, str]:
    """
    Fire a shell command batch on the EC2 via SSM Run Command, wait for
    completion, return (stdout, stderr). Raises RuntimeError on failure
    so the calling handler can catch + notify.
    """
    log.info("SSM SendCommand: %s", commands[0][:160])
    resp = ssm.send_command(
        InstanceIds=[INSTANCE_ID],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
        TimeoutSeconds=60,
    )
    cmd_id = resp["Command"]["CommandId"]

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(4)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=INSTANCE_ID)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        status = inv["Status"]
        if status == "Success":
            return inv["StandardOutputContent"], inv["StandardErrorContent"]
        if status in ("Cancelled", "TimedOut", "Failed"):
            raise RuntimeError(
                f"SSM command {cmd_id} status={status}\n"
                f"stdout:\n{inv.get('StandardOutputContent', '')}\n"
                f"stderr:\n{inv.get('StandardErrorContent', '')}"
            )
    raise RuntimeError(f"SSM command {cmd_id} timed out after {timeout}s")


def get_param(name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"].strip().lower()


def read_approved_release() -> tuple[str, str]:
    pcr0 = get_param(APPROVED_PCR0_PARAM)
    commit = get_param(APPROVED_COMMIT_PARAM)
    if not PCR0_RE.fullmatch(pcr0):
        raise GateFailure(f"{APPROVED_PCR0_PARAM} is not 96 lowercase hex: '{pcr0}'")
    if not COMMIT_RE.fullmatch(commit):
        raise GateFailure(f"{APPROVED_COMMIT_PARAM} is not a 40-hex commit SHA: '{commit}'")
    return pcr0, commit


def extract(stdout: str, label: str, pattern: str) -> str:
    m = re.search(rf"{label}:\s*({pattern})", stdout)
    if not m:
        raise RuntimeError(
            f"could not find '{label}: <value>' in rotate-jwks.sh output\n"
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
        cond = stmt.setdefault("Condition", {}).setdefault("StringEqualsIgnoreCase", {})
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
        updated = sorted(current)
        cond["kms:RecipientAttestation:ImageSha384"] = (
            updated[0] if len(updated) == 1 else updated
        )
        changed = True
        log.info("KMS %s: %s -> %s", key_id, sorted(v.lower() for v in existing), updated)
    if not changed:
        raise RuntimeError(f"no statement in {key_id} matched Sid prefix {sid_prefix}")
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy, indent=2))


def notify(subject: str, body: str):
    try:
        sns.publish(TopicArn=SNS_ARN, Subject=subject[:100], Message=body)
    except Exception as e:  # noqa: BLE001 — alerting must never mask the real error
        log.error("SNS publish failed: %s", e)


def remaining_s(context) -> int:
    try:
        return int(context.get_remaining_time_in_millis() / 1000)
    except Exception:  # noqa: BLE001 — local invocation without a context
        return 900


def read_running_pcr0() -> str:
    out, _ = ssm_run(
        ["sudo nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0 // empty'"],
        timeout=60,
    )
    return out.strip().lower()


def canary_command(approved_pcr0: str) -> list[str]:
    """
    Shell for the end-to-end canary. Reads the parent-proxy bearer token
    from its env file (root-only), POSTs /health/enclave and prints the
    HTTP status + JSON body on marked lines.
    """
    if not URL_RE.fullmatch(PARENT_PROXY_URL):
        raise RuntimeError(f"PARENT_PROXY_URL looks wrong: {PARENT_PROXY_URL!r}")
    if CANARY_KMS_KEY_ID.lower() == "none":
        body = "{}"
    else:
        if not KEY_ID_RE.fullmatch(CANARY_KMS_KEY_ID):
            raise RuntimeError(f"CANARY_KMS_KEY_ID has unexpected characters: {CANARY_KMS_KEY_ID!r}")
        body = json.dumps({"kms_key_arn": CANARY_KMS_KEY_ID})
    return [
        "set -eu\n"
        "umask 077\n"
        "HDR=$(mktemp); RESP=$(mktemp)\n"
        "trap 'rm -f \"$HDR\" \"$RESP\"' EXIT\n"
        # The token never appears on a command line: curl reads the
        # header from a 0600 temp file (-H @file).
        "TOKEN=$(sudo sed -n 's/^PARENT_PROXY_AUTH_TOKEN=//p' /etc/rift-parent-proxy.env | tail -1 "
        "| sed -e 's/^\"//' -e 's/\"$//' -e \"s/^'//\" -e \"s/'$//\")\n"
        "printf 'authorization: Bearer %s\\n' \"$TOKEN\" > \"$HDR\"\n"
        "CODE=000\n"
        "for i in 1 2 3 4 5 6; do\n"
        "  CODE=$(curl -sS -o \"$RESP\" -w '%{http_code}' --max-time 20 -X POST "
        "-H 'content-type: application/json' -H @\"$HDR\" "
        f"--data '{body}' {PARENT_PROXY_URL}/health/enclave || echo 000)\n"
        "  [ \"$CODE\" = 200 ] && break\n"
        "  sleep 5\n"
        "done\n"
        "echo \"CANARY_HTTP=$CODE\"\n"
        "echo \"CANARY_JSON=$(tr -d '\\n' < \"$RESP\")\"\n"
    ]


def run_canary(approved_pcr0: str) -> dict:
    out, _ = ssm_run(canary_command(approved_pcr0), timeout=CANARY_TIMEOUT)
    code = re.search(r"CANARY_HTTP=(\d+)", out)
    js = re.search(r"CANARY_JSON=(.*)", out)
    if not code or code.group(1) != "200" or not js:
        raise RuntimeError(f"canary /health/enclave did not return 200:\n{out[-2000:]}")
    try:
        result = json.loads(js.group(1))
    except ValueError as e:
        raise RuntimeError(f"canary returned non-JSON body: {js.group(1)[:500]}") from e
    if str(result.get("pcr0", "")).lower() != approved_pcr0:
        raise RuntimeError(
            f"canary: running enclave reports PCR0 {result.get('pcr0')!r}, expected {approved_pcr0}"
        )
    if CANARY_KMS_KEY_ID.lower() != "none" and result.get("kms_checked") is not True:
        raise RuntimeError(f"canary: attested KMS round trip not confirmed: {result}")
    return result


def handler(event, context):
    log.info("event: %s", json.dumps(event))
    started = time.time()
    stage = "init"
    approved_pcr0 = approved_commit = old_pcr0 = "?"
    try:
        # ── 0. approved release ──
        stage = "read approved release"
        approved_pcr0, approved_commit = read_approved_release()
        log.info("approved release: commit=%s pcr0=%s", approved_commit, approved_pcr0)

        # ── 1. running PCR0; no-op if already deployed ──
        stage = "read running PCR0"
        old_pcr0 = read_running_pcr0()
        log.info("currently-running PCR0: %s", old_pcr0 or "<none>")
        if not PCR0_RE.fullmatch(old_pcr0 or ""):
            raise RuntimeError(f"unexpected running PCR0 shape: '{old_pcr0}'")
        if old_pcr0 == approved_pcr0:
            log.info("approved PCR0 already running — nothing to do")
            return {"ok": True, "noop": True, "pcr0": approved_pcr0}

        # ── 2. build the approved commit on the EC2 ──
        # SSM Run Command runs with a stripped env (HOME unset): export
        # what rotate-jwks.sh and the Makefile expect. Invoked via `bash`
        # so the run doesn't depend on the on-disk +x bit. The commit is
        # regex-validated (40 hex) before interpolation.
        stage = "build approved commit"
        build_budget = remaining_s(context) - POST_BUILD_RESERVE - 30
        if build_budget < 120:
            raise GateFailure(f"not enough Lambda time left for a build ({build_budget}s)")
        stdout, _ = ssm_run(
            [
                f"export HOME=/home/ec2-user "
                f"&& export ENCLAVE_SRC={ENCLAVE_DIR} "
                f"&& export PATH=/usr/local/bin:/usr/bin:/bin:$PATH "
                f"&& cd {ENCLAVE_DIR}/prod-automation "
                f"&& bash rotate-jwks.sh --approved-commit {approved_commit}"
            ],
            timeout=build_budget,
        )
        built_pcr0 = extract(stdout, "new PCR0", "[0-9a-fA-F]{96}")
        built_commit = extract(stdout, "built commit", "[0-9a-fA-F]{40}")
        log.info("built: commit=%s pcr0=%s", built_commit, built_pcr0)

        # ── 3. GATE ──
        stage = "approval gate"
        if built_commit != approved_commit:
            raise GateFailure(f"built commit {built_commit} != approved {approved_commit}")
        if built_pcr0 != approved_pcr0:
            raise GateFailure(
                f"built PCR0 does not match the approved PCR0 — refusing to touch KMS.\n"
                f"  approved: {approved_pcr0}\n  built:    {built_pcr0}\n"
                f"Likely causes: non-reproducible build (base image tag moved — pin "
                f"digests), wrong approved value, or a tampered build host."
            )

        # ── 4. KMS: add approved PCR0 to BOTH keys (overlap window) ──
        stage = "KMS add"
        if remaining_s(context) < POST_BUILD_RESERVE:
            raise GateFailure(
                "build finished but too little Lambda time is left to restart + canary; "
                "re-invoke (the Docker build is cached, the next run is fast)"
            )
        kms_update_pcr0(NEW_KEY, NEW_KEY_SID, add=approved_pcr0)
        kms_update_pcr0(OLD_KEY, OLD_KEY_SID, add=approved_pcr0)

        # ── 5. restart onto the verified EIF ──
        stage = "restart enclave"
        restart_stdout, _ = ssm_run(
            [
                f"set -eu\n"
                f"cd {ENCLAVE_DIR}\n"
                f"DISK_PCR0=$(sudo make -s pcr0 | tr -d '[:space:]' | tr 'A-F' 'a-f')\n"
                f'[ "$DISK_PCR0" = "{approved_pcr0}" ] || {{ echo "EIF on disk has PCR0 $DISK_PCR0"; exit 3; }}\n'
                f"sudo make kill\n"
                f"sudo make run-eif\n"
                f"sleep 3\n"
                f"NEW_CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')\n"
                f'echo "NEW_CID=$NEW_CID"\n'
                f'sudo sed -i "s/^ENCLAVE_CID=.*/ENCLAVE_CID=$NEW_CID/" /etc/rift-parent-proxy.env\n'
                f"sudo systemctl restart rift-parent-proxy\n"
                f"sleep 3\n"
                f"sudo systemctl is-active rift-parent-proxy\n"
                f"echo restart_ok\n"
            ],
            timeout=RESTART_TIMEOUT,
        )
        if "restart_ok" not in restart_stdout:
            raise RuntimeError(f"enclave restart didn't confirm ok:\n{restart_stdout}")

        # ── 6. canary: real vsock + KMS round trip into the new enclave ──
        stage = "canary"
        canary = run_canary(approved_pcr0)
        log.info("canary ok: %s", canary)

        # ── 7. graduate old PCR0 ──
        stage = "KMS remove old PCR0"
        kms_update_pcr0(NEW_KEY, NEW_KEY_SID, remove=old_pcr0)
        kms_update_pcr0(OLD_KEY, OLD_KEY_SID, remove=old_pcr0)

        elapsed = int(time.time() - started)
        msg = (
            f"✓ Enclave rotation succeeded in {elapsed}s\n"
            f"  commit  : {approved_commit}\n"
            f"  old PCR0: {old_pcr0}\n"
            f"  new PCR0: {approved_pcr0}\n"
            f"  canary  : {json.dumps(canary)}\n"
            f"Both KMS keys now allow only the new PCR0."
        )
        log.info(msg)
        notify("Rift enclave rotation — SUCCESS", msg)
        return {"ok": True, "old_pcr0": old_pcr0, "new_pcr0": approved_pcr0}

    except Exception as e:
        elapsed = int(time.time() - started)
        gate = isinstance(e, GateFailure)
        body = (
            f"✗ Enclave rotation FAILED at stage '{stage}' after {elapsed}s\n"
            f"{'(approval gate: NO KMS policy was changed, running enclave untouched)' if gate else ''}\n\n"
            f"approved commit: {approved_commit}\n"
            f"approved PCR0  : {approved_pcr0}\n"
            f"running PCR0   : {old_pcr0}\n\n"
            f"Error:\n{e}\n\n"
            f"Runbook:\n"
            f"  1. CloudWatch Logs: /aws/lambda/rift-jwks-rotator\n"
            f"  2. SSM into EC2, check enclave state:\n"
            f"       sudo nitro-cli describe-enclaves\n"
            f"       sudo systemctl status rift-parent-proxy\n"
            f"  3. If the enclave died mid-rotation, relaunch the verified EIF:\n"
            f"       cd {ENCLAVE_DIR} && sudo make kill && sudo make run-eif\n"
            f"  4. If the failure was AFTER 'KMS add', both PCR0s are allowed\n"
            f"     (overlap window). Inspect before removing either:\n"
            f"       aws kms get-key-policy --key-id {NEW_KEY} --policy-name default\n"
            f"       aws kms get-key-policy --key-id {OLD_KEY} --policy-name default\n"
        )
        log.error(body)
        notify(
            "Rift enclave rotation — "
            + ("BLOCKED by approval gate" if gate else "FAILED"),
            body,
        )
        raise
