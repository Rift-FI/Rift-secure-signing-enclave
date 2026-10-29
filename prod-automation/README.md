# prod-automation — self-host the Rift signer enclave

Everything an institution (bank, fintech) needs to stand up Rift's signing infrastructure in their own AWS account. The signer runs inside an AWS Nitro Enclave; your users' keys are generated and used inside the enclave and never accessible to Rift or to you as the operator.

```
integrator-controls-everything
├── AWS account, region, VPC     ← your infra
├── EC2 (Nitro Enclave)          ← runs the signer
├── KMS CMK                      ← attestation-gated
├── ALB + ACM + DNS              ← your endpoint
└── Pimlico / RPC / secrets      ← your commercial accounts

rift-controls-code
├── enclave source (pinned tag)  ← reproducible PCR0
├── canonical PCR0 publication   ← verify what you built = what we ship
└── backend routing              ← calls your smart-wallet URL
```

## Files

| File | What it does |
|---|---|
| [`INTEGRATOR-SETUP.md`](INTEGRATOR-SETUP.md) | The runbook. Start here. |
| [`aws-provision.sh`](aws-provision.sh) | Laptop-side: creates IAM, KMS, security group, EC2. Idempotent. |
| [`ec2-bootstrap.sh`](ec2-bootstrap.sh) | On the EC2: installs nitro-cli/docker/rust, clones enclave at a pinned tag, builds EIF, captures PCR0. |
| [`verify-pcr0.sh`](verify-pcr0.sh) | Compares your built PCR0 against Rift's canonical published value. Run before pinning. |
| [`smart-wallet-bootstrap.sh`](smart-wallet-bootstrap.sh) | On the EC2: clones smart-wallet, writes env, installs systemd unit. |
| [`templates/`](templates/) | IAM trust + permissions policies; KMS placeholder + hardened policies. |
| [`rotate-jwks.sh`](rotate-jwks.sh) | `--approved-commit <sha>`: build exactly that commit and print its PCR0 (used by the rotation Lambda). `--refresh-jwks`: prepare a JWKS-refresh candidate (CI / release engineer). |
| [`update-kms-pcr0.sh`](update-kms-pcr0.sh) | Manual add/remove of a PCR0 on both KMS key policies. |
| [`lambda/`](lambda/) | Approval-gated rotation Lambda + its deploy script. |

## Enclave release approval

KMS releases user data keys to whatever image's PCR0 is in the key
policy, so *adding a PCR0 is the most security-critical operation in
this repo*. Nothing on the EC2 (which is the untrusted host in the
enclave threat model) may decide which PCR0 gets added. The rotation
Lambda therefore only ever adds a PCR0 that an approver published out
of band, and only if the EC2 build of the approved commit reproduces it.

SSM parameters (Standard tier, `String`; names configurable via the
Lambda env vars `APPROVED_PCR0_PARAM` / `APPROVED_COMMIT_PARAM`):

| Parameter | Value |
|---|---|
| `/rift/enclave/approved-commit` | full 40-hex commit SHA of the reviewed release |
| `/rift/enclave/approved-pcr0` | 96-hex PCR0 of the EIF built from that commit |

Procedure for every enclave release (code change or weekly JWKS refresh):

1. **Prepare.** For a JWKS refresh run `rotate-jwks.sh --refresh-jwks` on a
   CI runner / workstation with docker + nitro-cli (not the prod EC2). It
   patches `enclave/src/pinned_jwks.rs` and prints a candidate PCR0. Open
   a PR with the diff (code changes go through a normal PR).
2. **Review + merge.** A second engineer reviews the diff — for JWKS,
   compare the key IDs/moduli against `https://www.googleapis.com/oauth2/v3/certs`
   and `https://appleid.apple.com/auth/keys` independently.
3. **Reproduce.** From a *clean* checkout of the merged commit, CI builds
   the EIF (`make eif && make pcr0`). Ideally two independent builders;
   the PCR0s must agree. (Base images are referenced by tag — pin them
   by digest in the Dockerfile to make this reliable.)
4. **Approve.** A principal that is NOT the rotation Lambda and NOT the
   EC2 instance role writes both parameters:
   ```sh
   aws ssm put-parameter --overwrite --type String --name /rift/enclave/approved-commit --value <sha>
   aws ssm put-parameter --overwrite --type String --name /rift/enclave/approved-pcr0   --value <pcr0>
   ```
   Restrict `ssm:PutParameter` on `arn:aws:ssm:*:*:parameter/rift/enclave/*`
   to the approver role (and CI's release job) via IAM/SCP; the Lambda
   role only has `ssm:GetParameter` on these two ARNs (`lambda/deploy.sh`).
   Parameter history gives the audit trail; consider CloudTrail alerts on
   `PutParameter` for this path.
5. **Deploy.** Invoke the Lambda (or wait for its weekly schedule). It:
   no-ops if the approved PCR0 is already running; otherwise builds the
   approved commit on the EC2 (`rotate-jwks.sh --approved-commit`),
   **aborts with an SNS alert and no KMS change if the PCR0 differs**,
   adds the PCR0 to both keys, restarts onto the verified EIF
   (`make run-eif`), runs the `/health/enclave` canary (enclave reports
   the approved PCR0 from its NSM + attested KMS GenerateDataKey/Decrypt
   round trip) and only then removes the old PCR0.

The scheduled run no longer refreshes JWKS by itself: if nobody approves
a refresh, the enclave keeps the previously pinned keys. Google rotates
roughly weekly and keeps old keys published for a while, but a stale
pin eventually breaks Google sign-in signing — schedule step 1 weekly in
CI.

## Read this first

`INTEGRATOR-SETUP.md` is the runbook. It walks you from empty AWS account to sandbox live in 12 steps, with a security-critical manual checkpoint at step 6. Reading it end-to-end takes 15 min; running it takes 2–3 hours the first time.

## Support

- Public: `admin@riftfi.com`
- Security disclosures: `security@riftfi.com`
- Enclave release notes + canonical PCR0s: `https://riftfi.com/enclave/`
