# Self-host the Rift signer enclave

For institutions (banks, fintechs) deploying Rift's signing infrastructure into their own AWS account.

At the end, you own — in your AWS account, in your region — a hardened Nitro Enclave that signs UserOps on behalf of your users, and a KMS key whose plaintext only that specific enclave can retrieve. Rift never sees your users' keys. If you turn off your AWS account tomorrow, the signing goes dark. That's the point.

---

## What Rift ships and what you provide

| | Rift ships | You provide |
|---|---|---|
| Enclave source (Rust) | ✅ (public, pinned tag) | — |
| Parent-proxy source (Rust) | ✅ (same repo) | — |
| Smart-wallet source (Node) | ✅ (public, pinned tag) | — |
| Canonical PCR0 per tag | ✅ (published at `riftfi.com/enclave/pcr0/<tag>`) | — |
| AWS account, region, VPC | — | ✅ |
| KMS CMK, IAM role, EC2 | — | ✅ (created by `aws-provision.sh`) |
| Pimlico / bundler API keys | — | ✅ (your commercial account) |
| RPC URLs (Alchemy, Infura, …) | — | ✅ |
| ACM cert, DNS record, ALB | — | ✅ |
| `RIFT_BACKEND_URL` + shared secret | ✅ (issued on registration) | — |

Nothing about your users' keys, your customer data, or your transaction volume leaves your AWS account. Rift's backend calls your smart-wallet URL over HTTPS with a shared secret — that's the only inbound coupling.

---

## What's automated vs manual

| Step | Automated? | Why |
|---|---|---|
| IAM role + instance profile + inline `kms:Decrypt` policy | ✅ `aws-provision.sh` | Boring, repeatable. |
| KMS CMK with placeholder policy | ✅ `aws-provision.sh` | Placeholder = no attestation gate yet. You add the gate manually in step 6. |
| Security group + Nitro-enabled EC2 launch | ✅ `aws-provision.sh` | Idempotent, tag-gated. |
| Install nitro-cli / docker / rust / allocator | ✅ `ec2-bootstrap.sh` | Repeatable. |
| Clone signer enclave at pinned tag, build EIF, capture PCR0 | ✅ `ec2-bootstrap.sh` | Deterministic (with a pinned `ENCLAVE_REF`). |
| Verify your PCR0 = Rift's canonical PCR0 | ✅ `verify-pcr0.sh` | Automated check, MANUAL decision on the result. |
| **Pin PCR0 into your KMS key policy** | ❌ **you paste it, by hand** | This is the entire security guarantee. Automating it means one bug silently disables the gate. You see the hex, you save the policy, you know it's right. |
| Deploy smart-wallet as systemd unit | ✅ `smart-wallet-bootstrap.sh` | Repeatable. |
| ALB + ACM cert + DNS | ❌ manual | Depends on your VPC + org DNS conventions. |
| Register your smart-wallet URL with Rift | ❌ manual (email us) | Rift issues you a `RIFT_BACKEND_SHARED_SECRET`. |

If you see "manual", it's manual on purpose.

---

## Prerequisites (on the operator's laptop)

1. **AWS CLI** installed and configured for the target account:
   ```sh
   aws sts get-caller-identity   # should print your integrator account
   ```
2. **AWS Session Manager plugin** (for SSM access to the EC2):
   - Windows: `winget install --id=Amazon.SessionManagerPlugin`
   - macOS: `brew install --cask session-manager-plugin`
   - Linux: [AWS docs](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
3. The operator's IAM principal needs: `iam:*`, `kms:*`, `ec2:*`, `ssm:StartSession`.
4. This `prod-automation/` folder from `Rift-FI/Rift-secure-signing-enclave` at the same tag you intend to deploy.

---

## Step 1 — Choose the release you're pinning

Rift publishes released enclave versions as git tags on `Rift-FI/Rift-secure-signing-enclave`. Each release has a canonical PCR0 hash published at:

```
https://riftfi.com/enclave/pcr0/<tag>.txt         # raw hex, 96 chars
https://riftfi.com/enclave/pcr0/<tag>.json        # metadata (sha, date, notes)
```

Pick a tag (e.g. `v1.0.0`). You'll pass it to every step as `ENCLAVE_REF`.

**Do NOT run production against `main`.** `main` is a moving target; your PCR0 will drift under you and you'll lose the "code matches what Rift ships" guarantee. Sandbox against `main` is fine for dev.

---

## Step 2 — Provision AWS infrastructure (SANDBOX)

From this folder on your laptop:

```sh
cd prod-automation
export AWS_REGION=us-east-1        # or eu-west-1, af-south-1 — fit your data residency
ENV_TAG=sandbox ./aws-provision.sh
```

The script creates (all namespaced with `-sandbox-`):
- IAM role `rift-signer-enclave-sandbox-role` with `AmazonSSMManagedInstanceCore` + inline `kms:Decrypt` on the CMK
- Instance profile
- KMS CMK aliased `alias/rift-sandbox-user-keys` (SYMMETRIC_DEFAULT, placeholder policy — attestation gate added in step 6)
- Security group (443/tcp from 0.0.0.0/0 — tighten later once you know your ALB CIDR)
- One EC2 instance, `c6g.large` arm64, Nitro-Enclave-enabled, tagged `rift-role=signer-enclave`

Prints instance ID, KMS ARN, role ARN. Save these — you'll need them.

**Cost**: `c6g.large` is ~$0.06/hr — about $45/month for sandbox sitting idle. Prod sizing depends on your load.

---

## Step 3 — SSM into the instance

```sh
aws ssm start-session --target <INSTANCE_ID> --region us-east-1
sudo su - ec2-user
```

Wait ~60s after `aws-provision.sh` finishes so the SSM agent registers.

---

## Step 4 — Bootstrap the enclave

Copy this folder onto the instance (any way — heredoc via SSM, or if you've forked the repo publicly, `git clone` and cd in). Then:

```sh
ENV_TAG=sandbox \
ENCLAVE_REF=v1.0.0 \                # use main for sandbox dev, tags for prod
./ec2-bootstrap.sh
```

The script:
1. Installs system packages, docker, nitro-cli, rust
2. Configures the Nitro allocator (1 vCPU + 1024 MiB default)
3. Clones the enclave at your pinned `ENCLAVE_REF`
4. Builds the EIF (~5–10 min first time — Rust builds inside Docker)
5. Prints the PCR0 (96 hex chars) and writes `~/rift/state.json`
6. Installs `rift-parent-proxy` as a systemd unit

At the end you'll see:

```
  ref         : v1.0.0
  built sha   : <full commit SHA>
  PCR0        : 0d3e4b8a…   ← 96 hex chars
```

Copy the PCR0. Do not proceed without verifying it in the next step.

---

## Step 5 — Verify PCR0 = Rift's canonical PCR0

Also on the instance:

```sh
./verify-pcr0.sh                    # reads ~/rift/state.json automatically
```

- `✓ MATCH` → the enclave you built is byte-identical to Rift's ship. Safe to pin.
- `✗ MISMATCH` → do NOT continue. Common causes are printed by the script; most often you cloned a different repo or applied a local patch.
- `canonical PCR0 not available` → the tag isn't published yet. Contact Rift; don't fall back to unverified PCR0 in prod.

---

## Step 6 — Pin PCR0 into your KMS key policy (MANUAL)

**This is the security step.** After it, KMS releases plaintext only when the request carries an attestation signed by the Nitro Security Module reporting exactly this PCR0. Any change to source, dependencies, base image, or toolchain produces a different PCR0 → decryption stops. That's the guarantee.

1. AWS console → KMS → Customer managed keys → `rift-sandbox-user-keys` → **Key policy** → **Edit**.
2. Generate the hardened policy locally:
   ```sh
   sed -e "s|__ACCOUNT_ID__|<YOUR ACCOUNT ID>|g" \
       -e "s|__ROLE_NAME__|rift-signer-enclave-sandbox-role|g" \
       -e "s|__PCR0__|<PCR0 you just verified>|g" \
       templates/kms-key-policy-hardened.json
   ```
3. Replace the entire policy in the KMS console with the output.
4. **Save.**

The hardened template has three statements: root admin, `Allow kms:Decrypt` conditional on `kms:RecipientAttestation:ImageSha384 = <your PCR0>`, and an explicit `Deny kms:Decrypt` when there's no attestation. The Deny is belt-and-suspenders — an IAM misconfig can't accidentally leak plaintext.

---

## Step 7 — Launch the enclave + wire the parent-proxy

```sh
cd ~/rift/Rift-secure-signing-enclave

# First launch in debug mode so you can see console output
sudo make run-debug
sudo make describe               # note EnclaveCID

# Point the parent-proxy at the enclave
CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
sudo tee /etc/rift-parent-proxy.env >/dev/null <<EOF
ENCLAVE_CID=$CID
EOF
sudo systemctl restart rift-parent-proxy

# Smoke test
curl -s http://127.0.0.1:7777/health
# → "ok"
```

If `/health` returns `ok`, the enclave-vsock-parent-proxy chain works. Kill the debug enclave and start it in production mode:

```sh
sudo make kill
sudo make run
```

---

## Step 8 — Deploy the smart-wallet

Assemble your operator-specific env values into a file (e.g. `/tmp/integrator.env`):

```env
# Bundler
PIMLICO_URL_BASE=https://api.pimlico.io/v2/base/rpc?apikey=…
PIMLICO_URL_ARB=https://api.pimlico.io/v2/arbitrum/rpc?apikey=…

# RPC
ALCHEMY_RPC_URL_BASE=https://base-mainnet.g.alchemy.com/v2/…

# Auth between YOUR backend and this smart-wallet
JWT_SIGNING_SECRET=<32+ random bytes>

# Rift issues these on registration (step 10)
RIFT_BACKEND_URL=https://backend.riftfi.com
RIFT_BACKEND_SHARED_SECRET=<Rift issues this>

# Phase-0 legacy fallback — only if migrating users off pre-v3 keys.
# New integrators can omit.
# ENCRYPTION_KEY=<same 32-byte key that encrypted pre-v3 rows>
```

Then:

```sh
KMS_KEY_ARN=<sandbox KMS ARN from step 2> \
ENV_TAG=sandbox \
ENV_FILE_EXTRA=/tmp/integrator.env \
./smart-wallet-bootstrap.sh
```

The script clones smart-wallet at `SMART_WALLET_REF` (recommend same tag family as your `ENCLAVE_REF`), writes `/etc/rift-smartwallet.env`, and installs a systemd unit that binds `:443` without needing root.

Verify:
```sh
sudo journalctl -u rift-smartwallet -f
curl -k https://127.0.0.1:443/health
```

---

## Step 9 — Frontend (ALB + ACM + DNS)

Manual, depends on your VPC + DNS conventions:

1. Request an ACM cert for `smartwallet-sandbox.yourorg.com` (or your naming).
2. Create an ALB → target group → the EC2 on :443 (health check `/health`).
3. Point `smartwallet-sandbox.yourorg.com` DNS at the ALB.
4. Tighten the EC2 SG: replace `0.0.0.0/0` on 443 with the ALB's SG.

---

## Step 10 — Register with Rift

Email `admin@riftfi.com`:
- Your public smart-wallet URL (e.g. `https://smartwallet-sandbox.yourorg.com`)
- Your pinned `ENCLAVE_REF` (e.g. `v1.0.0`)
- Your `verify-pcr0.sh` output (should say ✓ MATCH)
- Your AWS account ID + region
- Corridors / user cohorts you want to route

Rift issues you a `RIFT_BACKEND_SHARED_SECRET` and configures its backend to route matching traffic to your URL. `JWT_SIGNING_SECRET` is yours and stays yours.

---

## Step 11 — Sandbox soak

Run at least **72 hours** of real sandbox transactions before doing the prod pass. Watching for:
- Zero `kms attestation rejected` errors
- Zero enclave OOMs (`journalctl -k | grep -i oom`)
- Latency in the range Rift quoted
- Zero transactions that failed to sign

If anything trips, DO NOT graduate. Contact Rift.

---

## Step 12 — Production

Repeat steps 2–10 with `ENV_TAG=prod`. The scripts create separate `-prod-` resources — sandbox isn't touched.

- Different KMS key = different attestation gate = you can't accidentally use sandbox creds in prod
- Different EC2 = you can kill sandbox without touching prod
- Prod `ENCLAVE_REF` = same released tag as sandbox, once soak passes

`aws-provision.sh` prompts for `yes-prod` confirmation before creating prod resources.

---

## Rollback

- **Cutover**: ask Rift to route away from your URL. Your instance keeps running, unused, until you delete it.
- **KMS attestation gate misfire** (enclave stops decrypting): temporarily revert your KMS policy to `kms-key-policy-placeholder.json` (drop the `Deny` and the `Condition`). This restores signing but is a **security downgrade** — only do it if you've confirmed the enclave is the code you trust.
- **Wipe and rebuild**: `sudo make kill && sudo make clean && sudo make eif && sudo make pcr0`. If PCR0 differs, update the KMS policy before running.
- **Delete everything**: terminate EC2, schedule KMS key deletion (7-day window, reversible), delete IAM role. Nothing else in your account is touched.

---

## Upgrading to a new Rift release

When Rift publishes `v1.1.0`:

1. Read the release notes.
2. Rebuild sandbox: `ENCLAVE_REF=v1.1.0 ./ec2-bootstrap.sh`.
3. `./verify-pcr0.sh` — must MATCH.
4. **Both** old + new PCR0 in the KMS policy simultaneously (add a second Allow statement), so you can flip between them without downtime.
5. Restart the enclave from the new EIF.
6. Soak.
7. Remove the old PCR0 from the KMS policy.

Never delete the old PCR0 from the policy before the new enclave is running with attested access.

---

## Common errors

| Symptom | Cause | Fix |
|---|---|---|
| `/dev/nitro_enclaves` missing | Instance launched without `--enclave-options Enabled=true`, or wrong type | Terminate + re-launch via `aws-provision.sh` |
| `nitro-cli build-enclave` OOM | Not enough RAM to build Docker image | Use a bigger builder instance, or move build to CI |
| `verify-pcr0.sh` MISMATCH | Not on Rift's canonical build | Check git remote, git tag, and any local patches |
| `kms attestation rejected` | PCR0 in KMS policy ≠ enclave's PCR0 | Re-run `make pcr0`, update the policy statement |
| Parent-proxy fails to bind vsock | Enclave not running | `sudo make run`, then restart `rift-parent-proxy` |
| `403 AccessDenied` from KMS | IAM permissions policy missing | Re-run `aws-provision.sh` (idempotent) |
| Smart-wallet can't bind :443 | Missing `CAP_NET_BIND_SERVICE` | Check systemd unit wasn't edited |
| Smart-wallet fails to reach Rift backend | `RIFT_BACKEND_URL` or shared secret wrong | Re-check values Rift issued |

---

## Before you start

- [ ] Your AWS account ID + region
- [ ] The `ENCLAVE_REF` tag you're pinning (Rift can tell you the current recommended tag)
- [ ] Pimlico / bundler API keys for the chains you support
- [ ] RPC URLs
- [ ] The DNS name you'll use for the smart-wallet
- [ ] An email thread with Rift for registration + shared secret
- [ ] 2–3 hours uninterrupted for the sandbox pass; ~1 hour later for prod

Don't do this at 11pm on a Friday.
