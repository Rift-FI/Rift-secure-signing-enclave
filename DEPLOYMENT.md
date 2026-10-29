# DEPLOYMENT — Rift signing enclave + parent-proxy

End-to-end runbook for getting Phase 1 (Nitro Enclave signing) live in **sandbox**, with **production untouched** until you explicitly graduate.

Prerequisites already satisfied earlier in the Phase 1 setup:

- ✅ EC2 instance `i-0f67d7e2e35a36d09` (c6g.large, Amazon Linux 2023, `us-east-1`)
- ✅ Nitro Enclaves enabled, `/dev/nitro_enclaves` exists, allocator service running with 1 vCPU + 1024 MiB reserved
- ✅ Docker + nitro-cli installed
- ✅ IAM role `rift-signer-enclave-role` attached (currently SSM access only)
- ✅ KMS CMKs already created:
  - prod    `arn:aws:kms:us-east-1:957814222213:key/3ca4d104-d45f-4e9c-b11e-2c96cdcb5dbd`
  - sandbox `arn:aws:kms:us-east-1:957814222213:key/a537dc0f-6010-4ab5-ac63-c1e5b313b640`

You'll do everything below as the EC2 user via SSM Session Manager — no SSH, no key files.

---

## 1 — Build the enclave EIF + capture PCR0

```sh
# Once: install Rust on the EC2 (rust-toolchain.toml auto-installs 1.92.0,
# the same version the Dockerfile's rust:1.92.0-bookworm builder uses)
sudo dnf install -y git jq
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"

# Clone + build
git clone https://github.com/Rift-FI/Rift-secure-signing-enclave.git
cd Rift-secure-signing-enclave

# Tests run on Linux too, of course.
make test

# Build the EIF. This compiles the enclave binary, packs it into a
# Docker image, then converts to .eif via nitro-cli.
make eif

# CAPTURE THIS — pin in the KMS key policy in step 3.
make pcr0
# → outputs a 96-char hex string. Save it.
```

Mark this hash on a sticky note as **`PCR0_v1`**. Any change to source code, Cargo.lock, base image, or toolchain produces a different PCR0; you'd repeat this step + step 3 each time. That's the whole point.

---

## 2 — Build + install the parent-proxy as a systemd service

```sh
make build-parent-proxy
make install-parent-proxy
sudo systemctl status rift-parent-proxy --no-pager | head -8
```

You should see `active (running)`. The proxy is listening on `HTTP_BIND` (default **`0.0.0.0:7777`**, i.e. all interfaces) for HTTP signing requests and on vsock port 5006 for KMS proxy callbacks. It won't have anything to forward to until the enclave is running (step 4).

> **Auth (fail closed):** the proxy **refuses to start** when `HTTP_BIND` is not a loopback address and `PARENT_PROXY_AUTH_TOKEN` is unset. Put the token in `/etc/rift-parent-proxy.env` (root:root 0600) **before** `make install-parent-proxy` starts the unit, or bind `HTTP_BIND=127.0.0.1:7777`. For a throwaway dev box only, `PARENT_PROXY_ALLOW_INSECURE=1` overrides the check; the proxy then logs an `INSECURE` error line on every start. With a token set, every enclave route (`/sign`, `/generate-wallet`, `/migrate-envelope`, `/reseal-v3`, `/health/enclave`) requires `Authorization: Bearer <token>`; `/health` stays open.
>
> ```sh
> sudo install -o root -g root -m 0600 /dev/null /etc/rift-parent-proxy.env
> echo "PARENT_PROXY_AUTH_TOKEN=$(openssl rand -hex 32)" | sudo tee -a /etc/rift-parent-proxy.env >/dev/null
> ```
>
> **Runs as `rift-proxy`, not root.** `make install-parent-proxy` creates the `rift-proxy` system user (no shell, no home) and the unit sets `User=`/`Group=`. AF_VSOCK on ports ≥ 1024, TCP 7777 and IMDS credentials need no privileges; systemd reads the env file before dropping privileges. If you upgrade an existing host, re-run `make install-parent-proxy` so the user exists before the new unit starts.
>
> **Load limits (env, optional):** `PARENT_PROXY_MAX_CONCURRENCY` (default 4 enclave requests in flight across all routes), `PARENT_PROXY_QUEUE_TIMEOUT_MS` (default 10000; no slot within this → `503 {"error":"parent-proxy overloaded"}`), `PARENT_PROXY_REQUEST_TIMEOUT_SECS` (default 30 → `504 {"error":"enclave request timed out"}`). Request bodies over 1 MiB (the vsock frame cap) get `413`.
>
> **KMS proxy peer check:** the vsock KMS proxy (5006) serves only connections whose peer CID equals `ENCLAVE_CID`. Keep `ENCLAVE_CID` correct (`make run` pins 17) or the enclave's KMS calls are refused.
>
> **Enclave canary:** `GET /health/enclave` (bearer) round-trips vsock to the enclave's health port (5010, `ENCLAVE_HEALTH_PORT`) and returns `{"status":"ok","version":..,"pcr0":..,"kms_checked":false}` with the PCR0 the enclave reads from its NSM. `POST /health/enclave` with `{"kms_key_arn":"<key>"}` additionally runs an attested KMS GenerateDataKey + Decrypt round trip (`kms_checked: true`). Unlike `/health`, this proves the enclave is actually serving. Older enclave images don't listen on 5010 → 502.

---

## 3 — Update the KMS sandbox CMK key policy with the PCR0 condition

This is the single most important step — it's what makes the security guarantee real. **Production CMK is NOT touched.**

In the AWS console:

1. KMS → Customer managed keys → `rift-sandbox-user-keys`
2. **Key policy** tab → **Edit**
3. Add a new statement that gates `kms:Decrypt` on attestation matching your PCR0:

```jsonc
{
  "Sid": "AllowAttestedDecryptFromSignerEnclave",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::957814222213:role/rift-signer-enclave-role"
  },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<PASTE PCR0_v1 HERE>"
    }
  }
}
```

4. Save the policy.
5. Also attach a basic IAM policy to `rift-signer-enclave-role` letting it call `kms:Decrypt` on the sandbox CMK (it needs the IAM grant in addition to the key-policy condition):

```jsonc
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowKmsDecrypt",
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "arn:aws:kms:us-east-1:957814222213:key/a537dc0f-6010-4ab5-ac63-c1e5b313b640"
  }]
}
```

**Why both?** AWS KMS access requires *both* the IAM principal to have the action allowed AND the key policy to allow the principal. The `kms:RecipientAttestation:ImageSha384` condition adds a *third* gate: KMS releases plaintext only when the request carries an attestation document signed by the Nitro Security Module reporting that exact PCR0 value.

So even with valid IAM credentials, the parent-proxy *cannot* decrypt unless the legit enclave (matching `PCR0_v1`) is the one asking.

---

## 4 — Launch the enclave + wire up the parent-proxy's CID env

```sh
# Launch in debug mode for the first run so you can tail the console.
make run-debug
make describe   # confirms it's running, gives you the EnclaveCID
```

Note the `EnclaveCID` (e.g. `16`). Tell the parent-proxy about it via env file:

```sh
# Update ENCLAVE_CID in place — do NOT overwrite the file, it holds
# PARENT_PROXY_AUTH_TOKEN (the proxy will not start on 0.0.0.0 without it).
CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
sudo sed -i '/^ENCLAVE_CID=/d' /etc/rift-parent-proxy.env
echo "ENCLAVE_CID=$CID" | sudo tee -a /etc/rift-parent-proxy.env >/dev/null
sudo systemctl restart rift-parent-proxy
sudo journalctl -u rift-parent-proxy -n 20 --no-pager
```

You should see `KMS proxy listener ready on vsock` and `HTTP listener ready`.

---

## 5 — Smoke test the enclave end-to-end

From the same EC2 shell:

```sh
# 5a — Health check the parent-proxy (process liveness only).
curl -s http://127.0.0.1:7777/health
# → "ok"

# 5a' — Real enclave round trip: vsock → enclave → NSM PCR0, plus an
#       attested KMS GenerateDataKey + Decrypt against the sandbox key.
SANDBOX_ARN="arn:aws:kms:us-east-1:957814222213:key/a537dc0f-6010-4ab5-ac63-c1e5b313b640"
TOKEN=$(sudo sed -n 's/^PARENT_PROXY_AUTH_TOKEN=//p' /etc/rift-parent-proxy.env)
curl -s -X POST -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  --data "{\"kms_key_arn\":\"$SANDBOX_ARN\"}" http://127.0.0.1:7777/health/enclave
# → {"status":"ok","version":"0.1.0","pcr0":"<same as make pcr0>","kms_checked":true}
#   (pcr0 is all zeros in --debug-mode)

# 5b — Encrypt a test plaintext via the SANDBOX KMS CMK + craft an envelope.
PLAINTEXT_PK="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # known Hardhat dev key
SANDBOX_ARN="arn:aws:kms:us-east-1:957814222213:key/a537dc0f-6010-4ab5-ac63-c1e5b313b640"

# Generate a DEK + wrap it via KMS.
DEK_OUT=$(aws kms generate-data-key --key-id "$SANDBOX_ARN" --key-spec AES_256)
DEK_PLAIN=$(echo "$DEK_OUT" | jq -r .Plaintext)
DEK_WRAPPED=$(echo "$DEK_OUT" | jq -r .CiphertextBlob)

# AES-256-CBC encrypt the plaintext PK with the DEK.
IV_HEX=$(openssl rand -hex 16)
DEK_HEX=$(echo "$DEK_PLAIN" | base64 -d | xxd -p -c64)
CIPHERTEXT_HEX=$(echo -n "$PLAINTEXT_PK" | openssl enc -aes-256-cbc -K "$DEK_HEX" -iv "$IV_HEX" | xxd -p -c1024 | tr -d '\n')

# 5c — Ask the parent-proxy to sign a known hash.
USER_OP_HASH="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

curl -s -X POST http://127.0.0.1:7777/sign \
  -H "content-type: application/json" \
  -d "$(cat <<EOF
{
  "user_op_hash_hex": "$USER_OP_HASH",
  "wrapped_dek_b64": "$DEK_WRAPPED",
  "ciphertext_hex": "$CIPHERTEXT_HEX",
  "iv_hex": "$IV_HEX",
  "kms_key_arn": "$SANDBOX_ARN"
}
EOF
)"
```

Expected response:

```json
{ "signature_hex": "0x<128 hex chars><27 or 28>" }
```

If you see this, **the entire chain works**: parent-proxy ↔ enclave vsock ↔ NSM attestation ↔ KMS Decrypt-with-Recipient ↔ RSA-OAEP unwrap ↔ AES decrypt ↔ secp256k1 sign.

If you see `{ "error": "kms attestation rejected" }` or a 502, the most common cause is a PCR0 mismatch in the key policy. Re-run `make pcr0`, compare to what you pasted in step 3, and try again.

---

## 6 — Deploy the smart-wallet (in enclave mode) onto this EC2

The smart-wallet *parent process* (Node) runs on the EC2, NOT in the enclave. It listens for HTTPS from the backend, builds the UserOp, asks the parent-proxy at `127.0.0.1:7777/sign` for the signature, and submits to Pimlico.

```sh
sudo dnf install -y nodejs npm
git clone https://github.com/Rift-FI/smart-wallet.git
cd smart-wallet
git checkout feat/enclave-mode
npm ci

# Production .env on this EC2:
sudo tee /etc/rift-smartwallet.env >/dev/null <<EOF
NODE_ENV=production
PORT=443
SIGNING_MODE=enclave
PARENT_PROXY_URL=http://127.0.0.1:7777

# Required for enclave mode — the CMK the enclave will Decrypt against.
# Sandbox box uses the sandbox CMK; if you ever build a separate prod
# box, use the prod CMK there.
KMS_KEY_ARN=arn:aws:kms:us-east-1:957814222213:key/a537dc0f-6010-4ab5-ac63-c1e5b313b640

# Legacy fallback — only needed for users whose encrypted_keys row is
# still in pre-Phase-0 AES format (i.e. not yet migrated). Same value
# as the backend's ENCRYPTION_KEY. Drop once bulk migration completes.
ENCRYPTION_KEY=<same as backend>

# … plus all the Pimlico bundler URLs etc. from your existing Railway smart-wallet env
EOF

# Install as systemd unit (assumes you have one — copy from existing Railway setup).
```

Expose `:443` to the internet behind nginx or via an ALB + ACM cert — pointing `smartwallet-tee.riftfi.xyz` at this box.

---

## 7 — Tell the backend to route SANDBOX traffic to the new URL

On Railway, set this env on the **backend** service:

```
ENCLAVE_SMART_WALLET_BASE_URL=https://smartwallet-tee.riftfi.xyz/api
```

That's it. The backend's `selectSmartWalletEndpoint()` will:

- Route `X-Rift-Mode: sandbox` requests to `smartwallet-tee.riftfi.xyz` (this new EC2).
- Route everything else (production) to the existing Railway smart-wallet — **production is unchanged**.
- Circuit-breaker: if `smartwallet-tee.riftfi.xyz` returns 5xx 3 times in a minute, sandbox traffic transparently falls back to Railway for 10 minutes. So even a Nitro outage doesn't break sandbox signing.

---

## 8 — Smoke test from end to end

Do a sandbox sign-in + offramp via your test user. Watch logs in three places simultaneously:

```sh
# Smart-wallet (on the EC2)
journalctl -u rift-smartwallet -f

# Parent proxy
journalctl -u rift-parent-proxy -f

# Enclave debug console
make console
```

You should see, in order:

1. Smart-wallet receives `POST /api/transfer`.
2. `[signingMode] enclave signing via parent-proxy at http://127.0.0.1:7777`
3. Parent-proxy: `forwarding sign request to enclave at cid=16 port=5005`
4. Enclave: `signing request received`, `signing complete, returning signature`.
5. Parent-proxy: returns HTTP 200 with signature.
6. Smart-wallet: submits UserOp to Pimlico, returns transactionHash.

If you see step 6 → migration to enclave signing is real and validated end-to-end.

---

## 9 — Graduate to production (only after sandbox is stable for ≥7 days)

When you're ready:

1. On the sandbox CMK + the **production** CMK, add the same `kms:RecipientAttestation:ImageSha384` condition with `PCR0_v1`.
2. Change backend env to ALSO route prod through the enclave:
   ```
   ENCLAVE_SMART_WALLET_PROD_TOO=true
   ```
   (Add the supporting code in a separate commit when ready — backend
   currently hard-codes mode==sandbox gating; lifting that is ~10 LOC.)
3. Verify with one low-value production user first. Watch CloudTrail for the Decrypt calls.
4. Roll out gradually by feature-flagging projects.

---

## Rollback procedure

If anything goes wrong:

| Symptom | Rollback |
|---|---|
| Sandbox 502s on every signing | Unset `ENCLAVE_SMART_WALLET_BASE_URL` on Railway. Sandbox immediately routes back to legacy smart-wallet. |
| Enclave crashes / refuses to start | `make kill` on the EC2, `systemctl stop rift-parent-proxy`. Sandbox traffic still 502s until you unset the env var. |
| Bad PCR0 deployed | The new EIF's PCR0 won't match the key policy → enclave returns "kms attestation rejected." Restart with the old EIF, leave key policy as-is. |
| KMS Decrypt fails with AccessDenied | Check `IAM Role + Key Policy + RecipientAttestation` all three. `aws kms get-key-policy --key-id <sandbox-arn>` to confirm the condition string matches your current PCR0. |

---

## Recovery — break-glass if you lose the enclave

The CMK is **single-region** by default. If you accidentally delete it OR the EC2 is gone for an extended outage, sandbox signing stops. **Production is unaffected** since it routes to legacy Railway.

For a multi-AZ / break-glass story:

1. Replicate both CMKs to a second region using AWS Multi-Region Keys (post-Phase-1).
2. Launch a second c6g.large in a second AZ + ALB, attestation-policy the second region's CMK to the same PCR0.
3. Keep an encrypted backup of every user's plaintext key, wrapped under a separate "break-glass" CMK whose key policy requires 3-of-5 humans to approve any Decrypt. Use only in catastrophe.

Documented for completeness; **not part of Phase 1 GA.**

---

## What's pinned to PCR0

Anything that changes the binary changes PCR0:

- `rust-toolchain.toml`
- `Cargo.lock`
- Source code under `enclave/src/`
- Docker base images (`rust:1.92.0-bookworm` builder, `debian:bookworm-slim` runtime) — referenced by tag, so a re-pushed tag shifts PCR0; pin by digest for fully reproducible builds
- The Dockerfile itself
- Compile-time switches in source: `envelope::V1_SIGNING_ENABLED`, `reseal_helpers::RESEAL_REQUIRE_BOUND_CHALLENGE`, the WebAuthn default policy, pinned JWKS

**Standard rotation flow** when you ship a code change: approval-gated, see [prod-automation/README.md — Enclave release approval](prod-automation/README.md#enclave-release-approval). In short:

1. Review + merge the change. CI (or a release engineer) builds the EIF from the merged commit on a clean checkout and records its PCR0.
2. An approver writes the commit SHA to `/rift/enclave/approved-commit` and the PCR0 to `/rift/enclave/approved-pcr0` (SSM).
3. The rotation Lambda builds that exact commit on the EC2, refuses unless the PCR0 matches, adds it to both KMS policies, restarts the enclave from the verified EIF (`make run-eif`), runs the `/health/enclave` canary (PCR0 + attested KMS round trip) and only then removes the old PCR0.

Manual equivalent: `make eif && make pcr0` → compare with the approved value → `update-kms-pcr0.sh --add` → `make kill && make run-eif` → `POST /health/enclave` → `update-kms-pcr0.sh --remove <old>`.

This is the only "zero-downtime + rollback-safe" pattern for attested enclaves. Drop one PCR0 from the policy before adding the next and your KMS calls start failing the instant any in-flight request lands on the old image.

---

## Open follow-ups

- [x] ~~Refactor the smart-wallet signing sites to use `makeSigner({...})`~~ — **done.** `abstraction.ts:submitTransaction` and `abstraction.ts:submitUniversalTransaction` now both call `makeSigner`, and `routes.ts` threads `req.body.ownerEncryptedKey` + `process.env.KMS_KEY_ARN` through. The other 4 sites originally on the list (`relay.ts` ×2, `estimateBridge.ts`, `estimateTransfer.ts`) turned out to either use a stub signer for fee estimation or live in the v2 client-side-sign flow that doesn't touch keys, so they didn't need refactoring.
- [ ] Replace the silent fallback-to-local in `signerFactory.makeSigner` with a hard error before declaring GA. Today it falls back to keep the rollout safe; once Phase 1 is stable, the enclave should be the only signing path.
- [ ] Wire CloudWatch alarms on parent-proxy 5xx rates so an enclave problem pages the on-call instead of silently exhausting the circuit breaker.
- [ ] Multi-AZ standby (second EC2 + same PCR0, ALB).
