# rift-signer-enclave

The Rust binary that runs inside an AWS Nitro Enclave and signs Safe
UserOperations for Rift, plus generates fresh EOAs on demand. It is
the only process anywhere in the Rift stack that ever sees a user's
plaintext private key.

The repo contains two binaries:

1. The enclave itself (the rift-signer-enclave binary, built into an
   EIF and launched with nitro-cli). Runs inside the TEE. Has no
   network. Talks to the parent only over vsock.
2. The parent-proxy (rift-parent-proxy, built into a regular Linux
   binary and run as a systemd unit on the EC2 host). Bridges HTTP
   from the outside world to vsock in to the enclave, and bridges
   vsock from the enclave out to AWS KMS over HTTPS.

This README covers the threat model, the on-the-wire protocols
between the three actors (backend or smart-wallet, parent-proxy,
enclave), the build pipeline, and the deploy steps.

## Why this exists

Pre-Phase 0, every Rift user's EOA private key was AES-encrypted at
rest with a single ENCRYPTION_KEY environment variable. Anyone who
got that env var (a leak, a curious employee, a compromised CI run)
could decrypt every user's wallet.

Phase 0 moved the at-rest format to a KMS envelope: each user's key
is AES-encrypted with a fresh data encryption key, and that DEK is
itself KMS-wrapped. To decrypt, you need IAM access to call
kms:Decrypt on the CMK. The plaintext ENCRYPTION_KEY stops being
load-bearing for new rows.

Phase 0.5 closed the wire surface. Backend used to send plaintext
private keys to the smart-wallet over HTTPS. Now it sends the
envelope blob, and the smart-wallet does the KMS Decrypt in process.

Phase 1 closed the in-process surface. Instead of any Node process
holding the plaintext in memory for the duration of a sign call, the
plaintext lives only inside a Nitro Enclave that nobody (including
AWS, including Rift) can introspect. KMS releases the wrapped DEK
only to attestation documents whose PCR0 hash matches a specific
allowlist in the CMK key policy. So even with full IAM access, you
cannot decrypt unless you can also run an enclave image with the
exact same hash. Rebuild the EIF with a different toolchain or any
code change and the hash changes and KMS refuses.

Phase 2 added wallet generation to the enclave. Before Phase 2,
fresh EOAs were generated in the backend with ethers.Wallet.createRandom
and immediately KMS-encrypted. The plaintext lived in Node RAM for a
few milliseconds. Phase 2 moves the generation inside the enclave
too. The backend asks the parent-proxy "generate me a wallet", the
enclave does it end to end (RSA ephemeral key, NSM attest, KMS
GenerateDataKey with recipient, build envelope blob, return), and
the backend never sees the private key at any point in its life.

| Risk | Pre-Phase 0 | Phase 0/0.5 | Phase 1 | Phase 2 |
|---|---|---|---|---|
| ENCRYPTION_KEY env var leak | Drains every user | No-op for new rows | No-op | No-op |
| Backend or smart-wallet HTTPS plaintext intercept | Plaintext in body | Opaque envelope | Opaque envelope | Opaque envelope |
| Backend or smart-wallet host root compromise | Plaintext in process memory | Plaintext in process memory | Not visible (signing happens in enclave) | Not visible (signing and keygen happen in enclave) |
| AWS IAM credentials leak | n/a | KMS Decrypt callable directly | KMS only releases plaintext to the attested enclave PCR0 | Same plus GenerateDataKey is gated the same way |

## Architecture

```
                  EC2 c6g.large (Amazon Linux 2023)
                  +------------------------------------------+
                  |  rift-parent-proxy (systemd unit)        |
   HTTPS in  ---> |   POST /sign              POST /gen-wallet
   from           |    |                          |          |
   backend or    -|----+--------------------------+----------|
   smart-wallet   |   vsock to enclave (ports 5005 and 5007) |
                  |                       ^                  |
                  |                       |                  |
                  |   vsock from enclave  | (port 5006)      |
                  |   carrying KMS-proxy  |                  |
                  |   requests            |                  |
                  |   (Decrypt or         |                  |
                  |    GenerateDataKey)   |                  |
                  |          |            |                  |
                  |          v            |                  |
                  |   HTTPS to AWS KMS    |                  |
                  +------------------------------------------+
                                          |
                                          |
                  +------------------------------------------+
                  |  rift-signer-enclave (the EIF)           |
                  |  No network, no disk.                    |
                  |  Two vsock listeners:                    |
                  |   - port 5005 sign loop                  |
                  |   - port 5007 generate-wallet loop       |
                  |  Crypto primitives:                      |
                  |   - RSA-2048 keygen (for KMS recipient)  |
                  |   - NSM attestation document             |
                  |   - CMS EnvelopedData unwrap (openssl)   |
                  |   - AES-256-CBC decrypt / encrypt        |
                  |   - secp256k1 sign_prehash               |
                  |   - keccak256 (for EVM address derive)   |
                  +------------------------------------------+
```

The PCR0 of the EIF is pinned in the KMS CMK key policy. KMS releases
plaintext only to attestation documents signed by NSM that report
that exact PCR0. Two consequences:

- AWS itself cannot decrypt by reading the ciphertext.
- Even with full IAM access to the account, an attacker cannot
  decrypt without running the exact enclave image. A different image
  produces a different PCR0 and KMS refuses.
- If you accidentally deploy a malicious enclave image, the new PCR0
  will not match and KMS refuses. You have to add it to the policy
  on purpose.

## Repo layout

```
.
+-- Cargo.toml                Rust manifest, pinned deps for reproducibility
+-- rust-toolchain.toml       Pins rustc version. Changing this changes PCR0.
+-- Dockerfile                Multi-stage build of the enclave runtime image
+-- Makefile                  build / eif / run / pcr0 / kill targets
+-- enclave/
|   +-- src/
|       +-- main.rs           entry point, tracing, vsock listener
|       +-- protocol.rs       SignRequest / GenerateWalletRequest types
|       +-- attestation.rs    NSM attestation document generation
|       +-- envelope.rs       AES-256-CBC of the envelope payload
|       +-- signing.rs        secp256k1 sign_prehash
|       +-- vsock_server.rs   accept loop, framing, sign + generate-wallet pipelines
+-- parent-proxy/
|   +-- src/
|       +-- main.rs           HTTPS frontend, vsock client (out), vsock server (KMS proxy)
+-- systemd/
    +-- rift-parent-proxy.service
```

## Wire protocols

All three flows use length-prefixed JSON over vsock. The HTTPS
front-end at the parent-proxy speaks plain JSON. Bearer-token
auth on all HTTPS endpoints.

### POST /sign (HTTP, parent-proxy)

What the smart-wallet posts when it needs a Safe UserOperation
signature.

Request body:

```json
{
  "user_op_hash_hex": "0x<32 bytes hex>",
  "wrapped_dek_b64": "<base64 of KMS-wrapped DEK from the envelope>",
  "ciphertext_hex": "<hex of AES ciphertext from the envelope>",
  "iv_hex": "<hex of the 16-byte AES IV>",
  "kms_key_arn": "arn:aws:kms:us-east-1:<account>:key/<key-id>"
}
```

Response:

```json
{ "signature_hex": "0x<r 32 bytes><s 32 bytes><v 1 byte>" }
```

v is 27 or 28.

### POST /generate-wallet (HTTP, parent-proxy)

What the backend posts when it needs to provision a new EOA for a
user.

Request body:

```json
{ "kms_key_arn": "arn:aws:kms:us-east-1:<account>:key/<key-id>" }
```

Response:

```json
{
  "envelope_blob": "enc:v1:<wrapped_dek_b64>:<iv_hex>:<ciphertext_hex>",
  "owner_address": "0x<lowercase 40-char hex>"
}
```

The envelope_blob is byte-for-byte the same shape the backend's
encryptKey() helper produces, so storing it directly in
encrypted_keys.encryptedKeys works and any decryption path that
already exists (the enclave's /sign path, the smart-wallet's
in-process KMS path, the backend's legacy decryptKey) works against
it without modification.

### Vsock between parent-proxy and enclave

Two ports:

- Port 5005: sign requests in, signed-userOp-hash out. The body is
  the SignRequest JSON above wrapped in a length prefix. The reply
  is a SignResponse enum, JSON shape:

```json
{ "Ok": { "signature_hex": "0x..." } }
```

or

```json
{ "Err": { "reason": "..." } }
```

- Port 5007: generate-wallet requests in, envelope-plus-address out.
  Same length-prefixed JSON shape.

### Vsock from enclave back to parent-proxy (KMS proxy)

The enclave has no network. When it needs to call KMS, it opens a
fresh vsock connection to the parent's KMS proxy on port 5006 and
sends a tagged enum:

```json
{ "op": "Decrypt", "attestation_doc_b64": "...", "wrapped_dek_b64": "...", "kms_key_arn": "..." }
```

or

```json
{ "op": "GenerateDataKey", "attestation_doc_b64": "...", "kms_key_arn": "..." }
```

The parent calls AWS KMS over HTTPS with the appropriate operation
and returns the result. For Decrypt the response carries
CiphertextForRecipient (RSA-OAEP-SHA-256 encrypted to the public key
inside the attestation doc). For GenerateDataKey it carries both
CiphertextBlob (the KMS-wrapped DEK, goes verbatim into the
envelope) and CiphertextForRecipient (the RSA-OAEP-wrapped plaintext
DEK that the enclave unwraps to actually use).

The recipient encryption is what makes the parent process truly
unable to see plaintext, even though it is the network proxy. The
parent forwards bytes whose recipient is the enclave's ephemeral
public key. Only the enclave can decrypt them.

### Inside the enclave: sign pipeline

```
1. Receive SignRequest on vsock 5005.
2. Generate ephemeral RSA-2048 keypair (private key never leaves
   this function's stack).
3. NSM attest(ephemeral RSA pubkey, random nonce) returns the
   COSE_Sign1 attestation document.
4. Build a KmsProxyRequest::Decrypt and send to vsock 5006.
5. Parent calls kms:Decrypt with the attestation document in the
   Recipient field.
6. KMS verifies PCR0 against the key policy and, if it matches,
   returns CiphertextForRecipient (CMS EnvelopedData, RSA-OAEP'd
   to the recipient pubkey).
7. CMS unwrap with openssl (BER-aware, the pure-Rust crates only do
   strict DER which KMS does not produce) to recover the plaintext
   DEK.
8. AES-256-CBC decrypt the envelope's ciphertext_hex with the DEK
   and iv_hex to recover the EOA private key as UTF-8 hex.
9. Parse the hex into 32 raw bytes, secp256k1.sign_prehash the
   userOpHash with recovery, produce the 65-byte (r, s, v) signature.
10. Zeroize the DEK and the private key bytes.
11. Reply with SignResponse::Ok.
```

### Inside the enclave: generate-wallet pipeline

```
1. Receive GenerateWalletRequest on vsock 5007.
2. Generate ephemeral RSA-2048 keypair (for the KMS recipient
   channel).
3. NSM attest(RSA pubkey, random nonce).
4. Build a KmsProxyRequest::GenerateDataKey and send to vsock 5006.
5. Parent calls kms:GenerateDataKey with the attestation Recipient.
6. KMS verifies PCR0, returns CiphertextBlob (the KMS-wrapped DEK
   to store in the envelope) and CiphertextForRecipient (the
   RSA-OAEP-wrapped plaintext DEK for the enclave to use right now).
7. CMS unwrap CiphertextForRecipient to get the plaintext DEK.
8. Generate a fresh secp256k1 keypair entirely inside the enclave.
9. Derive the EVM owner address: keccak256(uncompressed_pubkey[1..])
   then take the last 20 bytes. Hex-encode with 0x prefix.
10. Generate a random 16-byte IV. AES-256-CBC encrypt the secp256k1
    private key (encoded as 0x<64 hex chars> UTF-8 string) with the
    DEK and the IV.
11. Assemble the envelope blob:
    enc:v1:<base64 of KMS CiphertextBlob>:<hex of IV>:<hex of AES ciphertext>
12. Zeroize the DEK and the secp256k1 private key bytes.
13. Reply with GenerateWalletResponse::Ok(envelope_blob, owner_address).
```

The point: the plaintext secp256k1 private key exists only on the
enclave's stack for the duration of step 10. It never crosses any
vsock boundary, never goes to KMS, never leaves the TEE.

## Bound reseal challenge (`rift-reseal-v1`) — client implementation

`POST /reseal-v3` appends an auth method (a new passkey, or a linked
Google / Apple identity) to an existing v3 wallet. Consent is an
`auth_proof` from a method that is *already* enrolled.

**Legacy behaviour (being retired):** the proof was over the raw
32-byte `prehashed_hex` the backend handed out. The enclave cannot tell
where those 32 bytes came from, so any proof the user ever produced over
any 32-byte value — including an ordinary *transaction* proof, whose
challenge is a UserOp hash — could be replayed by whoever controls the
backend or parent host to enrol an attacker's passkey.

**Bound mode:** the client signs a challenge that the enclave derives
itself, binding the proof to *this* wallet, *this* one-shot server
nonce and *this* new method:

```text
challenge = SHA-256(
    "rift-reseal-v1"     14 bytes, ASCII, no terminator
 || 0x00                 1 byte
 || owner_address        20 raw bytes (the wallet's EOA address, NOT hex text)
 || server_nonce         32 raw bytes = hex-decode(challengeHex from
                         POST /wallet/methods/challenge) — the same value
                         the backend forwards as `prehashed_hex`
 || canonical(new_method)
)

canonical(new_method):
  OIDC    : 0x01 || u32be(len(iss)) || iss (UTF-8) || u32be(len(sub)) || sub (UTF-8)
  Passkey : 0x02 || u32be(len(cred_id)) || cred_id || u32be(len(cose)) || cose
            where cred_id = base64-decode(new_method.cred_id_b64)
                  cose    = base64-decode(new_method.cose_pubkey_b64)
            (decoded bytes — padding / alphabet differences don't matter)
```

`u32be` is a 4-byte big-endian length. `new_method` must be byte-for-byte
the method the client then sends in the request (same `iss`/`sub`
strings, same credential bytes).

How the challenge is used:

| Proof kind | What to put in the ceremony |
|---|---|
| Passkey (`navigator.credentials.get`) | `challenge` = the 32 raw challenge bytes (clientDataJSON.challenge is then their base64url) |
| OIDC (Google / Apple) | `nonce` = lowercase hex of the 32 challenge bytes (64 chars, no `0x`) |

Request shape is unchanged: the client/backend still sends
`prehashed_hex = <server_nonce hex>` — the enclave recomputes the bound
challenge from it and never treats it as the challenge itself.

Test vectors (also asserted in `enclave/src/reseal_helpers.rs`):

```text
owner_address = 00112233445566778899aabbccddeeff00112233
server_nonce  = ab × 32
OIDC  {iss: "https://accounts.google.com", sub: "1234567890"}
  canonical = 010000001b68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d0000000a31323334353637383930
  challenge = 377f6d645f6d470848bad62021c2c318e7da4ad82139f00f05b18a6ac43355cb
Passkey {cred_id: 01020304, cose: a50102}
  canonical = 02000000040102030400000003a50102
  challenge = 5b812e4547e39fba673c5e3b9f30a68f0e454c89e8ba179e240afc0365c4dadd
```

TypeScript sketch:

```ts
const enc = new TextEncoder();
const u32 = (n: number) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const lv = (b: Uint8Array) => concat(u32(b.length), b);
const canonical = m.kind === "oidc"
  ? concat(Uint8Array.of(1), lv(enc.encode(m.iss)), lv(enc.encode(m.sub)))
  : concat(Uint8Array.of(2), lv(b64decode(m.cred_id_b64)), lv(b64decode(m.cose_pubkey_b64)));
const challenge = new Uint8Array(await crypto.subtle.digest("SHA-256",
  concat(enc.encode("rift-reseal-v1"), Uint8Array.of(0), hexToBytes(ownerAddress), hexToBytes(challengeHex), canonical)));
```

Rollout / enforcement: the enclave accepts bound proofs immediately and
keeps accepting legacy proofs until either (a) a project's signed config
bundle sets `"require_bound_reseal": true` (per project, no rebuild), or
(b) `RESEAL_REQUIRE_BOUND_CHALLENGE` in `enclave/src/reseal_helpers.rs`
is flipped to `true` (all projects; rebuild → new PCR0). Legacy accepts
are logged as a warning inside the enclave.

WebAuthn `signCount` is **not** checked on reseal (or sign): the
enclave is stateless and the sealed envelope stores no per-credential
counter. Storing one would not help — the backend can always present an
older envelope blob — and synced platform passkeys report a constant 0.
Replay protection comes from the one-shot server nonce plus the binding
above.

## WebAuthn origin policy

The compiled-in (default) policy accepts only the `https://` Rift hosts
listed in `enclave/src/webauthn_verification.rs`, RP-IDs `riftfi.xyz` /
`riftfi.com`. `localhost` and `http://localhost:3000` are present only
when the enclave crate is built with `--features dev-localhost`, which
the Dockerfile never does.

Cross-origin ceremonies (`clientDataJSON.crossOrigin == true`, i.e. the
passkey prompt ran inside an iframe) and any `topOrigin` member are
**rejected** unless a project's signed config lists the embedding page
in `accepted_top_origins` — then the assertion needs `crossOrigin: true`
AND a `topOrigin` that is exactly one of those values.

## Local development (Mac or Windows)

The portable modules compile and run their unit tests on any
platform. Linux-only code (NSM, vsock, openssl-vendored) is gated by
cfg(target_os = "linux"), so cargo check on Mac or Windows
typechecks the whole repo but skips the gated modules.

| Command | Where | What it does |
|---|---|---|
| cargo check --workspace | any platform | Typecheck. About 5 to 10 seconds after the first build. |
| cargo test | any platform | Unit tests for signing.rs and envelope.rs round trips. |
| make eif | EC2 only | Build the Docker image and convert to EIF. |
| make run-debug | EC2 only | Launch the enclave in debug mode. |
| make console | EC2 only | Tail the enclave's stdout. |
| make kill | EC2 only | Terminate any running enclaves. |
| make pcr0 | EC2 only | Print the EIF's PCR0 hash. |

Recommended inner loop:

1. Edit code in your IDE.
2. cargo check on your laptop.
3. cargo test on your laptop.
4. Commit, push.
5. SSH to the EC2 (or use AWS Session Manager), git pull, make eif,
   capture the new PCR0, integration test.

## Building on the EC2

Prereqs already installed in Phase 1 step 2: docker, nitro-cli, the
Nitro Enclaves allocator service running with at least 1 vCPU and
1024 MiB allocated.

```sh
git clone <repo>
cd rift-signer-enclave
make eif
```

The build runs Cargo inside a Debian container, so the host's
toolchain choices do not affect PCR0. Output ends with a
measurements block:

```json
{
  "Measurements": {
    "PCR0": "<96 hex chars>",
    "PCR1": "...",
    "PCR2": "..."
  }
}
```

Save the PCR0. It is what you add to the KMS CMK key policy.

## Configuring KMS

Two statements per CMK (sandbox and production):

```json
{
  "Sid": "AllowAttestedDecryptFromSignerEnclave",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account>:role/rift-signer-enclave-role" },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<your PCR0>"
    }
  }
}
```

```json
{
  "Sid": "AllowAttestedGenerateDataKeyFromSignerEnclave",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account>:role/rift-signer-enclave-role" },
  "Action": "kms:GenerateDataKey",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:ImageSha384": "<your PCR0>"
    }
  }
}
```

The IAM role on the EC2 instance (rift-signer-enclave-role in our
infra) also needs an identity-based policy allowing kms:Decrypt and
kms:GenerateDataKey on the same CMK ARN. Without both the policy on
the key and the policy on the principal, the call is denied.

## Deploying

Once the EIF is built and the KMS policies are in place:

```sh
make kill                       # stop any old enclave
make install-parent-proxy       # rebuild + install the parent-proxy binary and unit
sudo systemctl restart rift-parent-proxy
make run-debug                  # bring up the new enclave
make console                    # in another shell, tail the enclave
```

Important: nitro-cli assigns enclave CIDs sequentially. Each
make run-debug bumps the CID by 1. The parent-proxy reads
ENCLAVE_CID from /etc/rift-parent-proxy.env. If the new enclave is
at CID 20 and the env file still says ENCLAVE_CID=19, the
parent-proxy will time out trying to reach it. Update the env file
and systemctl restart rift-parent-proxy after each launch.

Smoke test:

```sh
curl -sS -X POST http://127.0.0.1:7777/generate-wallet \
  -H "Authorization: Bearer $PARENT_PROXY_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kms_key_arn":"<your CMK ARN>"}'
```

Expected:

```json
{
  "envelope_blob": "enc:v1:AQID...:0a1b...:8f9e...",
  "owner_address": "0x..."
}
```

## Threat model out of scope

- Side-channel attacks on Graviton SEV-SNP. Nitro's threat model
  assumes hardware integrity. We do not defend against speculation
  or microarchitectural attacks.
- An insider who can both push a malicious enclave image and update
  the KMS key policy to trust its PCR0. KMS attestation defends
  against this for the data path, but if the same person can do
  both, they bypass us. Mitigation lives in IAM and SCP, not here.
- Catastrophic loss of the CMK. Handled separately by a multi-region
  replicated break-glass backup CMK (Phase 1 step 7).

## License

Proprietary. See LICENSE.
