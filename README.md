# rift-signer-enclave

A tiny Rust binary that runs inside an [AWS Nitro Enclave](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html) and does exactly one thing: **decrypt envelope-encrypted EOA private keys via KMS attestation and sign Safe UserOperation hashes** for the Rift smart-wallet service.

This is Phase 1 of Rift's key-management roadmap (Phase 0 = at-rest KMS envelope in the DB; Phase 0.5 = envelope-over-HTTPS to smart-wallet; Phase 1 = signing happens inside an attested enclave so even AWS root can't see the plaintext).

## Why this exists

| Risk | Pre-Phase-0 | After Phase 0/0.5 | After Phase 1 (this) |
|---|---|---|---|
| `ENCRYPTION_KEY` env var leak | Drains every user | No-op; KMS access required | No-op |
| Backend/smart-wallet HTTPS plaintext intercept | Plaintext key in body | Opaque envelope | Opaque envelope |
| Backend or smart-wallet host root compromise | Plaintext keys in process memory | Plaintext keys in process memory | **Not visible — keys only ever in enclave RAM** |
| AWS IAM credentials leak | n/a | KMS Decrypt callable | Decrypt succeeds but plaintext is encrypted-to-enclave-public-key; only this exact enclave image can use it |

The PCR0 of this enclave image is pinned in the KMS CMK's key policy. KMS releases plaintext **only** to attestation documents signed by NSM and reporting that exact PCR0. So:

- ✅ Even AWS itself can't decrypt by reading the ciphertext
- ✅ Even with full IAM access to your account, an attacker can't decrypt without running the exact enclave image
- ✅ Even if you accidentally deploy a malicious enclave image, the new PCR0 won't match and KMS refuses

## Architecture

```
                  ┌──────────────────────────────────────────┐
                  │ EC2 c6g.large (Amazon Linux 2023)        │
   HTTPS ───────► │ ┌──────────────────────────────────────┐ │
   from backend   │ │ Parent process (Node, separate repo) │ │
                  │ │ - HTTPS frontend                     │ │
                  │ │ - Pimlico API, UserOp encoding       │ │
                  │ │ - vsock client → enclave             │ │
                  │ │ - vsock server ← enclave (KMS proxy) │ │
                  │ └────────────────┬─────────────────────┘ │
                  │                  │ vsock                 │
                  │ ┌────────────────▼─────────────────────┐ │
                  │ │ rift-signer-enclave (THIS REPO)      │ │
                  │ │ ─────────────────────────────────────│ │
                  │ │ 1. recv {userOpHash, envelope}        │ │
                  │ │ 2. NSM attest(ephemeral_pubkey)       │ │
                  │ │ 3. ─→ parent → KMS Decrypt(attest,    │ │
                  │ │       wrapped_dek)                    │ │
                  │ │ 4. ←─ CiphertextForRecipient          │ │
                  │ │ 5. RSA-OAEP unwrap → plaintext DEK    │ │
                  │ │ 6. AES-256-CBC decrypt envelope       │ │
                  │ │ 7. secp256k1 sign userOpHash          │ │
                  │ │ 8. zeroize everything                 │ │
                  │ │ 9. return 65-byte signature           │ │
                  │ └──────────────────────────────────────┘ │
                  └──────────────────────────────────────────┘
```

## Repo layout

```
.
├── Cargo.toml                # Rust manifest; pinned deps for build reproducibility
├── rust-toolchain.toml       # Pins rustc version — changing this changes PCR0
├── Dockerfile                # Multi-stage build → enclave runtime image
├── Makefile                  # build / eif / run / pcr0 / kill
├── src/
│   ├── main.rs               # entry point, tracing setup, vsock listener
│   ├── protocol.rs           # SignRequest / SignResponse / KmsDecryptRequest
│   ├── attestation.rs        # NSM attestation document generation
│   ├── envelope.rs           # AES-256-CBC of the envelope payload
│   ├── signing.rs            # secp256k1 sign_prehash
│   └── vsock_server.rs       # accept loop, frame I/O, signing pipeline
└── README.md (this file)
```

## Local development (Mac / Windows)

You can't actually *run* the enclave off a Nitro-capable EC2 — but you can typecheck:

```sh
make check
```

That runs `cargo check --locked` which catches type errors fast without a full build. For everything else, ssh to the EC2 via SSM Session Manager and run there.

## Building on the EC2

Prereqs already installed in Phase 1 step 2: `docker`, `nitro-cli`, the Nitro Enclaves allocator service running, your user in the `ne` group (or just `sudo`).

```sh
git clone <repo-url>
cd rift-signer-enclave
make eif
```

Output ends with a measurements block:

```
"Measurements": {
  "PCR0": "<long hex>",
  ...
}
```

**Save the PCR0.** That hex string is what we'll add to the KMS CMK key policy in Phase 1 step 5 — the condition that gates plaintext release on this exact image.

## Running it

```sh
make run-debug   # enclave + console output visible via `make console`
make describe    # show running enclaves
make console     # tail the enclave's stdout (debug-mode only)
make kill        # terminate
```

Default allocation is 1 vCPU + 1024 MiB. Override per-invocation:

```sh
ENCLAVE_MEMORY_MIB=2048 make run-debug
```

## Wire protocol

Vsock, length-prefixed JSON. See `src/protocol.rs` for the exact shapes.

**Parent → enclave (port 5005):**

```json
{
  "user_op_hash_hex": "0x...",            // 32-byte Safe UserOp hash
  "wrapped_dek_b64": "...",               // KMS-wrapped DEK from envelope
  "ciphertext_hex": "...",                // envelope payload
  "iv_hex": "...",                        // envelope IV
  "kms_key_arn": "arn:aws:kms:..."        // for parent's KMS proxy routing
}
```

**Enclave → parent (response):**

```json
{ "Ok": { "signature_hex": "0x<r><s><v>" } }
```

or

```json
{ "Err": { "reason": "..." } }
```

**Enclave → parent (port 5006, KMS proxy round trip):**

The enclave initiates this connection when it needs a KMS Decrypt; the parent forwards the call to the real KMS endpoint and returns the CiphertextForRecipient.

## Status

This repo currently scaffolds the runtime: vsock listener, framing, NSM init, signing primitive, envelope AES decrypt. **The real KMS attested-decrypt flow is stubbed** (see `vsock_server.rs::process` and the `TODO(rift-1)` marker). Next session wires:

1. ephemeral RSA-2048 keypair generation per request
2. NSM attestation with embedded public key
3. vsock round-trip to the parent's KMS proxy
4. RSA-OAEP-SHA-256 unwrap of CiphertextForRecipient
5. envelope::decrypt + signing::sign_user_op_hash
6. hex-encoded signature back to the parent

After that, the parent proxy gets built (separate repo / directory).

## Threat model out of scope (Phase 2+)

- **Side-channel attacks on Graviton SEV-SNP**: Nitro's threat model assumes hardware integrity. We don't try to defend against speculation-style attacks.
- **Insider with AWS root + ability to silently sub a malicious enclave image**: KMS attestation defends against this for the data path, but if an insider can both push a malicious image AND update the KMS key policy to trust its PCR0, they bypass us. Mitigation lives in IAM / SCP land, not here.
- **Catastrophic loss of the CMK**: handled separately by the multi-region replicated break-glass backup CMK (Phase 1 step 7).

## License

Proprietary. See LICENSE (TBD).
