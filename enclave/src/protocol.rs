//! Wire protocol between the parent EC2 process and the enclave.
//!
//! Frame format on vsock (both directions):
//!   - 4-byte big-endian length prefix (u32)
//!   - that many bytes of UTF-8 JSON
//!
//! No streaming, no chunking — a signing payload is small (a few hundred
//! bytes max). One request → one response, both terminated by EOF on
//! the socket if the peer wants to close the connection.

use serde::{Deserialize, Serialize};

/// Parent → Enclave: please sign this UserOperation hash using the
/// EOA private key whose envelope we're handing you.
///
/// Two envelope formats share this request struct so the wire shape is
/// stable across the v1 → v2 rollout:
///
///   v1: AES-256-CBC, KMS-only. Set `ciphertext_hex` + `iv_hex`. Leave
///       `password`, `salt_b64`, `nonce_hex`, `tag_hex` unset.
///   v2: AES-256-GCM, KMS + password-derived. Set `password`, `salt_b64`,
///       `nonce_hex`, `ciphertext_hex`, `tag_hex`. Leave `iv_hex` unset.
///
/// The enclave picks the path by which set of fields is populated. If
/// both are populated or both are empty, the request is rejected.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// Hex (with or without 0x prefix), 32 bytes once decoded. The
    /// 32-byte hash the backend computed off-enclave (Safe UserOp hash
    /// per ERC-4337 + EIP-712, computed in the parent / smart-wallet).
    pub user_op_hash_hex: String,

    /// The KMS-wrapped data encryption key, base64-encoded.
    pub wrapped_dek_b64: String,

    /// The AES ciphertext containing the EOA private key, hex-encoded.
    /// v1: AES-256-CBC ciphertext (variable length, PKCS#7 padded).
    /// v2: AES-256-GCM ciphertext (32 bytes for the raw secp256k1 key,
    ///     NOT counting the tag which lives in `tag_hex`).
    pub ciphertext_hex: String,

    /// v1 only: the AES-CBC IV, hex-encoded, 16 bytes once decoded.
    #[serde(default)]
    pub iv_hex: String,

    /// v2 only: the user's password, plaintext UTF-8. The enclave runs
    /// HKDF-SHA256 over (password, salt) to derive K_user and XORs it
    /// with the KMS-released DEK. Without the correct password the
    /// AES-GCM tag check fails and the enclave returns "invalid
    /// credentials" without leaking which factor was wrong.
    #[serde(default)]
    pub password: Option<String>,

    /// v2 only: the HKDF salt, base64-encoded. 32 bytes. Per-envelope
    /// random, generated at envelope-create time.
    #[serde(default)]
    pub salt_b64: Option<String>,

    /// v2 only: the AES-GCM nonce, hex-encoded. 12 bytes.
    #[serde(default)]
    pub nonce_hex: Option<String>,

    /// v2 only: the AES-GCM authentication tag, hex-encoded. 16 bytes.
    #[serde(default)]
    pub tag_hex: Option<String>,

    /// Mode-specific KMS key ARN — passed through verbatim to KMS
    /// Decrypt by the parent's proxy.
    pub kms_key_arn: String,

    // ─── v3 fields ───────────────────────────────────────────────────
    //
    // v3 envelopes carry the EOA private key + a list of enrolled
    // auth methods (Passkey / OIDC) sealed under AES-GCM with the
    // KMS-released DEK. The caller proves user consent via
    // `auth_proof`. Set `v3_envelope_blob` AND `auth_proof` for v3.
    // Leave the v1 and v2 fields blank.
    /// v3 only: the full envelope blob (enc:v3:...). The enclave parses
    /// it inline so the wire shape is one field rather than four.
    #[serde(default)]
    pub v3_envelope_blob: Option<String>,

    /// v3 only: the user's consent proof — either an OIDC id_token
    /// bound to this transaction (nonce=user_op_hash), or a WebAuthn
    /// assertion challenged with this transaction's hash.
    #[serde(default)]
    pub auth_proof: Option<AuthProof>,
}

/// Tagged union of consent proofs accepted by v3 envelopes. The
/// enclave dispatches on `kind` and verifies inline (no network).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AuthProof {
    /// Google or Apple id_token. The `nonce` claim MUST equal the
    /// hex-encoded user op hash this request is signing. iss / aud /
    /// sub / exp are verified against the enclave's pinned policy.
    Oidc {
        /// The compact JWS form: header.payload.signature (base64url).
        id_token: String,
    },
    /// WebAuthn assertion from `navigator.credentials.get()`.
    Passkey {
        /// Credential ID of the credential that produced this assertion.
        /// Used to look up the matching public key inside the v3
        /// envelope payload.
        cred_id_b64: String,
        /// Raw bytes of clientDataJSON, base64-no-pad-encoded.
        client_data_json_b64: String,
        /// Raw bytes of authenticatorData, base64-encoded.
        authenticator_data_b64: String,
        /// DER-encoded ECDSA signature, base64-encoded.
        signature_b64: String,
    },
}

/// Enclave → Parent: the signature, or an error string.
#[derive(Debug, Serialize, Deserialize)]
pub enum SignResponse {
    /// 65-byte secp256k1 signature, hex-encoded with 0x prefix:
    /// `0x<r_32><s_32><v_1>` where v is 27 or 28.
    Ok { signature_hex: String },

    /// Something went wrong. The string is for human eyes only; the
    /// enclave's tracing log has the detailed cause.
    Err { reason: String },
}

/// Enclave → Parent (KMS proxy port): "please call KMS Decrypt with
/// this attestation doc + ciphertext blob, and give me back the
/// CiphertextForRecipient."
#[derive(Debug, Serialize, Deserialize)]
pub struct KmsDecryptRequest {
    /// COSE_Sign1 attestation document, base64-encoded.
    pub attestation_doc_b64: String,

    /// The KMS-wrapped DEK we received in the SignRequest.
    pub wrapped_dek_b64: String,

    /// The CMK ARN, so the parent calls the right key.
    pub kms_key_arn: String,
}

/// Parent → Enclave (KMS proxy response): the CiphertextForRecipient
/// blob KMS returned. The enclave unwraps it with its RSA private key.
#[derive(Debug, Serialize, Deserialize)]
pub enum KmsDecryptResponse {
    Ok {
        /// Base64 of the CiphertextForRecipient — RSA-OAEP-SHA-256
        /// encrypted under the public key we embedded in the
        /// attestation document.
        ciphertext_for_recipient_b64: String,
    },
    Err {
        reason: String,
    },
}

// ─── Wallet generation (Phase 2) ────────────────────────────────────
//
// New op: backend → parent-proxy /generate-wallet → enclave. Asks
// the enclave to generate a fresh secp256k1 EOA, wrap its private
// key in a KMS envelope (via kms:GenerateDataKey + Recipient
// attestation), and return:
//   - envelope_blob: `enc:v1:<wrapped_dek_b64>:<iv_hex>:<ct_hex>`
//   - owner_address: 0x-prefixed Ethereum address (keccak256 of
//     uncompressed pubkey[1..], last 20 bytes)
// The plaintext private key NEVER leaves the enclave.

/// Parent → Enclave: generate a brand-new EOA and return its envelope.
///
/// Format-selection cascade (first match wins):
///   1. `enrolled_methods` non-empty   → v3 (Passkey / OIDC bound)
///   2. `password` present             → v2 (password-bound)
///   3. otherwise                      → v1 (KMS-only, legacy)
///
/// v3 is the path for users who sign in with Google / Apple / Passkey
/// and have no password to bind. The auth_methods list is sealed
/// INSIDE the encrypted payload so an engineer with DB write access
/// cannot add a method without breaking the AES-GCM tag.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateWalletRequest {
    /// CMK to wrap the freshly-generated DEK with.
    pub kms_key_arn: String,

    /// Optional v2 user password.
    #[serde(default)]
    pub password: Option<String>,

    /// Optional v3 enrolled auth methods. When non-empty the enclave
    /// produces a v3 envelope and the password field is ignored.
    #[serde(default)]
    pub enrolled_methods: Vec<EnrolledMethod>,
}

/// Wire shape of an enrolled method, as accepted by /generate-wallet
/// and the migration endpoint. Mirrors `envelope_v3::AuthMethod` but
/// uses base64 for bytes so the JSON wire is text-safe.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EnrolledMethod {
    Oidc { iss: String, sub: String },
    Passkey {
        cred_id_b64: String,
        cose_pubkey_b64: String,
    },
}

/// Enclave → Parent: the new EOA's envelope blob + public address.
#[derive(Debug, Serialize, Deserialize)]
pub enum GenerateWalletResponse {
    Ok {
        /// `enc:v1:<wrapped_dek_b64>:<iv_hex>:<ciphertext_hex>` — the
        /// same shape backend's `encryptKey()` produces, so the smart-
        /// wallet's `decryptKey` reads it without modification.
        envelope_blob: String,
        /// 0x-prefixed lowercase EOA address.
        owner_address: String,
    },
    Err {
        reason: String,
    },
}

/// Enclave → Parent (KMS proxy port): "please call kms:GenerateDataKey
/// with this attestation doc and return BOTH the CiphertextBlob (KMS-
/// wrapped DEK to store in the envelope) AND CiphertextForRecipient
/// (RSA-OAEP'd plaintext DEK for the enclave to unwrap)."
#[derive(Debug, Serialize, Deserialize)]
pub struct KmsGenerateDataKeyRequest {
    /// COSE_Sign1 attestation document, base64-encoded.
    pub attestation_doc_b64: String,
    /// The CMK ARN.
    pub kms_key_arn: String,
}

/// Parent → Enclave: migrate an existing v1 or v2 envelope to v3.
///
/// Pipeline:
///   1. KMS-Decrypt the old wrapped DEK (Recipient-attested).
///   2. Open the old envelope's payload (CBC for v1, GCM for v2) using
///      the same logic as the sign path — for v2 we require the
///      current password as proof the migration is authorised by the
///      legitimate user.
///   3. KMS-GenerateDataKey to mint a fresh DEK.
///   4. Re-seal the EOA private key + the supplied enrolled methods
///      under the new DEK as a v3 envelope.
///   5. Return the new envelope blob + the owner address.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrateEnvelopeRequest {
    pub kms_key_arn: String,
    /// The current envelope blob in v1 or v2 form.
    pub old_envelope_blob: String,
    /// Required iff the old envelope is v2.
    #[serde(default)]
    pub old_password: Option<String>,
    /// Methods to enrol on the new v3 envelope. Must be non-empty.
    pub enrolled_methods: Vec<EnrolledMethod>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MigrateEnvelopeResponse {
    Ok {
        envelope_blob: String,
        owner_address: String,
    },
    Err {
        reason: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KmsGenerateDataKeyResponse {
    Ok {
        /// Base64 of the KMS-wrapped DEK — stored verbatim in the
        /// envelope as `wrapped_dek_b64`.
        ciphertext_blob_b64: String,
        /// Base64 of CiphertextForRecipient — RSA-OAEP-SHA-256
        /// encrypted under the public key embedded in the
        /// attestation document. The enclave RSA-unwraps to get the
        /// plaintext DEK.
        ciphertext_for_recipient_b64: String,
    },
    Err {
        reason: String,
    },
}
