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
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// Hex (with or without 0x prefix), 32 bytes once decoded. The
    /// 32-byte hash the backend computed off-enclave (Safe UserOp hash
    /// per ERC-4337 + EIP-712, computed in the parent / smart-wallet).
    pub user_op_hash_hex: String,

    /// The KMS-wrapped data encryption key, base64-encoded. This is the
    /// `wrapped_dek` portion of the backend's envelope blob (everything
    /// between `enc:v1:` and the first `:`).
    pub wrapped_dek_b64: String,

    /// The AES-256-CBC ciphertext containing the EOA private key,
    /// hex-encoded. This is the `ciphertext` portion of the envelope.
    pub ciphertext_hex: String,

    /// The AES IV, hex-encoded, 16 bytes once decoded. The `iv` portion
    /// of the envelope.
    pub iv_hex: String,

    /// Mode-specific KMS key ARN — passed through verbatim to KMS
    /// Decrypt by the parent's proxy. We don't trust this in the
    /// enclave (KMS verifies the ciphertext belongs to the CMK), but
    /// it helps the parent route the call to the right region/key.
    pub kms_key_arn: String,
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
