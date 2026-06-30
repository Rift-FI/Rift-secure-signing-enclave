//! v2 envelope parse and serialize.
//!
//! The v2 format is:
//!   `enc:v2:<kms_wrapped_dek_b64>:<salt_b64>:<nonce_hex>:<ciphertext_hex>:<tag_hex>`
//!
//! v1 was AES-256-CBC over the hex-encoded private key under a KMS-derived
//! DEK only. v2 is AES-256-GCM over the raw 32-byte private key under
//! (KMS DEK XOR HKDF(password, salt)). See `password_derivation` for the
//! key derivation and the security rationale.
//!
//! This module is just the wire-format parser and the serializer; the
//! cryptographic primitives live in `password_derivation`.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::password_derivation::{GCM_NONCE_LEN, GCM_TAG_LEN, SALT_LEN};

const PREFIX: &str = "enc:v2:";

/// Parsed components of an `enc:v2:` envelope blob.
#[derive(Debug, Clone)]
pub struct EnvelopeV2 {
    /// Raw bytes of the KMS-wrapped DEK (base64-decoded).
    pub wrapped_dek: Vec<u8>,
    /// 32-byte HKDF salt.
    pub salt: [u8; SALT_LEN],
    /// 12-byte AES-256-GCM nonce.
    pub nonce: [u8; GCM_NONCE_LEN],
    /// AES-256-GCM ciphertext concatenated with its 16-byte tag.
    /// (Standard for the aes-gcm crate: tag is appended to ct.)
    pub ciphertext_with_tag: Vec<u8>,
}

impl EnvelopeV2 {
    /// Parse a blob string. Returns `Err` if the format is wrong.
    pub fn parse(blob: &str) -> Result<Self> {
        if !blob.starts_with(PREFIX) {
            bail!("not a v2 envelope (missing prefix)");
        }
        let rest = &blob[PREFIX.len()..];
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 5 {
            bail!(
                "v2 envelope must have 5 colon-separated parts, got {}",
                parts.len()
            );
        }

        let wrapped_dek = B64.decode(parts[0]).context("decode wrapped_dek_b64")?;

        let salt_bytes = B64.decode(parts[1]).context("decode salt_b64")?;
        if salt_bytes.len() != SALT_LEN {
            bail!(
                "salt must decode to {} bytes, got {}",
                SALT_LEN,
                salt_bytes.len()
            );
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_bytes);

        let nonce_bytes = hex::decode(parts[2]).context("decode nonce_hex")?;
        if nonce_bytes.len() != GCM_NONCE_LEN {
            bail!(
                "nonce must decode to {} bytes, got {}",
                GCM_NONCE_LEN,
                nonce_bytes.len()
            );
        }
        let mut nonce = [0u8; GCM_NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext = hex::decode(parts[3]).context("decode ciphertext_hex")?;
        let tag = hex::decode(parts[4]).context("decode tag_hex")?;
        if tag.len() != GCM_TAG_LEN {
            bail!(
                "tag must decode to {} bytes, got {}",
                GCM_TAG_LEN,
                tag.len()
            );
        }

        let mut ciphertext_with_tag = ciphertext;
        ciphertext_with_tag.extend_from_slice(&tag);

        Ok(EnvelopeV2 {
            wrapped_dek,
            salt,
            nonce,
            ciphertext_with_tag,
        })
    }

    /// Serialize to the wire format.
    pub fn to_blob(&self) -> String {
        // ciphertext_with_tag = ciphertext || tag, where tag is the last
        // GCM_TAG_LEN bytes (aes-gcm crate convention). Split for the
        // wire format which uses separate hex strings.
        let tag_len = GCM_TAG_LEN.min(self.ciphertext_with_tag.len());
        let split = self.ciphertext_with_tag.len() - tag_len;
        let (ct, tag) = self.ciphertext_with_tag.split_at(split);
        format!(
            "{}{}:{}:{}:{}:{}",
            PREFIX,
            B64.encode(&self.wrapped_dek),
            B64.encode(self.salt),
            hex::encode(self.nonce),
            hex::encode(ct),
            hex::encode(tag),
        )
    }
}

/// True if the blob looks like a v2 envelope (prefix only, not full parse).
pub fn is_v2(blob: &str) -> bool {
    blob.starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> EnvelopeV2 {
        EnvelopeV2 {
            wrapped_dek: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            salt: [0xBB; SALT_LEN],
            nonce: [0xDD; GCM_NONCE_LEN],
            ciphertext_with_tag: vec![0xEE; 32 + GCM_TAG_LEN], // privkey + tag
        }
    }

    #[test]
    fn round_trip_blob_format() {
        let original = sample_envelope();
        let blob = original.to_blob();
        assert!(is_v2(&blob), "serialized blob must have enc:v2: prefix");

        let parsed = EnvelopeV2::parse(&blob).expect("parse");
        assert_eq!(parsed.wrapped_dek, original.wrapped_dek);
        assert_eq!(parsed.salt, original.salt);
        assert_eq!(parsed.nonce, original.nonce);
        assert_eq!(parsed.ciphertext_with_tag, original.ciphertext_with_tag);
    }

    #[test]
    fn rejects_v1_envelope() {
        let v1_blob = "enc:v1:Zm9vYmFy:0123456789abcdef0123456789abcdef:abcdef1234";
        assert!(!is_v2(v1_blob));
        let result = EnvelopeV2::parse(v1_blob);
        assert!(result.is_err(), "v1 must not parse as v2");
    }

    #[test]
    fn rejects_truncated_blob() {
        // Missing the tag field.
        let truncated = "enc:v2:Zm9v:Zm9v:0102030405060708090a0b0c:deadbeef";
        let result = EnvelopeV2::parse(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_salt_length() {
        // Salt b64 decodes to too few bytes.
        let bad = format!(
            "enc:v2:{}:{}:{}:{}:{}",
            B64.encode([0u8; 4]),                                  // wrapped_dek (4 bytes)
            B64.encode([0u8; 8]),                                  // salt only 8 bytes
            hex::encode([0u8; GCM_NONCE_LEN]),                     // nonce ok
            hex::encode([0u8; 32]),                                // ct ok
            hex::encode([0u8; GCM_TAG_LEN])                        // tag ok
        );
        let result = EnvelopeV2::parse(&bad);
        assert!(result.is_err(), "salt length mismatch must fail parse");
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let bad = format!(
            "enc:v2:{}:{}:{}:{}:{}",
            B64.encode([0u8; 4]),
            B64.encode([0u8; SALT_LEN]),
            hex::encode([0u8; 8]),                                 // nonce too short
            hex::encode([0u8; 32]),
            hex::encode([0u8; GCM_TAG_LEN])
        );
        let result = EnvelopeV2::parse(&bad);
        assert!(result.is_err(), "nonce length mismatch must fail parse");
    }
}
