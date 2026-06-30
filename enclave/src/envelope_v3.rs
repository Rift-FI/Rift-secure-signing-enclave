//! v3 envelope: device-bound, non-custodial signing for users with no
//! password.
//!
//! v2's trick was XOR-combining a password-derived key into the AES
//! key. That's airtight crypto but it only works if the user has a
//! password to type. For users who sign in with Google, Apple, or a
//! Passkey, there is no password — so v3 takes a different path:
//!
//!   - Encrypt the EOA private key AND a list of authorised auth
//!     methods under the KMS-released DEK (AES-256-GCM).
//!   - Every sign request carries an `auth_proof`. The enclave
//!     decrypts the payload, then verifies the proof against the
//!     stored methods. If it matches, sign.
//!
//! The KMS attestation policy still gates the DEK release (only this
//! enclave's PCR0 can decrypt). The auth-proof check sits on top —
//! even an engineer who somehow exfiltrated a DEK plaintext (which
//! they can't, but humour the threat model) would also need a valid,
//! freshly-issued OIDC token or WebAuthn assertion bound to the
//! specific transaction. Both controls have to fail for funds to move.
//!
//! Wire format:
//!
//!   enc:v3:<wrapped_dek_b64>:<nonce_hex>:<ciphertext_hex>:<tag_hex>
//!
//! Ciphertext encrypts a CBOR-encoded `EnvelopePayload`:
//!
//!   {
//!     "k": <32 bytes raw secp256k1 private key>,
//!     "m": [ <AuthMethod>, <AuthMethod>, ... ]
//!   }
//!
//! AuthMethod is a tagged union:
//!
//!   Oidc:    { "t": "oidc",    "iss": str, "sub": str }
//!   Passkey: { "t": "passkey", "cred_id": bytes, "cose": bytes }
//!
//! A user can have multiple methods — typically one passkey + Google
//! as a recovery — and any one matching proof is enough to sign.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::password_derivation::{GCM_NONCE_LEN, GCM_TAG_LEN};

pub const V3_PREFIX: &str = "enc:v3:";

/// One enrolled authentication method, stored INSIDE the encrypted
/// payload so an attacker with DB write access cannot add or alter
/// authorised methods — every change to the auth_methods list would
/// fail the AES-GCM tag check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum AuthMethod {
    #[serde(rename = "oidc")]
    Oidc { iss: String, sub: String },

    #[serde(rename = "passkey")]
    Passkey {
        /// Credential ID as returned by the authenticator at enrolment.
        #[serde(with = "serde_bytes")]
        cred_id: Vec<u8>,
        /// COSE_Key CBOR — the public key the assertion must verify against.
        #[serde(with = "serde_bytes")]
        cose: Vec<u8>,
    },
}

/// What the encrypted payload deserialises to inside the enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopePayload {
    /// Raw secp256k1 private key. 32 bytes.
    #[serde(with = "serde_bytes", rename = "k")]
    pub eoa_private_key: Vec<u8>,
    /// At least one enrolled auth method.
    #[serde(rename = "m")]
    pub auth_methods: Vec<AuthMethod>,
}

impl EnvelopePayload {
    /// CBOR-encode for sealing under AES-GCM.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| anyhow!("CBOR encode EnvelopePayload: {e}"))?;
        Ok(out)
    }

    /// CBOR-decode after AES-GCM unsealing.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let v: EnvelopePayload = ciborium::de::from_reader(bytes)
            .map_err(|e| anyhow!("CBOR decode EnvelopePayload: {e}"))?;
        if v.eoa_private_key.len() != 32 {
            bail!(
                "EOA private key must be 32 bytes, got {}",
                v.eoa_private_key.len()
            );
        }
        if v.auth_methods.is_empty() {
            bail!("envelope must enrol at least one auth method");
        }
        Ok(v)
    }
}

/// Wire form of a parsed v3 envelope blob. All fields are post-decode
/// (base64 + hex stripped) so the caller can hand them straight to
/// AES-GCM.
#[derive(Debug, Clone)]
pub struct EnvelopeV3 {
    pub wrapped_dek: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

impl EnvelopeV3 {
    pub fn parse(blob: &str) -> Result<Self> {
        let rest = blob
            .strip_prefix(V3_PREFIX)
            .ok_or_else(|| anyhow!("envelope blob is not v3 (missing prefix {V3_PREFIX})"))?;
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 4 {
            bail!(
                "v3 envelope must have 4 colon-separated fields after the prefix, got {}",
                parts.len()
            );
        }
        let wrapped_dek = B64
            .decode(parts[0])
            .context("base64-decode wrapped_dek")?;

        let nonce_v = hex::decode(parts[1].trim_start_matches("0x"))
            .context("hex-decode nonce")?;
        if nonce_v.len() != GCM_NONCE_LEN {
            bail!("v3 nonce must be {} bytes, got {}", GCM_NONCE_LEN, nonce_v.len());
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);

        let ciphertext = hex::decode(parts[2].trim_start_matches("0x"))
            .context("hex-decode ciphertext")?;

        let tag_v = hex::decode(parts[3].trim_start_matches("0x"))
            .context("hex-decode tag")?;
        if tag_v.len() != GCM_TAG_LEN {
            bail!("v3 tag must be {} bytes, got {}", GCM_TAG_LEN, tag_v.len());
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_v);

        Ok(Self {
            wrapped_dek,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Re-serialise to the wire format. Called when generating new
    /// envelopes after a successful generate-wallet or migration.
    pub fn to_blob(&self, wrapped_dek_b64: &str) -> String {
        format!(
            "{V3_PREFIX}{wrapped_dek_b64}:{}:{}:{}",
            hex::encode(self.nonce),
            hex::encode(&self.ciphertext),
            hex::encode(self.tag),
        )
    }
}

/// Open a v3 envelope: AES-GCM decrypt under `dek` and CBOR-decode.
/// The returned EOA private key is wrapped in Zeroizing so it gets
/// scrubbed on drop.
pub fn open(env: &EnvelopeV3, dek: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, Vec<AuthMethod>)> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new(dek.into());
    // aes-gcm expects ciphertext || tag.
    let mut ct = Vec::with_capacity(env.ciphertext.len() + 16);
    ct.extend_from_slice(&env.ciphertext);
    ct.extend_from_slice(&env.tag);

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&env.nonce), ct.as_ref())
        .map_err(|_| anyhow!("invalid credentials"))?;
    let payload = EnvelopePayload::from_cbor(&plaintext)?;
    let priv_key = Zeroizing::new(payload.eoa_private_key.clone());
    Ok((priv_key, payload.auth_methods))
}

/// Seal a v3 envelope. Used by generate-wallet and migration paths.
/// Returns the wire blob.
pub fn seal(
    eoa_private_key: &[u8; 32],
    auth_methods: Vec<AuthMethod>,
    dek: &[u8; 32],
    nonce: &[u8; 12],
    wrapped_dek_b64: &str,
) -> Result<String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let payload = EnvelopePayload {
        eoa_private_key: eoa_private_key.to_vec(),
        auth_methods,
    };
    let cbor = payload.to_cbor()?;

    let cipher = Aes256Gcm::new(dek.into());
    let mut ct_with_tag = cipher
        .encrypt(Nonce::from_slice(nonce), cbor.as_ref())
        .map_err(|e| anyhow!("AES-GCM seal failed: {e}"))?;
    // Split tag (last 16 bytes) from ciphertext.
    let tag_start = ct_with_tag.len() - 16;
    let tag = ct_with_tag.split_off(tag_start);

    Ok(format!(
        "{V3_PREFIX}{wrapped_dek_b64}:{}:{}:{}",
        hex::encode(nonce),
        hex::encode(&ct_with_tag),
        hex::encode(&tag),
    ))
}

/// Helper for ad-hoc CBOR access during integration. Not used by the
/// production hot path.
#[allow(dead_code)]
fn cbor_value_kind(v: &CborValue) -> &'static str {
    match v {
        CborValue::Integer(_) => "int",
        CborValue::Bytes(_) => "bytes",
        CborValue::Text(_) => "text",
        CborValue::Array(_) => "array",
        CborValue::Map(_) => "map",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_blob_parse() {
        let blob = format!(
            "{V3_PREFIX}{}:{}:{}:{}",
            B64.encode([0xaa; 24]),
            hex::encode([0xbb; 12]),
            hex::encode([0xcc; 64]),
            hex::encode([0xdd; 16]),
        );
        let parsed = EnvelopeV3::parse(&blob).unwrap();
        assert_eq!(parsed.wrapped_dek, vec![0xaa; 24]);
        assert_eq!(parsed.nonce, [0xbb; 12]);
        assert_eq!(parsed.ciphertext, vec![0xcc; 64]);
        assert_eq!(parsed.tag, [0xdd; 16]);
    }

    #[test]
    fn rejects_v1_prefix() {
        let err = EnvelopeV3::parse("enc:v1:foo:bar:baz").unwrap_err();
        assert!(err.to_string().contains("v3"), "{err:#}");
    }

    #[test]
    fn rejects_wrong_part_count() {
        let blob = format!("{V3_PREFIX}aaa:bbb:ccc");
        let err = EnvelopeV3::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("4 colon"), "{err:#}");
    }

    #[test]
    fn rejects_wrong_nonce_len() {
        let blob = format!(
            "{V3_PREFIX}{}:{}:{}:{}",
            B64.encode([0u8; 16]),
            hex::encode([0u8; 8]), // wrong length
            hex::encode([0u8; 32]),
            hex::encode([0u8; 16]),
        );
        let err = EnvelopeV3::parse(&blob).unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err:#}");
    }

    #[test]
    fn seal_and_open_round_trip() {
        let priv_key = [7u8; 32];
        let auth_methods = vec![
            AuthMethod::Oidc {
                iss: "https://accounts.google.com".into(),
                sub: "abc-123".into(),
            },
            AuthMethod::Passkey {
                cred_id: vec![1, 2, 3, 4],
                cose: vec![5, 6, 7, 8],
            },
        ];
        let dek = [9u8; 32];
        let nonce = [3u8; 12];
        let wrapped_b64 = B64.encode([0xff; 32]);

        let blob = seal(&priv_key, auth_methods.clone(), &dek, &nonce, &wrapped_b64).unwrap();
        let parsed = EnvelopeV3::parse(&blob).unwrap();
        let (recovered_key, recovered_methods) = open(&parsed, &dek).unwrap();

        assert_eq!(&recovered_key[..], &priv_key[..]);
        assert_eq!(recovered_methods, auth_methods);
    }

    #[test]
    fn open_fails_with_wrong_dek() {
        let priv_key = [1u8; 32];
        let auth_methods = vec![AuthMethod::Oidc {
            iss: "i".into(),
            sub: "s".into(),
        }];
        let dek = [9u8; 32];
        let nonce = [0u8; 12];
        let wrapped_b64 = B64.encode([0u8; 16]);

        let blob = seal(&priv_key, auth_methods, &dek, &nonce, &wrapped_b64).unwrap();
        let parsed = EnvelopeV3::parse(&blob).unwrap();
        let wrong_dek = [8u8; 32];
        let err = open(&parsed, &wrong_dek).unwrap_err();
        assert!(err.to_string().contains("invalid credentials"), "{err:#}");
    }

    #[test]
    fn cbor_round_trip() {
        let p = EnvelopePayload {
            eoa_private_key: vec![1u8; 32],
            auth_methods: vec![AuthMethod::Oidc {
                iss: "iss".into(),
                sub: "sub".into(),
            }],
        };
        let cbor = p.to_cbor().unwrap();
        let back = EnvelopePayload::from_cbor(&cbor).unwrap();
        assert_eq!(back.eoa_private_key, p.eoa_private_key);
        assert_eq!(back.auth_methods, p.auth_methods);
    }

    #[test]
    fn cbor_rejects_wrong_key_length() {
        // Construct a payload with 16-byte "key" — fromCbor must reject.
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(
            &CborValue::Map(vec![
                (CborValue::Text("k".into()), CborValue::Bytes(vec![0u8; 16])),
                (
                    CborValue::Text("m".into()),
                    CborValue::Array(vec![CborValue::Map(vec![
                        (
                            CborValue::Text("t".into()),
                            CborValue::Text("oidc".into()),
                        ),
                        (
                            CborValue::Text("iss".into()),
                            CborValue::Text("i".into()),
                        ),
                        (
                            CborValue::Text("sub".into()),
                            CborValue::Text("s".into()),
                        ),
                    ])]),
                ),
            ]),
            &mut bytes,
        )
        .unwrap();
        let err = EnvelopePayload::from_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err:#}");
    }

    #[test]
    fn cbor_rejects_empty_auth_methods() {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(
            &CborValue::Map(vec![
                (CborValue::Text("k".into()), CborValue::Bytes(vec![0u8; 32])),
                (CborValue::Text("m".into()), CborValue::Array(vec![])),
            ]),
            &mut bytes,
        )
        .unwrap();
        let err = EnvelopePayload::from_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err:#}");
    }
}
