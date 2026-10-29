//! Vsock KMS proxy: the enclave has no network, so it asks the parent
//! to call AWS KMS on its behalf.
//!
//! Every request carries an NSM attestation document. We pass it to KMS
//! as the `Recipient`, so KMS encrypts the plaintext data key to the
//! enclave's ephemeral RSA key (`CiphertextForRecipient`). This process
//! never sees plaintext key material — it is a pure relay, and the KMS
//! key policy (conditioned on the enclave's PCR0) is what enforces
//! that only the genuine enclave image can use the key.
//!
//! Wire shapes are FROZEN and must match `enclave/src/protocol.rs`:
//!
//! Request (internally tagged by `op`):
//!   `{"op":"Decrypt","attestation_doc_b64":..,"wrapped_dek_b64":..,"kms_key_arn":..}`
//!   `{"op":"GenerateDataKey","attestation_doc_b64":..,"kms_key_arn":..}`
//!
//! Response (externally tagged, serde's default enum representation):
//!   `{"Ok":{"ciphertext_for_recipient_b64":..}}`                         (Decrypt)
//!   `{"Ok":{"ciphertext_blob_b64":..,"ciphertext_for_recipient_b64":..}}` (GenerateDataKey)
//!   `{"Err":{"reason":..}}`

use anyhow::{anyhow, Context, Result};
use aws_sdk_kms::{
    primitives::Blob,
    types::{DataKeySpec, KeyEncryptionMechanism, RecipientInfo},
    Client as KmsClient,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::framing::{read_frame, write_frame};

#[derive(Deserialize)]
pub struct KmsDecryptRequest {
    attestation_doc_b64: String,
    wrapped_dek_b64: String,
    kms_key_arn: String,
}

#[derive(Deserialize)]
pub struct KmsGenerateDataKeyRequest {
    attestation_doc_b64: String,
    kms_key_arn: String,
}

#[derive(Deserialize)]
#[serde(tag = "op")]
pub enum KmsProxyRequest {
    Decrypt(KmsDecryptRequest),
    GenerateDataKey(KmsGenerateDataKeyRequest),
}

#[derive(Serialize)]
enum KmsDecryptResponse {
    Ok {
        ciphertext_for_recipient_b64: String,
    },
    Err {
        reason: String,
    },
}

#[derive(Serialize)]
enum KmsGenerateDataKeyResponse {
    Ok {
        ciphertext_blob_b64: String,
        ciphertext_for_recipient_b64: String,
    },
    Err {
        reason: String,
    },
}

/// Accept loop on the parent side of vsock. Linux-only (tokio-vsock).
///
/// Only connections whose peer CID equals `enclave_cid` (the configured
/// `ENCLAVE_CID`) are served; anything else — another enclave on the
/// host, or a local process via vsock loopback (CID 1) — is dropped
/// before a byte is read. KMS would still refuse a non-enclave
/// attestation, but this keeps the instance role's KMS permissions from
/// being exercised (or rate-limited) by arbitrary local peers.
#[cfg(target_os = "linux")]
pub async fn run(port: u32, enclave_cid: u32, kms: std::sync::Arc<KmsClient>) -> Result<()> {
    use tokio_vsock::{VsockAddr, VsockListener};
    use tracing::{info, warn};

    // Bind VMADDR_CID_ANY (the enclave reaches us at CID 3 = parent),
    // then filter on the peer's CID per connection.
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr).context("vsock bind for KMS proxy")?;
    info!(port, enclave_cid, "KMS proxy listener ready on vsock");
    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept")?;
        if !peer_allowed(peer.cid(), enclave_cid) {
            warn!(
                peer_cid = peer.cid(),
                enclave_cid, "KMS proxy: rejected connection from unexpected vsock CID"
            );
            drop(stream);
            continue;
        }
        let kms = kms.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &kms).await {
                warn!(peer_cid = peer.cid(), error = ?e, "KMS proxy conn handler aborted");
            }
        });
    }
}

/// Peer-CID gate for the KMS proxy: exact match with the configured
/// enclave CID only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn peer_allowed(peer_cid: u32, enclave_cid: u32) -> bool {
    peer_cid == enclave_cid
}

/// Serve exactly one request/response exchange on `stream`.
///
/// A malformed request frame aborts the connection without a response
/// (unchanged behaviour); a KMS failure is reported back to the
/// enclave as an `Err { reason }` frame.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub async fn handle_conn<S>(mut stream: S, kms: &KmsClient) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req_bytes = read_frame(&mut stream).await?;
    let req: KmsProxyRequest = serde_json::from_slice(&req_bytes)?;

    let body = match req {
        KmsProxyRequest::Decrypt(req) => {
            let response = match call_kms_decrypt(kms, &req).await {
                Ok(cfr) => KmsDecryptResponse::Ok {
                    ciphertext_for_recipient_b64: B64.encode(&cfr),
                },
                Err(e) => KmsDecryptResponse::Err {
                    reason: format!("{e:#}"),
                },
            };
            serde_json::to_vec(&response)?
        }
        KmsProxyRequest::GenerateDataKey(req) => {
            let response = match call_kms_generate_data_key(kms, &req).await {
                Ok((blob, cfr)) => KmsGenerateDataKeyResponse::Ok {
                    ciphertext_blob_b64: B64.encode(&blob),
                    ciphertext_for_recipient_b64: B64.encode(&cfr),
                },
                Err(e) => KmsGenerateDataKeyResponse::Err {
                    reason: format!("{e:#}"),
                },
            };
            serde_json::to_vec(&response)?
        }
    };

    write_frame(&mut stream, &body).await
}

fn recipient(attestation_doc_b64: &str) -> Result<RecipientInfo> {
    let attestation_doc = B64
        .decode(attestation_doc_b64)
        .context("base64-decode attestation document")?;
    Ok(RecipientInfo::builder()
        .attestation_document(Blob::new(attestation_doc))
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .build())
}

/// kms:Decrypt with the attestation Recipient. Returns
/// CiphertextForRecipient.
async fn call_kms_decrypt(kms: &KmsClient, req: &KmsDecryptRequest) -> Result<Vec<u8>> {
    let recipient = recipient(&req.attestation_doc_b64)?;
    let wrapped_dek = B64
        .decode(&req.wrapped_dek_b64)
        .context("base64-decode wrapped DEK")?;

    let out = kms
        .decrypt()
        .ciphertext_blob(Blob::new(wrapped_dek))
        .key_id(&req.kms_key_arn)
        .recipient(recipient)
        .send()
        .await
        .context("KMS Decrypt with Recipient")?;

    let cfr = out.ciphertext_for_recipient.ok_or_else(|| {
        anyhow!("KMS returned no CiphertextForRecipient — was attestation valid?")
    })?;
    Ok(cfr.into_inner())
}

/// kms:GenerateDataKey with the attestation Recipient. Returns
/// (CiphertextBlob, CiphertextForRecipient).
async fn call_kms_generate_data_key(
    kms: &KmsClient,
    req: &KmsGenerateDataKeyRequest,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let recipient = recipient(&req.attestation_doc_b64)?;

    let out = kms
        .generate_data_key()
        .key_id(&req.kms_key_arn)
        .key_spec(DataKeySpec::Aes256)
        .recipient(recipient)
        .send()
        .await
        .context("KMS GenerateDataKey with Recipient")?;

    let blob = out
        .ciphertext_blob
        .ok_or_else(|| anyhow!("KMS returned no CiphertextBlob"))?
        .into_inner();
    let cfr = out
        .ciphertext_for_recipient
        .ok_or_else(|| anyhow!("KMS returned no CiphertextForRecipient — was attestation valid?"))?
        .into_inner();
    Ok((blob, cfr))
}

#[cfg(test)]
mod tests {
    //! Pin the exact JSON the enclave expects. The enclave deserialises
    //! these with `#[derive(Deserialize)] enum KmsDecryptResponse { Ok
    //! {..}, Err {..} }` (externally tagged), so any drift here breaks
    //! every signing request.
    use super::*;

    #[test]
    fn decrypt_ok_wire_shape() {
        let v = serde_json::to_value(KmsDecryptResponse::Ok {
            ciphertext_for_recipient_b64: "Q0ZS".into(),
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"Ok": {"ciphertext_for_recipient_b64": "Q0ZS"}})
        );
    }

    #[test]
    fn decrypt_err_wire_shape() {
        let v = serde_json::to_value(KmsDecryptResponse::Err {
            reason: "boom".into(),
        })
        .unwrap();
        assert_eq!(v, serde_json::json!({"Err": {"reason": "boom"}}));
    }

    #[test]
    fn generate_data_key_ok_wire_shape() {
        let v = serde_json::to_value(KmsGenerateDataKeyResponse::Ok {
            ciphertext_blob_b64: "QkxPQg==".into(),
            ciphertext_for_recipient_b64: "Q0ZS".into(),
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"Ok": {
                "ciphertext_blob_b64": "QkxPQg==",
                "ciphertext_for_recipient_b64": "Q0ZS"
            }})
        );
    }

    #[test]
    fn generate_data_key_err_wire_shape() {
        let v = serde_json::to_value(KmsGenerateDataKeyResponse::Err {
            reason: "denied".into(),
        })
        .unwrap();
        assert_eq!(v, serde_json::json!({"Err": {"reason": "denied"}}));
    }

    #[test]
    fn parses_enclave_decrypt_request() {
        // Exactly what enclave/src/vsock_server.rs::KmsProxyRequest emits.
        let raw = r#"{"op":"Decrypt","attestation_doc_b64":"QQ==","wrapped_dek_b64":"Qg==","kms_key_arn":"arn:aws:kms:x"}"#;
        match serde_json::from_str::<KmsProxyRequest>(raw).unwrap() {
            KmsProxyRequest::Decrypt(r) => {
                assert_eq!(r.attestation_doc_b64, "QQ==");
                assert_eq!(r.wrapped_dek_b64, "Qg==");
                assert_eq!(r.kms_key_arn, "arn:aws:kms:x");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parses_enclave_generate_data_key_request() {
        let raw = r#"{"op":"GenerateDataKey","attestation_doc_b64":"QQ==","kms_key_arn":"arn:aws:kms:x"}"#;
        match serde_json::from_str::<KmsProxyRequest>(raw).unwrap() {
            KmsProxyRequest::GenerateDataKey(r) => {
                assert_eq!(r.attestation_doc_b64, "QQ==");
                assert_eq!(r.kms_key_arn, "arn:aws:kms:x");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn only_configured_enclave_cid_is_allowed() {
        assert!(peer_allowed(17, 17));
        assert!(!peer_allowed(16, 17));
        assert!(!peer_allowed(1, 17)); // VMADDR_CID_LOCAL (loopback)
        assert!(!peer_allowed(2, 17)); // VMADDR_CID_HOST
        assert!(!peer_allowed(3, 17));
        assert!(!peer_allowed(u32::MAX, 17));
    }

    #[test]
    fn rejects_unknown_op() {
        let raw = r#"{"op":"Encrypt","attestation_doc_b64":"QQ==","kms_key_arn":"k"}"#;
        assert!(serde_json::from_str::<KmsProxyRequest>(raw).is_err());
    }
}
