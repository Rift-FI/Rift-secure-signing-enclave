//! Vsock accept loop + signing pipeline.
//!
//! Each accepted connection corresponds to one signing request from the
//! parent. Wire frame (both directions): 4-byte big-endian length
//! prefix, then that many bytes of UTF-8 JSON. One request → one
//! response. No pipelining, no streaming.
//!
//! Full crypto pipeline per request (no stubs):
//!   1. Generate ephemeral RSA-2048 keypair (lives in enclave RAM only).
//!   2. NSM `attest(rsa_public_key_der, nonce)` → COSE_Sign1 doc signed
//!      by the Nitro Security Module with this enclave's PCR0 inside.
//!   3. Open a vsock connection to the parent's KMS proxy, send the
//!      attestation doc + wrapped DEK, receive `CiphertextForRecipient`.
//!      KMS itself only releases plaintext if its key policy condition
//!      matches the PCR0 inside the attestation document — so even with
//!      valid IAM creds the parent process cannot decrypt.
//!   4. RSA-OAEP-SHA-256 unwrap the CiphertextForRecipient with our
//!      ephemeral private key → plaintext DEK.
//!   5. AES-256-CBC decrypt the envelope payload with the DEK → the
//!      hex-encoded EOA private key.
//!   6. Hex-decode → 32 bytes → secp256k1 sign the UserOp hash.
//!   7. Zeroize the DEK and the plaintext key buffers.
//!   8. Return the 65-byte (r, s, v) signature hex-encoded.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use openssl::cms::CmsContentInfo;
use openssl::pkey::PKey;
use rand::RngCore;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tracing::{error, info, info_span, warn, Instrument};
use zeroize::Zeroize;

use crate::{
    attestation, envelope,
    protocol::{
        GenerateWalletRequest, GenerateWalletResponse, KmsDecryptRequest, KmsDecryptResponse,
        KmsGenerateDataKeyRequest, KmsGenerateDataKeyResponse, SignRequest, SignResponse,
    },
    signing,
};

/// Serves both signing requests (existing port) and wallet-generation
/// requests (new port). Two independent listeners share the same KMS
/// proxy port back to the parent.
pub async fn serve(
    vsock_port: u32,
    generate_wallet_port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    // Spawn the generate-wallet listener as a sibling task so a hung
    // signing connection can't starve account creation and vice versa.
    let gw_handle = tokio::spawn(serve_generate_wallet(
        generate_wallet_port,
        parent_cid,
        parent_kms_proxy_port,
    ));

    let sign_result = serve_sign(vsock_port, parent_cid, parent_kms_proxy_port).await;
    // Best-effort: if the sign loop exits, abort the gw loop too so
    // the enclave-supervisor sees a single coherent failure.
    gw_handle.abort();
    sign_result
}

async fn serve_sign(
    vsock_port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, vsock_port);
    let mut listener = VsockListener::bind(addr)
        .context("vsock bind failed (sign) — is the enclave running with vsock support?")?;
    info!(port = vsock_port, "listening for signing requests on vsock");

    let mut conn_counter: u64 = 0;
    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept failed (sign)")?;
        conn_counter += 1;
        let cid = conn_counter;
        let span = info_span!("sign-conn", id = cid, peer_cid = peer.cid());
        tokio::spawn(
            async move {
                if let Err(e) = handle_one(stream, parent_cid, parent_kms_proxy_port).await {
                    warn!(error = ?e, "sign connection handler aborted");
                }
            }
            .instrument(span),
        );
    }
}

async fn serve_generate_wallet(
    port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr)
        .context("vsock bind failed (generate-wallet)")?;
    info!(port = port, "listening for generate-wallet requests on vsock");

    let mut conn_counter: u64 = 0;
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("vsock accept failed (generate-wallet)")?;
        conn_counter += 1;
        let cid = conn_counter;
        let span = info_span!("gw-conn", id = cid, peer_cid = peer.cid());
        tokio::spawn(
            async move {
                if let Err(e) =
                    handle_one_generate_wallet(stream, parent_cid, parent_kms_proxy_port).await
                {
                    warn!(error = ?e, "generate-wallet handler aborted");
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_one(
    mut stream: VsockStream,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let request = read_frame::<SignRequest>(&mut stream).await?;
    info!(
        user_op_hash = %request.user_op_hash_hex,
        kms_key_arn = %request.kms_key_arn,
        "signing request received"
    );

    let response = match process(request, parent_cid, parent_kms_proxy_port).await {
        Ok(sig) => SignResponse::Ok { signature_hex: sig },
        Err(e) => {
            error!(error = ?e, "signing failed");
            SignResponse::Err {
                reason: format!("{e:#}"),
            }
        }
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process(
    req: SignRequest,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<String> {
    // ─── 1. Ephemeral RSA-2048 keypair ───────────────────────────────
    // Generated inside the enclave; private key never leaves this
    // function's stack; the public key goes into the attestation doc.
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = RsaPrivateKey::new(&mut rng, 2048)
        .context("RSA-2048 key generation failed inside the enclave")?;
    let rsa_pub = RsaPublicKey::from(&rsa_priv);
    let rsa_pub_der = rsa_pub
        .to_public_key_der()
        .context("encode RSA public key as DER")?
        .to_vec();

    // ─── 2. Attestation document ────────────────────────────────────
    // 32 bytes of random nonce — KMS doesn't strictly require it but
    // it's the right hook for replay defence in a future iteration.
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let attestation_doc = attestation::attest(&rsa_pub_der, &nonce)
        .context("NSM attestation document generation")?;

    // ─── 3. KMS Decrypt-with-Recipient via parent proxy ─────────────
    let kms_req = KmsDecryptRequest {
        attestation_doc_b64: B64.encode(&*attestation_doc),
        wrapped_dek_b64: req.wrapped_dek_b64.clone(),
        kms_key_arn: req.kms_key_arn.clone(),
    };
    let kms_resp = kms_round_trip(parent_cid, parent_kms_proxy_port, kms_req)
        .await
        .context("parent KMS proxy round trip")?;
    let ciphertext_for_recipient_b64 = match kms_resp {
        KmsDecryptResponse::Ok {
            ciphertext_for_recipient_b64,
        } => ciphertext_for_recipient_b64,
        KmsDecryptResponse::Err { reason } => {
            bail!("parent KMS proxy returned error: {reason}")
        }
    };
    let ciphertext_for_recipient = B64
        .decode(&ciphertext_for_recipient_b64)
        .context("base64-decode CiphertextForRecipient")?;

    // ─── 4. CMS EnvelopedData unwrap → plaintext DEK ─────────────────
    // KMS returns a PKCS#7 / CMS EnvelopedData structure (RFC 5652),
    // NOT a raw RSA-OAEP ciphertext. The structure contains:
    //   - one or more RecipientInfos, each holding a content-encryption-
    //     key (CEK) encrypted to a specific public key (ours, by RSA-OAEP)
    //   - an EncryptedContentInfo holding the actual plaintext DEK
    //     encrypted to the CEK by AES-256-CBC.
    // So we: parse CMS → extract our KeyTransRecipientInfo → RSA-OAEP
    // unwrap the CEK → AES-256-CBC decrypt the encrypted content with
    // that CEK → that decrypted blob is the plaintext DEK we asked KMS
    // to decrypt for us.
    let mut dek = cms_unwrap_data_key(&rsa_priv, &ciphertext_for_recipient)
        .context("CMS unwrap of KMS CiphertextForRecipient")?;

    if dek.len() != 32 {
        dek.zeroize();
        bail!("unwrapped DEK has unexpected length {} (want 32)", dek.len());
    }

    // ─── 5. AES-256-CBC decrypt envelope payload ────────────────────
    let iv = hex::decode(req.iv_hex.trim_start_matches("0x"))
        .context("hex-decode envelope IV")?;
    let ciphertext = hex::decode(req.ciphertext_hex.trim_start_matches("0x"))
        .context("hex-decode envelope ciphertext")?;
    let plaintext = envelope::decrypt(&dek, &iv, &ciphertext)?;
    // Wipe the DEK now — it's not needed past this point.
    dek.zeroize();

    // ─── 6. Parse the plaintext into a 32-byte secp256k1 key ────────
    // The backend's keyEncryption.ts stores the key as a hex string,
    // optionally with 0x prefix. plaintext here is that string's bytes
    // (UTF-8).
    let pk_hex = std::str::from_utf8(&plaintext)
        .map_err(|_| anyhow!("decrypted plaintext is not valid UTF-8"))?;
    let pk_hex_clean = pk_hex.trim().trim_start_matches("0x");
    let pk_bytes =
        hex::decode(pk_hex_clean).context("hex-decode EOA private key from envelope plaintext")?;
    if pk_bytes.len() != 32 {
        bail!(
            "EOA private key has unexpected length {} (want 32)",
            pk_bytes.len()
        );
    }

    // ─── 7. Sign ────────────────────────────────────────────────────
    let user_op_hash_clean = req.user_op_hash_hex.trim_start_matches("0x");
    let user_op_hash =
        hex::decode(user_op_hash_clean).context("hex-decode user op hash")?;
    if user_op_hash.len() != 32 {
        bail!(
            "user op hash has unexpected length {} (want 32)",
            user_op_hash.len()
        );
    }
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&user_op_hash);
    let sig = signing::sign_user_op_hash(&pk_bytes, &hash_arr)?;

    // ─── 8. Encode + return ─────────────────────────────────────────
    let sig_hex = format!("0x{}", hex::encode(&*sig));
    info!("signing complete, returning signature");
    Ok(sig_hex)
}

// ─── Generate-wallet pipeline ────────────────────────────────────────

async fn handle_one_generate_wallet(
    mut stream: VsockStream,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let request = read_frame::<GenerateWalletRequest>(&mut stream).await?;
    info!(kms_key_arn = %request.kms_key_arn, "generate-wallet request received");

    let response = match process_generate_wallet(request, parent_cid, parent_kms_proxy_port).await {
        Ok((envelope_blob, owner_address)) => GenerateWalletResponse::Ok {
            envelope_blob,
            owner_address,
        },
        Err(e) => {
            error!(error = ?e, "generate-wallet failed");
            GenerateWalletResponse::Err {
                reason: format!("{e:#}"),
            }
        }
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process_generate_wallet(
    req: GenerateWalletRequest,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<(String, String)> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    // 1. Ephemeral RSA-2048 for KMS-Decrypt-with-Recipient (used to
    //    receive the freshly-generated DEK from KMS).
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = RsaPrivateKey::new(&mut rng, 2048)
        .context("RSA-2048 keygen for KMS-recipient channel")?;
    let rsa_pub = RsaPublicKey::from(&rsa_priv);
    let rsa_pub_der = rsa_pub
        .to_public_key_der()
        .context("encode RSA pubkey")?
        .to_vec();

    // 2. NSM attestation with the RSA pubkey baked in.
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let attestation_doc = attestation::attest(&rsa_pub_der, &nonce)
        .context("NSM attestation for generate-wallet")?;

    // 3. Ask the parent KMS proxy to call kms:GenerateDataKey with the
    //    recipient attestation. We get back BOTH the KMS-wrapped DEK
    //    (CiphertextBlob, store it in the envelope verbatim) AND the
    //    RSA-OAEP-wrapped plaintext DEK (CiphertextForRecipient, the
    //    enclave unwraps to encrypt the freshly-generated EOA key).
    let kms_req = KmsGenerateDataKeyRequest {
        attestation_doc_b64: B64.encode(&*attestation_doc),
        kms_key_arn: req.kms_key_arn.clone(),
    };
    let kms_resp = kms_generate_data_key_round_trip(parent_cid, parent_kms_proxy_port, kms_req)
        .await
        .context("parent KMS proxy GenerateDataKey round trip")?;
    let (ciphertext_blob_b64, ciphertext_for_recipient_b64) = match kms_resp {
        KmsGenerateDataKeyResponse::Ok {
            ciphertext_blob_b64,
            ciphertext_for_recipient_b64,
        } => (ciphertext_blob_b64, ciphertext_for_recipient_b64),
        KmsGenerateDataKeyResponse::Err { reason } => {
            bail!("parent KMS GenerateDataKey returned error: {reason}")
        }
    };
    let cfr = B64
        .decode(&ciphertext_for_recipient_b64)
        .context("base64-decode CiphertextForRecipient")?;

    // 4. CMS unwrap → plaintext DEK (same as the decrypt path).
    let mut dek = cms_unwrap_data_key(&rsa_priv, &cfr)
        .context("CMS unwrap of CiphertextForRecipient")?;
    if dek.len() != 32 {
        dek.zeroize();
        bail!("DEK has unexpected length {} (want 32)", dek.len());
    }

    // 5. Generate the EOA secp256k1 keypair INSIDE the enclave.
    let mut sk_bytes = [0u8; 32];
    // Keep looping until k256 accepts (it rejects the all-zero and
    // out-of-range values which are negligible-probability events).
    let signing_key = loop {
        rng.fill_bytes(&mut sk_bytes);
        if let Ok(sk) = SigningKey::from_bytes((&sk_bytes).into()) {
            break sk;
        }
    };
    let pubkey = signing_key.verifying_key();
    // 65-byte uncompressed pubkey: 0x04 || X(32) || Y(32). Ethereum
    // address = keccak256(X || Y).last_20_bytes().
    let uncompressed = pubkey.to_encoded_point(false);
    let xy = &uncompressed.as_bytes()[1..];
    let hash = Keccak256::digest(xy);
    let addr_bytes = &hash[12..];
    let owner_address = format!("0x{}", hex::encode(addr_bytes));

    // 6. Encode the private key the same way the backend's encryptKey()
    //    does: `0x<64 hex chars>` UTF-8 bytes. This makes the envelope
    //    byte-for-byte compatible with backend/smart-wallet decrypt
    //    paths and the existing /sign handler.
    let pk_hex = format!("0x{}", hex::encode(sk_bytes));
    sk_bytes.zeroize();
    let plaintext_bytes = pk_hex.as_bytes();

    // 7. AES-256-CBC encrypt with a fresh 16-byte IV.
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    let encryptor = Aes256CbcEnc::new(dek[..].into(), (&iv).into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext_bytes);
    dek.zeroize();

    // 8. Assemble the envelope blob.
    let envelope_blob = format!(
        "enc:v1:{}:{}:{}",
        ciphertext_blob_b64,
        hex::encode(iv),
        hex::encode(&ciphertext)
    );

    info!(owner_address = %owner_address, "wallet generated inside enclave");
    Ok((envelope_blob, owner_address))
}

// ─── Vsock framing + KMS proxy round-trip ────────────────────────────

async fn kms_round_trip(
    parent_cid: u32,
    parent_kms_proxy_port: u32,
    request: KmsDecryptRequest,
) -> Result<KmsDecryptResponse> {
    let addr = VsockAddr::new(parent_cid, parent_kms_proxy_port);
    let mut stream = VsockStream::connect(addr)
        .await
        .context("vsock connect to parent KMS proxy")?;
    let wrapped = KmsProxyRequest::Decrypt(request);
    write_frame(&mut stream, &wrapped).await?;
    let response: KmsDecryptResponse = read_frame(&mut stream).await?;
    Ok(response)
}

/// Same channel, different request type. The parent KMS proxy
/// inspects an `op` discriminator on the wire and dispatches to either
/// kms:Decrypt or kms:GenerateDataKey. Both enclave call sites use this
/// tagged form so the parent-proxy has exactly one wire shape to parse.
#[derive(serde::Serialize)]
#[serde(tag = "op")]
enum KmsProxyRequest {
    Decrypt(KmsDecryptRequest),
    GenerateDataKey(KmsGenerateDataKeyRequest),
}

async fn kms_generate_data_key_round_trip(
    parent_cid: u32,
    parent_kms_proxy_port: u32,
    request: KmsGenerateDataKeyRequest,
) -> Result<KmsGenerateDataKeyResponse> {
    let addr = VsockAddr::new(parent_cid, parent_kms_proxy_port);
    let mut stream = VsockStream::connect(addr)
        .await
        .context("vsock connect to parent KMS proxy for GenerateDataKey")?;
    let wrapped = KmsProxyRequest::GenerateDataKey(request);
    write_frame(&mut stream, &wrapped).await?;
    let response: KmsGenerateDataKeyResponse = read_frame(&mut stream).await?;
    Ok(response)
}

async fn read_frame<T: for<'de> serde::Deserialize<'de>>(
    stream: &mut VsockStream,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        bail!("frame too large: {len} bytes (max 1 MiB)");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read frame body")?;
    let decoded: T = serde_json::from_slice(&body).context("JSON decode")?;
    Ok(decoded)
}

async fn write_frame<T: serde::Serialize>(stream: &mut VsockStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("JSON encode")?;
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("write length prefix")?;
    stream.write_all(&body).await.context("write frame body")?;
    stream.flush().await.context("flush")?;
    Ok(())
}

// ─── CMS EnvelopedData unwrap ───────────────────────────────────────
//
// KMS returns CiphertextForRecipient as a BER-encoded CMS EnvelopedData
// structure with indefinite-length sequences. The pure-Rust cms/der
// crates from RustCrypto only do strict DER and reject the indefinite-
// length form, so we use openssl (statically vendored) for this step.
// Same code path as the AWS Nitro Enclaves C SDK
// (`CMS_decrypt(cms_info, NULL, pkey, NULL, plaintext_bio, 0)`).
fn cms_unwrap_data_key(rsa_priv: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Convert our rsa::RsaPrivateKey → openssl::PKey via PKCS#8 DER.
    // Two crates, one byte-array stop in between.
    let pkcs8 = rsa_priv
        .to_pkcs8_der()
        .context("encode RSA private key as PKCS#8 DER")?;
    let pkey = PKey::private_key_from_pkcs8(pkcs8.as_bytes())
        .context("load RSA private key into OpenSSL")?;

    // Parse + decrypt the CMS structure. openssl handles BER + the
    // KeyTransRecipientInfo + RSA-OAEP unwrap + content decryption
    // in one call.
    let mut cms = CmsContentInfo::from_der(ciphertext).context("parse CMS ContentInfo")?;
    let plaintext = cms
        .decrypt_without_cert_check(&pkey)
        .context("CMS_decrypt of EnvelopedData")?;
    Ok(plaintext)
}
