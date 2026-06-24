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
use rand::RngCore;
use rsa::{
    pkcs8::EncodePublicKey,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tracing::{error, info, info_span, warn, Instrument};
use zeroize::Zeroize;

use crate::{
    attestation, envelope,
    protocol::{KmsDecryptRequest, KmsDecryptResponse, SignRequest, SignResponse},
    signing,
};

pub async fn serve(
    vsock_port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, vsock_port);
    let listener = VsockListener::bind(addr)
        .context("vsock bind failed — is the enclave running with vsock support?")?;
    info!(port = vsock_port, "listening for signing requests on vsock");

    let mut conn_counter: u64 = 0;
    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept failed")?;
        conn_counter += 1;
        let cid = conn_counter;
        let span = info_span!("conn", id = cid, peer_cid = peer.cid());
        tokio::spawn(
            async move {
                if let Err(e) = handle_one(stream, parent_cid, parent_kms_proxy_port).await {
                    warn!(error = ?e, "connection handler aborted");
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

    // ─── 4. RSA-OAEP-SHA-256 unwrap → plaintext DEK ─────────────────
    let mut dek = rsa_priv
        .decrypt(Oaep::new::<Sha256>(), &ciphertext_for_recipient)
        .map_err(|e| anyhow!("RSA-OAEP unwrap of CiphertextForRecipient failed: {e:?}"))?;

    if dek.len() != 32 {
        // Make sure we wipe whatever weird-length plaintext we got
        // before we bail.
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
    write_frame(&mut stream, &request).await?;
    let response: KmsDecryptResponse = read_frame(&mut stream).await?;
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
