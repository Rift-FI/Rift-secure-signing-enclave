//! Vsock accept loop. Each accepted connection corresponds to one
//! signing request from the parent.
//!
//! Wire frame (both directions): 4-byte big-endian length prefix, then
//! that many bytes of UTF-8 JSON. One request → one response. No
//! pipelining, no streaming.
//!
//! The handler is intentionally infallible at the connection level:
//! every error becomes a SignResponse::Err string back to the parent,
//! not a TCP-level reset. The parent can then surface that as an HTTP
//! 502 to its caller and the operator can chase it in CloudWatch.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tracing::{error, info, info_span, warn, Instrument};

use crate::protocol::{KmsDecryptRequest, KmsDecryptResponse, SignRequest, SignResponse};

/// Listen forever on `vsock_port`. For each accepted connection, read
/// one length-prefixed SignRequest, do the signing dance, write back
/// the SignResponse, then close.
pub async fn serve(
    vsock_port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    // VMADDR_CID_ANY (`-1` as u32 = 0xFFFFFFFF) means "accept on any
    // CID" — for an enclave there's only one CID anyway.
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
    _parent_cid: u32,
    _parent_kms_proxy_port: u32,
) -> Result<()> {
    let request = read_frame::<SignRequest>(&mut stream).await?;
    info!(
        user_op_hash = %request.user_op_hash_hex,
        kms_key_arn = %request.kms_key_arn,
        "signing request received"
    );

    let response = process(request, _parent_cid, _parent_kms_proxy_port).await;
    let response = match response {
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

/// The signing pipeline. Splits cleanly so it can be unit-tested with
/// mocked KMS / NSM later.
///
/// TODO(rift-1): wire the real KMS Decrypt round trip via the parent's
/// proxy. For now this is stubbed to surface the protocol shape; the
/// next session will fill in:
///   1. generate ephemeral RSA-2048 keypair for the attestation
///   2. NSM attest(public_key, nonce)
///   3. open vsock connection to (parent_cid, parent_kms_proxy_port)
///   4. send KmsDecryptRequest, receive KmsDecryptResponse
///   5. RSA-OAEP-SHA-256 unwrap the CiphertextForRecipient with the
///      ephemeral private key → plaintext DEK
///   6. envelope::decrypt(dek, iv, ciphertext) → plaintext EOA key hex
///   7. parse hex → 32 bytes → signing::sign_user_op_hash
///   8. hex-encode the 65-byte signature, return
async fn process(
    req: SignRequest,
    _parent_cid: u32,
    _parent_kms_proxy_port: u32,
) -> Result<String> {
    // Currently a stub so the binary compiles + runs end-to-end:
    // returns a clearly-fake signature so integration tests can wire
    // the parent + enclave first, then we plug in real crypto.
    let _ = req;
    Ok("0xdeadbeef_PLACEHOLDER_signature_pending_kms_attestation_wiring".to_string())
}

// ─── framing helpers ─────────────────────────────────────────────────

async fn read_frame<T: for<'de> serde::Deserialize<'de>>(
    stream: &mut VsockStream,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        anyhow::bail!("frame too large: {len} bytes (max 1 MiB)");
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

#[allow(dead_code)]
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
