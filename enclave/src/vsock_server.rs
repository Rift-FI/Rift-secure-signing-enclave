//! Vsock accept loops + signing / envelope pipelines.
//!
//! Each accepted connection corresponds to one request from the parent.
//! Wire frame (both directions, FROZEN): 4-byte big-endian length
//! prefix, then that many bytes of UTF-8 JSON. One request → one
//! response. No pipelining, no streaming.
//!
//! Full crypto pipeline per sign request (no stubs):
//!   1. Generate ephemeral RSA-2048 keypair (lives in enclave RAM only).
//!   2. NSM `attest(rsa_public_key_der, nonce)` → COSE_Sign1 doc signed
//!      by the Nitro Security Module with this enclave's PCR0 inside.
//!   3. Open a vsock connection to the parent's KMS proxy, send the
//!      attestation doc + wrapped DEK, receive `CiphertextForRecipient`.
//!      KMS itself only releases plaintext if its key policy condition
//!      matches the PCR0 inside the attestation document — so even with
//!      valid IAM creds the parent process cannot decrypt.
//!   4. CMS-unwrap the CiphertextForRecipient with our ephemeral private
//!      key → plaintext DEK.
//!   5. Decrypt the envelope payload (v1 CBC / v2 GCM / v3 GCM+CBOR).
//!   6. (v3) verify the consent proof against the sealed methods.
//!   7. secp256k1 sign the UserOp hash.
//!   8. Return the 65-byte (r, s, v) signature hex-encoded.
//!
//! Secret hygiene: every DEK, derived key, recovered private key and
//! decrypted payload lives in a `Zeroizing` container (or a type with a
//! zeroizing `Drop`), so it is wiped on EVERY exit path, including `?`
//! early returns — no hand-written `zeroize()` calls to forget.

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
use zeroize::Zeroizing;

use crate::{
    attestation, envelope, envelope_v3, oidc_verification, password_derivation, pinned_jwks,
    project_config,
    protocol::{
        AuthProof, EnrolledMethod, GenerateWalletRequest, GenerateWalletResponse, HealthRequest,
        HealthResponse, KmsDecryptRequest, KmsDecryptResponse, KmsGenerateDataKeyRequest,
        KmsGenerateDataKeyResponse, MigrateEnvelopeRequest, MigrateEnvelopeResponse,
        ResealV3Request, ResealV3Response, SignRequest, SignResponse,
    },
    reseal_helpers::{
        bound_reseal_challenge, enrolled_to_authmethod, is_duplicate_method, parse_hex32,
        reseal_requires_bound, verify_reseal_consent,
    },
    signing, webauthn_verification,
};

/// Error text when v1 is disabled at build time (`V1_SIGNING_ENABLED`).
const V1_DISABLED: &str =
    "v1 envelopes are disabled in this enclave build — migrate the wallet to v3 (/migrate-envelope)";

/// Serves five concurrent vsock listeners — sign (5005),
/// generate-wallet (5007), migrate-envelope (5008), reseal-v3 (5009)
/// and health (5010). Each is an independent tokio task so a hung
/// listener of one kind cannot starve the others.
pub async fn serve(
    vsock_port: u32,
    generate_wallet_port: u32,
    migrate_port: u32,
    reseal_port: u32,
    health_port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let gw_handle = tokio::spawn(serve_generate_wallet(
        generate_wallet_port,
        parent_cid,
        parent_kms_proxy_port,
    ));
    let mig_handle = tokio::spawn(serve_migrate(
        migrate_port,
        parent_cid,
        parent_kms_proxy_port,
    ));
    let reseal_handle = tokio::spawn(serve_reseal(
        reseal_port,
        parent_cid,
        parent_kms_proxy_port,
    ));
    let health_handle = tokio::spawn(serve_health(
        health_port,
        parent_cid,
        parent_kms_proxy_port,
    ));

    let sign_result = serve_sign(vsock_port, parent_cid, parent_kms_proxy_port).await;
    // Best-effort: if the sign loop exits, abort the others too so the
    // enclave-supervisor sees a single coherent failure rather than a
    // partially-up enclave.
    gw_handle.abort();
    mig_handle.abort();
    reseal_handle.abort();
    health_handle.abort();
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
    // v3 path takes priority: if the caller set v3_envelope_blob, we
    // parse it inline and ignore the v1/v2 fields entirely. This is
    // the device-bound, no-password path used by Passkey / OIDC users.
    if let Some(blob) = req.v3_envelope_blob.as_ref() {
        return process_v3(
            req.user_op_hash_hex.clone(),
            blob.clone(),
            req.auth_proof.clone(),
            req.kms_key_arn.clone(),
            req.project_id.clone(),
            req.signed_config_json.clone(),
            req.signed_config_signature_b64.clone(),
            parent_cid,
            parent_kms_proxy_port,
        )
        .await;
    }

    let is_v2 = req.password.is_some()
        && req.salt_b64.is_some()
        && req.nonce_hex.is_some()
        && req.tag_hex.is_some();
    // v1 kill switch: refuse BEFORE any KMS call so a disabled build
    // exposes no CBC surface at all.
    if !is_v2 && !envelope::V1_SIGNING_ENABLED {
        bail!(V1_DISABLED);
    }

    // ─── 1-4. KMS Decrypt-with-Recipient → plaintext DEK ────────────
    let (dek, _attestation_ts) = kms_decrypt_dek(
        parent_cid,
        parent_kms_proxy_port,
        &req.wrapped_dek_b64,
        &req.kms_key_arn,
    )
    .await?;

    // ─── 5. Decrypt envelope payload (v1 CBC vs v2 GCM) ─────────────
    // v2 path: password + salt + nonce + tag are all set. We derive
    // K_user from the password and combine with the KMS DEK, then
    // authenticate-decrypt with AES-GCM. Wrong password fails the GCM
    // tag check and we return "invalid credentials" without leaking
    // which factor failed.
    //
    // v1 path: legacy AES-CBC with the raw KMS DEK only. EVERY v1
    // failure collapses to the single `envelope::V1_OPEN_FAILED` error
    // (padding-oracle hardening — see envelope.rs).
    let pk: Zeroizing<[u8; 32]> = if let (Some(password), Some(salt_b64), Some(nonce_hex), Some(tag_hex)) = (
        req.password.as_ref(),
        req.salt_b64.as_ref(),
        req.nonce_hex.as_ref(),
        req.tag_hex.as_ref(),
    ) {
        let dek_arr = dek_to_array(dek)?;
        open_v2(&dek_arr, password.as_bytes(), salt_b64, nonce_hex, &req.ciphertext_hex, tag_hex)?
    } else {
        envelope::open_v1_private_key(&dek, &req.iv_hex, &req.ciphertext_hex)?
    };

    // ─── 7. Sign ────────────────────────────────────────────────────
    let hash_arr = parse_hex32(&req.user_op_hash_hex, "user op hash")?;
    let sig = signing::sign_user_op_hash(&pk[..], &hash_arr)?;

    // ─── 8. Encode + return ─────────────────────────────────────────
    let sig_hex = format!("0x{}", hex::encode(*sig));
    info!("signing complete, returning signature");
    Ok(sig_hex)
}

/// Open a v2 (password-bound AES-GCM) payload. Plaintext is the raw
/// 32-byte key. Shared by sign and migrate.
fn open_v2(
    dek: &[u8; 32],
    password: &[u8],
    salt_b64: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
    tag_hex: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let salt = B64.decode(salt_b64).context("decode salt_b64")?;
    if salt.len() != password_derivation::SALT_LEN {
        bail!(
            "salt must be {} bytes, got {}",
            password_derivation::SALT_LEN,
            salt.len()
        );
    }
    let k_user = password_derivation::derive_user_key(password, &salt)?;
    let k_aes = password_derivation::combine_keys(dek, &k_user);

    let nonce_bytes =
        hex::decode(nonce_hex.trim_start_matches("0x")).context("hex-decode nonce")?;
    if nonce_bytes.len() != password_derivation::GCM_NONCE_LEN {
        bail!(
            "nonce must be {} bytes, got {}",
            password_derivation::GCM_NONCE_LEN,
            nonce_bytes.len()
        );
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let mut ct = hex::decode(ciphertext_hex.trim_start_matches("0x"))
        .context("hex-decode v2 ciphertext")?;
    let tag = hex::decode(tag_hex.trim_start_matches("0x")).context("hex-decode tag")?;
    if tag.len() != password_derivation::GCM_TAG_LEN {
        bail!(
            "tag must be {} bytes, got {}",
            password_derivation::GCM_TAG_LEN,
            tag.len()
        );
    }
    ct.extend_from_slice(&tag);

    let pt = password_derivation::aead_decrypt(&k_aes, &nonce_arr, &ct)?;
    if pt.len() != 32 {
        bail!(
            "v2 plaintext has unexpected length {} (want 32 raw bytes)",
            pt.len()
        );
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&pt);
    Ok(out)
}

// ─── v3 sign pipeline ───────────────────────────────────────────────
//
// Same KMS Decrypt-with-Recipient round trip as v1/v2, but the
// decrypted payload is the v3 CBOR record (EOA priv + auth_methods).
// Before signing we verify the caller-supplied auth_proof against the
// stored methods — without this the engineer-with-deploy-access
// threat model wins.

#[allow(clippy::too_many_arguments)]
async fn process_v3(
    user_op_hash_hex: String,
    v3_blob: String,
    auth_proof: Option<AuthProof>,
    kms_key_arn: String,
    project_id: Option<String>,
    signed_config_json: Option<String>,
    signed_config_signature_b64: Option<String>,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<String> {
    let proof = auth_proof
        .ok_or_else(|| anyhow!("v3 sign request missing auth_proof"))?;

    // Parse the envelope FIRST so a malformed blob fails fast without
    // burning a KMS call.
    let env = envelope_v3::EnvelopeV3::parse(&v3_blob)
        .context("parse v3 envelope blob")?;
    let wrapped_dek_b64 = B64.encode(&env.wrapped_dek);

    // KMS Decrypt-with-Recipient round trip identical to v1/v2.
    let (dek, attestation_ts) =
        kms_decrypt_dek(parent_cid, parent_kms_proxy_port, &wrapped_dek_b64, &kms_key_arn).await?;
    let dek_arr = dek_to_array(dek)?;

    // Open the v3 envelope. On any AES-GCM tag failure we return the
    // exact same "invalid credentials" string as v2 — no leak of
    // which factor (KMS unwrap vs payload decrypt) actually failed.
    let (priv_key, methods) = envelope_v3::open(&env, &dek_arr)?;
    drop(dek_arr);

    // 32 raw bytes for the WebAuthn challenge comparison AND for the
    // secp256k1 sign call.
    let hash_arr = parse_hex32(&user_op_hash_hex, "user op hash")?;

    // Resolve the WebAuthn accept-list policy for this request. If
    // the parent-proxy passed a Rift-signed per-project bundle AND
    // it verifies AND matches the request's project_id AND isn't
    // stale, use those accept lists. Otherwise fall through to the
    // hardcoded default (Rift's own hosts). Never hard-errors —
    // a broken bundle silently degrades to default, so a bad deploy
    // of this feature can't take down Rift's own signing.
    let per_project_policy = resolve_project_policy(
        signed_config_json.as_deref(),
        signed_config_signature_b64.as_deref(),
        project_id.as_deref(),
        attestation_ts,
    );

    // Verify the auth_proof against one of the enrolled methods. We
    // pick the matching method by `kind`; if none verifies we refuse.
    verify_auth_proof(&proof, &methods, &hash_arr, attestation_ts, per_project_policy.as_ref())
        .context("v3 auth_proof verification failed")?;

    // Sign.
    let sig = signing::sign_user_op_hash(&priv_key[..], &hash_arr)?;
    let sig_hex = format!("0x{}", hex::encode(*sig));
    info!("v3 signing complete, returning signature");
    Ok(sig_hex)
}

fn resolve_project_policy(
    signed_config_json: Option<&str>,
    signed_config_signature_b64: Option<&str>,
    project_id: Option<&str>,
    now_unix_secs: i64,
) -> Option<project_config::ResolvedProjectPolicy> {
    match (signed_config_json, signed_config_signature_b64, project_id) {
        (Some(json), Some(sig), Some(pid)) => {
            project_config::resolve_policy(json.as_bytes(), sig, now_unix_secs, pid)
                .unwrap_or(None)
        }
        _ => None,
    }
}

/// Run the auth_proof against the stored auth_methods. The proof
/// matches if EITHER an OIDC token verifies against a stored
/// `Oidc { iss, sub }` row OR a WebAuthn assertion verifies against a
/// stored `Passkey { cred_id, cose }` row whose cred_id matches.
///
/// `challenge` is the 32-byte value the proof must be bound to: the
/// UserOp hash on the sign path, the bound reseal challenge (or, while
/// legacy is allowed, the raw server nonce) on the reseal path.
///
/// WebAuthn signCount: NOT checked. The enclave is stateless and the
/// sealed envelope stores no per-credential counter; storing one would
/// be defeated by the backend replaying an older envelope blob, and
/// synced platform passkeys (iCloud / Google Password Manager) always
/// report 0. Replay protection comes from the challenge binding instead
/// (one-shot server nonce / per-transaction UserOp hash).
fn verify_auth_proof(
    proof: &AuthProof,
    methods: &[envelope_v3::AuthMethod],
    challenge: &[u8; 32],
    now_unix_secs: i64,
    per_project_policy: Option<&project_config::ResolvedProjectPolicy>,
) -> Result<()> {
    match proof {
        AuthProof::Oidc { id_token } => {
            let challenge_hex = hex::encode(challenge);
            let jwks = pinned_jwks::current_jwks();
            let policy = oidc_verification::OidcTrustPolicy::default_prod();
            // Merge per-project OIDC audiences with the baked default
            // list. For partners with their own Google client_id
            // (e.g. Blockfinax) this is the only way an id_token
            // with their aud passes the accept-list check.
            let empty: Vec<String> = Vec::new();
            let extra_audiences = per_project_policy
                .map(|p| p.oidc_audiences.as_slice())
                .unwrap_or(empty.as_slice());
            let verified = oidc_verification::verify_id_token(
                id_token,
                &challenge_hex,
                now_unix_secs,
                &jwks,
                &policy,
                extra_audiences,
            )?;
            // Must match an enrolled OIDC method by (iss, sub).
            let matched = methods.iter().any(|m| match m {
                envelope_v3::AuthMethod::Oidc { iss, sub } => {
                    iss == &verified.iss && sub == &verified.sub
                }
                _ => false,
            });
            if !matched {
                bail!("OIDC token verified but no enrolled method matches (iss, sub)");
            }
            Ok(())
        }
        AuthProof::Passkey {
            cred_id_b64,
            client_data_json_b64,
            authenticator_data_b64,
            signature_b64,
        } => {
            let cred_id = B64
                .decode(cred_id_b64)
                .context("base64-decode passkey cred_id")?;
            let client_data_json = B64
                .decode(client_data_json_b64)
                .context("base64-decode clientDataJSON")?;
            let authenticator_data = B64
                .decode(authenticator_data_b64)
                .context("base64-decode authenticatorData")?;
            let signature = B64
                .decode(signature_b64)
                .context("base64-decode signature")?;

            // Look up the stored COSE pubkey by cred_id.
            let cose_bytes = methods
                .iter()
                .find_map(|m| match m {
                    envelope_v3::AuthMethod::Passkey { cred_id: stored, cose } if stored == &cred_id => {
                        Some(cose.clone())
                    }
                    _ => None,
                })
                .ok_or_else(|| anyhow!("no enrolled passkey matches the assertion's cred_id"))?;

            let cose = webauthn_verification::CoseP256PublicKey::from_cose_cbor(&cose_bytes)?;
            // Prefer the signed per-project policy's WebAuthn overrides
            // if the caller provided a bundle AND it verified upstream
            // (see project_config::resolve_policy). If not, fall back
            // to the hardcoded Rift-only default.
            let default_policy = webauthn_verification::WebAuthnPolicy::default_prod();
            let policy = per_project_policy
                .map(|p| &p.webauthn)
                .unwrap_or(&default_policy);
            webauthn_verification::verify_assertion(
                &cose,
                &client_data_json,
                &authenticator_data,
                &signature,
                challenge,
                policy,
            )
        }
    }
}

/// Run the KMS Decrypt-with-Recipient round trip end-to-end and return
/// the plaintext DEK plus the attestation timestamp (used as the trusted
/// "now" for OIDC exp/iat checks). Shared by every decrypt path.
async fn kms_decrypt_dek(
    parent_cid: u32,
    parent_kms_proxy_port: u32,
    wrapped_dek_b64: &str,
    kms_key_arn: &str,
) -> Result<(Zeroizing<Vec<u8>>, i64)> {
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = RsaPrivateKey::new(&mut rng, 2048)
        .context("RSA-2048 key generation failed inside the enclave")?;
    let rsa_pub = RsaPublicKey::from(&rsa_priv);
    let rsa_pub_der = rsa_pub
        .to_public_key_der()
        .context("encode RSA public key as DER")?
        .to_vec();

    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let (attestation_doc, attestation_ts) =
        attestation::attest_with_timestamp(&rsa_pub_der, &nonce)
            .context("NSM attestation document generation")?;

    let kms_req = KmsDecryptRequest {
        attestation_doc_b64: B64.encode(&*attestation_doc),
        wrapped_dek_b64: wrapped_dek_b64.to_string(),
        kms_key_arn: kms_key_arn.to_string(),
    };
    let kms_resp = kms_round_trip(parent_cid, parent_kms_proxy_port, kms_req)
        .await
        .context("parent KMS proxy round trip")?;
    let ciphertext_for_recipient_b64 = match kms_resp {
        KmsDecryptResponse::Ok { ciphertext_for_recipient_b64 } => ciphertext_for_recipient_b64,
        KmsDecryptResponse::Err { reason } => bail!("parent KMS proxy returned error: {reason}"),
    };
    let ciphertext_for_recipient = B64
        .decode(&ciphertext_for_recipient_b64)
        .context("base64-decode CiphertextForRecipient")?;
    let dek = cms_unwrap_data_key(&rsa_priv, &ciphertext_for_recipient)
        .context("CMS unwrap of KMS CiphertextForRecipient")?;
    Ok((dek, attestation_ts))
}

/// Attested kms:GenerateDataKey: returns (CiphertextBlob as base64 —
/// stored in the envelope verbatim, plaintext DEK). Shared by
/// generate-wallet, migrate, reseal and the health canary.
async fn kms_generate_dek(
    parent_cid: u32,
    parent_kms_proxy_port: u32,
    kms_key_arn: &str,
) -> Result<(String, Zeroizing<[u8; 32]>)> {
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = RsaPrivateKey::new(&mut rng, 2048)
        .context("RSA-2048 keygen for KMS-recipient channel")?;
    let rsa_pub = RsaPublicKey::from(&rsa_priv);
    let rsa_pub_der = rsa_pub
        .to_public_key_der()
        .context("encode RSA pubkey")?
        .to_vec();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let attestation_doc = attestation::attest(&rsa_pub_der, &nonce)
        .context("NSM attestation for GenerateDataKey")?;

    let kms_req = KmsGenerateDataKeyRequest {
        attestation_doc_b64: B64.encode(&*attestation_doc),
        kms_key_arn: kms_key_arn.to_string(),
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
    let dek = cms_unwrap_data_key(&rsa_priv, &cfr)
        .context("CMS unwrap of CiphertextForRecipient")?;
    Ok((ciphertext_blob_b64, dek_to_array(dek)?))
}

/// Length-check a DEK and move it into a fixed array. Both sides are
/// `Zeroizing`, so nothing is left behind on either path.
fn dek_to_array(dek: Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>> {
    if dek.len() != 32 {
        bail!("unwrapped DEK has unexpected length {} (want 32)", dek.len());
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&dek);
    Ok(arr)
}

/// Ethereum address (0x-prefixed lowercase) + raw 20 bytes of a raw
/// secp256k1 private key.
fn owner_address_of(priv_key: &[u8]) -> Result<([u8; 20], String)> {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    if priv_key.len() != 32 {
        bail!("private key must be 32 bytes, got {}", priv_key.len());
    }
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| anyhow!("recovered priv key rejected by k256: {e}"))?;
    let uncompressed = signing_key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok((addr, format!("0x{}", hex::encode(addr))))
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

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let is_v1 = req.enrolled_methods.is_empty() && req.password.is_none();
    if is_v1 && !envelope::V1_SIGNING_ENABLED {
        bail!(V1_DISABLED);
    }

    // Validate + convert enrolled methods BEFORE generating any key
    // material or calling KMS.
    let mut auth_methods: Vec<envelope_v3::AuthMethod> =
        Vec::with_capacity(req.enrolled_methods.len());
    for m in &req.enrolled_methods {
        match m {
            EnrolledMethod::Oidc { iss, sub } => {
                auth_methods.push(envelope_v3::AuthMethod::Oidc {
                    iss: iss.clone(),
                    sub: sub.clone(),
                });
            }
            EnrolledMethod::Passkey { cred_id_b64, cose_pubkey_b64 } => {
                let cred_id = B64
                    .decode(cred_id_b64)
                    .context("base64-decode enrolled cred_id")?;
                let cose = B64
                    .decode(cose_pubkey_b64)
                    .context("base64-decode enrolled cose")?;
                // Validate the COSE bytes parse — refuse a bad
                // enrolment at the gate rather than at first sign.
                webauthn_verification::CoseP256PublicKey::from_cose_cbor(&cose)
                    .context("validate enrolled passkey COSE_Key")?;
                auth_methods.push(envelope_v3::AuthMethod::Passkey { cred_id, cose });
            }
        }
    }

    // 1-4. Attested GenerateDataKey → (wrapped DEK for the envelope,
    //      plaintext DEK for us).
    let (ciphertext_blob_b64, dek) =
        kms_generate_dek(parent_cid, parent_kms_proxy_port, &req.kms_key_arn).await?;

    // 5. Generate the EOA secp256k1 keypair INSIDE the enclave.
    let mut rng = rand::rngs::OsRng;
    let mut sk_bytes = Zeroizing::new([0u8; 32]);
    // Keep looping until k256 accepts (it rejects the all-zero and
    // out-of-range values which are negligible-probability events).
    loop {
        rng.fill_bytes(&mut sk_bytes[..]);
        if SigningKey::from_bytes((&*sk_bytes).into()).is_ok() {
            break;
        }
    }
    let (_addr, owner_address) = owner_address_of(&sk_bytes[..])?;

    // 6+7+8. Three paths, picked in priority order:
    //   v3 (enrolled_methods non-empty): device-bound, no password.
    //   v2 (password present): password-bound XOR-share scheme.
    //   v1 (neither): KMS-only legacy (refused when V1 is disabled).
    let envelope_blob = if !auth_methods.is_empty() {
        let mut nonce_bytes = [0u8; password_derivation::GCM_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        envelope_v3::seal(&sk_bytes, auth_methods, &dek, &nonce_bytes, &ciphertext_blob_b64)?
    } else if let Some(password) = req.password.as_ref() {
        // v2: AES-256-GCM with K_aes = DEK XOR HKDF(password, salt).
        // Plaintext is the raw 32-byte private key (no hex encoding).
        let mut salt = [0u8; password_derivation::SALT_LEN];
        rng.fill_bytes(&mut salt);
        let k_user = password_derivation::derive_user_key(password.as_bytes(), &salt)?;
        let k_aes = password_derivation::combine_keys(&dek, &k_user);

        let mut nonce_bytes = [0u8; password_derivation::GCM_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        let ct_with_tag = password_derivation::aead_encrypt(&k_aes, &nonce_bytes, &sk_bytes[..])?;

        // Split ct from tag for the wire format.
        let tag_start = ct_with_tag.len() - password_derivation::GCM_TAG_LEN;
        let (ct, tag) = ct_with_tag.split_at(tag_start);

        format!(
            "enc:v2:{}:{}:{}:{}:{}",
            ciphertext_blob_b64,
            B64.encode(salt),
            hex::encode(nonce_bytes),
            hex::encode(ct),
            hex::encode(tag)
        )
    } else {
        // v1: AES-256-CBC, KMS-only, plaintext is hex-encoded.
        let pk_hex = Zeroizing::new(format!("0x{}", hex::encode(&sk_bytes[..])));

        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        let encryptor = Aes256CbcEnc::new((&*dek).into(), (&iv).into());
        let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(pk_hex.as_bytes());

        format!(
            "enc:v1:{}:{}:{}",
            ciphertext_blob_b64,
            hex::encode(iv),
            hex::encode(&ciphertext)
        )
    };

    info!(owner_address = %owner_address, "wallet generated inside enclave");
    Ok((envelope_blob, owner_address))
}

// ─── Migrate-envelope pipeline ───────────────────────────────────────
//
// Upgrade an existing v1 or v2 envelope to v3 without ever exposing
// the EOA private key outside the enclave. Pipeline:
//
//   1. KMS-Decrypt the OLD wrapped DEK (Recipient-attested).
//   2. Open the OLD envelope payload — CBC for v1, GCM for v2 (and the
//      v2 path requires the caller-supplied old_password).
//   3. Recover the raw secp256k1 private key + derive the owner addr.
//   4. KMS-GenerateDataKey to mint a FRESH DEK (so the new v3 envelope
//      has no shared DEK with the old one — clean cryptographic break).
//   5. Seal (priv_key + enrolled_methods) as a new v3 envelope.
//   6. Return the new blob + owner_address.
//
// Migration from v1 stays available even when `V1_SIGNING_ENABLED` is
// false — it is the only way off v1.

async fn serve_migrate(
    port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr)
        .context("vsock bind failed (migrate)")?;
    info!(port = port, "listening for migrate-envelope requests on vsock");

    let mut conn_counter: u64 = 0;
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("vsock accept failed (migrate)")?;
        conn_counter += 1;
        let cid = conn_counter;
        let span = info_span!("mig-conn", id = cid, peer_cid = peer.cid());
        tokio::spawn(
            async move {
                if let Err(e) =
                    handle_one_migrate(stream, parent_cid, parent_kms_proxy_port).await
                {
                    warn!(error = ?e, "migrate handler aborted");
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_one_migrate(
    mut stream: VsockStream,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let request = read_frame::<MigrateEnvelopeRequest>(&mut stream).await?;
    info!(
        kms_key_arn = %request.kms_key_arn,
        method_count = request.enrolled_methods.len(),
        "migrate-envelope request received"
    );

    let response = match process_migrate(request, parent_cid, parent_kms_proxy_port).await {
        Ok((envelope_blob, owner_address)) => MigrateEnvelopeResponse::Ok {
            envelope_blob,
            owner_address,
        },
        Err(e) => {
            error!(error = ?e, "migrate-envelope failed");
            MigrateEnvelopeResponse::Err {
                reason: format!("{e:#}"),
            }
        }
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process_migrate(
    req: MigrateEnvelopeRequest,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<(String, String)> {
    if req.enrolled_methods.is_empty() {
        bail!("migrate requires at least one enrolled method on the new v3 envelope");
    }

    // ─── 1. Parse old envelope ───────────────────────────────────────
    let (old_wrapped_dek_b64, old_kind) = parse_old_envelope_prefix(&req.old_envelope_blob)?;
    if matches!(old_kind, OldEnvelopeKind::V2) && req.old_password.is_none() {
        bail!("v2 → v3 migration requires the user's existing password");
    }

    // Validate the new methods before touching KMS.
    let mut auth_methods: Vec<envelope_v3::AuthMethod> =
        Vec::with_capacity(req.enrolled_methods.len());
    for m in &req.enrolled_methods {
        match m {
            EnrolledMethod::Oidc { iss, sub } => {
                auth_methods.push(envelope_v3::AuthMethod::Oidc {
                    iss: iss.clone(),
                    sub: sub.clone(),
                });
            }
            EnrolledMethod::Passkey { cred_id_b64, cose_pubkey_b64 } => {
                let cred_id = B64.decode(cred_id_b64).context("decode cred_id")?;
                let cose = B64.decode(cose_pubkey_b64).context("decode cose")?;
                webauthn_verification::CoseP256PublicKey::from_cose_cbor(&cose)
                    .context("validate enrolled passkey COSE_Key")?;
                auth_methods.push(envelope_v3::AuthMethod::Passkey { cred_id, cose });
            }
        }
    }

    // ─── 2. KMS-Decrypt the OLD DEK ──────────────────────────────────
    let (old_dek, _attestation_ts) = kms_decrypt_dek(
        parent_cid,
        parent_kms_proxy_port,
        &old_wrapped_dek_b64,
        &req.kms_key_arn,
    )
    .await?;

    // ─── 3. Open the old envelope → raw priv key ─────────────────────
    let priv_key: Zeroizing<[u8; 32]> = match old_kind {
        OldEnvelopeKind::V1 => {
            // v1 layout: enc:v1:<wrapped_dek>:<iv_hex>:<ct_hex>. Every
            // failure (layout included) is the single opaque v1 error.
            let rest = req.old_envelope_blob.strip_prefix("enc:v1:").unwrap_or("");
            let parts: Vec<&str> = rest.split(':').collect();
            let (iv_hex, ct_hex) = if parts.len() == 3 {
                (parts[1], parts[2])
            } else {
                ("", "")
            };
            envelope::open_v1_private_key(&old_dek, iv_hex, ct_hex)?
        }
        OldEnvelopeKind::V2 => {
            // v2 layout: enc:v2:<wrapped_dek>:<salt_b64>:<nonce_hex>:<ct_hex>:<tag_hex>
            // Caller must supply the user's existing password to
            // authorise the migration — without it the AES-GCM tag
            // check fails.
            let password = req
                .old_password
                .as_ref()
                .ok_or_else(|| anyhow!("v2 → v3 migration requires the user's existing password"))?;
            let parts: Vec<&str> = req
                .old_envelope_blob
                .strip_prefix("enc:v2:")
                .unwrap_or("")
                .split(':')
                .collect();
            if parts.len() != 5 {
                bail!("malformed v2 envelope: expected 5 fields, got {}", parts.len());
            }
            let dek_arr = dek_to_array(old_dek)?;
            open_v2(&dek_arr, password.as_bytes(), parts[1], parts[2], parts[3], parts[4])?
        }
    };

    // ─── 4. Derive owner address from the recovered priv key ─────────
    let (_addr, owner_address) = owner_address_of(&priv_key[..])?;

    // ─── 5. KMS-GenerateDataKey for a fresh DEK ──────────────────────
    let (new_wrapped_dek_b64, new_dek) =
        kms_generate_dek(parent_cid, parent_kms_proxy_port, &req.kms_key_arn).await?;

    // ─── 6. Seal as v3 ───────────────────────────────────────────────
    let mut new_nonce = [0u8; password_derivation::GCM_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut new_nonce);

    let new_blob = envelope_v3::seal(
        &priv_key,
        auth_methods,
        &new_dek,
        &new_nonce,
        &new_wrapped_dek_b64,
    )?;

    info!(owner_address = %owner_address, "envelope migrated to v3 inside enclave");
    Ok((new_blob, owner_address))
}

// ─── v3 reseal pipeline ─────────────────────────────────────────────
//
// Adds a new AuthMethod to an already-v3 envelope. Same crypto shape
// as migrate — KMS-Decrypt old DEK, unwrap, verify consent, KMS-
// GenerateDataKey new DEK, seal — but:
//   1. Input is v3 (not v1/v2), so we go straight through envelope_v3.
//   2. Consent is `auth_proof` against an already-enrolled method,
//      over the domain-separated bound challenge (see reseal_helpers),
//      NOT a v2 password.
//   3. Duplicate check: refuse to append a method that would collide
//      with an existing one (same cred_id, or same iss+sub).

async fn serve_reseal(
    port: u32,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr)
        .context("vsock bind failed (reseal)")?;
    info!(port = port, "listening for reseal-v3 requests on vsock");

    let mut conn_counter: u64 = 0;
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("vsock accept failed (reseal)")?;
        conn_counter += 1;
        let cid = conn_counter;
        let span = info_span!("reseal-conn", id = cid, peer_cid = peer.cid());
        tokio::spawn(
            async move {
                if let Err(e) =
                    handle_one_reseal(stream, parent_cid, parent_kms_proxy_port).await
                {
                    warn!(error = ?e, "reseal handler aborted");
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_one_reseal(
    mut stream: VsockStream,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<()> {
    let request = read_frame::<ResealV3Request>(&mut stream).await?;
    info!(
        kms_key_arn = %request.kms_key_arn,
        auth_proof_kind = auth_proof_kind_str(&request.auth_proof),
        new_method_kind = enrolled_method_kind_str(&request.new_method),
        "reseal-v3 request received"
    );

    let response = match process_reseal_v3(request, parent_cid, parent_kms_proxy_port).await {
        Ok((envelope_blob, owner_address)) => ResealV3Response::Ok {
            envelope_blob,
            owner_address,
        },
        Err(e) => {
            error!(error = ?e, "reseal-v3 failed");
            ResealV3Response::Err {
                reason: format!("{e:#}"),
            }
        }
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

async fn process_reseal_v3(
    req: ResealV3Request,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<(String, String)> {
    // ── 1. Parse inputs that need no secrets ─────────────────────────
    let env = envelope_v3::EnvelopeV3::parse(&req.old_envelope_blob)
        .context("parse old v3 envelope blob")?;
    let wrapped_dek_b64 = B64.encode(&env.wrapped_dek);
    let server_nonce = parse_hex32(&req.prehashed_hex, "challenge (prehashed_hex)")?;
    let new_method = enrolled_to_authmethod(&req.new_method)?;

    // ── 2. KMS-Decrypt the OLD DEK (Recipient-attested) ───────────────
    let (old_dek, attestation_ts) = kms_decrypt_dek(
        parent_cid,
        parent_kms_proxy_port,
        &wrapped_dek_b64,
        &req.kms_key_arn,
    )
    .await?;
    let old_dek_arr = dek_to_array(old_dek)?;

    // ── 3. Open the envelope → (priv_key, existing_methods) ──────────
    let (priv_key, existing_methods) = envelope_v3::open(&env, &old_dek_arr)?;
    drop(old_dek_arr);
    if existing_methods.is_empty() {
        bail!("existing envelope has no enrolled methods — reseal would corrupt the wallet");
    }

    // ── 4. Owner address (derived in-enclave; part of the challenge) ─
    let (owner_raw, owner_address) = owner_address_of(&priv_key[..])?;

    // ── 5. Verify consent proof against EXISTING methods ─────────────
    // Same `verify_auth_proof` used on the sign path, but over the
    // domain-separated bound challenge. Legacy (raw prehashed_hex)
    // proofs are accepted only while neither the enclave constant nor
    // the project's signed bundle requires bound challenges.
    let per_project_policy = resolve_project_policy(
        req.signed_config_json.as_deref(),
        req.signed_config_signature_b64.as_deref(),
        req.project_id.as_deref(),
        attestation_ts,
    );
    let require_bound = reseal_requires_bound(
        per_project_policy
            .as_ref()
            .map(|p| p.require_bound_reseal)
            .unwrap_or(false),
    );
    let bound_challenge = bound_reseal_challenge(&owner_raw, &server_nonce, &new_method);
    let mode = verify_reseal_consent(&bound_challenge, &server_nonce, require_bound, |c| {
        verify_auth_proof(
            &req.auth_proof,
            &existing_methods,
            c,
            attestation_ts,
            per_project_policy.as_ref(),
        )
    })
    .context("reseal-v3 auth_proof verification failed")?;
    match mode {
        crate::reseal_helpers::ResealChallengeMode::Bound => {
            info!("reseal consent verified over bound challenge")
        }
        crate::reseal_helpers::ResealChallengeMode::Legacy => warn!(
            "reseal consent verified over LEGACY unbound challenge — client must migrate to rift-reseal-v1"
        ),
    }

    // ── 6. Duplicate check ───────────────────────────────────────────
    if is_duplicate_method(&existing_methods, &new_method) {
        bail!("new_method is already enrolled — refusing to append a duplicate");
    }

    // ── 7. KMS-GenerateDataKey → fresh DEK ───────────────────────────
    let (new_wrapped_dek_b64, new_dek) =
        kms_generate_dek(parent_cid, parent_kms_proxy_port, &req.kms_key_arn).await?;

    // ── 8. Append + seal fresh v3 envelope ───────────────────────────
    let mut merged_methods = existing_methods;
    merged_methods.push(new_method);

    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk_arr.copy_from_slice(&priv_key[..]);

    let mut new_nonce = [0u8; password_derivation::GCM_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut new_nonce);

    let new_blob = envelope_v3::seal(
        &sk_arr,
        merged_methods,
        &new_dek,
        &new_nonce,
        &new_wrapped_dek_b64,
    )?;

    info!(
        owner_address = %owner_address,
        "v3 envelope resealed with new auth method appended"
    );
    Ok((new_blob, owner_address))
}

fn auth_proof_kind_str(p: &AuthProof) -> &'static str {
    match p {
        AuthProof::Oidc { .. } => "oidc",
        AuthProof::Passkey { .. } => "passkey",
    }
}

fn enrolled_method_kind_str(m: &EnrolledMethod) -> &'static str {
    match m {
        EnrolledMethod::Oidc { .. } => "oidc",
        EnrolledMethod::Passkey { .. } => "passkey",
    }
}

#[derive(Debug, Clone, Copy)]
enum OldEnvelopeKind {
    V1,
    V2,
}

fn parse_old_envelope_prefix(blob: &str) -> Result<(String, OldEnvelopeKind)> {
    if let Some(rest) = blob.strip_prefix("enc:v1:") {
        let first = rest
            .split_once(':')
            .map(|(a, _)| a.to_string())
            .ok_or_else(|| anyhow!("malformed v1 envelope"))?;
        Ok((first, OldEnvelopeKind::V1))
    } else if let Some(rest) = blob.strip_prefix("enc:v2:") {
        let first = rest
            .split_once(':')
            .map(|(a, _)| a.to_string())
            .ok_or_else(|| anyhow!("malformed v2 envelope"))?;
        Ok((first, OldEnvelopeKind::V2))
    } else if blob.starts_with("enc:v3:") {
        bail!("envelope is already v3 — nothing to migrate");
    } else {
        bail!("envelope blob has no recognized version prefix")
    }
}

// ─── Health / canary pipeline (port 5010) ───────────────────────────

async fn serve_health(port: u32, parent_cid: u32, parent_kms_proxy_port: u32) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr).context("vsock bind failed (health)")?;
    info!(port = port, "listening for health requests on vsock");
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .context("vsock accept failed (health)")?;
        let span = info_span!("health-conn", peer_cid = peer.cid());
        tokio::spawn(
            async move {
                let result = async {
                    let req = read_frame::<HealthRequest>(&mut stream).await?;
                    let resp = match process_health(req, parent_cid, parent_kms_proxy_port).await {
                        Ok(r) => r,
                        Err(e) => HealthResponse::Err { reason: format!("{e:#}") },
                    };
                    write_frame(&mut stream, &resp).await
                }
                .await;
                if let Err(e) = result {
                    warn!(error = ?e, "health handler aborted");
                }
            }
            .instrument(span),
        );
    }
}

async fn process_health(
    req: HealthRequest,
    parent_cid: u32,
    parent_kms_proxy_port: u32,
) -> Result<HealthResponse> {
    let pcr0 = hex::encode(attestation::describe_pcr0()?);
    let kms_checked = match req.kms_key_arn.as_deref() {
        Some(arn) if !arn.is_empty() => {
            // Proves KMS accepts THIS image's attestation on BOTH paths
            // the wallet depends on: GenerateDataKey (new wallets) and
            // Decrypt (every signature — this is the statement whose
            // ImageSha384 condition rotation edits). Round trip a fresh
            // DEK through both and compare. Both copies are wiped on
            // drop; the wrapped blob is discarded.
            let (wrapped_b64, dek) = kms_generate_dek(parent_cid, parent_kms_proxy_port, arn)
                .await
                .context("health: attested KMS GenerateDataKey")?;
            let (dek_again, _ts) =
                kms_decrypt_dek(parent_cid, parent_kms_proxy_port, &wrapped_b64, arn)
                    .await
                    .context("health: attested KMS Decrypt")?;
            if dek_again.as_slice() != dek.as_slice() {
                bail!("health: KMS Decrypt returned a different data key than GenerateDataKey");
            }
            true
        }
        _ => false,
    };
    Ok(HealthResponse::Ok {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pcr0,
        kms_checked,
    })
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
    // The raw frame can contain a v2 password: wipe it after decoding.
    let mut body = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut body).await.context("read frame body")?;
    let decoded: T = serde_json::from_slice(&body).context("JSON decode")?;
    Ok(decoded)
}

async fn write_frame<T: serde::Serialize>(stream: &mut VsockStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("JSON encode")?;
    let len = u32::try_from(body.len())
        .context("frame body too large to encode")?
        .to_be_bytes();
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
fn cms_unwrap_data_key(rsa_priv: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Convert our rsa::RsaPrivateKey → openssl::PKey via PKCS#8 DER.
    // (`SecretDocument` zeroizes the DER on drop.)
    let pkcs8 = rsa_priv
        .to_pkcs8_der()
        .context("encode RSA private key as PKCS#8 DER")?;
    let pkey = PKey::private_key_from_pkcs8(pkcs8.as_bytes())
        .context("load RSA private key into OpenSSL")?;

    // Parse + decrypt the CMS structure. openssl handles BER + the
    // KeyTransRecipientInfo + RSA-OAEP unwrap + content decryption
    // in one call.
    let cms = CmsContentInfo::from_der(ciphertext).context("parse CMS ContentInfo")?;
    let plaintext = cms
        .decrypt_without_cert_check(&pkey)
        .context("CMS_decrypt of EnvelopedData")?;
    Ok(Zeroizing::new(plaintext))
}
