//! Rift parent-proxy: HTTP↔vsock bridge that runs on the EC2 host.
//!
//! The smart-wallet (Node) cannot speak vsock natively, and the enclave
//! has no network. This binary sits in between:
//!
//!  Smart-wallet (Node, on EC2)
//!    ▼ HTTP POST localhost:7777/sign
//!  Parent proxy (this binary)
//!    ▼ vsock to enclave:5005      ← signing requests
//!    ▲ vsock from enclave:5006    ← KMS proxy callbacks
//!    ▼ HTTPS → AWS KMS Decrypt-with-Recipient
//!
//! Two concurrent listeners:
//!  - HTTP on 0.0.0.0:7777 (or 127.0.0.1:7777 if you want it host-local)
//!    accepts signing requests from the smart-wallet, forwards each one
//!    to the enclave over vsock, returns the signature.
//!  - Vsock on port 5006 accepts KMS-proxy requests originating in the
//!    enclave. Each request carries an attestation document; we call
//!    KMS Decrypt with that attestation in the Recipient field and
//!    return the CiphertextForRecipient blob to the enclave.
//!
//! Why a Rust parent proxy instead of Node:
//!  - Native vsock support is mature in Rust (tokio-vsock), nonexistent
//!    in Node.
//!  - aws-sdk-kms in Rust supports the Recipient parameter (attestation
//!    document + key encryption algorithm) natively.
//!  - Tiny binary, no node_modules surface, easy systemd unit.
//!
//! Env (set in the systemd unit, see DEPLOYMENT.md):
//!   ENCLAVE_CID                — the enclave's vsock CID (usually 16)
//!   ENCLAVE_PORT               — the enclave's signing port (default 5005)
//!   KMS_PROXY_PORT             — the vsock port we listen on (default 5006)
//!   HTTP_BIND                  — HTTP listen address (default 127.0.0.1:7777)
//!   AWS_REGION                 — for the AWS KMS client (default us-east-1)
//!   AWS_ACCESS_KEY_ID / etc.   — standard AWS SDK env, comes from the
//!                                EC2 instance role most of the time.

use anyhow::{anyhow, bail, Context, Result};
use aws_sdk_kms::{
    primitives::Blob,
    types::{KeyEncryptionMechanism, RecipientInfo},
    Client as KmsClient,
};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

const DEFAULT_ENCLAVE_CID: u32 = 16;
const DEFAULT_ENCLAVE_PORT: u32 = 5005;
const DEFAULT_KMS_PROXY_PORT: u32 = 5006;
const DEFAULT_GENERATE_WALLET_PORT: u32 = 5007;
const DEFAULT_MIGRATE_PORT: u32 = 5008;
// Public by default so Railway smart-wallet can reach us. When you
// want to keep this proxy localhost-only (smart-wallet on the same
// host), set HTTP_BIND=127.0.0.1:7777 in the systemd env file.
const DEFAULT_HTTP_BIND: &str = "0.0.0.0:7777";

#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    enclave_port: u32,
    /// Phase 2 — separate vsock port for wallet generation. Decoupled
    /// from the sign port so a hung signing request doesn't starve
    /// account creation and vice versa.
    enclave_generate_wallet_port: u32,
    /// Phase 3 — separate vsock port for v1/v2 → v3 envelope migration.
    enclave_migrate_port: u32,
    #[allow(dead_code)]
    kms: Arc<KmsClient>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rift_parent_proxy=debug".into()),
        )
        .init();

    let enclave_cid = env_u32("ENCLAVE_CID", DEFAULT_ENCLAVE_CID);
    let enclave_port = env_u32("ENCLAVE_PORT", DEFAULT_ENCLAVE_PORT);
    let enclave_generate_wallet_port = env_u32(
        "ENCLAVE_GENERATE_WALLET_PORT",
        DEFAULT_GENERATE_WALLET_PORT,
    );
    let enclave_migrate_port = env_u32("ENCLAVE_MIGRATE_PORT", DEFAULT_MIGRATE_PORT);
    let kms_proxy_port = env_u32("KMS_PROXY_PORT", DEFAULT_KMS_PROXY_PORT);
    let http_bind = std::env::var("HTTP_BIND").unwrap_or_else(|_| DEFAULT_HTTP_BIND.to_string());

    info!(
        enclave_cid,
        enclave_port,
        enclave_generate_wallet_port,
        enclave_migrate_port,
        kms_proxy_port,
        http_bind = %http_bind,
        "starting rift-parent-proxy"
    );

    // Pin the AWS SDK behavior version so future SDK upgrades don't
    // silently change semantics on us. Switching back to `from_env()`
    // would trigger a deprecation warning every build.
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let kms = Arc::new(KmsClient::new(&aws_config));

    let state = AppState {
        enclave_cid,
        enclave_port,
        enclave_generate_wallet_port,
        enclave_migrate_port,
        kms: kms.clone(),
    };

    // ─── vsock KMS proxy ────────────────────────────────────────────
    // Runs forever in the background. The enclave initiates connections
    // to this listener whenever it needs an attested KMS Decrypt.
    #[cfg(target_os = "linux")]
    {
        let kms_for_proxy = kms.clone();
        tokio::spawn(async move {
            if let Err(e) = run_kms_proxy(kms_proxy_port, kms_for_proxy).await {
                error!(error = ?e, "KMS proxy loop terminated");
            }
        });
    }

    // ─── HTTP signing frontend ──────────────────────────────────────
    // Bearer-token auth middleware on /sign. Layered AFTER the health
    // route so /health stays open for load-balancer probes etc.
    let app = Router::new()
        .route(
            "/sign",
            post(sign_handler).route_layer(middleware::from_fn(bearer_auth)),
        )
        .route(
            "/generate-wallet",
            post(generate_wallet_handler).route_layer(middleware::from_fn(bearer_auth)),
        )
        .route(
            "/migrate-envelope",
            post(migrate_envelope_handler).route_layer(middleware::from_fn(bearer_auth)),
        )
        .route("/health", post(health_handler))
        .route("/health", axum::routing::get(health_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&http_bind)
        .await
        .with_context(|| format!("bind HTTP listener on {http_bind}"))?;
    info!(addr = %http_bind, "HTTP listener ready");
    axum::serve(listener, app).await.context("HTTP serve")?;
    Ok(())
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ─── HTTP signing frontend ──────────────────────────────────────────

/// JSON body the smart-wallet sends to POST /sign.
///
/// Two envelope formats share this body shape:
///   v1 (legacy KMS-only): set ciphertext_hex + iv_hex. Leave password,
///        salt_b64, nonce_hex, tag_hex unset.
///   v2 (password-bound, non-custodial): set ciphertext_hex, password,
///        salt_b64, nonce_hex, tag_hex. Leave iv_hex unset.
///
/// The enclave picks the path. The parent-proxy is a pure pass-through.
#[derive(Debug, Deserialize)]
struct SignBody {
    /// 32-byte Safe UserOp hash, hex-encoded with or without 0x prefix.
    user_op_hash_hex: String,
    /// Envelope's wrapped DEK, base64-encoded.
    wrapped_dek_b64: String,
    /// Envelope's ciphertext, hex-encoded.
    ciphertext_hex: String,
    /// v1: the AES-CBC IV, hex-encoded (16 bytes). Empty string in v2.
    #[serde(default)]
    iv_hex: String,
    /// v2: the user's password (plaintext UTF-8). Empty in v1.
    #[serde(default)]
    password: Option<String>,
    /// v2: HKDF salt, base64-encoded (32 bytes). Empty in v1.
    #[serde(default)]
    salt_b64: Option<String>,
    /// v2: AES-GCM nonce, hex-encoded (12 bytes). Empty in v1.
    #[serde(default)]
    nonce_hex: Option<String>,
    /// v2: AES-GCM auth tag, hex-encoded (16 bytes). Empty in v1.
    #[serde(default)]
    tag_hex: Option<String>,
    /// CMK ARN for the active mode (production/sandbox).
    kms_key_arn: String,

    // ─── v3 (device-bound, no password) fields ──────────────────────
    // When `v3_envelope_blob` is set the enclave ignores all v1/v2
    // fields above. `auth_proof` carries the user's consent — either
    // an OIDC id_token whose `nonce` is the user op hash, or a
    // WebAuthn assertion challenged with the user op hash.
    #[serde(default)]
    v3_envelope_blob: Option<String>,
    #[serde(default)]
    auth_proof: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SignSuccess {
    signature_hex: String,
}

#[derive(Debug, Serialize)]
struct SignError {
    error: String,
}

async fn health_handler() -> &'static str {
    "ok"
}

/// Bearer-token auth — reads the expected secret from
/// `PARENT_PROXY_AUTH_TOKEN` env at request time so a rotation
/// (write new env, `systemctl restart rift-parent-proxy`) takes
/// effect without rebuilding.
///
/// When the env var is unset/empty, auth is DISABLED. This keeps
/// `make run-debug` + curl-smoke-test ergonomic on the EC2 itself
/// (parent-proxy listening on localhost, no public exposure yet).
/// Setting the env var locks down /sign immediately on next restart.
async fn bearer_auth(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<SignError>)> {
    let expected = std::env::var("PARENT_PROXY_AUTH_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return Ok(next.run(req).await);
    }
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let want = format!("Bearer {expected}");
    if header == want {
        Ok(next.run(req).await)
    } else {
        warn!("rejected /sign request — missing or wrong Bearer token");
        Err((
            StatusCode::UNAUTHORIZED,
            Json(SignError {
                error: "unauthorized".to_string(),
            }),
        ))
    }
}

async fn sign_handler(
    State(state): State<AppState>,
    Json(body): Json<SignBody>,
) -> Result<Json<SignSuccess>, (StatusCode, Json<SignError>)> {
    #[cfg(target_os = "linux")]
    {
        let enclave_req = serde_json::json!({
            "user_op_hash_hex": body.user_op_hash_hex,
            "wrapped_dek_b64": body.wrapped_dek_b64,
            "ciphertext_hex": body.ciphertext_hex,
            "iv_hex": body.iv_hex,
            "password": body.password,
            "salt_b64": body.salt_b64,
            "nonce_hex": body.nonce_hex,
            "tag_hex": body.tag_hex,
            "kms_key_arn": body.kms_key_arn,
            "v3_envelope_blob": body.v3_envelope_blob,
            "auth_proof": body.auth_proof,
        });

        match forward_to_enclave(state.enclave_cid, state.enclave_port, &enclave_req).await {
            Ok(resp) => {
                if let Some(sig) = resp
                    .get("Ok")
                    .and_then(|ok| ok.get("signature_hex"))
                    .and_then(|s| s.as_str())
                {
                    Ok(Json(SignSuccess {
                        signature_hex: sig.to_string(),
                    }))
                } else if let Some(err) = resp
                    .get("Err")
                    .and_then(|e| e.get("reason"))
                    .and_then(|s| s.as_str())
                {
                    warn!(reason = %err, "enclave returned error");
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("enclave: {err}"),
                        }),
                    ))
                } else {
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("malformed enclave response: {resp}"),
                        }),
                    ))
                }
            }
            Err(e) => {
                error!(error = ?e, "forward to enclave failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    Json(SignError {
                        error: format!("forward to enclave: {e:#}"),
                    }),
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, body);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SignError {
                error: "parent proxy only runs on Linux".to_string(),
            }),
        ))
    }
}

#[cfg(target_os = "linux")]
async fn forward_to_enclave(
    enclave_cid: u32,
    enclave_port: u32,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let addr = VsockAddr::new(enclave_cid, enclave_port);
    let mut stream = VsockStream::connect(addr)
        .await
        .with_context(|| format!("vsock connect to enclave at cid={enclave_cid} port={enclave_port}"))?;
    let payload = serde_json::to_vec(body)?;
    write_frame(&mut stream, &payload).await?;
    let resp_bytes = read_frame(&mut stream).await?;
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes)?;
    Ok(resp)
}

// ─── /generate-wallet HTTP handler ──────────────────────────────────

/// JSON body the backend sends to POST /generate-wallet.
///
/// Format-selection cascade (first match wins):
///   1. `enrolled_methods` non-empty → v3 (Passkey / OIDC bound)
///   2. `password` present           → v2 (password-bound)
///   3. otherwise                    → v1 (KMS-only, legacy)
///
/// The parent-proxy is a pass-through; the enclave does the picking.
#[derive(Debug, Deserialize)]
struct GenerateWalletBody {
    /// CMK to wrap the freshly-generated DEK with.
    kms_key_arn: String,
    /// v2 path: the user's password.
    #[serde(default)]
    password: Option<String>,
    /// v3 path: enrolled auth methods (OIDC and/or Passkey).
    #[serde(default)]
    enrolled_methods: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct GenerateWalletSuccess {
    envelope_blob: String,
    owner_address: String,
}

async fn generate_wallet_handler(
    State(state): State<AppState>,
    Json(body): Json<GenerateWalletBody>,
) -> Result<Json<GenerateWalletSuccess>, (StatusCode, Json<SignError>)> {
    #[cfg(target_os = "linux")]
    {
        let enclave_req = serde_json::json!({
            "kms_key_arn": body.kms_key_arn,
            "password": body.password,
            "enrolled_methods": body.enrolled_methods,
        });

        match forward_to_enclave(
            state.enclave_cid,
            state.enclave_generate_wallet_port,
            &enclave_req,
        )
        .await
        {
            Ok(resp) => {
                if let Some(ok) = resp.get("Ok") {
                    let envelope_blob = ok
                        .get("envelope_blob")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let owner_address = ok
                        .get("owner_address")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if envelope_blob.is_empty() || owner_address.is_empty() {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            Json(SignError {
                                error: format!("malformed enclave response: {resp}"),
                            }),
                        ));
                    }
                    Ok(Json(GenerateWalletSuccess {
                        envelope_blob,
                        owner_address,
                    }))
                } else if let Some(err) = resp
                    .get("Err")
                    .and_then(|e| e.get("reason"))
                    .and_then(|s| s.as_str())
                {
                    warn!(reason = %err, "enclave generate-wallet returned error");
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("enclave: {err}"),
                        }),
                    ))
                } else {
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("malformed enclave response: {resp}"),
                        }),
                    ))
                }
            }
            Err(e) => {
                error!(error = ?e, "forward to enclave (generate-wallet) failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    Json(SignError {
                        error: format!("forward to enclave: {e:#}"),
                    }),
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, body);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SignError {
                error: "parent proxy only runs on Linux".to_string(),
            }),
        ))
    }
}

// ─── /migrate-envelope HTTP handler ─────────────────────────────────
//
// Upgrade an existing v1 or v2 envelope to v3 without ever touching
// the plaintext private key. Backend posts the OLD envelope blob and
// the user's newly-enrolled auth methods (Passkey / OIDC); the enclave
// decrypts the old envelope, re-seals under v3 with a fresh DEK, and
// returns the new blob.

/// JSON body backend posts to POST /migrate-envelope.
#[derive(Debug, Deserialize)]
struct MigrateBody {
    /// CMK ARN for the active mode.
    kms_key_arn: String,
    /// The existing envelope blob — `enc:v1:...` or `enc:v2:...`.
    old_envelope_blob: String,
    /// Required if `old_envelope_blob` is v2 — proves migration is
    /// user-authorised. The enclave's GCM tag check fails on a wrong
    /// password and surfaces as a generic "invalid credentials" error.
    #[serde(default)]
    old_password: Option<String>,
    /// Enrolled auth methods for the new v3 envelope. Must be non-empty.
    enrolled_methods: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct MigrateSuccess {
    envelope_blob: String,
    owner_address: String,
}

async fn migrate_envelope_handler(
    State(state): State<AppState>,
    Json(body): Json<MigrateBody>,
) -> Result<Json<MigrateSuccess>, (StatusCode, Json<SignError>)> {
    #[cfg(target_os = "linux")]
    {
        if body.enrolled_methods.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(SignError {
                    error: "enrolled_methods must be non-empty".to_string(),
                }),
            ));
        }
        let enclave_req = serde_json::json!({
            "kms_key_arn": body.kms_key_arn,
            "old_envelope_blob": body.old_envelope_blob,
            "old_password": body.old_password,
            "enrolled_methods": body.enrolled_methods,
        });

        match forward_to_enclave(
            state.enclave_cid,
            state.enclave_migrate_port,
            &enclave_req,
        )
        .await
        {
            Ok(resp) => {
                if let Some(ok) = resp.get("Ok") {
                    let envelope_blob = ok
                        .get("envelope_blob")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let owner_address = ok
                        .get("owner_address")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if envelope_blob.is_empty() || owner_address.is_empty() {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            Json(SignError {
                                error: format!("malformed enclave response: {resp}"),
                            }),
                        ));
                    }
                    Ok(Json(MigrateSuccess {
                        envelope_blob,
                        owner_address,
                    }))
                } else if let Some(err) = resp
                    .get("Err")
                    .and_then(|e| e.get("reason"))
                    .and_then(|s| s.as_str())
                {
                    warn!(reason = %err, "enclave migrate-envelope returned error");
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("enclave: {err}"),
                        }),
                    ))
                } else {
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(SignError {
                            error: format!("malformed enclave response: {resp}"),
                        }),
                    ))
                }
            }
            Err(e) => {
                error!(error = ?e, "forward to enclave (migrate-envelope) failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    Json(SignError {
                        error: format!("forward to enclave: {e:#}"),
                    }),
                ))
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, body);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SignError {
                error: "parent proxy only runs on Linux".to_string(),
            }),
        ))
    }
}

// ─── vsock KMS proxy ────────────────────────────────────────────────
//
// Phase 2: requests carry an `op` discriminator. Two ops today:
//   - "Decrypt"        — kms:Decrypt with attestation Recipient
//   - "GenerateDataKey" — kms:GenerateDataKey with attestation Recipient

/// Same shape as enclave's `protocol::KmsDecryptRequest`.
#[derive(Deserialize)]
struct KmsDecryptRequest {
    attestation_doc_b64: String,
    wrapped_dek_b64: String,
    kms_key_arn: String,
}

#[derive(Deserialize)]
struct KmsGenerateDataKeyRequest {
    attestation_doc_b64: String,
    kms_key_arn: String,
}

#[derive(Deserialize)]
#[serde(tag = "op")]
enum KmsProxyRequest {
    Decrypt(KmsDecryptRequest),
    GenerateDataKey(KmsGenerateDataKeyRequest),
}

// Response variants. Wire shape matches the enclave's
// `enum KmsDecryptResponse` / `enum KmsGenerateDataKeyResponse`
// (serde default for unit-tagged enums: `{ "Ok": {...} }` / `{ "Err": {...} }`).
#[derive(Serialize)]
#[serde(untagged)]
enum KmsDecryptResponse {
    Ok {
        #[serde(rename = "Ok")]
        ok: KmsDecryptOk,
    },
    Err {
        #[serde(rename = "Err")]
        err: KmsErr,
    },
}

#[derive(Serialize)]
struct KmsDecryptOk {
    ciphertext_for_recipient_b64: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum KmsGenerateDataKeyResponse {
    Ok {
        #[serde(rename = "Ok")]
        ok: KmsGenerateDataKeyOk,
    },
    Err {
        #[serde(rename = "Err")]
        err: KmsErr,
    },
}

#[derive(Serialize)]
struct KmsGenerateDataKeyOk {
    ciphertext_blob_b64: String,
    ciphertext_for_recipient_b64: String,
}

#[derive(Serialize)]
struct KmsErr {
    reason: String,
}

#[cfg(target_os = "linux")]
async fn run_kms_proxy(port: u32, kms: Arc<KmsClient>) -> Result<()> {
    let addr = VsockAddr::new(u32::MAX, port);
    let mut listener = VsockListener::bind(addr).context("vsock bind for KMS proxy")?;
    info!(port, "KMS proxy listener ready on vsock");
    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept")?;
        let kms = kms.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_kms_proxy_conn(stream, kms).await {
                warn!(peer_cid = peer.cid(), error = ?e, "KMS proxy conn handler aborted");
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn handle_kms_proxy_conn(mut stream: VsockStream, kms: Arc<KmsClient>) -> Result<()> {
    let req_bytes = read_frame(&mut stream).await?;
    let req: KmsProxyRequest = serde_json::from_slice(&req_bytes)?;

    let body = match req {
        KmsProxyRequest::Decrypt(req) => {
            let response = match call_kms_decrypt(&kms, &req).await {
                Ok(ciphertext_for_recipient) => KmsDecryptResponse::Ok {
                    ok: KmsDecryptOk {
                        ciphertext_for_recipient_b64: B64.encode(&ciphertext_for_recipient),
                    },
                },
                Err(e) => KmsDecryptResponse::Err {
                    err: KmsErr {
                        reason: format!("{e:#}"),
                    },
                },
            };
            serde_json::to_vec(&response)?
        }
        KmsProxyRequest::GenerateDataKey(req) => {
            let response = match call_kms_generate_data_key(&kms, &req).await {
                Ok((blob, cfr)) => KmsGenerateDataKeyResponse::Ok {
                    ok: KmsGenerateDataKeyOk {
                        ciphertext_blob_b64: B64.encode(&blob),
                        ciphertext_for_recipient_b64: B64.encode(&cfr),
                    },
                },
                Err(e) => KmsGenerateDataKeyResponse::Err {
                    err: KmsErr {
                        reason: format!("{e:#}"),
                    },
                },
            };
            serde_json::to_vec(&response)?
        }
    };

    write_frame(&mut stream, &body).await?;
    Ok(())
}

async fn call_kms_decrypt(kms: &KmsClient, req: &KmsDecryptRequest) -> Result<Vec<u8>> {
    let attestation_doc = B64
        .decode(&req.attestation_doc_b64)
        .context("base64-decode attestation document")?;
    let wrapped_dek = B64
        .decode(&req.wrapped_dek_b64)
        .context("base64-decode wrapped DEK")?;

    let recipient = RecipientInfo::builder()
        .attestation_document(Blob::new(attestation_doc))
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .build();

    let out = kms
        .decrypt()
        .ciphertext_blob(Blob::new(wrapped_dek))
        .key_id(&req.kms_key_arn)
        .recipient(recipient)
        .send()
        .await
        .context("KMS Decrypt with Recipient")?;

    let cfr = out
        .ciphertext_for_recipient
        .ok_or_else(|| anyhow!("KMS returned no CiphertextForRecipient — was attestation valid?"))?;
    Ok(cfr.into_inner())
}

/// Calls kms:GenerateDataKey with the recipient attestation. Returns
/// (CiphertextBlob, CiphertextForRecipient).
async fn call_kms_generate_data_key(
    kms: &KmsClient,
    req: &KmsGenerateDataKeyRequest,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let attestation_doc = B64
        .decode(&req.attestation_doc_b64)
        .context("base64-decode attestation document")?;

    let recipient = RecipientInfo::builder()
        .attestation_document(Blob::new(attestation_doc))
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .build();

    let out = kms
        .generate_data_key()
        .key_id(&req.kms_key_arn)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
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

// ─── Vsock framing helpers ──────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn read_frame(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        bail!("frame too large: {len} bytes (max 1 MiB)");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read frame body")?;
    Ok(body)
}

#[cfg(target_os = "linux")]
async fn write_frame(stream: &mut VsockStream, body: &[u8]) -> Result<()> {
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("write length prefix")?;
    stream.write_all(body).await.context("write frame body")?;
    stream.flush().await.context("flush")?;
    Ok(())
}
