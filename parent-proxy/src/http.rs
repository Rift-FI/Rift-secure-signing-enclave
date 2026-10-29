//! HTTP frontend: the backend / smart-wallet talk to the enclave
//! through these routes.
//!
//! The HTTP API is a FROZEN contract with `backend` and `smart-wallet`:
//! route paths, request bodies, success bodies, status codes and the
//! `{"error": "..."}` error body (including its message text) must not
//! change. The parent-proxy is a pass-through — every security decision
//! is made inside the enclave.
//!
//! | Route                    | Auth   | Enclave vsock port        |
//! |--------------------------|--------|---------------------------|
//! | `POST /sign`             | bearer | sign (5005)               |
//! | `POST /generate-wallet`  | bearer | generate-wallet (5007)    |
//! | `POST /migrate-envelope` | bearer | migrate (5008)            |
//! | `POST /reseal-v3`        | bearer | reseal (5009)             |
//! | `GET\|POST /health/enclave` | bearer | health (5010) — additive |
//! | `GET\|POST /health`      | none   | — (does NOT reach enclave)|
//!
//! Load protection (additive; only visible under overload): every
//! enclave-bound route shares one concurrency budget
//! ([`Limits::max_concurrency`]). A request that cannot get a slot within
//! [`Limits::queue_timeout`] gets `503 {"error":"parent-proxy overloaded"}`;
//! one that runs longer than [`Limits::request_timeout`] gets
//! `504 {"error":"enclave request timed out"}`. Request bodies above
//! [`crate::framing::MAX_FRAME_LEN`] are refused with 413 before any
//! enclave contact (they could never fit in a vsock frame anyway).

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tokio::sync::Semaphore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{error, warn};

use crate::enclave::{self, EnclaveEndpoints};

// ─── Wire types ─────────────────────────────────────────────────────
//
// None of the request bodies derive `Debug`: several carry user
// passwords (`password`, `old_password`) or bearer-equivalent consent
// proofs, and a stray `{:?}` in a future log line must not be able to
// print them.

/// POST /sign.
///
/// Envelope formats sharing this body:
///   v1 (legacy KMS-only): `ciphertext_hex` + `iv_hex`.
///   v2 (password-bound):  `ciphertext_hex`, `password`, `salt_b64`,
///                         `nonce_hex`, `tag_hex`.
///   v3 (device-bound):    `v3_envelope_blob` + `auth_proof`; the v1/v2
///                         fields are absent (hence `#[serde(default)]`).
///
/// `project_id` / `signed_config_json` / `signed_config_signature_b64`
/// are the optional Rift-signed per-project accept-list bundle (Option
/// C). They MUST be forwarded verbatim, otherwise partner users hit
/// "aud/origin not in the pinned accept list" inside the enclave.
#[derive(Deserialize)]
pub struct SignBody {
    user_op_hash_hex: String,
    #[serde(default)]
    wrapped_dek_b64: String,
    #[serde(default)]
    ciphertext_hex: String,
    #[serde(default)]
    iv_hex: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    salt_b64: Option<String>,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    tag_hex: Option<String>,
    kms_key_arn: String,
    #[serde(default)]
    v3_envelope_blob: Option<String>,
    #[serde(default)]
    auth_proof: Option<Value>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    signed_config_json: Option<String>,
    #[serde(default)]
    signed_config_signature_b64: Option<String>,
}

#[derive(Serialize)]
pub struct SignSuccess {
    signature_hex: String,
}

/// POST /generate-wallet. Enclave picks the format: non-empty
/// `enrolled_methods` → v3, else `password` → v2, else v1.
#[derive(Deserialize)]
pub struct GenerateWalletBody {
    kms_key_arn: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    enrolled_methods: Vec<Value>,
}

/// POST /migrate-envelope: upgrade a v1/v2 envelope to v3 inside the
/// enclave. `old_password` is required by the enclave for v2.
#[derive(Deserialize)]
pub struct MigrateBody {
    kms_key_arn: String,
    old_envelope_blob: String,
    #[serde(default)]
    old_password: Option<String>,
    enrolled_methods: Vec<Value>,
}

/// POST /reseal-v3: append a method to an existing v3 envelope, gated
/// by an `auth_proof` from a method already inside it, signed over the
/// 32-byte `prehashed_hex` challenge.
#[derive(Deserialize)]
pub struct ResealBody {
    kms_key_arn: String,
    old_envelope_blob: String,
    auth_proof: Value,
    prehashed_hex: String,
    new_method: Value,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    signed_config_json: Option<String>,
    #[serde(default)]
    signed_config_signature_b64: Option<String>,
}

/// Success body shared by generate-wallet, migrate-envelope and
/// reseal-v3.
#[derive(Serialize)]
pub struct EnvelopeSuccess {
    envelope_blob: String,
    owner_address: String,
}

/// Optional body of `POST /health/enclave`. `kms_key_arn` asks the
/// enclave to also prove an attested KMS GenerateDataKey round trip.
#[derive(Deserialize, Default)]
pub struct HealthEnclaveBody {
    #[serde(default)]
    kms_key_arn: Option<String>,
}

#[derive(Serialize)]
pub struct HealthEnclaveSuccess {
    status: &'static str,
    version: String,
    pcr0: String,
    kms_checked: bool,
}

/// Stable overload / timeout error strings (clients may match on them).
pub const OVERLOADED_ERROR: &str = "parent-proxy overloaded";
pub const TIMEOUT_ERROR: &str = "enclave request timed out";

/// Error body for every non-2xx response: `{"error": "..."}`.
#[derive(Serialize)]
pub struct ErrorBody {
    error: String,
}

pub type ApiError = (StatusCode, Json<ErrorBody>);

fn api_error(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(ErrorBody { error: msg.into() }))
}

// ─── Router ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub enclave: EnclaveEndpoints,
}

/// Concurrency / time budget for enclave-bound routes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max requests in flight to the enclave at once (all routes
    /// combined). The enclave runs on a single vCPU and does an
    /// RSA-2048 keygen per request, so a small number is right.
    pub max_concurrency: usize,
    /// How long a request may wait for a free slot before 503.
    pub queue_timeout: Duration,
    /// Max wall time of one enclave-bound request (after it got a
    /// slot) before 504.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            queue_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
struct LimitState {
    permits: Arc<Semaphore>,
    limits: Limits,
}

pub fn router(state: AppState, auth: Arc<BearerAuth>, limits: Limits) -> Router {
    // `route_layer` (not `layer`) so the auth check only runs for
    // requests that matched a route + method; /health stays open for
    // load-balancer probes.
    let authed = || middleware::from_fn_with_state(auth.clone(), bearer_auth);
    let limit_state = LimitState {
        permits: Arc::new(Semaphore::new(limits.max_concurrency.max(1))),
        limits,
    };
    let enclave_routes = Router::new()
        .route("/sign", post(sign_handler).route_layer(authed()))
        .route(
            "/generate-wallet",
            post(generate_wallet_handler).route_layer(authed()),
        )
        .route(
            "/migrate-envelope",
            post(migrate_envelope_handler).route_layer(authed()),
        )
        .route("/reseal-v3", post(reseal_v3_handler).route_layer(authed()))
        .route(
            "/health/enclave",
            get(health_enclave_get)
                .post(health_enclave_post)
                .route_layer(authed()),
        )
        // One shared semaphore for every route above (the middleware
        // state is cloned per route, the Arc<Semaphore> inside is not).
        .layer(middleware::from_fn_with_state(limit_state, enclave_limits))
        .layer(DefaultBodyLimit::max(crate::framing::MAX_FRAME_LEN));
    Router::new()
        .merge(enclave_routes)
        .route("/health", get(health_handler).post(health_handler))
        .with_state(state)
}

/// Shared concurrency + timeout guard for enclave-bound routes.
async fn enclave_limits(State(ls): State<LimitState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let permit = match tokio::time::timeout(
        ls.limits.queue_timeout,
        ls.permits.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        // The semaphore is never closed; treat any failure as overload.
        Ok(Err(_)) | Err(_) => {
            warn!(path = %path, "no enclave slot within queue timeout — shedding request");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, OVERLOADED_ERROR).into_response();
        }
    };
    let resp = match tokio::time::timeout(ls.limits.request_timeout, next.run(req)).await {
        Ok(r) => r,
        Err(_) => {
            error!(path = %path, "enclave request exceeded request timeout");
            api_error(StatusCode::GATEWAY_TIMEOUT, TIMEOUT_ERROR).into_response()
        }
    };
    drop(permit);
    resp
}

/// Liveness only — answers without contacting the enclave.
async fn health_handler() -> &'static str {
    "ok"
}

// ─── Bearer auth ────────────────────────────────────────────────────

/// Expected `Authorization` header value, captured once at startup
/// from `PARENT_PROXY_AUTH_TOKEN`. Rotation = edit the env file +
/// `systemctl restart rift-parent-proxy` (unchanged).
///
/// Empty / unset token ⇒ auth DISABLED (unchanged, for on-box smoke
/// tests). `main` logs a loud warning when that is combined with a
/// non-loopback bind.
pub struct BearerAuth {
    expected_header: Option<Vec<u8>>,
}

impl BearerAuth {
    pub fn new(token: &str) -> Self {
        Self {
            expected_header: (!token.is_empty()).then(|| format!("Bearer {token}").into_bytes()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.expected_header.is_some()
    }

    fn allows(&self, header: &str) -> bool {
        match &self.expected_header {
            None => true,
            Some(expected) => constant_time_eq(header.as_bytes(), expected),
        }
    }
}

/// Compare without an early exit on the first differing byte, so
/// response timing does not reveal how much of a guessed token was
/// correct. (Length is not secret: it is fixed per deployment.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

async fn bearer_auth(
    State(auth): State<Arc<BearerAuth>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth.allows(header) {
        Ok(next.run(req).await)
    } else {
        warn!(path = %req.uri().path(), "rejected request — missing or wrong Bearer token");
        Err(api_error(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

// ─── Handlers ───────────────────────────────────────────────────────

async fn sign_handler(
    State(state): State<AppState>,
    Json(body): Json<SignBody>,
) -> Result<Json<SignSuccess>, ApiError> {
    let enclave_req = json!({
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
        "project_id": body.project_id,
        "signed_config_json": body.signed_config_json,
        "signed_config_signature_b64": body.signed_config_signature_b64,
    });
    let resp = enclave::forward(state.enclave.cid, state.enclave.sign_port, &enclave_req).await;
    map_enclave_response("sign", resp, |ok| {
        let signature_hex = ok.get("signature_hex")?.as_str()?.to_string();
        Some(SignSuccess { signature_hex })
    })
}

async fn generate_wallet_handler(
    State(state): State<AppState>,
    Json(body): Json<GenerateWalletBody>,
) -> Result<Json<EnvelopeSuccess>, ApiError> {
    let enclave_req = json!({
        "kms_key_arn": body.kms_key_arn,
        "password": body.password,
        "enrolled_methods": body.enrolled_methods,
    });
    let resp = enclave::forward(
        state.enclave.cid,
        state.enclave.generate_wallet_port,
        &enclave_req,
    )
    .await;
    map_enclave_response("generate-wallet", resp, extract_envelope_success)
}

async fn migrate_envelope_handler(
    State(state): State<AppState>,
    Json(body): Json<MigrateBody>,
) -> Result<Json<EnvelopeSuccess>, ApiError> {
    if body.enrolled_methods.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "enrolled_methods must be non-empty",
        ));
    }
    let enclave_req = json!({
        "kms_key_arn": body.kms_key_arn,
        "old_envelope_blob": body.old_envelope_blob,
        "old_password": body.old_password,
        "enrolled_methods": body.enrolled_methods,
    });
    let resp = enclave::forward(state.enclave.cid, state.enclave.migrate_port, &enclave_req).await;
    map_enclave_response("migrate-envelope", resp, extract_envelope_success)
}

async fn reseal_v3_handler(
    State(state): State<AppState>,
    Json(body): Json<ResealBody>,
) -> Result<Json<EnvelopeSuccess>, ApiError> {
    // Cheap sanity checks for obviously-broken client calls. The real
    // validation (and every security check) happens in the enclave.
    if !body.old_envelope_blob.starts_with("enc:v3:") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "old_envelope_blob must start with enc:v3:",
        ));
    }
    if body.prehashed_hex.trim_start_matches("0x").len() != 64 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "prehashed_hex must be 32 bytes (64 hex chars)",
        ));
    }
    let enclave_req = json!({
        "kms_key_arn": body.kms_key_arn,
        "old_envelope_blob": body.old_envelope_blob,
        "auth_proof": body.auth_proof,
        "prehashed_hex": body.prehashed_hex,
        "new_method": body.new_method,
        "project_id": body.project_id,
        "signed_config_json": body.signed_config_json,
        "signed_config_signature_b64": body.signed_config_signature_b64,
    });
    let resp = enclave::forward(state.enclave.cid, state.enclave.reseal_port, &enclave_req).await;
    map_enclave_response("reseal-v3", resp, extract_envelope_success)
}

/// GET /health/enclave — vsock round trip to the enclave's health port;
/// returns the PCR0 the enclave reads from its own NSM. No KMS call.
async fn health_enclave_get(
    State(state): State<AppState>,
) -> Result<Json<HealthEnclaveSuccess>, ApiError> {
    health_enclave(state, HealthEnclaveBody::default()).await
}

/// POST /health/enclave — same, optionally with `{"kms_key_arn": ".."}`
/// to also prove an attested KMS round trip (the rotation canary).
/// An empty body is accepted.
async fn health_enclave_post(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Json<HealthEnclaveSuccess>, ApiError> {
    let parsed = if body.iter().all(u8::is_ascii_whitespace) {
        HealthEnclaveBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?
    };
    health_enclave(state, parsed).await
}

async fn health_enclave(
    state: AppState,
    body: HealthEnclaveBody,
) -> Result<Json<HealthEnclaveSuccess>, ApiError> {
    let enclave_req = json!({ "kms_key_arn": body.kms_key_arn });
    let resp = enclave::forward(state.enclave.cid, state.enclave.health_port, &enclave_req).await;
    map_enclave_response("health-enclave", resp, |ok| {
        Some(HealthEnclaveSuccess {
            status: "ok",
            version: ok.get("version")?.as_str()?.to_string(),
            pcr0: ok.get("pcr0")?.as_str()?.to_string(),
            kms_checked: ok.get("kms_checked")?.as_bool()?,
        })
    })
}

fn extract_envelope_success(ok: &Value) -> Option<EnvelopeSuccess> {
    let field = |name: &str| {
        ok.get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Some(EnvelopeSuccess {
        envelope_blob: field("envelope_blob")?,
        owner_address: field("owner_address")?,
    })
}

/// Translate the enclave's `{"Ok": {..}}` / `{"Err": {"reason": ..}}`
/// response (or a transport failure) into the frozen HTTP contract:
///
///   - `Ok` with the expected fields      → 200 + success body
///   - `Err { reason }`                   → 502 `enclave: <reason>`
///   - anything else                      → 502 `malformed enclave response: <json>`
///   - vsock / framing / JSON failure     → 502 `forward to enclave: <error chain>`
fn map_enclave_response<T>(
    route: &'static str,
    resp: anyhow::Result<Value>,
    extract_ok: impl FnOnce(&Value) -> Option<T>,
) -> Result<Json<T>, ApiError> {
    let resp = match resp {
        Ok(resp) => resp,
        Err(e) => {
            error!(route, error = ?e, "forward to enclave failed");
            return Err(api_error(
                StatusCode::BAD_GATEWAY,
                format!("forward to enclave: {e:#}"),
            ));
        }
    };
    if let Some(ok) = resp.get("Ok").and_then(extract_ok) {
        return Ok(Json(ok));
    }
    if let Some(reason) = resp
        .get("Err")
        .and_then(|e| e.get("reason"))
        .and_then(Value::as_str)
    {
        warn!(route, reason = %reason, "enclave returned error");
        return Err(api_error(
            StatusCode::BAD_GATEWAY,
            format!("enclave: {reason}"),
        ));
    }
    Err(api_error(
        StatusCode::BAD_GATEWAY,
        format!("malformed enclave response: {resp}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request as HttpRequest};
    use tower::ServiceExt;

    fn test_router(token: &str) -> Router {
        router(
            AppState {
                enclave: EnclaveEndpoints {
                    cid: 16,
                    sign_port: 5005,
                    generate_wallet_port: 5007,
                    migrate_port: 5008,
                    reseal_port: 5009,
                    health_port: 5010,
                },
            },
            Arc::new(BearerAuth::new(token)),
            Limits::default(),
        )
    }

    async fn call(app: Router, req: HttpRequest<Body>) -> (StatusCode, String) {
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn post_json(path: &str, auth: Option<&str>, body: Value) -> HttpRequest<Body> {
        let mut b = HttpRequest::post(path).header(header::CONTENT_TYPE, "application/json");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    // ── auth ──

    #[test]
    fn constant_time_eq_semantics() {
        assert!(constant_time_eq(b"Bearer abc", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer abd", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer ab", b"Bearer abc"));
        assert!(!constant_time_eq(b"", b"Bearer abc"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn bearer_auth_matching_is_exact() {
        let auth = BearerAuth::new("s3cret");
        assert!(auth.is_enabled());
        assert!(auth.allows("Bearer s3cret"));
        assert!(!auth.allows("bearer s3cret"));
        assert!(!auth.allows("Bearer s3cret "));
        assert!(!auth.allows("s3cret"));
        assert!(!auth.allows(""));
    }

    #[test]
    fn empty_token_disables_auth() {
        let auth = BearerAuth::new("");
        assert!(!auth.is_enabled());
        assert!(auth.allows(""));
    }

    #[tokio::test]
    async fn protected_routes_reject_missing_or_wrong_token() {
        for path in [
            "/sign",
            "/generate-wallet",
            "/migrate-envelope",
            "/reseal-v3",
            "/health/enclave",
        ] {
            for auth in [None, Some("Bearer wrong")] {
                let (status, body) =
                    call(test_router("s3cret"), post_json(path, auth, json!({}))).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
                assert_eq!(body, r#"{"error":"unauthorized"}"#, "{path}");
            }
        }
    }

    #[tokio::test]
    async fn health_is_open_on_get_and_post() {
        let get_req = HttpRequest::get("/health").body(Body::empty()).unwrap();
        assert_eq!(
            call(test_router("s3cret"), get_req).await,
            (StatusCode::OK, "ok".into())
        );
        let post_req = HttpRequest::post("/health").body(Body::empty()).unwrap();
        assert_eq!(
            call(test_router("s3cret"), post_req).await,
            (StatusCode::OK, "ok".into())
        );
    }

    // ── request validation (runs before any enclave contact) ──

    #[tokio::test]
    async fn migrate_rejects_empty_enrolled_methods() {
        let req = post_json(
            "/migrate-envelope",
            Some("Bearer t"),
            json!({"kms_key_arn": "k", "old_envelope_blob": "enc:v1:a:b:c", "enrolled_methods": []}),
        );
        let (status, body) = call(test_router("t"), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"enrolled_methods must be non-empty"}"#);
    }

    #[tokio::test]
    async fn reseal_rejects_non_v3_blob_and_bad_challenge() {
        let base = |blob: &str, hash: &str| {
            json!({
                "kms_key_arn": "k",
                "old_envelope_blob": blob,
                "auth_proof": {"kind": "oidc", "id_token": "x"},
                "prehashed_hex": hash,
                "new_method": {"kind": "oidc", "iss": "i", "sub": "s"},
            })
        };
        let ok_hash = "0x".to_string() + &"ab".repeat(32);

        let (status, body) = call(
            test_router("t"),
            post_json("/reseal-v3", Some("Bearer t"), base("enc:v2:x", &ok_hash)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            r#"{"error":"old_envelope_blob must start with enc:v3:"}"#
        );

        let (status, body) = call(
            test_router("t"),
            post_json("/reseal-v3", Some("Bearer t"), base("enc:v3:x", "abcd")),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            r#"{"error":"prehashed_hex must be 32 bytes (64 hex chars)"}"#
        );
    }

    // ── enclave response mapping (the frozen error contract) ──

    fn sign_extract(ok: &Value) -> Option<String> {
        ok.get("signature_hex")?.as_str().map(str::to_string)
    }

    fn err_of<T>(r: Result<Json<T>, ApiError>) -> (StatusCode, String) {
        match r {
            Ok(_) => panic!("expected error"),
            Err((s, Json(b))) => (s, b.error),
        }
    }

    #[test]
    fn maps_ok_response() {
        let r = map_enclave_response(
            "sign",
            Ok(json!({"Ok": {"signature_hex": "0xabc"}})),
            sign_extract,
        );
        assert_eq!(r.ok().unwrap().0, "0xabc");
    }

    #[test]
    fn maps_enclave_err_reason() {
        let r = map_enclave_response(
            "sign",
            Ok(json!({"Err": {"reason": "invalid credentials"}})),
            sign_extract,
        );
        assert_eq!(
            err_of(r),
            (
                StatusCode::BAD_GATEWAY,
                "enclave: invalid credentials".into()
            )
        );
    }

    #[test]
    fn maps_malformed_response() {
        let r = map_enclave_response("sign", Ok(json!({"Ok": {}})), sign_extract);
        assert_eq!(
            err_of(r),
            (
                StatusCode::BAD_GATEWAY,
                r#"malformed enclave response: {"Ok":{}}"#.into()
            )
        );
    }

    #[test]
    fn maps_transport_error() {
        let r = map_enclave_response::<String>(
            "sign",
            Err(anyhow::anyhow!("inner").context("outer")),
            sign_extract,
        );
        assert_eq!(
            err_of(r),
            (
                StatusCode::BAD_GATEWAY,
                "forward to enclave: outer: inner".into()
            )
        );
    }

    #[test]
    fn envelope_success_requires_both_fields_non_empty() {
        assert!(extract_envelope_success(
            &json!({"envelope_blob": "enc:v3:x", "owner_address": "0x1"})
        )
        .is_some());
        assert!(
            extract_envelope_success(&json!({"envelope_blob": "", "owner_address": "0x1"}))
                .is_none()
        );
        assert!(extract_envelope_success(&json!({"envelope_blob": "enc:v3:x"})).is_none());
    }

    // ── load protection ──

    /// Same middleware in front of a handler we can hold open, so the
    /// overload behaviour is testable without vsock.
    fn limited_router(limits: Limits) -> Router {
        let ls = LimitState {
            permits: Arc::new(Semaphore::new(limits.max_concurrency)),
            limits,
        };
        Router::new()
            .route(
                "/slow",
                post(|| async {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    "done"
                }),
            )
            .layer(middleware::from_fn_with_state(ls, enclave_limits))
    }

    #[tokio::test]
    async fn overload_returns_503_with_stable_body() {
        let app = limited_router(Limits {
            max_concurrency: 1,
            queue_timeout: Duration::from_millis(20),
            request_timeout: Duration::from_secs(5),
        });
        let first = tokio::spawn(call(app.clone(), post_json("/slow", None, json!({}))));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (status, body) = call(app.clone(), post_json("/slow", None, json!({}))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, r#"{"error":"parent-proxy overloaded"}"#);
        assert_eq!(first.await.unwrap().0, StatusCode::OK);
        // Slot released: the next request succeeds.
        assert_eq!(call(app, post_json("/slow", None, json!({}))).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn slow_request_returns_504() {
        let app = limited_router(Limits {
            max_concurrency: 2,
            queue_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_millis(50),
        });
        let (status, body) = call(app, post_json("/slow", None, json!({}))).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body, r#"{"error":"enclave request timed out"}"#);
    }

    #[tokio::test]
    async fn oversized_body_rejected_before_enclave() {
        let big = "x".repeat(crate::framing::MAX_FRAME_LEN + 10);
        let req = HttpRequest::post("/sign")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer t")
            .body(Body::from(format!(
                r#"{{"user_op_hash_hex":"{big}","kms_key_arn":"k"}}"#
            )))
            .unwrap();
        let (status, _) = call(test_router("t"), req).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn health_enclave_is_forwarded_not_answered_locally() {
        // Off-Linux the forwarder always fails, which proves the route is
        // wired to the enclave (502) rather than answered like /health.
        let req = HttpRequest::get("/health/enclave")
            .header(header::AUTHORIZATION, "Bearer t")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(test_router("t"), req).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("forward to enclave"), "{body}");

        let bad = HttpRequest::post("/health/enclave")
            .header(header::AUTHORIZATION, "Bearer t")
            .body(Body::from("{not json"))
            .unwrap();
        assert_eq!(call(test_router("t"), bad).await.0, StatusCode::BAD_REQUEST);
    }
}
