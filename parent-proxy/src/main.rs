//! Rift parent-proxy: HTTP↔vsock bridge that runs on the EC2 host,
//! OUTSIDE the enclave.
//!
//! ```text
//!  backend / smart-wallet
//!    │  HTTP  :7777  /sign /generate-wallet /migrate-envelope /reseal-v3
//!    │               /health/enclave (canary)
//!    ▼
//!  parent-proxy (this binary)
//!    │  vsock → enclave:5005/5007/5008/5009/5010 (one port per operation)
//!    │  vsock ← enclave → :5006               (KMS proxy callbacks)
//!    ▼
//!  AWS KMS  Decrypt / GenerateDataKey with attestation Recipient
//! ```
//!
//! This process holds no key material: KMS encrypts every data key to
//! the enclave's attested ephemeral RSA key. It does hold the EC2
//! instance role's KMS permissions and is the only network path to the
//! enclave, so it is still security-relevant (see `http::BearerAuth`).
//!
//! Modules:
//!   - [`http`]      — routes, bearer auth, load limits, response mapping
//!   - [`enclave`]   — forwarding one request to an enclave vsock port
//!   - [`kms_proxy`] — vsock listener the enclave calls for KMS
//!   - [`framing`]   — 4-byte length-prefixed JSON frames
//!
//! Environment (systemd `EnvironmentFile=/etc/rift-parent-proxy.env`):
//!   ENCLAVE_CID                   enclave vsock CID; also the ONLY peer
//!                                 CID the KMS proxy accepts  (default 16)
//!   ENCLAVE_PORT                  sign port                    (default 5005)
//!   ENCLAVE_GENERATE_WALLET_PORT  generate-wallet port         (default 5007)
//!   ENCLAVE_MIGRATE_PORT          migrate-envelope port        (default 5008)
//!   ENCLAVE_RESEAL_PORT           reseal-v3 port               (default 5009)
//!   ENCLAVE_HEALTH_PORT           health/canary port           (default 5010)
//!   KMS_PROXY_PORT                vsock port we listen on      (default 5006)
//!   HTTP_BIND                     HTTP listen address          (default 0.0.0.0:7777)
//!   PARENT_PROXY_AUTH_TOKEN       Bearer token for all enclave routes.
//!                                 REQUIRED when HTTP_BIND is not loopback:
//!                                 the proxy refuses to start without it …
//!   PARENT_PROXY_ALLOW_INSECURE   … unless this is exactly "1" (logged
//!                                 loudly at ERROR level on every start).
//!   PARENT_PROXY_MAX_CONCURRENCY  enclave requests in flight   (default 4)
//!   PARENT_PROXY_QUEUE_TIMEOUT_MS wait for a slot before 503   (default 10000)
//!   PARENT_PROXY_REQUEST_TIMEOUT_SECS per-request limit → 504  (default 30)
//!   AWS_REGION, AWS_*             standard AWS SDK configuration
//!   RUST_LOG                      tracing filter

mod enclave;
mod framing;
mod http;
mod kms_proxy;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aws_sdk_kms::Client as KmsClient;
use tracing::{error, info, warn};

use crate::enclave::EnclaveEndpoints;
use crate::http::{AppState, BearerAuth, Limits};

const DEFAULT_ENCLAVE_CID: u32 = 16;
const DEFAULT_ENCLAVE_PORT: u32 = 5005;
const DEFAULT_KMS_PROXY_PORT: u32 = 5006;
const DEFAULT_GENERATE_WALLET_PORT: u32 = 5007;
const DEFAULT_MIGRATE_PORT: u32 = 5008;
const DEFAULT_RESEAL_PORT: u32 = 5009;
const DEFAULT_HEALTH_PORT: u32 = 5010;
/// Public by default so a remote smart-wallet (behind nginx/TLS) can
/// reach us. Set `HTTP_BIND=127.0.0.1:7777` to keep it host-local. A
/// non-loopback bind requires `PARENT_PROXY_AUTH_TOKEN` (see
/// [`check_auth_posture`]).
const DEFAULT_HTTP_BIND: &str = "0.0.0.0:7777";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rift_parent_proxy=debug".into()),
        )
        .init();

    let endpoints = EnclaveEndpoints {
        cid: env_u32("ENCLAVE_CID", DEFAULT_ENCLAVE_CID),
        sign_port: env_u32("ENCLAVE_PORT", DEFAULT_ENCLAVE_PORT),
        generate_wallet_port: env_u32("ENCLAVE_GENERATE_WALLET_PORT", DEFAULT_GENERATE_WALLET_PORT),
        migrate_port: env_u32("ENCLAVE_MIGRATE_PORT", DEFAULT_MIGRATE_PORT),
        reseal_port: env_u32("ENCLAVE_RESEAL_PORT", DEFAULT_RESEAL_PORT),
        health_port: env_u32("ENCLAVE_HEALTH_PORT", DEFAULT_HEALTH_PORT),
    };
    let kms_proxy_port = env_u32("KMS_PROXY_PORT", DEFAULT_KMS_PROXY_PORT);
    let http_bind = std::env::var("HTTP_BIND").unwrap_or_else(|_| DEFAULT_HTTP_BIND.to_string());
    let auth = Arc::new(BearerAuth::new(
        &std::env::var("PARENT_PROXY_AUTH_TOKEN").unwrap_or_default(),
    ));
    let defaults = Limits::default();
    let limits = Limits {
        max_concurrency: env_u32(
            "PARENT_PROXY_MAX_CONCURRENCY",
            defaults.max_concurrency as u32,
        )
        .max(1) as usize,
        queue_timeout: Duration::from_millis(u64::from(env_u32(
            "PARENT_PROXY_QUEUE_TIMEOUT_MS",
            defaults.queue_timeout.as_millis() as u32,
        ))),
        request_timeout: Duration::from_secs(u64::from(env_u32(
            "PARENT_PROXY_REQUEST_TIMEOUT_SECS",
            defaults.request_timeout.as_secs() as u32,
        ))),
    };

    info!(
        enclave_cid = endpoints.cid,
        enclave_port = endpoints.sign_port,
        enclave_generate_wallet_port = endpoints.generate_wallet_port,
        enclave_migrate_port = endpoints.migrate_port,
        enclave_reseal_port = endpoints.reseal_port,
        enclave_health_port = endpoints.health_port,
        kms_proxy_port,
        http_bind = %http_bind,
        auth_enabled = auth.is_enabled(),
        max_concurrency = limits.max_concurrency,
        queue_timeout_ms = limits.queue_timeout.as_millis() as u64,
        request_timeout_secs = limits.request_timeout.as_secs(),
        "starting rift-parent-proxy"
    );

    let allow_insecure = std::env::var("PARENT_PROXY_ALLOW_INSECURE").ok();
    match check_auth_posture(auth.is_enabled(), &http_bind, allow_insecure.as_deref()) {
        AuthPosture::Ok => {}
        AuthPosture::InsecureOverride => error!(
            http_bind = %http_bind,
            "INSECURE: PARENT_PROXY_AUTH_TOKEN is not set and HTTP_BIND is not loopback, \
             but PARENT_PROXY_ALLOW_INSECURE=1 is set. /sign, /generate-wallet, \
             /migrate-envelope, /reseal-v3 and /health/enclave are reachable WITHOUT \
             authentication. Never run like this in production."
        ),
        AuthPosture::Refuse => bail!(
            "refusing to start: HTTP_BIND={http_bind} is not loopback and \
             PARENT_PROXY_AUTH_TOKEN is not set. Set PARENT_PROXY_AUTH_TOKEN, or bind \
             HTTP_BIND=127.0.0.1:7777, or (dev only) set PARENT_PROXY_ALLOW_INSECURE=1."
        ),
    }

    // `BehaviorVersion::latest()` (rather than the deprecated
    // `from_env()`) so SDK upgrades don't silently change semantics.
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let kms = Arc::new(KmsClient::new(&aws_config));

    // vsock KMS proxy: runs for the life of the process. The enclave
    // connects here whenever it needs an attested KMS call.
    #[cfg(target_os = "linux")]
    {
        let enclave_cid = endpoints.cid;
        tokio::spawn(async move {
            if let Err(e) = kms_proxy::run(kms_proxy_port, enclave_cid, kms).await {
                tracing::error!(error = ?e, "KMS proxy loop terminated");
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (kms, kms_proxy_port);
        warn!("non-Linux build: vsock is unavailable, enclave routes will return 502");
    }

    let app = http::router(AppState { enclave: endpoints }, auth, limits);
    let listener = tokio::net::TcpListener::bind(&http_bind)
        .await
        .with_context(|| format!("bind HTTP listener on {http_bind}"))?;
    info!(addr = %http_bind, "HTTP listener ready");
    axum::serve(listener, app).await.context("HTTP serve")?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum AuthPosture {
    /// Token set, or bound to loopback only.
    Ok,
    /// No token on a non-loopback bind, explicitly overridden.
    InsecureOverride,
    /// No token on a non-loopback bind: fail closed.
    Refuse,
}

/// Fail-closed startup rule: an unauthenticated proxy may only listen on
/// loopback, unless the operator sets `PARENT_PROXY_ALLOW_INSECURE=1`
/// (exactly "1"; anything else is ignored).
fn check_auth_posture(auth_enabled: bool, http_bind: &str, allow_insecure: Option<&str>) -> AuthPosture {
    if auth_enabled || is_loopback_bind(http_bind) {
        AuthPosture::Ok
    } else if allow_insecure.map(str::trim) == Some("1") {
        AuthPosture::InsecureOverride
    } else {
        AuthPosture::Refuse
    }
}

/// Read a `u32` env var. Unset ⇒ `default`. Set-but-unparseable ⇒
/// `default` too (unchanged behaviour), but now with a warning, since
/// silently falling back on e.g. a mistyped `ENCLAVE_CID` sends every
/// request to the wrong enclave.
fn env_u32(name: &str, default: u32) -> u32 {
    match std::env::var(name) {
        Err(_) => default,
        Ok(raw) => raw.parse().unwrap_or_else(|_| {
            warn!(var = name, value = %raw, default, "unparseable env var; using default");
            default
        }),
    }
}

/// True only for literal loopback socket addresses. Hostnames
/// (including "localhost") return false so the check errs on the side
/// of requiring a token.
fn is_loopback_bind(bind: &str) -> bool {
    bind.parse::<SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_bind("127.0.0.1:7777"));
        assert!(is_loopback_bind("[::1]:7777"));
        assert!(!is_loopback_bind("0.0.0.0:7777"));
        assert!(!is_loopback_bind("10.0.0.5:7777"));
        assert!(!is_loopback_bind("localhost:7777"));
    }

    #[test]
    fn fails_closed_without_token_on_public_bind() {
        assert_eq!(check_auth_posture(false, "0.0.0.0:7777", None), AuthPosture::Refuse);
        assert_eq!(check_auth_posture(false, "0.0.0.0:7777", Some("0")), AuthPosture::Refuse);
        assert_eq!(check_auth_posture(false, "0.0.0.0:7777", Some("true")), AuthPosture::Refuse);
        assert_eq!(check_auth_posture(false, "localhost:7777", None), AuthPosture::Refuse);
        assert_eq!(
            check_auth_posture(false, "0.0.0.0:7777", Some("1")),
            AuthPosture::InsecureOverride
        );
        assert_eq!(check_auth_posture(false, "127.0.0.1:7777", None), AuthPosture::Ok);
        assert_eq!(check_auth_posture(true, "0.0.0.0:7777", None), AuthPosture::Ok);
    }
}
