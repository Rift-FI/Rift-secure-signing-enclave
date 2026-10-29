//! Per-project WebAuthn accept-list config, signed by Rift and
//! verified inside the enclave.
//!
//! # Why this exists
//!
//! WebAuthn's origin + rpIdHash checks require the enclave to know
//! which RP-IDs + origins to accept. Before this module, that list
//! was baked into the EIF at compile time (see
//! `webauthn_verification::WebAuthnPolicy::default_prod`). Adding
//! a new integrator (e.g. a partner with `app.acme.com`) meant
//! rebuilding the enclave image, computing a new PCR0, updating
//! the KMS key policy to accept the new PCR0, and migrating every
//! `project_enclave_configs.pcr0` row to the new hash — a full
//! ops cycle per integrator. Doesn't scale.
//!
//! # Trust model
//!
//! The Rift backend holds an ed25519 PRIVATE key (in Railway env
//! `RIFT_PROJECT_CONFIG_SIGNING_PRIVATE_KEY_B64`). This module
//! holds the matching PUBLIC key, baked into the EIF as a
//! constant — so PCR0 covers WHICH public key is trusted, and
//! changing the trusted signer is a deliberate rebuild.
//!
//! On each sign request the parent-proxy may include a
//! `signed_config_json` + `signed_config_signature_b64` bundle
//! sourced from the project's DB row. This module verifies the
//! signature with the baked pubkey and, on success, produces a
//! WebAuthnPolicy tailored to that project. If the bundle is
//! absent OR verification fails, callers fall back to the
//! hardcoded `default_prod()` policy — so Rift's own users are
//! unaffected by this feature's presence or absence.
//!
//! # Wire format
//!
//! `signed_config_json` is the EXACT JSON string that was signed,
//! passed through byte-for-byte. Both sides must agree:
//!
//! ```text
//! {"accepted_audiences":[...],"accepted_origins":[...],"accepted_rp_ids":[...],"accepted_top_origins":[...],"project_id":"...","require_bound_reseal":true,"signed_at":<unix_secs>}
//! ```
//!
//! `accepted_audiences`, `accepted_top_origins` and
//! `require_bound_reseal` are optional (absent ⇒ empty / false), so
//! bundles signed before they existed keep verifying unchanged. When
//! present they must sit at their alphabetical position like every
//! other key.
//!
//! - Keys sorted alphabetically (JS: manually; Rust: BTreeMap→
//!   serde_json produces sorted keys by default).
//! - Arrays in the order the ops team entered them (order matters
//!   for the signature; verifier doesn't re-sort).
//! - No pretty-printing, no whitespace between tokens.
//! - `signed_at` is a Unix timestamp in seconds. Verifier enforces
//!   a max age (currently 90 days) — signatures older than that
//!   are rejected as stale even if cryptographically valid, so a
//!   compromised historical signature can't be replayed forever.
//!
//! Signature: `ed25519_sign(sha256(json_bytes), private_key)`,
//! serialized as STANDARD base64 (same alphabet as everywhere
//! else on our wire format).
//!
//! # Failure posture
//!
//! Every error path returns `Ok(None)` from `resolve_policy`
//! rather than propagating — the caller falls back to the
//! hardcoded policy. Rationale: a badly-signed config or a stale
//! timestamp should NEVER take down signing for a project; worst
//! case we deny per-project overrides and go back to Rift's own
//! accept list. That means a broken deploy of this feature is
//! invisible to Rift's own users, and only blocks per-project
//! customizations — safe default.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::webauthn_verification::WebAuthnPolicy;

/// Public half of the ed25519 signing keypair Rift uses to sign
/// per-project config bundles. Change here + rebuild EIF only when
/// the signing key is rotated (rare, planned event; all currently-
/// signed configs will need re-signing).
///
/// Generated 2026-08-08 for the initial multi-tenant rollout.
///
/// Hex form (for cross-referencing with the backend):
///   356d065531b9a346e0930ae32ab27f41403208d8ed6a6b48f51af9ad874865d6
pub const RIFT_PROJECT_CONFIG_SIGNING_PUBKEY: [u8; 32] = [
    0x35, 0x6d, 0x06, 0x55, 0x31, 0xb9, 0xa3, 0x46,
    0xe0, 0x93, 0x0a, 0xe3, 0x2a, 0xb2, 0x7f, 0x41,
    0x40, 0x32, 0x08, 0xd8, 0xed, 0x6a, 0x6b, 0x48,
    0xf5, 0x1a, 0xf9, 0xad, 0x87, 0x48, 0x65, 0xd6,
];

/// Max age of a signed config before we treat it as stale, in
/// seconds. 90 days — long enough that config rotation is truly
/// intentional (not accidental), short enough that a compromised
/// historical signature can't be replayed indefinitely.
///
/// If a project's config is older than this the verifier returns
/// `Ok(None)` and the caller falls back to the hardcoded policy.
/// Ops action: re-sign the project's config via the backend admin
/// endpoint to reset the timestamp.
const MAX_CONFIG_AGE_SECS: i64 = 90 * 24 * 60 * 60;

/// Deserialised view of the signed JSON payload. Field names + order
/// MUST match the canonical JSON the backend produces (alphabetical
/// key order).
#[derive(Debug, Clone, Deserialize)]
pub struct SignedProjectConfig {
    /// Extra OAuth client_ids (Google/Apple aud values) accepted for
    /// this project on top of the enclave's baked-in default list.
    /// Optional: omitted OR empty means "no per-project OIDC additions",
    /// so any OIDC signing for this project must use one of the baked
    /// audiences (which for a non-Rift partner will always fail).
    /// Backward compat: bundles signed before this field existed just
    /// parse it as empty via #[serde(default)].
    #[serde(default)]
    pub accepted_audiences: Vec<String>,
    pub accepted_origins: Vec<String>,
    pub accepted_rp_ids: Vec<String>,
    /// Top-level origins allowed to embed an accepted origin in an
    /// iframe for a cross-origin WebAuthn ceremony
    /// (`clientDataJSON.crossOrigin == true`). Optional; empty ⇒
    /// cross-origin assertions rejected (the default).
    #[serde(default)]
    pub accepted_top_origins: Vec<String>,
    pub project_id: String,
    /// When true, `/reseal-v3` for this project only accepts consent
    /// proofs over the domain-separated bound challenge (see
    /// `reseal_helpers::bound_reseal_challenge`); legacy proofs over the
    /// raw `prehashed_hex` are refused. Optional; absent ⇒ false.
    #[serde(default)]
    pub require_bound_reseal: bool,
    /// Unix seconds. Verifier enforces MAX_CONFIG_AGE_SECS.
    pub signed_at: i64,
}

/// Bundled per-project policy the caller (vsock_server) hands to
/// verify_auth_proof. Groups the two policies that a project can
/// override in one object so the sign path can either accept them
/// wholesale or fall back to hardcoded defaults, not have to check
/// each subsystem separately.
///
/// Not derived Debug/Clone because WebAuthnPolicy contains &'static
/// slices that make those derives awkward, and neither is needed on
/// the hot path (this struct is built once per sign request and
/// consumed immediately).
pub struct ResolvedProjectPolicy {
    pub webauthn: WebAuthnPolicy,
    /// Additional OIDC audiences merged with the enclave's default
    /// list at verify time. Empty means "no per-project additions".
    pub oidc_audiences: Vec<String>,
    /// Signed opt-in to bound-challenge-only reseal for this project.
    pub require_bound_reseal: bool,
}

/// Verify a signed per-project config and produce a WebAuthnPolicy
/// suitable for that project. Returns `Ok(None)` on any failure —
/// callers fall back to the hardcoded default policy.
///
/// `signed_config_json`: the EXACT bytes that were signed. Do not
///   re-canonicalize — verifier hashes these bytes directly.
/// `signature_b64`: STANDARD base64 ed25519 signature (64 raw bytes).
/// `now_unix_secs`: trusted "now" from the enclave's NSM attestation
///   timestamp (same source OIDC exp checks use). We enforce
///   max-age against THIS time, not any client-supplied value.
/// `expected_project_id`: the project id the caller believes this
///   signing request belongs to. Verifier checks it matches the
///   signed payload — prevents a signature from project A being
///   replayed against project B's request.
///
/// Errors are logged at debug and swallowed to `Ok(None)`. Never
/// panics.
pub fn resolve_policy(
    signed_config_json: &[u8],
    signature_b64: &str,
    now_unix_secs: i64,
    expected_project_id: &str,
) -> Result<Option<ResolvedProjectPolicy>> {
    match verify_and_parse(signed_config_json, signature_b64, now_unix_secs, expected_project_id) {
        Ok(bundle) => Ok(Some(bundle)),
        Err(e) => {
            tracing::debug!(
                error = %e,
                expected_project_id = %expected_project_id,
                "per-project signed config verification failed; falling back to default policy"
            );
            Ok(None)
        }
    }
}

fn verify_and_parse(
    signed_config_json: &[u8],
    signature_b64: &str,
    now_unix_secs: i64,
    expected_project_id: &str,
) -> Result<ResolvedProjectPolicy> {
    verify_and_parse_with_key(
        &RIFT_PROJECT_CONFIG_SIGNING_PUBKEY,
        signed_config_json,
        signature_b64,
        now_unix_secs,
        expected_project_id,
    )
}

/// The real verifier, parameterised on the trusted public key so the
/// unit tests exercise exactly this code (production always passes
/// `RIFT_PROJECT_CONFIG_SIGNING_PUBKEY`).
fn verify_and_parse_with_key(
    pubkey: &[u8; 32],
    signed_config_json: &[u8],
    signature_b64: &str,
    now_unix_secs: i64,
    expected_project_id: &str,
) -> Result<ResolvedProjectPolicy> {
    // 1. Decode signature (STANDARD base64, 64 raw bytes for ed25519).
    let sig_bytes = B64
        .decode(signature_b64.trim())
        .context("decode signature_b64")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be exactly 64 bytes, got {}", sig_bytes.len()))?;
    let sig = Signature::from_bytes(&sig_arr);

    // 2. Verify signature over sha256(json_bytes). Signing target
    //    is the HASH, not the raw JSON — matches what the backend
    //    signer does. Ed25519 itself doesn't require pre-hashing
    //    (it's not RSA-PSS) but doing so keeps the wire format
    //    identical to how we'd verify with other algs later.
    let vk = VerifyingKey::from_bytes(pubkey)
        .context("baked verifier pubkey is invalid — build-time bug")?;
    let hash = Sha256::digest(signed_config_json);
    vk.verify(hash.as_slice(), &sig)
        .context("ed25519 signature verification failed")?;

    // 3. Parse the JSON. Only allowed once the signature is verified —
    //    prevents an attacker from probing with malformed JSON to
    //    exercise parser bugs before hitting the crypto gate.
    let cfg: SignedProjectConfig = serde_json::from_slice(signed_config_json)
        .context("parse signed_config_json (post-verify)")?;

    // 4. Project-id binding: the signature covers a specific project.
    //    Rejecting a config with the wrong project_id prevents replay
    //    across projects (project A's config being applied to project
    //    B's sign request).
    if cfg.project_id != expected_project_id {
        anyhow::bail!(
            "signed config's project_id {:?} does not match expected {:?}",
            cfg.project_id,
            expected_project_id
        );
    }

    // 5. Freshness. Reject signatures older than MAX_CONFIG_AGE_SECS.
    //    Ops rotates by re-signing; a lost signing key can't be
    //    exploited indefinitely via a captured historical config.
    let age = now_unix_secs.saturating_sub(cfg.signed_at);
    if age > MAX_CONFIG_AGE_SECS {
        anyhow::bail!(
            "signed config is stale: age {}s exceeds max {}s (signed_at={}, now={})",
            age,
            MAX_CONFIG_AGE_SECS,
            cfg.signed_at,
            now_unix_secs
        );
    }
    // Also reject configs signed in the far future (clock skew is
    // real; 5-min tolerance is generous but bounded).
    if cfg.signed_at > now_unix_secs + 5 * 60 {
        anyhow::bail!(
            "signed config's signed_at ({}) is in the future vs now ({})",
            cfg.signed_at,
            now_unix_secs
        );
    }

    // 6. Sanity: reject empty accept lists — a policy that accepts
    //    nothing would just silently break the project, better to
    //    fall back to Rift's default (which at least lets us know
    //    what's going on).
    if cfg.accepted_origins.is_empty() || cfg.accepted_rp_ids.is_empty() {
        anyhow::bail!(
            "signed config has empty accepted_origins or accepted_rp_ids — refusing to build an accept-nothing policy"
        );
    }

    // 7. Build the per-project policy bundle. WebAuthn lists become
    //    owned via from_owned (see webauthn_verification::RpList).
    //    OIDC audiences pass through as-is; verify_id_token merges
    //    them with the baked default at verify time.
    Ok(ResolvedProjectPolicy {
        webauthn: WebAuthnPolicy::from_owned(
            cfg.accepted_rp_ids,
            cfg.accepted_origins,
            cfg.accepted_top_origins,
            /* require_user_verified */ true,
        ),
        oidc_audiences: cfg.accepted_audiences,
        require_bound_reseal: cfg.require_bound_reseal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    /// ed25519-dalek is built without its `rand_core` feature (the
    /// enclave only verifies), so build test keys from raw OS entropy.
    fn fresh_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// Build a fresh keypair + set the baked pubkey to match via a
    /// verifier constructed from the fresh key. Avoids depending on
    /// the compiled-in pubkey during tests.
    fn signed_bundle(
        sk: &SigningKey,
        json: &[u8],
    ) -> String {
        let hash = Sha256::digest(json);
        let sig = sk.sign(hash.as_slice());
        B64.encode(sig.to_bytes())
    }

    /// Thin alias so the tests below read naturally; calls the REAL
    /// production verifier with a test key.
    fn verify_with_pubkey(
        pubkey: &[u8; 32],
        signed_config_json: &[u8],
        signature_b64: &str,
        now_unix_secs: i64,
        expected_project_id: &str,
    ) -> Result<ResolvedProjectPolicy> {
        verify_and_parse_with_key(pubkey, signed_config_json, signature_b64, now_unix_secs, expected_project_id)
    }

    #[test]
    fn valid_signature_produces_policy() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = format!(
            r#"{{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":{}}}"#,
            now - 60
        );
        let sig = signed_bundle(&sk, json.as_bytes());
        let bundle = verify_with_pubkey(&pubkey, json.as_bytes(), &sig, now, "proj-1").unwrap();
        assert_eq!(bundle.webauthn.owned_origins().unwrap(), &["https://app.acme.com"]);
        assert_eq!(bundle.webauthn.owned_rp_ids().unwrap(), &["acme.com"]);
        // Old-format JSON has no accepted_audiences → parses as empty.
        assert!(bundle.oidc_audiences.is_empty());
    }

    #[test]
    fn forged_signature_rejected() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = br#"{"accepted_origins":["https://evil.com"],"accepted_rp_ids":["evil.com"],"project_id":"proj-1","signed_at":1723456729}"#;
        // Signature over DIFFERENT bytes than what we pass to verifier
        let sig = signed_bundle(&sk, b"different bytes");
        let err = verify_with_pubkey(&pubkey, json, &sig, now, "proj-1").err().expect("verification must fail");
        assert!(format!("{err:#}").contains("signature verification failed"), "{err:#}");
    }

    #[test]
    fn wrong_project_id_rejected() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = br#"{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-A","signed_at":1723456729}"#;
        let sig = signed_bundle(&sk, json);
        // Request context claims proj-B but signed config is for proj-A
        let err = verify_with_pubkey(&pubkey, json, &sig, now, "proj-B").err().expect("verification must fail");
        assert!(err.to_string().contains("project_id"), "{err}");
    }

    #[test]
    fn stale_config_rejected() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 2_000_000_000;
        // Signed 100 days ago
        let signed_at = now - 100 * 24 * 60 * 60;
        let json = format!(
            r#"{{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":{}}}"#,
            signed_at
        );
        let sig = signed_bundle(&sk, json.as_bytes());
        let err = verify_with_pubkey(&pubkey, json.as_bytes(), &sig, now, "proj-1").err().expect("verification must fail");
        assert!(err.to_string().contains("stale"), "{err}");
    }

    #[test]
    fn empty_lists_rejected() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = br#"{"accepted_origins":[],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":1723456729}"#;
        let sig = signed_bundle(&sk, json);
        let err = verify_with_pubkey(&pubkey, json, &sig, now, "proj-1").err().expect("verification must fail");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn future_signed_at_rejected() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = format!(
            r#"{{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":{}}}"#,
            now + 3600
        );
        let sig = signed_bundle(&sk, json.as_bytes());
        let err = verify_with_pubkey(&pubkey, json.as_bytes(), &sig, now, "proj-1").err().expect("must fail");
        assert!(err.to_string().contains("future"), "{err}");
    }

    #[test]
    fn baked_key_rejects_bundle_signed_by_other_key() {
        // The production entry point (baked pubkey) must refuse a bundle
        // signed by any other key and degrade to None.
        let sk = fresh_signing_key();
        let now: i64 = 1_723_456_789;
        let json = br#"{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":1723456729}"#;
        let sig = signed_bundle(&sk, json);
        assert!(resolve_policy(json, &sig, now, "proj-1").unwrap().is_none());
    }

    #[test]
    fn optional_fields_parse() {
        let sk = fresh_signing_key();
        let pubkey = sk.verifying_key().to_bytes();
        let now: i64 = 1_723_456_789;
        let json = br#"{"accepted_audiences":["aud-1"],"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"accepted_top_origins":["https://shop.acme.com"],"project_id":"proj-1","require_bound_reseal":true,"signed_at":1723456729}"#;
        let sig = signed_bundle(&sk, json);
        let p = verify_with_pubkey(&pubkey, json, &sig, now, "proj-1").unwrap();
        assert!(p.require_bound_reseal);
        assert_eq!(p.oidc_audiences, vec!["aud-1".to_string()]);
        assert!(p.webauthn.accepted_top_origins.iter().any(|o| o == "https://shop.acme.com"));

        // Absent ⇒ false / empty.
        let json = br#"{"accepted_origins":["https://app.acme.com"],"accepted_rp_ids":["acme.com"],"project_id":"proj-1","signed_at":1723456729}"#;
        let sig = signed_bundle(&sk, json);
        let p = verify_with_pubkey(&pubkey, json, &sig, now, "proj-1").unwrap();
        assert!(!p.require_bound_reseal);
        assert_eq!(p.webauthn.accepted_top_origins.iter().count(), 0);
    }
}
