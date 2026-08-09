//! OIDC id_token verification, performed entirely inside the enclave.
//!
//! Threat model: a backend engineer with code-deploy access could
//! otherwise forge "this Google user authorized signing" claims and
//! drain user funds. v3 closes that hole by requiring the enclave to
//! verify a real, fresh id_token from Google or Apple before signing.
//!
//! How we do it inside an enclave with no network:
//!
//!   - JWKS keys are PINNED at EIF build time (see `pinned_jwks.rs`).
//!     Google rotates ~weekly; rebuild + redeploy on that cadence.
//!     The enclave PCR0 covers the pinned bytes, so the KMS policy
//!     keeps the trust chain honest: a tampered JWKS = different
//!     PCR0 = KMS refuses to release the DEK.
//!
//!   - Replay protection by `nonce`. The client must request an OIDC
//!     token with `nonce=<user_op_hash>`. The IdP signs that nonce into
//!     the JWT. The enclave checks the JWT's `nonce` claim equals the
//!     prehash being signed, so a token issued for transaction A
//!     cannot authorize transaction B.
//!
//!   - Clock comes from the Nitro attestation document timestamp, not
//!     from a system call. The enclave has no NTP. Attestation
//!     timestamps are signed by AWS, so they're trustworthy.
//!
//! Supported algorithms:
//!   - RS256 (Google) — RSA-PKCS1-v1.5 SHA-256 over `header.payload`
//!   - ES256 (Apple)  — ECDSA P-256 SHA-256 over `header.payload`
//!
//! Anything else (RS384, RS512, ES384, EdDSA, HS*) is rejected. HS*
//! would be catastrophic — a symmetric secret check is meaningless for
//! a third-party IdP.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use rsa::pkcs1v15::{Signature as RsaPkcs1Sig, VerifyingKey as RsaVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use sha2::Sha256;

/// One JWK entry. We accept both RSA and EC P-256 keys.
///
/// All byte fields are base64url-no-pad (the JWK wire format from
/// Google / Apple). When we ship this into the EIF as pinned bytes we
/// keep the same shape so updates are a one-line diff.
#[derive(Clone, Debug, Deserialize)]
pub struct PinnedJwk {
    pub kid: String,
    pub kty: String, // "RSA" | "EC"
    pub alg: String, // "RS256" | "ES256"
    pub iss: String, // "https://accounts.google.com" | "https://appleid.apple.com"

    // RSA keys.
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,

    // EC keys (P-256).
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// The set of issuers and audiences the enclave will accept. These are
/// PINNED — a backend engineer cannot widen the accept list without
/// rebuilding the EIF and triggering a KMS policy update.
pub struct OidcTrustPolicy {
    /// Issuers we accept. e.g. ["https://accounts.google.com",
    /// "https://appleid.apple.com"].
    pub accepted_issuers: &'static [&'static str],

    /// The audience (OAuth client ID) we require. Pinned per-deployment
    /// — sandbox and prod each have one, baked into the EIF.
    pub accepted_audiences: &'static [&'static str],

    /// Maximum age of an id_token, in seconds, measured from the JWT's
    /// `iat` to the attestation document timestamp. Typical bound: 600s
    /// (10 minutes). We keep it tight because every transaction needs
    /// a freshly-minted token anyway.
    pub max_iat_skew_secs: i64,
}

impl OidcTrustPolicy {
    /// Default sandbox policy. Update if you add an IdP, rotate a
    /// client ID, or add a platform — every change rebuilds the EIF
    /// and the PCR0, so the KMS policy condition will need to be
    /// updated alongside.
    ///
    /// Sandbox values (2026-06-30). Production deploy will add a
    /// separate `default_prod()` variant or patch in place.
    pub fn default_prod() -> Self {
        Self {
            accepted_issuers: &[
                "https://accounts.google.com",
                "https://appleid.apple.com",
            ],
            accepted_audiences: &[
                // Rift Sandbox Web (Google OAuth, configured 2026-06-30).
                // Covers http://localhost:3000, https://sandbox.riftfi.xyz,
                // https://sandbox.riftfi.com origins.
                "875173959914-fuvg3763feb4adcii6g2m2kc0g2scups.apps.googleusercontent.com",
                // Apple Service ID — TODO once Apple Sign In is set up.
                // Leaving the placeholder here means Apple id_tokens are
                // rejected at the aud check; Google works fine.
                "com.riftfi.app",
            ],
            max_iat_skew_secs: 600,
        }
    }
}

/// JWT header and the subset of payload claims we need to verify.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    aud: serde_json::Value, // string or array per RFC 7519
    sub: String,
    /// Issued-at, seconds since epoch.
    iat: i64,
    /// Expiry, seconds since epoch.
    exp: i64,
    /// REQUIRED by Rift — the user op hash bound into this token.
    nonce: String,
}

/// Result of a successful verification. The enclave uses (iss, sub) to
/// look up the stored auth method in the envelope payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidc {
    pub iss: String,
    pub sub: String,
    pub aud: String,
}

/// Verify an id_token end-to-end. Returns the (iss, sub) on success so
/// the caller can match it against the envelope's stored auth method.
///
/// `now_unix_secs` should be the timestamp from the most recent
/// Nitro attestation document — that's a trusted clock source. Using
/// the host's wall clock would defeat the purpose since the host is
/// untrusted.
// `extra_audiences` (added below): additional aud values accepted for
// this call, sourced from a verified per-project signed config bundle
// at the caller. Empty slice means "no per-project additions"; the aud
// must then match the baked default. Kept as a separate parameter
// (rather than mutating `policy`) so the `OidcTrustPolicy` struct stays
// `&'static` and the compile-time-pinned default is unmoved. Order
// doesn't matter — this is a set-membership check.
pub fn verify_id_token(
    id_token: &str,
    expected_nonce_hex: &str,
    now_unix_secs: i64,
    jwks: &[PinnedJwk],
    policy: &OidcTrustPolicy,
    extra_audiences: &[String],
) -> Result<VerifiedOidc> {
    // ─── 1. Parse JWT structure ──────────────────────────────────────
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        bail!("malformed id_token: expected 3 dot-separated segments, got {}", parts.len());
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = B64URL.decode(header_b64).context("base64url-decode JWT header")?;
    let payload_bytes = B64URL.decode(payload_b64).context("base64url-decode JWT payload")?;
    let signature = B64URL.decode(sig_b64).context("base64url-decode JWT signature")?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes).context("parse JWT header JSON")?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes).context("parse JWT payload JSON")?;

    // ─── 2. Algorithm whitelist ──────────────────────────────────────
    // Refuse anything outside the two algorithms we trust.
    if header.alg != "RS256" && header.alg != "ES256" {
        bail!("rejecting JWT with unsupported algorithm {}", header.alg);
    }
    if header.alg == "HS256" || header.alg == "none" {
        // Belt-and-braces — these would already have failed the check
        // above but it's worth being explicit since they're the famous
        // JWT footguns.
        bail!("symmetric / unsigned JWTs are never accepted");
    }

    // ─── 3. Look up the JWK by (iss, kid) ────────────────────────────
    // We require the iss claim to be in our accept list AND the JWK to
    // be marked for that same issuer. Mixing keys across IdPs is a
    // confused-deputy vector if we don't.
    if !policy.accepted_issuers.contains(&claims.iss.as_str()) {
        bail!("issuer {} is not in the pinned accept list", claims.iss);
    }
    let jwk = jwks
        .iter()
        .find(|k| k.kid == header.kid && k.iss == claims.iss && k.alg == header.alg)
        .ok_or_else(|| {
            anyhow!(
                "no pinned JWK matches (iss={}, kid={}, alg={}). Rebuild EIF with refreshed JWKS.",
                claims.iss,
                header.kid,
                header.alg
            )
        })?;

    // ─── 4. Verify the signature ─────────────────────────────────────
    let signing_input = format!("{header_b64}.{payload_b64}");
    match header.alg.as_str() {
        "RS256" => verify_rs256(jwk, signing_input.as_bytes(), &signature)?,
        "ES256" => verify_es256(jwk, signing_input.as_bytes(), &signature)?,
        _ => unreachable!("alg whitelist enforced above"),
    }

    // ─── 5. Verify the claims ────────────────────────────────────────
    // 5a. aud — must be in the baked default list OR the per-project
    // extras list. Helper closure keeps both membership checks in one
    // place so the array-branch and single-string branch stay in sync.
    let is_accepted_aud = |s: &str| -> bool {
        policy.accepted_audiences.contains(&s)
            || extra_audiences.iter().any(|e| e == s)
    };
    let aud_str = match &claims.aud {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            // RFC 7519 allows arrays. We require at least one element
            // is in our accept list AND we return that element so the
            // caller knows which client ID succeeded.
            let mut matched: Option<String> = None;
            for v in arr {
                if let Some(s) = v.as_str() {
                    if is_accepted_aud(s) {
                        matched = Some(s.to_string());
                        break;
                    }
                }
            }
            matched.ok_or_else(|| anyhow!("none of the aud array entries are in the accept list"))?
        }
        _ => bail!("aud claim has unexpected type"),
    };
    if !is_accepted_aud(&aud_str) {
        bail!("aud {} is not in the pinned accept list", aud_str);
    }

    // 5b. exp — must be in the future relative to attestation time.
    if claims.exp <= now_unix_secs {
        bail!(
            "id_token expired: exp={} but attestation time is {}",
            claims.exp,
            now_unix_secs
        );
    }
    // 5c. iat — must be reasonably recent. A token from 7 days ago
    // can be signed by a key still in the JWKS, but we don't want it.
    let age = now_unix_secs.saturating_sub(claims.iat);
    if age > policy.max_iat_skew_secs {
        bail!(
            "id_token too old: iat={} attestation_time={} age={}s > max_skew={}s",
            claims.iat,
            now_unix_secs,
            age,
            policy.max_iat_skew_secs
        );
    }

    // 5d. nonce — MUST equal the user op hash (normalized). This is the
    // anti-replay invariant. Without this, a stolen id_token from a
    // legitimate login could authorize any transaction within the
    // token's lifetime.
    let expected = expected_nonce_hex.trim_start_matches("0x").to_lowercase();
    let actual = claims.nonce.trim_start_matches("0x").to_lowercase();
    if expected != actual {
        bail!("nonce binding failed: token nonce does not equal the prehash being signed");
    }

    Ok(VerifiedOidc {
        iss: claims.iss,
        sub: claims.sub,
        aud: aud_str,
    })
}

fn verify_rs256(jwk: &PinnedJwk, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    if jwk.kty != "RSA" {
        bail!("kty {} cannot verify RS256", jwk.kty);
    }
    let n_b64 = jwk.n.as_deref().context("JWK missing 'n'")?;
    let e_b64 = jwk.e.as_deref().context("JWK missing 'e'")?;
    let n = BigUint::from_bytes_be(&B64URL.decode(n_b64).context("decode JWK n")?);
    let e = BigUint::from_bytes_be(&B64URL.decode(e_b64).context("decode JWK e")?);
    let pub_key = RsaPublicKey::new(n, e).context("construct RSA public key from JWK")?;
    let verifying_key = RsaVerifyingKey::<Sha256>::new(pub_key);
    let sig = RsaPkcs1Sig::try_from(signature).context("parse RS256 signature")?;
    verifying_key
        .verify(signing_input, &sig)
        .context("RS256 signature verification failed")?;
    Ok(())
}

fn verify_es256(jwk: &PinnedJwk, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature as P256Sig, VerifyingKey as P256Vk};
    use p256::EncodedPoint;

    if jwk.kty != "EC" {
        bail!("kty {} cannot verify ES256", jwk.kty);
    }
    if jwk.crv.as_deref() != Some("P-256") {
        bail!("unsupported EC curve for ES256");
    }
    let x = B64URL.decode(jwk.x.as_deref().context("JWK missing 'x'")?)
        .context("decode JWK x")?;
    let y = B64URL.decode(jwk.y.as_deref().context("JWK missing 'y'")?)
        .context("decode JWK y")?;
    if x.len() != 32 || y.len() != 32 {
        bail!("P-256 JWK coordinates must be 32 bytes each");
    }
    let point = EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    let verifying_key = P256Vk::from_encoded_point(&point)
        .map_err(|e| anyhow!("construct P-256 verifying key: {e}"))?;

    // ES256 over the wire is the raw r||s concatenation (64 bytes), not
    // the ASN.1 DER form used by OpenSSL. JWA RFC 7518 §3.4 mandates this.
    if signature.len() != 64 {
        bail!("ES256 signature must be 64 raw bytes, got {}", signature.len());
    }
    let sig = P256Sig::from_slice(signature).map_err(|e| anyhow!("parse ES256 signature: {e}"))?;
    verifying_key
        .verify(signing_input, &sig)
        .map_err(|e| anyhow!("ES256 signature verification failed: {e}"))?;
    Ok(())
}

#[allow(dead_code)]
fn b64_for_test(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as URL_B64;
    use p256::ecdsa::{signature::Signer, Signature as P256Sig, SigningKey as P256Sk};
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::signature::Keypair as _;
    use rsa::signature::RandomizedSigner;
    use rsa::traits::PublicKeyParts;

    fn b64u(bytes: &[u8]) -> String {
        URL_B64.encode(bytes)
    }

    fn make_rsa_jwt_and_jwk(
        kid: &str,
        iss: &str,
        aud: &str,
        sub: &str,
        nonce: &str,
        iat: i64,
        exp: i64,
    ) -> (String, PinnedJwk) {
        let mut rng = rand::thread_rng();
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let n_be = pub_key.n().to_bytes_be();
        let e_be = pub_key.e().to_bytes_be();

        let header = serde_json::json!({"alg":"RS256","kid":kid,"typ":"JWT"});
        let claims = serde_json::json!({
            "iss":iss,"aud":aud,"sub":sub,"iat":iat,"exp":exp,"nonce":nonce
        });
        let header_b64 = b64u(serde_json::to_vec(&header).unwrap().as_slice());
        let payload_b64 = b64u(serde_json::to_vec(&claims).unwrap().as_slice());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signing_key = RsaSigningKey::<Sha256>::new(priv_key);
        let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
        let sig_bytes: Box<[u8]> = signature.into();
        let sig_b64 = b64u(&sig_bytes);
        let jwt = format!("{signing_input}.{sig_b64}");

        let jwk = PinnedJwk {
            kid: kid.to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: iss.to_string(),
            n: Some(b64u(&n_be)),
            e: Some(b64u(&e_be)),
            crv: None,
            x: None,
            y: None,
        };
        let _ = signing_key.verifying_key(); // keep crate referenced
        (jwt, jwk)
    }

    fn make_es256_jwt_and_jwk(
        kid: &str,
        iss: &str,
        aud: &str,
        sub: &str,
        nonce: &str,
        iat: i64,
        exp: i64,
    ) -> (String, PinnedJwk) {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();

        let header = serde_json::json!({"alg":"ES256","kid":kid,"typ":"JWT"});
        let claims = serde_json::json!({
            "iss":iss,"aud":aud,"sub":sub,"iat":iat,"exp":exp,"nonce":nonce
        });
        let header_b64 = b64u(serde_json::to_vec(&header).unwrap().as_slice());
        let payload_b64 = b64u(serde_json::to_vec(&claims).unwrap().as_slice());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: P256Sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = b64u(&sig.to_bytes());
        let jwt = format!("{signing_input}.{sig_b64}");

        let jwk = PinnedJwk {
            kid: kid.to_string(),
            kty: "EC".to_string(),
            alg: "ES256".to_string(),
            iss: iss.to_string(),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(b64u(&x)),
            y: Some(b64u(&y)),
        };
        (jwt, jwk)
    }

    fn test_policy() -> OidcTrustPolicy {
        OidcTrustPolicy {
            accepted_issuers: &[
                "https://accounts.google.com",
                "https://appleid.apple.com",
            ],
            accepted_audiences: &["test-client-id.apps.googleusercontent.com", "com.test.app"],
            max_iat_skew_secs: 600,
        }
    }

    #[test]
    fn rs256_happy_path() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://accounts.google.com",
            "test-client-id.apps.googleusercontent.com",
            "user-google-123",
            "0xdeadbeef",
            now - 10,
            now + 600,
        );
        let verified = verify_id_token(&jwt, "0xdeadbeef", now, &[jwk], &test_policy(), &[]).unwrap();
        assert_eq!(verified.iss, "https://accounts.google.com");
        assert_eq!(verified.sub, "user-google-123");
    }

    #[test]
    fn es256_happy_path() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_es256_jwt_and_jwk(
            "apple-k1",
            "https://appleid.apple.com",
            "com.test.app",
            "user.apple.456",
            "0xfeedface",
            now - 5,
            now + 300,
        );
        let verified = verify_id_token(&jwt, "0xfeedface", now, &[jwk], &test_policy(), &[]).unwrap();
        assert_eq!(verified.iss, "https://appleid.apple.com");
        assert_eq!(verified.sub, "user.apple.456");
    }

    #[test]
    fn rejects_wrong_nonce() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://accounts.google.com",
            "test-client-id.apps.googleusercontent.com",
            "sub",
            "0xaaaa",
            now,
            now + 60,
        );
        let err = verify_id_token(&jwt, "0xbbbb", now, &[jwk], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err:#}");
    }

    #[test]
    fn rejects_expired_token() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://accounts.google.com",
            "test-client-id.apps.googleusercontent.com",
            "sub",
            "0xa",
            now - 1000,
            now - 1, // already expired
        );
        let err = verify_id_token(&jwt, "0xa", now, &[jwk], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err:#}");
    }

    #[test]
    fn rejects_unknown_kid() {
        let now = 1_700_000_000;
        let (jwt, mut jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://accounts.google.com",
            "test-client-id.apps.googleusercontent.com",
            "sub",
            "0xa",
            now,
            now + 60,
        );
        jwk.kid = "different-kid".into();
        let err = verify_id_token(&jwt, "0xa", now, &[jwk], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("no pinned JWK"), "{err:#}");
    }

    #[test]
    fn rejects_unknown_issuer() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://evil.example.com", // not in accept list
            "test-client-id.apps.googleusercontent.com",
            "sub",
            "0xa",
            now,
            now + 60,
        );
        let err = verify_id_token(&jwt, "0xa", now, &[jwk], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("issuer"), "{err:#}");
    }

    #[test]
    fn rejects_wrong_audience() {
        let now = 1_700_000_000;
        let (jwt, jwk) = make_rsa_jwt_and_jwk(
            "k1",
            "https://accounts.google.com",
            "stolen-app.apps.googleusercontent.com",
            "sub",
            "0xa",
            now,
            now + 60,
        );
        let err = verify_id_token(&jwt, "0xa", now, &[jwk], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("aud"), "{err:#}");
    }

    #[test]
    fn rejects_hs256() {
        // Hand-craft an HS256 JWT — these are the classic JWT
        // confusion attack: if a server accepts an algorithm specified
        // by the attacker, a symmetric key gets misused as a public
        // key. We must always reject.
        let header = serde_json::json!({"alg":"HS256","kid":"k1","typ":"JWT"});
        let claims = serde_json::json!({
            "iss":"https://accounts.google.com",
            "aud":"test-client-id.apps.googleusercontent.com",
            "sub":"sub","iat":1,"exp":9999999999i64,"nonce":"0xa"
        });
        let header_b64 = b64u(serde_json::to_vec(&header).unwrap().as_slice());
        let payload_b64 = b64u(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{header_b64}.{payload_b64}.AAAA");
        let err = verify_id_token(&jwt, "0xa", 100, &[], &test_policy(), &[]).unwrap_err();
        assert!(err.to_string().contains("unsupported algorithm"), "{err:#}");
    }
}
