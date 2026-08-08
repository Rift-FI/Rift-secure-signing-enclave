//! WebAuthn assertion verification, performed entirely inside the
//! enclave so the host has no opportunity to spoof "user pressed
//! their Touch ID button" to a backend engineer who controls deploys.
//!
//! Scope: assertions from `navigator.credentials.get()` — i.e.
//! signing flows. Enrolment (`create()`) is handled at the backend
//! layer because the only secret we need to extract is the public key
//! and that has no special handling requirements.
//!
//! What we verify (W3C WebAuthn Level 2, §7.2 Step 7+):
//!
//!   1. clientDataJSON.type == "webauthn.get"
//!   2. clientDataJSON.challenge (base64url) == the user op hash we
//!      are about to sign. THIS IS THE BINDING — without this every
//!      assertion is replayable across transactions.
//!   3. clientDataJSON.origin matches the pinned RP origin.
//!   4. authenticatorData.rpIdHash == SHA256(rp_id). Cross-RP
//!      assertions would otherwise be valid.
//!   5. authenticatorData.flags.UP (user present) is set.
//!   6. ECDSA P-256 signature verifies over
//!      authenticatorData || SHA256(clientDataJSON), using the COSE
//!      public key stored in the v3 envelope.
//!
//! Algorithms supported in this first cut: ES256 (COSE alg -7).
//! That covers iOS, Android (Google Password Manager), Windows Hello,
//! and every YubiKey shipped in the last 5+ years. We can add Ed25519
//! (alg -8) and RS256 (-257) later for legacy Windows Hello stacks.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use ciborium::value::Value as CborValue;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Pinned policy describing what counts as a valid assertion. Baked
/// into the EIF.
///
/// We accept MULTIPLE RP-IDs because the .xyz and .com sandboxes are
/// different registrable domains in the WebAuthn sense — a passkey
/// enrolled for `riftfi.xyz` cannot be used on `riftfi.com` and vice
/// versa. Each user enrols separately per domain they want to use.
/// `localhost` is its own RP-ID for local dev.
///
/// At verify time the enclave checks the assertion's `rpIdHash` matches
/// SHA256 of ANY of `accepted_rp_ids`. Origins are checked against
/// `accepted_origins`. Both lists must be set together.
pub struct WebAuthnPolicy {
    /// Allowed RP-IDs. Typically the eTLD+1 of each app origin.
    /// Examples: "riftfi.xyz", "riftfi.com", "localhost".
    ///
    /// Storage indirection (`Cow`) so we can carry EITHER the
    /// compiled-in `&'static [&'static str]` (default_prod path,
    /// zero allocation) OR a runtime-owned `Vec<String>` from a
    /// signed per-project config (see `project_config.rs`). Verify
    /// code just iterates &str either way.
    pub accepted_rp_ids: RpList,

    /// Allowed origins from clientDataJSON. Must include every origin
    /// the frontend SDK might call `navigator.credentials.get()` from.
    /// Same Cow trick as `accepted_rp_ids`.
    pub accepted_origins: RpList,

    /// If true, also require the UV (user verified) flag — meaning the
    /// authenticator confirmed presence + identity (biometric or PIN),
    /// not just touch. Most modern platforms always set UV; setting
    /// this to true gives a stronger guarantee.
    pub require_user_verified: bool,
}

/// Either a compile-time slice (default policy path) or an
/// owned Vec built from a signed per-project config. The verify
/// code just needs to iterate `&str`, so we abstract the source.
///
/// Not using `std::borrow::Cow<'static, [&'static str]>` because
/// that would require the runtime path to also carry `&'static str`
/// references, which we don't have from a runtime-parsed JSON.
/// This concrete two-variant enum is smaller + clearer.
pub enum RpList {
    Static(&'static [&'static str]),
    Owned(Vec<String>),
}

impl RpList {
    /// Iterate the list as `&str` regardless of storage. Verify
    /// code uses this to match rp_ids / origins.
    pub fn iter(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            RpList::Static(s) => Box::new(s.iter().copied()),
            RpList::Owned(v) => Box::new(v.iter().map(|s| s.as_str())),
        }
    }
}

impl WebAuthnPolicy {
    /// Sandbox policy. RP-IDs cover the .xyz + .com eTLD+1s + localhost
    /// for dev; origins enumerate every deployed frontend host we
    /// actually receive WebAuthn assertions from. Update + rebuild EIF
    /// when domains change — this list is compiled into the enclave
    /// image, no runtime override.
    ///
    /// Passkey assertions from any origin NOT in this list are rejected
    /// with "origin ... not in the pinned accept list" — a common cause
    /// of "consent factor missing/wrong" after a new frontend hostname
    /// is provisioned. If you see that, add the host here and rebuild.
    pub fn default_prod() -> Self {
        Self {
            accepted_rp_ids: RpList::Static(&[
                "riftfi.xyz",
                "riftfi.com",
                "localhost",
            ]),
            accepted_origins: RpList::Static(&[
                // Non-custodial sandbox — wallet + widget domains.
                "https://wallet.sandbox.riftfi.com",
                "https://widget.sandbox.riftfi.com",
                // Prod wallet hosts (pre-added so the sandbox → prod
                // promotion doesn't need another EIF rebuild + KMS
                // reattestation cycle just for origin plumbing).
                "https://wallet.riftfi.com",
                "https://wallet.riftfi.xyz",
                // Legacy sandbox landing hosts.
                "https://sandbox.riftfi.xyz",
                "https://sandbox.riftfi.com",
                // Prod-shape hostnames (referenced by tests / older
                // deployments — keep to avoid regressions once the
                // v3 sandbox promotes to prod).
                "https://app.riftfi.xyz",
                "https://app.riftfi.com",
                "https://dashboard.riftfi.xyz",
                "http://localhost:3000",
            ]),
            require_user_verified: true,
        }
    }

    /// Build a policy from runtime-owned string lists — used by
    /// `project_config::resolve_policy` when the caller provides a
    /// signed per-project accept-list bundle.
    ///
    /// Empty lists are permitted here (constructor doesn't validate);
    /// verification-time checks will fail closed if any list is empty
    /// (rp_id / origin match against an empty list returns false).
    /// Upstream (`project_config`) already rejects empty lists before
    /// reaching this constructor, so this path just wraps.
    pub fn from_owned(
        accepted_rp_ids: Vec<String>,
        accepted_origins: Vec<String>,
        require_user_verified: bool,
    ) -> Self {
        Self {
            accepted_rp_ids: RpList::Owned(accepted_rp_ids),
            accepted_origins: RpList::Owned(accepted_origins),
            require_user_verified,
        }
    }

    /// Test-only helper: extract the owned lists for round-trip
    /// assertions. Returns None if this policy is a Static (default)
    /// variant.
    #[cfg(test)]
    pub fn owned_origins(&self) -> Option<&[String]> {
        match &self.accepted_origins {
            RpList::Owned(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn owned_rp_ids(&self) -> Option<&[String]> {
        match &self.accepted_rp_ids {
            RpList::Owned(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

/// COSE_Key encoding of a P-256 ECDSA public key. The wire form of
/// stored credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseP256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl CoseP256PublicKey {
    /// Parse a COSE_Key from its CBOR encoding (the form `getPublicKey()`
    /// in browser-side WebAuthn returns when you call .toJSON() on
    /// the credential, or the raw bytes from
    /// `attestationObject.authData.attestedCredentialData.credentialPublicKey`).
    pub fn from_cose_cbor(cbor: &[u8]) -> Result<Self> {
        let value: CborValue = ciborium::de::from_reader(cbor)
            .map_err(|e| anyhow!("decode COSE_Key CBOR: {e}"))?;
        let map = value
            .as_map()
            .ok_or_else(|| anyhow!("COSE_Key must be a CBOR map"))?;

        // COSE_Key labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y.
        let mut kty: Option<i64> = None;
        let mut alg: Option<i64> = None;
        let mut crv: Option<i64> = None;
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;

        for (k, v) in map {
            let key = k.as_integer().and_then(|i| i64::try_from(i).ok());
            match (key, v) {
                (Some(1), CborValue::Integer(i)) => kty = i64::try_from(*i).ok(),
                (Some(3), CborValue::Integer(i)) => alg = i64::try_from(*i).ok(),
                (Some(-1), CborValue::Integer(i)) => crv = i64::try_from(*i).ok(),
                (Some(-2), CborValue::Bytes(b)) => x = Some(b.clone()),
                (Some(-3), CborValue::Bytes(b)) => y = Some(b.clone()),
                _ => {}
            }
        }

        if kty != Some(2) {
            bail!("only kty=EC2 (2) supported, got {:?}", kty);
        }
        if alg != Some(-7) {
            bail!("only alg=ES256 (-7) supported in this enclave build, got {:?}", alg);
        }
        if crv != Some(1) {
            bail!("only crv=P-256 (1) supported, got {:?}", crv);
        }
        let x = x.ok_or_else(|| anyhow!("COSE_Key missing x coordinate"))?;
        let y = y.ok_or_else(|| anyhow!("COSE_Key missing y coordinate"))?;
        if x.len() != 32 || y.len() != 32 {
            bail!(
                "P-256 coordinates must be 32 bytes each, got x={} y={}",
                x.len(),
                y.len()
            );
        }
        let mut x_arr = [0u8; 32];
        let mut y_arr = [0u8; 32];
        x_arr.copy_from_slice(&x);
        y_arr.copy_from_slice(&y);
        Ok(Self { x: x_arr, y: y_arr })
    }
}

/// Parsed clientDataJSON. Required fields per W3C WebAuthn §5.8.1.
#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String, // base64url-no-pad
    origin: String,
}

/// Bit positions of the flags byte inside authenticatorData.
const FLAG_USER_PRESENT: u8 = 1 << 0;
const FLAG_USER_VERIFIED: u8 = 1 << 2;

/// Verify a WebAuthn assertion bound to a specific user op hash. On
/// success the caller can be sure the user actually consented to
/// signing THIS transaction.
///
/// Arguments:
///  - `cose_pubkey`: the stored credential public key from the v3 envelope
///  - `client_data_json`: the raw bytes of clientDataJSON
///    (NOT a parsed string — the SHA256 must be over the bytes-on-the-wire)
///  - `authenticator_data`: raw bytes of authenticatorData
///  - `signature`: ECDSA signature, DER-encoded (the form passed by
///    `assertion.response.signature` to backends; standard browsers always
///    send this).
///  - `expected_challenge`: the user op hash to be signed (raw 32 bytes
///    — we base64url-encode and compare to clientDataJSON.challenge)
///  - `policy`: the pinned trust policy.
pub fn verify_assertion(
    cose_pubkey: &CoseP256PublicKey,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature_der: &[u8],
    expected_challenge: &[u8; 32],
    policy: &WebAuthnPolicy,
) -> Result<()> {
    // ─── 1. Parse + check clientDataJSON ────────────────────────────
    let cd: ClientData = serde_json::from_slice(client_data_json)
        .context("parse clientDataJSON")?;

    if cd.type_ != "webauthn.get" {
        bail!("clientDataJSON.type must be webauthn.get, got {}", cd.type_);
    }

    // Challenge MUST equal SHA-of-user-op-hash, base64url-no-pad
    // encoded. (Some clients pad with =. We trim before comparing so
    // browsers that disagree about padding still verify.)
    let cd_challenge_clean = cd.challenge.trim_end_matches('=');
    let expected_b64 = B64URL.encode(expected_challenge);
    if cd_challenge_clean != expected_b64 {
        bail!(
            "challenge binding failed: clientDataJSON.challenge does not equal the prehash being signed"
        );
    }

    // RpList::iter() gives us &str regardless of Static vs Owned
    // storage. cd.origin is a String owned by the parsed ClientData.
    if !policy.accepted_origins.iter().any(|o| o == cd.origin.as_str()) {
        bail!("origin {} is not in the pinned accept list", cd.origin);
    }

    // ─── 2. Check authenticatorData ─────────────────────────────────
    // Layout: rpIdHash(32) || flags(1) || signCount(4) || [attestedCredData] || [extensions]
    if authenticator_data.len() < 37 {
        bail!(
            "authenticatorData too short: {} bytes (need 37)",
            authenticator_data.len()
        );
    }
    let rp_id_hash = &authenticator_data[..32];
    let flags = authenticator_data[32];

    // Accept the assertion if its rpIdHash matches SHA256 of ANY of
    // the pinned RP-IDs. Cross-RP credentials remain isolated (a
    // credential created for riftfi.xyz still produces an rpIdHash
    // tied to that RP — it just gets accepted here because xyz is on
    // our allowed list).
    let matched_rp = policy.accepted_rp_ids.iter().any(|rp| {
        let h = Sha256::digest(rp.as_bytes());
        rp_id_hash == h.as_slice()
    });
    // (RpList::iter yields &str for both Static + Owned variants,
    // so `rp` is &str above and `.as_bytes()` works uniformly.)
    if !matched_rp {
        bail!("rpIdHash mismatch — assertion was signed for a different RP");
    }

    if flags & FLAG_USER_PRESENT == 0 {
        bail!("user-present (UP) flag not set");
    }
    if policy.require_user_verified && flags & FLAG_USER_VERIFIED == 0 {
        bail!("user-verified (UV) flag required but not set");
    }

    // ─── 3. Verify the ECDSA signature ──────────────────────────────
    // WebAuthn signs (authenticatorData || SHA256(clientDataJSON)).
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));

    use p256::ecdsa::{signature::Verifier, Signature as P256Sig, VerifyingKey as P256Vk};
    use p256::EncodedPoint;

    let point = EncodedPoint::from_affine_coordinates(
        (&cose_pubkey.x).into(),
        (&cose_pubkey.y).into(),
        false,
    );
    let vk = P256Vk::from_encoded_point(&point)
        .map_err(|e| anyhow!("construct P-256 VK from stored COSE key: {e}"))?;
    // Browsers send the DER-encoded signature. p256 has a from_der helper.
    let sig = P256Sig::from_der(signature_der)
        .map_err(|e| anyhow!("parse WebAuthn signature as DER ECDSA: {e}"))?;
    vk.verify(&signed, &sig)
        .map_err(|e| anyhow!("WebAuthn ECDSA verification failed: {e}"))?;

    Ok(())
}

#[allow(dead_code)]
fn debug_base64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature as P256Sig, SigningKey as P256Sk};

    fn test_policy() -> WebAuthnPolicy {
        WebAuthnPolicy {
            accepted_rp_ids: RpList::Static(&["test.riftfi.xyz"]),
            accepted_origins: RpList::Static(&["https://test.riftfi.xyz"]),
            require_user_verified: true,
        }
    }

    fn build_cose_pub(vk: &p256::ecdsa::VerifyingKey) -> (CoseP256PublicKey, Vec<u8>) {
        let point = vk.to_encoded_point(false);
        let x: [u8; 32] = point.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = point.y().unwrap().as_slice().try_into().unwrap();
        let cose = CoseP256PublicKey { x, y };

        // Serialize as COSE_Key CBOR map for the parser round-trip
        // test (separate test below).
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(
            &CborValue::Map(vec![
                (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
                (CborValue::Integer(3.into()), CborValue::Integer((-7).into())),
                (CborValue::Integer((-1).into()), CborValue::Integer(1.into())),
                (CborValue::Integer((-2).into()), CborValue::Bytes(x.to_vec())),
                (CborValue::Integer((-3).into()), CborValue::Bytes(y.to_vec())),
            ]),
            &mut cbor,
        )
        .unwrap();
        (cose, cbor)
    }

    fn make_assertion(
        sk: &P256Sk,
        rp_id: &str,
        origin: &str,
        challenge: &[u8; 32],
        flags_override: Option<u8>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let challenge_b64 = B64URL.encode(challenge);
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": origin,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        let flags = flags_override.unwrap_or(FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // signCount

        let mut signed = Vec::with_capacity(auth_data.len() + 32);
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig: P256Sig = sk.sign(&signed);
        let sig_der = sig.to_der().as_bytes().to_vec();

        (client_data_json, auth_data, sig_der)
    }

    #[test]
    fn happy_path() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let challenge: [u8; 32] = [0x42; 32];
        let (cd, ad, sig) = make_assertion(
            &sk,
            "test.riftfi.xyz",
            "https://test.riftfi.xyz",
            &challenge,
            None,
        );

        verify_assertion(&cose, &cd, &ad, &sig, &challenge, &test_policy()).unwrap();
    }

    #[test]
    fn rejects_replayed_challenge() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let signed_challenge: [u8; 32] = [1u8; 32];
        let (cd, ad, sig) = make_assertion(
            &sk,
            "test.riftfi.xyz",
            "https://test.riftfi.xyz",
            &signed_challenge,
            None,
        );

        // Caller asks the enclave to sign a DIFFERENT prehash.
        let different_prehash: [u8; 32] = [2u8; 32];
        let err =
            verify_assertion(&cose, &cd, &ad, &sig, &different_prehash, &test_policy()).unwrap_err();
        assert!(err.to_string().contains("challenge"), "{err:#}");
    }

    #[test]
    fn rejects_wrong_origin() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let challenge: [u8; 32] = [3u8; 32];
        let (cd, ad, sig) = make_assertion(
            &sk,
            "test.riftfi.xyz",
            "https://attacker.com",
            &challenge,
            None,
        );
        let err = verify_assertion(&cose, &cd, &ad, &sig, &challenge, &test_policy()).unwrap_err();
        assert!(err.to_string().contains("origin"), "{err:#}");
    }

    #[test]
    fn rejects_wrong_rp_id() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let challenge: [u8; 32] = [4u8; 32];
        let (cd, ad, sig) = make_assertion(
            &sk,
            "evil.example.com",  // wrong RP
            "https://test.riftfi.xyz",
            &challenge,
            None,
        );
        let err = verify_assertion(&cose, &cd, &ad, &sig, &challenge, &test_policy()).unwrap_err();
        assert!(err.to_string().contains("rpIdHash"), "{err:#}");
    }

    #[test]
    fn rejects_missing_uv_when_required() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let challenge: [u8; 32] = [5u8; 32];
        let (cd, ad, sig) = make_assertion(
            &sk,
            "test.riftfi.xyz",
            "https://test.riftfi.xyz",
            &challenge,
            Some(FLAG_USER_PRESENT), // UP only, no UV
        );
        let err = verify_assertion(&cose, &cd, &ad, &sig, &challenge, &test_policy()).unwrap_err();
        assert!(err.to_string().contains("user-verified"), "{err:#}");
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        let challenge: [u8; 32] = [6u8; 32];
        let (cd, ad, mut sig) = make_assertion(
            &sk,
            "test.riftfi.xyz",
            "https://test.riftfi.xyz",
            &challenge,
            None,
        );
        // Flip a byte in the signature
        let last = sig.len() - 1;
        sig[last] ^= 1;
        let err = verify_assertion(&cose, &cd, &ad, &sig, &challenge, &test_policy()).unwrap_err();
        // Either DER parse failure or signature verification failure — both fine.
        let s = err.to_string();
        assert!(s.contains("WebAuthn") || s.contains("parse"), "{err:#}");
    }

    #[test]
    fn accepts_any_of_multiple_rp_ids() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, _cbor) = build_cose_pub(sk.verifying_key());

        // Policy accepts both .xyz and .com — assertion signed for .com
        // must verify.
        let policy = WebAuthnPolicy {
            accepted_rp_ids: RpList::Static(&["riftfi.xyz", "riftfi.com", "localhost"]),
            accepted_origins: RpList::Static(&[
                "https://sandbox.riftfi.xyz",
                "https://sandbox.riftfi.com",
                "http://localhost:3000",
            ]),
            require_user_verified: true,
        };

        let challenge: [u8; 32] = [0x21; 32];
        // Enrolled for .com → assertion signed against riftfi.com
        let (cd, ad, sig) = make_assertion(
            &sk,
            "riftfi.com",
            "https://sandbox.riftfi.com",
            &challenge,
            None,
        );
        verify_assertion(&cose, &cd, &ad, &sig, &challenge, &policy).unwrap();

        // Same envelope can also verify a .xyz assertion (different
        // credential, but the policy accepts both RP-IDs).
        let (cd2, ad2, sig2) = make_assertion(
            &sk,
            "riftfi.xyz",
            "https://sandbox.riftfi.xyz",
            &challenge,
            None,
        );
        verify_assertion(&cose, &cd2, &ad2, &sig2, &challenge, &policy).unwrap();
    }

    #[test]
    fn cose_round_trip() {
        let mut rng = rand::thread_rng();
        let sk = P256Sk::random(&mut rng);
        let (cose, cbor) = build_cose_pub(sk.verifying_key());
        let parsed = CoseP256PublicKey::from_cose_cbor(&cbor).unwrap();
        assert_eq!(parsed, cose);
    }
}
