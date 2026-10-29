//! Pure, cross-platform helpers used by the v3 envelope reseal flow.
//!
//! Kept OUT of `vsock_server` because that module is `cfg(target_os =
//! "linux")` (tokio-vsock is Linux-only) — moving these here lets us
//! run their unit tests on any dev laptop with `cargo test`, not just
//! on the EC2 during `make test`. The reseal integration itself still
//! runs inside the enclave; this module holds only the deterministic
//! logic that never touches KMS or vsock.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::envelope_v3;
use crate::protocol::EnrolledMethod;
use crate::webauthn_verification;

/// Convert a wire `EnrolledMethod` (parent proxy shape) to the
/// in-enclave `envelope_v3::AuthMethod`. Validates:
///   - OIDC: iss + sub non-empty
///   - Passkey: cred_id non-empty, cose_pubkey parses as a valid
///     COSE_Key P-256 (rejects garbage before it can land in a sealed
///     envelope where it would only fail at first-use).
pub fn enrolled_to_authmethod(m: &EnrolledMethod) -> Result<envelope_v3::AuthMethod> {
    match m {
        EnrolledMethod::Oidc { iss, sub } => {
            if iss.is_empty() {
                bail!("OIDC method requires a non-empty iss");
            }
            if sub.is_empty() {
                bail!("OIDC method requires a non-empty sub");
            }
            Ok(envelope_v3::AuthMethod::Oidc {
                iss: iss.clone(),
                sub: sub.clone(),
            })
        }
        EnrolledMethod::Passkey {
            cred_id_b64,
            cose_pubkey_b64,
        } => {
            let cred_id = B64
                .decode(cred_id_b64)
                .context("decode cred_id_b64 (base64)")?;
            if cred_id.is_empty() {
                bail!("passkey cred_id cannot be empty");
            }
            let cose = B64
                .decode(cose_pubkey_b64)
                .context("decode cose_pubkey_b64 (base64)")?;
            webauthn_verification::CoseP256PublicKey::from_cose_cbor(&cose)
                .context("validate enrolled passkey COSE_Key")?;
            Ok(envelope_v3::AuthMethod::Passkey { cred_id, cose })
        }
    }
}

/// Match rule for "is this method already enrolled":
///   OIDC     → same (iss, sub)
///   Passkey  → same cred_id (cose_pubkey ignored — a rekey of the
///              same credential still collides with itself)
/// Different kinds never collide.
///
/// Pure fn so unit tests can pin behaviour without needing KMS.
pub fn is_duplicate_method(
    existing: &[envelope_v3::AuthMethod],
    candidate: &envelope_v3::AuthMethod,
) -> bool {
    existing.iter().any(|m| match (m, candidate) {
        (
            envelope_v3::AuthMethod::Oidc { iss: e_iss, sub: e_sub },
            envelope_v3::AuthMethod::Oidc { iss: n_iss, sub: n_sub },
        ) => e_iss == n_iss && e_sub == n_sub,
        (
            envelope_v3::AuthMethod::Passkey { cred_id: e_cid, .. },
            envelope_v3::AuthMethod::Passkey { cred_id: n_cid, .. },
        ) => e_cid == n_cid,
        _ => false,
    })
}

// ─── Bound (domain-separated) reseal challenge ──────────────────────
//
// Legacy reseal verified `auth_proof` against the caller-supplied
// `prehashed_hex` as-is. That value is just 32 bytes the backend picked,
// so ANY proof the user ever produced over ANY 32-byte value — notably a
// sign-path proof whose challenge is a UserOp hash — could be replayed
// by whoever controls the backend/parent to enrol an attacker's method.
//
// Bound mode: the enclave itself derives the challenge the proof must
// be over, from values it trusts or checks:
//
//   challenge = SHA-256(
//       "rift-reseal-v1"            14 ASCII bytes (domain tag)
//    || 0x00                        separator
//    || owner_address               20 raw bytes, derived INSIDE the
//                                   enclave from the unsealed key
//    || server_nonce                32 raw bytes = decoded prehashed_hex
//                                   (the backend's one-shot challenge;
//                                   TTL/one-shot still enforced upstream)
//    || canonical(new_method)       see `canonical_method_bytes`
//   )
//
// A proof over this value can only authorise appending THAT method to
// THAT wallet, and can never be confused with a sign-path proof (sign
// challenges are UserOp hashes, not outputs of this domain-tagged hash).
// The exact client recipe is in README.md § "Bound reseal challenge".

/// Domain tag for the bound reseal challenge. Changing it is a protocol
/// break for every client.
pub const RESEAL_DOMAIN_TAG: &[u8] = b"rift-reseal-v1";

/// Enclave-wide enforcement switch for bound reseal challenges.
///
/// `false` (current): a reseal proof over the bound challenge is always
/// accepted; a LEGACY proof over the raw `prehashed_hex` is still
/// accepted unless the project's signed config bundle sets
/// `require_bound_reseal: true`.
///
/// `true`: legacy reseal proofs are refused for every project. Flip once
/// all clients (sdk, wallet, widget, partners) produce bound challenges.
/// Code constant on purpose (not an env var: the enclave has no
/// trustworthy env), so flipping it is a reviewed rebuild + PCR0 change.
pub const RESEAL_REQUIRE_BOUND_CHALLENGE: bool = false;

/// Whether legacy (unbound) reseal proofs must be refused, given the
/// project's signed `require_bound_reseal` flag (false when there is no
/// valid bundle).
pub fn reseal_requires_bound(project_flag: bool) -> bool {
    RESEAL_REQUIRE_BOUND_CHALLENGE || project_flag
}

const METHOD_TAG_OIDC: u8 = 0x01;
const METHOD_TAG_PASSKEY: u8 = 0x02;

fn push_lv(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Unambiguous byte encoding of a method, over DECODED values (so
/// base64 padding / alphabet choices on the client can't change it):
///
///   OIDC:    0x01 || u32be(len(iss)) || iss(UTF-8) || u32be(len(sub)) || sub(UTF-8)
///   Passkey: 0x02 || u32be(len(cred_id)) || cred_id || u32be(len(cose)) || cose
pub fn canonical_method_bytes(m: &envelope_v3::AuthMethod) -> Vec<u8> {
    let mut out = Vec::new();
    match m {
        envelope_v3::AuthMethod::Oidc { iss, sub } => {
            out.push(METHOD_TAG_OIDC);
            push_lv(&mut out, iss.as_bytes());
            push_lv(&mut out, sub.as_bytes());
        }
        envelope_v3::AuthMethod::Passkey { cred_id, cose } => {
            out.push(METHOD_TAG_PASSKEY);
            push_lv(&mut out, cred_id);
            push_lv(&mut out, cose);
        }
    }
    out
}

/// The challenge a bound reseal proof must be over. See notes above.
pub fn bound_reseal_challenge(
    owner_address: &[u8; 20],
    server_nonce: &[u8; 32],
    new_method: &envelope_v3::AuthMethod,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RESEAL_DOMAIN_TAG);
    h.update([0u8]);
    h.update(owner_address);
    h.update(server_nonce);
    h.update(canonical_method_bytes(new_method));
    h.finalize().into()
}

/// Parse a 32-byte hex value (optional 0x). Used for `prehashed_hex`
/// and the user op hash.
pub fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .with_context(|| format!("hex-decode {what}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

/// Which challenge a reseal proof was accepted under. Logged only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResealChallengeMode {
    Bound,
    Legacy,
}

/// Decide which challenge(s) a reseal proof may be verified against and
/// run `verify` (the real proof verifier) accordingly:
///   1. Try the bound challenge. Success ⇒ `Bound`.
///   2. Else, if legacy is still allowed, try the raw server nonce.
///      Success ⇒ `Legacy`.
///   3. Else fail.
///
/// Pure (verification injected) so the policy is unit-testable without
/// KMS / NSM.
pub fn verify_reseal_consent<F>(
    bound_challenge: &[u8; 32],
    legacy_challenge: &[u8; 32],
    require_bound: bool,
    mut verify: F,
) -> Result<ResealChallengeMode>
where
    F: FnMut(&[u8; 32]) -> Result<()>,
{
    match verify(bound_challenge) {
        Ok(()) => Ok(ResealChallengeMode::Bound),
        Err(bound_err) => {
            if require_bound {
                return Err(bound_err.context(
                    "reseal requires a bound challenge (rift-reseal-v1); legacy proofs over prehashed_hex are disabled",
                ));
            }
            verify(legacy_challenge).map(|()| ResealChallengeMode::Legacy)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope_v3::AuthMethod;
    use crate::webauthn_verification::CoseP256PublicKey;

    // A syntactically valid COSE_Key P-256 built from a known point.
    // Reused across passkey tests. Keeps them independent of the
    // `webauthn_verification::tests` fixtures.
    fn sample_cose_cbor() -> Vec<u8> {
        let mut cose = Vec::new();
        cose.push(0xa5);
        cose.push(0x01);
        cose.push(0x02);
        cose.push(0x03);
        cose.push(0x26);
        cose.push(0x20);
        cose.push(0x01);
        cose.push(0x21);
        cose.push(0x58);
        cose.push(0x20);
        cose.extend_from_slice(&[0x11u8; 32]);
        cose.push(0x22);
        cose.push(0x58);
        cose.push(0x20);
        cose.extend_from_slice(&[0x22u8; 32]);
        // Sanity: the very validator we're about to lean on must accept
        // this. If this assert fails the whole test file is nonsense.
        CoseP256PublicKey::from_cose_cbor(&cose).expect("valid P-256 COSE");
        cose
    }

    // ─── enrolled_to_authmethod ────────────────────────────────────

    #[test]
    fn oidc_ok_round_trip() {
        let m = EnrolledMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "1234567890".into(),
        };
        let out = enrolled_to_authmethod(&m).unwrap();
        match out {
            AuthMethod::Oidc { iss, sub } => {
                assert_eq!(iss, "https://accounts.google.com");
                assert_eq!(sub, "1234567890");
            }
            _ => panic!("expected Oidc variant"),
        }
    }

    #[test]
    fn oidc_empty_iss_rejected() {
        let m = EnrolledMethod::Oidc {
            iss: "".into(),
            sub: "s".into(),
        };
        let err = enrolled_to_authmethod(&m).unwrap_err();
        assert!(err.to_string().contains("iss"), "{err:#}");
    }

    #[test]
    fn oidc_empty_sub_rejected() {
        let m = EnrolledMethod::Oidc {
            iss: "i".into(),
            sub: "".into(),
        };
        let err = enrolled_to_authmethod(&m).unwrap_err();
        assert!(err.to_string().contains("sub"), "{err:#}");
    }

    #[test]
    fn passkey_ok_round_trip() {
        let cose = sample_cose_cbor();
        let m = EnrolledMethod::Passkey {
            cred_id_b64: B64.encode(b"credid-bytes"),
            cose_pubkey_b64: B64.encode(&cose),
        };
        let out = enrolled_to_authmethod(&m).unwrap();
        match out {
            AuthMethod::Passkey { cred_id, cose: c } => {
                assert_eq!(cred_id, b"credid-bytes");
                assert_eq!(c, cose);
            }
            _ => panic!("expected Passkey variant"),
        }
    }

    #[test]
    fn passkey_empty_cred_id_rejected() {
        let cose = sample_cose_cbor();
        let m = EnrolledMethod::Passkey {
            cred_id_b64: B64.encode(&[] as &[u8]),
            cose_pubkey_b64: B64.encode(&cose),
        };
        let err = enrolled_to_authmethod(&m).unwrap_err();
        assert!(err.to_string().contains("cred_id"), "{err:#}");
    }

    #[test]
    fn passkey_bad_cose_rejected() {
        let m = EnrolledMethod::Passkey {
            cred_id_b64: B64.encode(b"credid"),
            cose_pubkey_b64: B64.encode(b"not-a-cose-key"),
        };
        let err = enrolled_to_authmethod(&m).unwrap_err();
        // Should surface COSE parse failure — not silently accept.
        assert!(
            err.to_string().to_lowercase().contains("cose"),
            "{err:#}"
        );
    }

    #[test]
    fn passkey_bad_base64_rejected() {
        let m = EnrolledMethod::Passkey {
            cred_id_b64: "!!not-b64!!".into(),
            cose_pubkey_b64: B64.encode(b"anything"),
        };
        let err = enrolled_to_authmethod(&m).unwrap_err();
        assert!(err.to_string().contains("cred_id"), "{err:#}");
    }

    // ─── is_duplicate_method ───────────────────────────────────────

    #[test]
    fn dup_detects_same_oidc_pair() {
        let existing = vec![AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "abc".into(),
        }];
        let candidate = AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "abc".into(),
        };
        assert!(is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_ignores_different_oidc_sub() {
        let existing = vec![AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "abc".into(),
        }];
        let candidate = AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "xyz".into(),
        };
        assert!(!is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_ignores_different_iss_same_sub() {
        // Same numeric sub but from Apple vs Google is a different
        // identity — must not collide.
        let existing = vec![AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "abc".into(),
        }];
        let candidate = AuthMethod::Oidc {
            iss: "https://appleid.apple.com".into(),
            sub: "abc".into(),
        };
        assert!(!is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_detects_same_passkey_cred_id_even_if_cose_differs() {
        // Enclave never wants two entries for one credential — even if
        // some upstream rekey mint a variant COSE, dedup by cred_id.
        let existing = vec![AuthMethod::Passkey {
            cred_id: vec![1, 2, 3, 4],
            cose: vec![0xa5, 0x01, 0x02, 0x03, 0x26],
        }];
        let candidate = AuthMethod::Passkey {
            cred_id: vec![1, 2, 3, 4],
            cose: vec![0xa5, 0x01, 0x02, 0x03, 0x27],
        };
        assert!(is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_ignores_different_passkey_cred_id() {
        let existing = vec![AuthMethod::Passkey {
            cred_id: vec![1, 2, 3, 4],
            cose: vec![0xa5],
        }];
        let candidate = AuthMethod::Passkey {
            cred_id: vec![9, 9, 9, 9],
            cose: vec![0xa5],
        };
        assert!(!is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_never_matches_across_kinds() {
        let existing = vec![AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "abc".into(),
        }];
        let candidate = AuthMethod::Passkey {
            cred_id: b"abc".to_vec(),
            cose: vec![0xa5],
        };
        assert!(!is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_empty_existing_never_matches() {
        let existing: Vec<AuthMethod> = vec![];
        let candidate = AuthMethod::Oidc {
            iss: "i".into(),
            sub: "s".into(),
        };
        assert!(!is_duplicate_method(&existing, &candidate));
    }

    #[test]
    fn dup_survives_bulk_scan() {
        // With many entries, the linear scan still finds the match.
        // Not a perf test — just guards against off-by-one iteration.
        let mut existing = Vec::new();
        for i in 0..100 {
            existing.push(AuthMethod::Oidc {
                iss: format!("iss-{i}"),
                sub: format!("sub-{i}"),
            });
        }
        let candidate = AuthMethod::Oidc {
            iss: "iss-73".into(),
            sub: "sub-73".into(),
        };
        assert!(is_duplicate_method(&existing, &candidate));
    }

    // ─── bound reseal challenge ────────────────────────────────────

    /// Fixed test vectors — README.md § "Bound reseal challenge" quotes
    /// these exact inputs and outputs so client teams can check their
    /// implementation. If this changes, the docs (and every client) must.
    #[test]
    fn bound_challenge_test_vectors() {
        let owner: [u8; 20] = hex::decode("00112233445566778899aabbccddeeff00112233")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = [0xabu8; 32];
        let oidc = AuthMethod::Oidc {
            iss: "https://accounts.google.com".into(),
            sub: "1234567890".into(),
        };
        assert_eq!(
            hex::encode(canonical_method_bytes(&oidc)),
            "010000001b68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d0000000a31323334353637383930"
        );
        assert_eq!(
            hex::encode(bound_reseal_challenge(&owner, &nonce, &oidc)),
            "377f6d645f6d470848bad62021c2c318e7da4ad82139f00f05b18a6ac43355cb"
        );
        let pk = AuthMethod::Passkey {
            cred_id: vec![1, 2, 3, 4],
            cose: vec![0xa5, 0x01, 0x02],
        };
        assert_eq!(
            hex::encode(canonical_method_bytes(&pk)),
            "02000000040102030400000003a50102"
        );
        assert_eq!(
            hex::encode(bound_reseal_challenge(&owner, &nonce, &pk)),
            "5b812e4547e39fba673c5e3b9f30a68f0e454c89e8ba179e240afc0365c4dadd"
        );
    }

    #[test]
    fn bound_challenge_binds_every_input() {
        let owner = [1u8; 20];
        let nonce = [2u8; 32];
        let m = AuthMethod::Oidc { iss: "i".into(), sub: "s".into() };
        let base = bound_reseal_challenge(&owner, &nonce, &m);
        assert_ne!(base, bound_reseal_challenge(&[9u8; 20], &nonce, &m));
        assert_ne!(base, bound_reseal_challenge(&owner, &[9u8; 32], &m));
        assert_ne!(
            base,
            bound_reseal_challenge(&owner, &nonce, &AuthMethod::Oidc { iss: "i".into(), sub: "t".into() })
        );
        // Length-prefixing: moving bytes between iss and sub changes it.
        assert_ne!(
            bound_reseal_challenge(&owner, &nonce, &AuthMethod::Oidc { iss: "ab".into(), sub: "c".into() }),
            bound_reseal_challenge(&owner, &nonce, &AuthMethod::Oidc { iss: "a".into(), sub: "bc".into() })
        );
        assert_ne!(base, nonce);
    }

    #[test]
    fn consent_policy_modes() {
        let bound = [1u8; 32];
        let legacy = [2u8; 32];
        let accept = |good: [u8; 32]| {
            move |c: &[u8; 32]| {
                if *c == good {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("challenge binding failed"))
                }
            }
        };
        assert_eq!(verify_reseal_consent(&bound, &legacy, false, accept(bound)).unwrap(), ResealChallengeMode::Bound);
        assert_eq!(verify_reseal_consent(&bound, &legacy, true, accept(bound)).unwrap(), ResealChallengeMode::Bound);
        assert_eq!(verify_reseal_consent(&bound, &legacy, false, accept(legacy)).unwrap(), ResealChallengeMode::Legacy);
        let err = verify_reseal_consent(&bound, &legacy, true, accept(legacy)).unwrap_err();
        assert!(format!("{err:#}").contains("bound challenge"), "{err:#}");
        assert!(verify_reseal_consent(&bound, &legacy, false, accept([3u8; 32])).is_err());
    }

    #[test]
    fn enforcement_flag_combines_constant_and_project() {
        assert!(reseal_requires_bound(true));
        assert_eq!(reseal_requires_bound(false), RESEAL_REQUIRE_BOUND_CHALLENGE);
    }

    #[test]
    fn parse_hex32_rules() {
        assert_eq!(parse_hex32(&"ab".repeat(32), "x").unwrap(), [0xab; 32]);
        assert_eq!(parse_hex32(&format!("0x{}", "cd".repeat(32)), "x").unwrap(), [0xcd; 32]);
        assert!(parse_hex32("abcd", "x").is_err());
        assert!(parse_hex32(&"zz".repeat(32), "x").is_err());
    }
}
