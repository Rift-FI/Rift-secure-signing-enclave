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
}
