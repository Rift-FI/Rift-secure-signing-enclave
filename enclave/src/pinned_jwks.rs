//! Pinned JWKS — Google and Apple public keys, baked into the EIF.
//!
//! Why pinned: the enclave has no network, so we cannot fetch the
//! latest JWKS at runtime. Even if we did, the host could feed us
//! arbitrary bytes since the host owns the network stack. The honest
//! security boundary is therefore "trust whatever the EIF was built
//! with" — and that's exactly what KMS's PCR0 attestation gates on.
//!
//! Rotation procedure (Google rotates ~weekly; Apple rotates rarely):
//!
//!   1. From a workstation:
//!        cd rift-signer-enclave
//!        node tools/fetch-jwks.mjs > /tmp/jwks-snippet.rs
//!   2. Paste the two functions (google_jwks, apple_jwks) from
//!      /tmp/jwks-snippet.rs into this file, replacing the existing
//!      ones below.
//!   3. Rebuild the EIF on EC2:
//!        ssh <ec2>; cd Rift-secure-signing-enclave; git pull; make eif
//!      Capture the new PCR0 from the build output.
//!   4. Update the KMS key policy (the sandbox + prod CMKs) so the
//!      `kms:RecipientAttestation:ImageSha384` condition includes the
//!      new PCR0. Keep the old PCR0 listed for a graceful overlap
//!      window so any in-flight signs can still complete.
//!   5. Restart the parent-proxy + enclave on EC2.
//!
//! Last refreshed: 2026-06-30. Schedule next refresh for ~2026-07-07.
//! Google JWKS endpoint: https://www.googleapis.com/oauth2/v3/certs
//! Apple JWKS endpoint:  https://appleid.apple.com/auth/keys

use crate::oidc_verification::PinnedJwk;

/// Current production-pinned JWKS. Build the EIF after every refresh.
pub fn current_jwks() -> Vec<PinnedJwk> {
    let mut keys: Vec<PinnedJwk> = Vec::new();
    keys.extend(google_jwks());
    keys.extend(apple_jwks());
    keys
}

/// Google's id_token signing keys. RS256 only.
///
/// Source: https://www.googleapis.com/oauth2/v3/certs
fn google_jwks() -> Vec<PinnedJwk> {
    vec![
        PinnedJwk {
            kid: "d12978ba4c29ef1154a34e4870c7a3a51d26df10".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://accounts.google.com".to_string(),
            n: Some("_YiYSsfKSMg0sWfZxdcui2BYLSUlm-wJ9uG-hNuF4LIvgSAmeFNPR0tMw-QHW0bDRITcHzHK1zRAWcbpXgZ7V8A7eA5sH4ivEcqXWCV37vJxx6FEpFllMIW1zXoW3NNuP3ULNGl6mdpxYsNjquOxrypo0Dol7TsS1eLdk2C7SNesmQzI_2j-ZFIMtESZwdIWATV9EiMUgF5riffKb5jyNFMpPRVkI2G8X5ImIkiLPOs663PQPidVijrfOc4nV8PmPCsCqYUWuBkMGgzT6Am-tBem2h_facDhfmdgSCDHnYHi6PxIgyHIQSKU4jtF5sDJGuIORHNZwBUK2VNRcqf8xw".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
        PinnedJwk {
            kid: "f36191371c8c4ffd162846cde91a9cb4c2bebae2".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://accounts.google.com".to_string(),
            n: Some("pO69ul58xhpxEvsHkAs-4vGIyonZ5bcy-fmsvW2IFHuPyntWLfTbm92pZJ50fx4DYLthKKiGsdJljcPfUPL4mQqGwsN38MtSCOMPocDrtYlsC2Gk909WYiSlB6g14K_fIN03CIm50PzIh1ycQL6oGEiwTaIxXD9mnomq0skJK-pTDis4yc5Kr25399ElfCnNaK3Ln44MHT7qKg7YmLzCkQdgQ3jf-eKvnQr9IkCe27jCGwweO43iRVsz6Tz0rK5U-zdm7pyIu6oeg2ox8WBv_gkuOo6eq08o3iMwM033Ic3sRa1fwMeaCN0Bqn7tOJWZ5iYgH-6aAImLsGzZ6fRGGQ".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
        PinnedJwk {
            kid: "8f4730071a99b44ef52dbd6dac2d96af3a7c9b3f".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://accounts.google.com".to_string(),
            n: Some("2eGGURDods69Y0yhtuq-zF3hLp1YotvE4WfmqxUoMXbfNy8lW4xiYVQRMlRDgEQgq01Yzm5vHjHcGWY2Ktgn62N4tWVjfStnlBavsF8MZ4JE7q3csepAzqa068r6Gkuyv7qqutx8G3WdBFhwlK6pwuVo1TNng6cmjumLIev2xy3ES7omfVRneHh-eHuim3ZJ8uSMAG2z4dcLUiTXKDofjkeBRHsgjbOwyHVyuYxnQTthHH8BmomQUu2hIqsHUTeJIEWreyQdjsAulLeFi1Ny3vWd4BQNvviQWjmBXNlCsaXEM5A2U1yvuGp_6zM4KJByEvPKH1cYfaw07xZAXViW2w".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
        PinnedJwk {
            kid: "f10f87405a979c1df36df26606734f33cd85c271".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://accounts.google.com".to_string(),
            n: Some("4rY5uwZK1dQ-UVgB5s4NLyC-u5LC2MT7b8GWZztiNgMsp0Nnqx0pM7Ofx0ws32N2aZcx10-J8ydQxnNb9uAcf-7LyhyOIcv_WEyzaSbUAMOgoF-nQmJetckxNg6ekhNfaFcTQS0T-29ql2_CBLIML6CvSh-r0fgWRsqN2ayB7wCl74Gv6OOVbvagUWhj5z2L6o_plmsPDwLVuvA7o3WDEDjoq-IXafRQowj92kQUenrOKD4YCopuLIBhel6VH8doFRNZ6KISQhMcOivWaLU_UtKKAMloGJieTf_3r-_nErs2h5wB7T7FrMCScmO7mvFQXKh8_4P-MlbfgS9CUvQksw".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
    ]
}

/// Apple's id_token signing keys (Sign In with Apple).
///
/// Source: https://appleid.apple.com/auth/keys
fn apple_jwks() -> Vec<PinnedJwk> {
    vec![
        PinnedJwk {
            kid: "5iq33lJBYj".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://appleid.apple.com".to_string(),
            n: Some("vcDUGnc9ITh348cRCn6CENlcFzOm4X_sxDyPumPZrM3YhH_zXfjNhBCQnvTGNFqGzsqok87ufbWSEqYiYQDsh8DMTT_tx5bcuRJI-LmuX3CkLOKq0KXVUzijpj45mTvdGoC_dL2ei_nGs9yz0EJwilNpwPZxkGxNhWi7MWobOd4BjzBIkqDw_HqKZ_486EKHhyV0qgXfwQYgnKT9blBYc6ZNej9MPHyve5lZs084uEiY_UYjV0rlxfZdYa0g3scG7wc2dWMlqZ4QvbPMj0KTzMNtO-9cr3aruTTPQ2qDqFAThZDNrPaScJIXAcgrARvqy1CAMT_8gSYFbb4Ld0tRbQ".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
        PinnedJwk {
            kid: "5RFOSiNIUm".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://appleid.apple.com".to_string(),
            n: Some("qaLbQzOrRmIXwJkuWpRu7T6ApMcoBA_QxFUO4foV5A1JhEE_Gg4uOCQ8kDSPJHGhPl8RBZ0o4niyUWYkS3IIgjUq3pMAwSDxczqKq00Z82gCN6nYAwlI-_iMsepM5kk86XjB_MJMVdU3NGCHReITotsyXnZ0A7v0RU_LYLzdgoobsK1jh5y4XsgiDf25ZGILiYjxVzYNcaJ5G01Rg9j0ydEJYMOC_dT9xcfQzy2LiOlhGn3rDpQIyhVuqprvUeLAJPEFQoH486VjcnDxKMLCs2L5aSlTj78BxgYNV24FRRTl8QAyhIMi4e0Ja_4i59OCOVZMbR4p1_o_cszhOGIlmw".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
        PinnedJwk {
            kid: "1E6VioIaNI".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            iss: "https://appleid.apple.com".to_string(),
            n: Some("ttL4HNkWLS_Oh0GADZqA4lTM8Y8UyaCR2NfIcvxby6quhwIISI9o9iCw3ggMYnqEG-dfRHcpsWLp2MZH_CNC-2pB0l_tDKeLi1eytR0_3YUHQBBQlkDjDP-hlyS0xJD1ds0un4mOIhc-oPHK2xiYbSVbJcBTKYA6FPoAa7u_YbsKN1YnUqzoRf2iOpARBurhCkvmJKjXwcH6RNGM9iScOO-U9orB5-EQivCKdDnMiwsPaA6_Jx1DzKyaZI6UCV_CZV3k59XvbeYGV3JXJMtKjlwaIumX3i5ecT4lz_XUr7ZYf1tA1v4ewGnrb5TFr86U-NE6uhvEtpA-_uVWPMmy_Q".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_jwks_has_both_issuers() {
        let keys = current_jwks();
        assert!(
            keys.iter().any(|k| k.iss == "https://accounts.google.com"),
            "no Google JWK pinned"
        );
        assert!(
            keys.iter().any(|k| k.iss == "https://appleid.apple.com"),
            "no Apple JWK pinned"
        );
    }

    #[test]
    fn google_keys_are_rsa_rs256() {
        for k in google_jwks() {
            assert_eq!(k.kty, "RSA");
            assert_eq!(k.alg, "RS256");
            assert!(k.n.is_some() && k.e.is_some());
        }
    }

    #[test]
    fn no_duplicate_kids_within_an_issuer() {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for k in current_jwks() {
            let key = (k.iss.clone(), k.kid.clone());
            assert!(
                seen.insert(key),
                "duplicate (iss, kid) — JWKS snapshot is malformed"
            );
        }
    }
}
