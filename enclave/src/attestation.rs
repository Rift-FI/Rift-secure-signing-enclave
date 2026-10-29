//! NSM attestation document generation.
//!
//! The Nitro Secure Module (NSM) is a hardware module exposed inside
//! every Nitro enclave at `/dev/nsm`. It signs attestation documents
//! that prove the running code's identity (PCR0..PCR4) — a third party
//! verifying the document can be cryptographically sure the requesting
//! enclave is exactly the image we deployed.
//!
//! AWS KMS will verify the document signature + a kms key policy
//! condition like:
//!   "kms:RecipientAttestation:ImageSha384":
//!     "<our enclave's PCR0 hex>"
//!
//! Only if the PCR0 inside the attestation matches the condition does
//! KMS release the plaintext data key.
//!
//! Implementation: thin wrapper around the upstream
//! `aws-nitro-enclaves-nsm-api` crate.

use anyhow::{anyhow, bail, Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
use ciborium::value::Value as CborValue;
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// Process-wide NSM file descriptor. Opened once at startup and kept
/// for the life of the enclave.
static NSM_FD: OnceLock<i32> = OnceLock::new();

/// Open /dev/nsm. Called once from `main` at boot.
pub fn init() -> Result<()> {
    let fd = nsm_driver::nsm_init();
    if fd < 0 {
        return Err(anyhow!("nsm_init returned {fd}; is /dev/nsm available?"));
    }
    NSM_FD
        .set(fd)
        .map_err(|_| anyhow!("NSM already initialized — init() called twice"))?;
    Ok(())
}

fn fd() -> Result<i32> {
    NSM_FD.get().copied().ok_or_else(|| anyhow!("NSM not initialized — call init() first"))
}

/// Generate a fresh attestation document.
///
/// `public_key` is the RSA-2048 public key whose corresponding private
/// key lives only inside this enclave. KMS will encrypt its Decrypt
/// response to this key (CiphertextForRecipient) so the plaintext DEK
/// never crosses outside the enclave's address space.
///
/// `nonce` is a 32-byte caller-supplied value that ends up inside the
/// attestation; we don't currently use it for replay defence but it's
/// the right hook for it. Pass random bytes per request.
pub fn attest(public_key: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: Some(nonce.to_vec().into()),
        public_key: Some(public_key.to_vec().into()),
    };

    let response = nsm_driver::nsm_process_request(fd()?, request);
    match response {
        NsmResponse::Attestation { document } => Ok(Zeroizing::new(document)),
        NsmResponse::Error(e) => Err(anyhow!("NSM attestation failed: {:?}", e)),
        other => Err(anyhow!("unexpected NSM response: {:?}", other)),
    }
    .context("attestation document generation")
}

/// Read this enclave's own PCR0 from the NSM. Used by the health /
/// canary port so rotation can confirm the image it just started is the
/// approved one. All zeros in debug mode.
pub fn describe_pcr0() -> Result<Vec<u8>> {
    match nsm_driver::nsm_process_request(fd()?, NsmRequest::DescribePCR { index: 0 }) {
        NsmResponse::DescribePCR { data, .. } => Ok(data),
        NsmResponse::Error(e) => Err(anyhow!("NSM DescribePCR failed: {:?}", e)),
        other => Err(anyhow!("unexpected NSM response: {:?}", other)),
    }
}

/// Same as `attest` but also returns the document's embedded trusted
/// timestamp as Unix seconds.
///
/// The attestation doc is a COSE_Sign1 array [protected, unprotected,
/// payload, signature]. The payload is itself a CBOR map signed by
/// the NSM, with `timestamp` (milliseconds since epoch) among the
/// claims. We extract that value so v3 OIDC verification has a trusted
/// "now" — using the host's wall clock would let a compromised host
/// extend the apparent validity window of an OIDC token.
pub fn attest_with_timestamp(public_key: &[u8], nonce: &[u8]) -> Result<(Zeroizing<Vec<u8>>, i64)> {
    let doc = attest(public_key, nonce)?;
    let ts = parse_attestation_timestamp(&doc)?;
    Ok((doc, ts))
}

fn parse_attestation_timestamp(doc: &[u8]) -> Result<i64> {
    let outer: CborValue = ciborium::de::from_reader(doc)
        .map_err(|e| anyhow!("decode attestation doc as CBOR: {e}"))?;
    let arr = outer
        .as_array()
        .ok_or_else(|| anyhow!("attestation doc is not a COSE_Sign1 array"))?;
    if arr.len() != 4 {
        bail!("COSE_Sign1 must be a 4-element array, got {}", arr.len());
    }
    // Element 2 is the payload bytes (a serialized CBOR map).
    let payload_bytes = arr[2]
        .as_bytes()
        .ok_or_else(|| anyhow!("COSE_Sign1 payload is not bytes"))?;
    let payload: CborValue = ciborium::de::from_reader(payload_bytes.as_slice())
        .map_err(|e| anyhow!("decode attestation payload CBOR: {e}"))?;
    let map = payload
        .as_map()
        .ok_or_else(|| anyhow!("attestation payload is not a map"))?;
    for (k, v) in map {
        if let Some(s) = k.as_text() {
            if s == "timestamp" {
                if let Some(i) = v.as_integer() {
                    let millis = i128::from(i);
                    let secs = millis.checked_div(1000)
                        .ok_or_else(|| anyhow!("attestation timestamp overflow"))?;
                    let secs_i64 = i64::try_from(secs)
                        .map_err(|_| anyhow!("attestation timestamp does not fit in i64"))?;
                    return Ok(secs_i64);
                }
            }
        }
    }
    bail!("attestation payload missing `timestamp` field")
}
