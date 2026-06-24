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

use anyhow::{anyhow, Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
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
