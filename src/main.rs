//! Rift signing enclave — entry point.
//!
//! Architecture in one paragraph: the enclave talks to its parent EC2
//! process over vsock and nothing else (no network, no disk, no shell).
//! For each signing request it (1) asks the NSM driver for an
//! attestation document, (2) hands the document + KMS-wrapped DEK back
//! to the parent over vsock — the parent calls KMS Decrypt on our
//! behalf because the enclave has no internet, (3) KMS returns the
//! plaintext DEK encrypted to the public key inside the attestation
//! document, (4) the enclave RSA-OAEP unwraps it, (5) AES-256-CBC
//! decrypts the envelope payload to recover the EOA private key, (6)
//! secp256k1 signs the UserOperation hash, (7) zeroizes everything,
//! (8) returns the signature.
//!
//! The KMS key policy is configured to release plaintext ONLY for
//! attestation documents whose PCR0 matches this enclave's exact image
//! hash. So even with valid IAM credentials, the parent process cannot
//! decrypt — only the legit enclave can.

use anyhow::Context;
use tracing::{error, info};

mod attestation;
mod envelope;
mod protocol;
mod signing;
mod vsock_server;

/// Vsock port the parent connects to. The parent listens on TCP 443
/// from the outside world and forwards each request body to us on this
/// port over the vsock socket.
const ENCLAVE_VSOCK_PORT: u32 = 5005;

/// Vsock CID the parent runs on (3 = parent of the running enclave).
/// Used when the enclave needs to call back to the parent (KMS proxy).
const PARENT_CID: u32 = 3;

/// Vsock port the parent's KMS-proxy listens on. The enclave sends
/// {attestation_doc, wrapped_dek} to this port; the parent calls
/// KMS Decrypt and returns the CiphertextForRecipient blob.
const PARENT_KMS_PROXY_PORT: u32 = 5006;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // The enclave console (--debug-mode) shows this output. In
    // production (non-debug enclaves) console output is suppressed.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rift_signer_enclave=debug".into()),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "rift-signer-enclave starting up"
    );

    // One-time NSM init. The driver creates a session against /dev/nsm.
    attestation::init().context("NSM init failed — is /dev/nsm present? Run inside a real enclave.")?;
    info!("NSM session initialized");

    // Listen for signing requests forever.
    vsock_server::serve(ENCLAVE_VSOCK_PORT, PARENT_CID, PARENT_KMS_PROXY_PORT)
        .await
        .map_err(|e| {
            error!(error = ?e, "vsock server terminated unexpectedly");
            e
        })?;

    Ok(())
}
