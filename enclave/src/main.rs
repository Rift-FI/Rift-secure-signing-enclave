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
//!
//! Platform note: this binary only does useful work on Linux (NSM and
//! vsock are Linux-only kernel features). On other platforms it
//! compiles so `cargo check` / `cargo test` work for the portable
//! crypto modules (`signing`, `envelope`, `protocol`) during local
//! development, but `main()` exits immediately with a friendly hint.

mod envelope;
mod envelope_v2;
mod envelope_v3;
mod oidc_verification;
mod password_derivation;
mod pinned_jwks;
mod protocol;
mod reseal_helpers;
mod signing;
mod webauthn_verification;

#[cfg(target_os = "linux")]
mod attestation;
#[cfg(target_os = "linux")]
mod vsock_server;

#[cfg(target_os = "linux")]
mod linux_main {
    use super::{attestation, vsock_server};
    use anyhow::Context;
    use tracing::{error, info};

    /// Vsock port the parent connects to for signing requests.
    pub const ENCLAVE_VSOCK_PORT: u32 = 5005;
    /// Vsock CID the parent runs on (3 = parent of running enclave).
    pub const PARENT_CID: u32 = 3;
    /// Vsock port the parent's KMS-proxy listens on.
    pub const PARENT_KMS_PROXY_PORT: u32 = 5006;
    /// Phase 2 — vsock port for wallet-generation requests. Separate
    /// from the sign port so a hung sign connection can't starve account
    /// creation and vice versa.
    pub const ENCLAVE_GENERATE_WALLET_PORT: u32 = 5007;
    /// Phase 3 — vsock port for v1/v2 → v3 envelope migration.
    /// Separate again so a stuck migration cannot starve sign or
    /// account creation.
    pub const ENCLAVE_MIGRATE_PORT: u32 = 5008;
    /// Phase 3 — vsock port for v3 envelope reseal (add/remove auth
    /// methods without changing the EOA key). Separate loop so a
    /// stuck reseal cannot block signing or account creation.
    pub const ENCLAVE_RESEAL_PORT: u32 = 5009;

    pub async fn run() -> anyhow::Result<()> {
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

        attestation::init().context("NSM init failed — is /dev/nsm present? Run inside a real enclave.")?;
        info!("NSM session initialized");

        vsock_server::serve(
            ENCLAVE_VSOCK_PORT,
            ENCLAVE_GENERATE_WALLET_PORT,
            ENCLAVE_MIGRATE_PORT,
            ENCLAVE_RESEAL_PORT,
            PARENT_CID,
            PARENT_KMS_PROXY_PORT,
        )
        .await
        .map_err(|e| {
            error!(error = ?e, "vsock server terminated unexpectedly");
            e
        })?;

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_main::run().await
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "rift-signer-enclave is a Linux-only binary (requires /dev/nsm + vsock).\n\
             You can run `cargo check` and `cargo test` on this platform for the\n\
             portable crypto modules (signing, envelope, protocol), but the real\n\
             binary must be built and run on the EC2.\n\
             \n\
             To build the enclave image: ssh to the EC2, `git pull`, `make eif`."
        );
        std::process::exit(2);
    }
}
