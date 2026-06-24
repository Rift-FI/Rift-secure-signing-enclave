//! secp256k1 ECDSA signing of the Safe UserOperation hash.
//!
//! The actual Safe + ERC-4337 UserOp construction (call encoding, gas
//! estimation, paymaster data, EIP-712 typed-data hashing) happens in
//! the parent process (Node, in the existing smart-wallet). We receive
//! the 32-byte hash to sign and produce a 65-byte signature.
//!
//! The signature format is the Ethereum-canonical (r, s, v):
//!   bytes 0..32  : r
//!   bytes 32..64 : s
//!   byte 64      : v ∈ {27, 28}
//!
//! v is recovered from the signature so the verifier can derive the
//! public key (and hence the EOA address) from the hash + signature
//! alone, no separate public key required.

use anyhow::{anyhow, Result};
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use zeroize::Zeroizing;

/// Sign a 32-byte hash with the given secp256k1 private key, producing
/// the 65-byte (r, s, v) signature.
///
/// `private_key_bytes` is the raw 32-byte secp256k1 private key —
/// NOT a hex string. Caller converts from hex first.
pub fn sign_user_op_hash(
    private_key_bytes: &[u8],
    user_op_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 65]>> {
    if private_key_bytes.len() != 32 {
        return Err(anyhow!(
            "private key must be 32 bytes, got {}",
            private_key_bytes.len()
        ));
    }

    let signing_key = SigningKey::from_bytes(private_key_bytes.into())
        .map_err(|e| anyhow!("invalid secp256k1 private key: {:?}", e))?;

    // sign_prehash: take an already-hashed 32-byte message. The Safe
    // UserOp hash IS the prehash — we'd corrupt it if we hashed again.
    let (signature, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash(user_op_hash)
        .map_err(|e| anyhow!("secp256k1 signing failed: {:?}", e))?;

    let mut output = Zeroizing::new([0u8; 65]);
    let sig_bytes = signature.to_bytes();
    output[0..64].copy_from_slice(&sig_bytes);
    // Ethereum v = recovery_id + 27.
    output[64] = u8::from(recovery_id) + 27;
    Ok(output)
}
