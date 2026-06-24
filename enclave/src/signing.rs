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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    // Known test vector: Hardhat's account 0 (well-known dev key).
    // ANYONE seeing this knows it — never reuse on a live chain.
    const TEST_PRIVKEY: [u8; 32] = [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ];
    const TEST_HASH: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
        0x67, 0x89,
    ];

    #[test]
    fn signs_and_recovers_pubkey() {
        let sig = sign_user_op_hash(&TEST_PRIVKEY, &TEST_HASH).expect("sign");
        assert_eq!(sig.len(), 65, "sig must be 65 bytes (r, s, v)");
        // v ∈ {27, 28}
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27 or 28");

        // Verify the signature against the public key.
        let signing_key = SigningKey::from_bytes((&TEST_PRIVKEY).into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        let sig_obj = Signature::from_slice(&sig[0..64]).unwrap();
        verifying_key
            .verify_prehash(&TEST_HASH, &sig_obj)
            .expect("signature must verify");
    }

    #[test]
    fn rejects_short_key() {
        let bad_key = [0u8; 31];
        let result = sign_user_op_hash(&bad_key, &TEST_HASH);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn rejects_zero_key() {
        let zero_key = [0u8; 32];
        let result = sign_user_op_hash(&zero_key, &TEST_HASH);
        // k256 rejects the all-zeros private key.
        assert!(result.is_err());
    }
}
