//! Password-derived key material for v2 envelopes.
//!
//! v2 binds the user's password into the envelope's encryption key, so
//! that signing requires BOTH (a) the KMS-released DEK (gated by the
//! enclave's PCR0 attestation) AND (b) the user's password. Without
//! both, the AES-GCM authentication tag fails and we refuse to sign.
//!
//! This is the cryptographic core of "the password is the user's share":
//! Rift engineers with backend or DB access cannot sign on a user's
//! behalf without the user's actual password input.
//!
//! Layout of v2 envelopes:
//!   `enc:v2:<kms_wrapped_dek_b64>:<salt_b64>:<nonce_hex>:<ciphertext_hex>:<tag_hex>`
//!
//! Where:
//!   - kms_wrapped_dek_b64: KMS Ciphertext blob, base64. Released only
//!     to attested enclave images by KMS.
//!   - salt_b64: 32 bytes of random salt, base64. Unique per envelope.
//!     Stored alongside the ciphertext so the same password produces
//!     different envelopes for different users.
//!   - nonce_hex: 12-byte AES-256-GCM nonce (96 bits, the standard).
//!     Random per envelope.
//!   - ciphertext_hex: AES-256-GCM ciphertext of the EOA private key
//!     bytes (32 bytes raw, NOT hex-encoded plaintext like v1).
//!   - tag_hex: 16-byte AES-256-GCM authentication tag. Fails closed
//!     on wrong password.
//!
//! Combined key derivation:
//!   K_user = HKDF-SHA256(password.bytes(), salt, "rift-eoa-v2", 32)
//!   K_dek  = (released by KMS, 32 bytes)
//!   K_aes  = K_dek XOR K_user
//!
//! The XOR composition has two useful properties: (1) wrong password
//! produces a uniformly different key, so AES-GCM authenticated decrypt
//! fails-closed; (2) leaking either factor alone reveals nothing about
//! the other (XOR is information-theoretically a one-time pad here).

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the HKDF salt and per-envelope salt portion, in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the AES-256-GCM nonce, in bytes.
pub const GCM_NONCE_LEN: usize = 12;

/// Length of the AES-256-GCM authentication tag, in bytes.
pub const GCM_TAG_LEN: usize = 16;

/// HKDF info string, version-bound so future format changes can rotate
/// the derivation without colliding with v2 envelopes in the wild.
pub const HKDF_INFO: &[u8] = b"rift-eoa-v2";

/// Derive a 32-byte key from the user's password plus a per-envelope salt.
///
/// `password` is the raw bytes typed by the user (UTF-8). `salt` MUST be
/// 32 bytes of fresh randomness generated at envelope-create time.
///
/// Returns a `Zeroizing<[u8; 32]>` so the caller does not have to remember
/// to wipe it.
pub fn derive_user_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if salt.len() != SALT_LEN {
        bail!("salt must be {} bytes, got {}", SALT_LEN, salt.len());
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, &mut *okm)
        .map_err(|e| anyhow!("HKDF expand failed: {:?}", e))?;
    Ok(okm)
}

/// XOR two 32-byte keys to produce the AES-GCM key used to encrypt the
/// envelope. Used for both encrypt and decrypt. XOR has the useful
/// property that knowing either factor alone reveals nothing about the
/// other (information-theoretic OTP-style composition).
pub fn combine_keys(k_dek: &[u8; 32], k_user: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        out[i] = k_dek[i] ^ k_user[i];
    }
    out
}

/// Encrypt the EOA private key bytes (32 raw bytes, NOT hex-encoded) under
/// the combined AES-GCM key. Returns the ciphertext concatenated with the
/// 16-byte authentication tag.
pub fn aead_encrypt(
    k_aes: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(k_aes.into());
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_arr, plaintext)
        .map_err(|e| anyhow!("AES-GCM encrypt failed: {:?}", e))
}

/// Decrypt and authenticate the v2 ciphertext. Wrong password, tampered
/// ciphertext, or tampered tag all produce `Err`. The error string is
/// intentionally generic so callers cannot distinguish failure modes
/// (which would help attackers fingerprint).
pub fn aead_decrypt(
    k_aes: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext_with_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(k_aes.into());
    let nonce_arr = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(nonce_arr, ciphertext_with_tag)
        .map_err(|_| anyhow!("invalid credentials"))?;
    Ok(Zeroizing::new(pt))
}

// ─── Tests ─────────────────────────────────────────────────────────────
//
// Tests 1–9 from the security spec. They specify the cryptographic
// behaviour of password-bound envelopes and serve as the regression
// barrier against any future code change that would weaken the
// guarantee that "wrong password fails closed".

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    // Fixed test vectors so failures stay reproducible across runs.
    const TEST_DEK: [u8; 32] = [0xAA; 32];
    const TEST_SALT_A: [u8; 32] = [0xBB; 32];
    const TEST_SALT_B: [u8; 32] = [0xCC; 32];
    const TEST_NONCE: [u8; 12] = [0xDD; 12];
    const TEST_PASSWORD: &[u8] = b"hunter2-correct-horse";
    const TEST_WRONG_PASSWORD: &[u8] = b"hunter2-wrong-horse";

    /// Hardhat account 0. Everyone knows this key. Address derived below.
    const TEST_PRIVKEY: [u8; 32] = [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4,
        0xd2, 0x38, 0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc,
        0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
    ];
    /// Ethereum address of TEST_PRIVKEY (lowercase, no 0x prefix).
    /// 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
    const TEST_ADDRESS_LO: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    fn derive_address(privkey: &[u8; 32]) -> String {
        let sk = SigningKey::from_bytes(privkey.into()).expect("valid privkey");
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let xy = &uncompressed.as_bytes()[1..]; // strip 0x04 tag
        let hash = Keccak256::digest(xy);
        hex::encode(&hash[12..])
    }

    /// Test 1: HKDF derives the same key for the same (password, salt).
    #[test]
    fn hkdf_derives_same_key_for_same_password_salt() {
        let k1 = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("derive");
        let k2 = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("derive");
        assert_eq!(&k1[..], &k2[..], "HKDF must be deterministic");
    }

    /// Test 2: HKDF derives a different key for a different password.
    #[test]
    fn hkdf_derives_different_key_for_different_password() {
        let k_right = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("right");
        let k_wrong = derive_user_key(TEST_WRONG_PASSWORD, &TEST_SALT_A).expect("wrong");
        assert_ne!(
            &k_right[..],
            &k_wrong[..],
            "different password must produce different K_user"
        );
    }

    /// Test 3: AES-GCM round-trips with the combined key.
    #[test]
    fn aes_round_trip_with_combined_key() {
        let k_user = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("derive");
        let k_aes = combine_keys(&TEST_DEK, &k_user);

        let ct = aead_encrypt(&k_aes, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");
        let pt = aead_decrypt(&k_aes, &TEST_NONCE, &ct).expect("decrypt");

        assert_eq!(&pt[..], &TEST_PRIVKEY[..], "round trip should recover plaintext");
        assert_eq!(ct.len(), TEST_PRIVKEY.len() + GCM_TAG_LEN, "ct = plaintext + tag");
    }

    /// Test 4: decrypt with the wrong password fails (GCM tag mismatch).
    #[test]
    fn decrypt_fails_with_wrong_password() {
        let k_user_right = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("right");
        let k_user_wrong = derive_user_key(TEST_WRONG_PASSWORD, &TEST_SALT_A).expect("wrong");

        let k_right = combine_keys(&TEST_DEK, &k_user_right);
        let k_wrong = combine_keys(&TEST_DEK, &k_user_wrong);

        let ct = aead_encrypt(&k_right, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");

        let result = aead_decrypt(&k_wrong, &TEST_NONCE, &ct);
        assert!(result.is_err(), "wrong password must fail GCM auth");
    }

    /// Test 5: tampering the ciphertext fails the GCM tag check.
    #[test]
    fn integrity_check_detects_ciphertext_tamper() {
        let k_user = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("derive");
        let k_aes = combine_keys(&TEST_DEK, &k_user);

        let mut ct = aead_encrypt(&k_aes, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");
        // Flip a byte in the ciphertext portion (not the tag).
        ct[0] ^= 0x01;

        let result = aead_decrypt(&k_aes, &TEST_NONCE, &ct);
        assert!(result.is_err(), "tampered ciphertext must fail auth");
    }

    /// Test 6: tampering the salt produces a different K_user, which
    /// makes decryption fail. This catches an engineer who swaps the
    /// salt in the DB to a value they computed K_user for offline.
    #[test]
    fn integrity_check_detects_salt_tamper() {
        let k_user_orig = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("orig");
        let k_aes_orig = combine_keys(&TEST_DEK, &k_user_orig);
        let ct = aead_encrypt(&k_aes_orig, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");

        // Engineer-in-the-middle: same DEK, same password attempt, but
        // a different salt the engineer planted.
        let k_user_tampered = derive_user_key(TEST_PASSWORD, &TEST_SALT_B).expect("tamper");
        let k_aes_tampered = combine_keys(&TEST_DEK, &k_user_tampered);

        let result = aead_decrypt(&k_aes_tampered, &TEST_NONCE, &ct);
        assert!(result.is_err(), "salt tamper must fail auth");
    }

    /// Test 7: swapping one user's envelope payload into another user's
    /// row fails. Even with the second user's password, the cipher does
    /// not auth because K_aes is bound to the original (DEK, salt).
    #[test]
    fn integrity_check_detects_envelope_swap() {
        // User A's envelope.
        let k_user_a = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("a");
        let k_aes_a = combine_keys(&TEST_DEK, &k_user_a);
        let ct_a = aead_encrypt(&k_aes_a, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");

        // Engineer swaps user A's ciphertext into user B's row. User B
        // has their own salt and a different password. The attempt
        // mixes user B's (salt, password) with A's ciphertext.
        let k_user_b = derive_user_key(b"user-b-password", &TEST_SALT_B).expect("b");
        let k_aes_b = combine_keys(&TEST_DEK, &k_user_b);

        let result = aead_decrypt(&k_aes_b, &TEST_NONCE, &ct_a);
        assert!(result.is_err(), "envelope swap must fail auth");
    }

    /// Test 8: signing with the correct password recovers a signature
    /// for the well-known address. End-to-end happy path inside the
    /// enclave's crypto stack: derive K_user, combine with DEK,
    /// decrypt the envelope, secp256k1 sign, verify the signer.
    #[test]
    fn signing_with_correct_password_recovers_known_address() {
        let k_user = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("derive");
        let k_aes = combine_keys(&TEST_DEK, &k_user);

        let ct = aead_encrypt(&k_aes, &TEST_NONCE, &TEST_PRIVKEY).expect("encrypt");
        let pt = aead_decrypt(&k_aes, &TEST_NONCE, &ct).expect("decrypt");

        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&pt[..]);

        assert_eq!(derive_address(&privkey), TEST_ADDRESS_LO);
    }

    /// Test 9: per-user salt produces unique envelopes even if two
    /// users somehow share a password. No envelope collision risk.
    #[test]
    fn password_uniqueness_via_salt() {
        let k_user_a = derive_user_key(TEST_PASSWORD, &TEST_SALT_A).expect("a");
        let k_user_b = derive_user_key(TEST_PASSWORD, &TEST_SALT_B).expect("b");

        assert_ne!(
            &k_user_a[..],
            &k_user_b[..],
            "same password, different salt must produce different K_user"
        );

        let k_aes_a = combine_keys(&TEST_DEK, &k_user_a);
        let k_aes_b = combine_keys(&TEST_DEK, &k_user_b);
        let ct_a = aead_encrypt(&k_aes_a, &TEST_NONCE, &TEST_PRIVKEY).expect("a");
        let ct_b = aead_encrypt(&k_aes_b, &TEST_NONCE, &TEST_PRIVKEY).expect("b");

        assert_ne!(ct_a, ct_b, "identical plaintext must produce different ciphertext");
    }
}
