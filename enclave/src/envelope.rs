//! AES-256-CBC decryption of the envelope payload.
//!
//! The backend's `utils/keyEncryption.ts` produces envelope blobs of
//! the form:
//!   enc:v1:<wrapped_dek_b64>:<iv_hex>:<ciphertext_hex>
//!
//! The parent splits this and hands each part to us. After KMS-attested
//! decrypt produces the plaintext DEK, this module turns the IV +
//! ciphertext + DEK into the plaintext EOA private key string.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Decrypt the AES-256-CBC ciphertext using the freshly-unwrapped DEK.
/// Returns the plaintext as a Zeroizing<Vec<u8>>; the caller is
/// responsible for parsing it into a hex string and feeding it to the
/// signer.
pub fn decrypt(
    dek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if dek.len() != 32 {
        return Err(anyhow!("DEK must be 32 bytes (AES-256), got {}", dek.len()));
    }
    if iv.len() != 16 {
        return Err(anyhow!("IV must be 16 bytes (AES block), got {}", iv.len()));
    }

    let decryptor = Aes256CbcDec::new(dek.into(), iv.into());
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow!("AES-CBC decrypt failed: {:?}", e))
        .context("envelope ciphertext decryption")?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// Round-trip: encrypt a known plaintext, decrypt it back. This is
    /// the same crypto the backend's keyEncryption.ts uses, so a green
    /// test here proves we'll be compatible with envelopes the backend
    /// writes.
    #[test]
    fn round_trip_known_plaintext() {
        let dek = [0xAB; 32]; // arbitrary 256-bit DEK
        let iv = [0xCD; 16]; // arbitrary 128-bit IV
        let plaintext = b"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let encryptor = Aes256CbcEnc::new(&dek.into(), &iv.into());
        let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let recovered = decrypt(&dek, &iv, &ciphertext).expect("decrypt");
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[test]
    fn rejects_wrong_dek_length() {
        let bad_dek = [0u8; 31];
        let iv = [0u8; 16];
        let cipher = [0u8; 32];
        let result = decrypt(&bad_dek, &iv, &cipher);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn rejects_wrong_iv_length() {
        let dek = [0u8; 32];
        let bad_iv = [0u8; 15];
        let cipher = [0u8; 32];
        let result = decrypt(&dek, &bad_iv, &cipher);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("16 bytes"));
    }

    #[test]
    fn rejects_corrupted_ciphertext() {
        let dek = [0xAB; 32];
        let iv = [0xCD; 16];
        let bad_ciphertext = [0u8; 32];
        let result = decrypt(&dek, &iv, &bad_ciphertext);
        // PKCS7 padding check should reject this.
        assert!(result.is_err());
    }
}
