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
