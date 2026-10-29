//! v1 envelope: AES-256-CBC decryption of the envelope payload.
//!
//! The backend's `utils/keyEncryption.ts` produces envelope blobs of
//! the form:
//!   enc:v1:<wrapped_dek_b64>:<iv_hex>:<ciphertext_hex>
//!
//! After KMS-attested decrypt produces the plaintext DEK, this module
//! turns the IV + ciphertext + DEK into the raw 32-byte EOA private key.
//!
//! # Padding-oracle hardening
//!
//! v1 is unauthenticated CBC. Whoever controls the ciphertext (the
//! backend / parent) can submit modified ciphertexts and observe the
//! result. If "bad padding", "not UTF-8", "not hex" and "wrong length"
//! were distinguishable (different error strings, or different code
//! paths with measurably different timing), that is a classic padding /
//! format oracle that recovers the plaintext private key byte by byte.
//!
//! So [`open_v1_private_key`] has exactly ONE failure value
//! ([`V1_OPEN_FAILED`]) and does the same work for every input of a
//! given (public) ciphertext length:
//!   - the CBC decrypt runs without the library's unpad step;
//!   - the PKCS#7 check is done branch-free over the whole last block;
//!   - the hex parse is branch-free over the whole candidate buffer;
//!   - all checks are folded into one flag that is tested once, at the
//!     very end.
//!
//! Residual: the candidate plaintext length (derived from the pad byte)
//! and the optional `0x`/whitespace stripping are still data-dependent
//! by a handful of byte comparisons. Each oracle query also costs a
//! fresh RSA-2048 keygen + KMS round trip inside the enclave (hundreds
//! of ms of jitter), which buries nanosecond-scale differences. The
//! real fix is to stop accepting v1 — see `V1_SIGNING_ENABLED`.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Build-time switch: accept v1 (KMS-only, unauthenticated AES-CBC)
/// envelopes on the SIGN path, and allow generate-wallet to mint new v1
/// envelopes.
///
/// Default `true` so existing v1 wallets keep signing. Once every v1
/// wallet has been migrated to v3 (`/migrate-envelope`, which keeps
/// working regardless of this flag so stragglers can still migrate),
/// flip this to `false` and rebuild: that removes the CBC oracle surface
/// from the sign path entirely. Changing it changes PCR0 (it is code).
pub const V1_SIGNING_ENABLED: bool = true;

/// The single error string for EVERY v1 decrypt/parse failure. Same
/// string the v2/v3 AEAD paths use for a tag failure, so a caller can't
/// even tell which envelope generation rejected the input.
pub const V1_OPEN_FAILED: &str = "invalid credentials";

const BLOCK: usize = 16;

/// Hex-decode, CBC-decrypt, PKCS#7-check and hex-parse a v1 payload in
/// one uniform pass. Returns the raw 32-byte EOA private key, or the
/// single opaque error [`V1_OPEN_FAILED`].
///
/// `iv_hex` / `ciphertext_hex` may carry a `0x` prefix (as before).
/// Plaintext accepted: optional surrounding ASCII whitespace, optional
/// `0x`, then exactly 64 hex digits (what `encryptKey(wallet.privateKey)`
/// and the enclave's own generate-wallet produce).
pub fn open_v1_private_key(
    dek: &[u8],
    iv_hex: &str,
    ciphertext_hex: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ok: u8 = 1;

    ok &= (dek.len() == 32) as u8;
    let mut key = Zeroizing::new([0u8; 32]);
    if dek.len() == 32 {
        key.copy_from_slice(dek);
    }

    let (iv_vec, iv_ok) = ct_hex_decode(iv_hex.trim_start_matches("0x").as_bytes());
    ok &= iv_ok & ((iv_vec.len() == BLOCK) as u8);
    let mut iv = [0u8; BLOCK];
    if iv_vec.len() == BLOCK {
        iv.copy_from_slice(&iv_vec);
    }

    let (mut buf, ct_ok) = ct_hex_decode(ciphertext_hex.trim_start_matches("0x").as_bytes());
    ok &= ct_ok;
    let ct_len_ok = (!buf.is_empty() && buf.len().is_multiple_of(BLOCK)) as u8;
    ok &= ct_len_ok;
    if ct_len_ok == 0 {
        // Keep the work shape identical-ish: decrypt a fixed dummy
        // buffer of the canonical v1 size (80 bytes) instead.
        buf = Zeroizing::new(vec![0u8; 5 * BLOCK]);
    }

    // CBC decrypt in place, no unpadding (the library unpad step returns
    // early on bad padding — exactly what we must not do).
    let dec = Aes256CbcDec::new((&*key).into(), (&iv).into());
    let decrypted_ok = dec.decrypt_padded_mut::<NoPadding>(&mut buf).is_ok() as u8;
    ok &= decrypted_ok;

    // Branch-free PKCS#7 check over the whole last block.
    let n = buf.len();
    let pad = buf[n - 1];
    let mut pad_ok: u8 = ct_ne_zero(pad) & ct_le(pad, BLOCK as u8);
    for i in 0..BLOCK {
        let byte = buf[n - 1 - i];
        // in_pad = (i < pad)
        let in_pad = ct_lt(i as u8, pad);
        let eq = ct_eq(byte, pad);
        // if in_pad then require eq
        pad_ok &= (!in_pad & 1) | eq;
    }
    ok &= pad_ok;
    // If the padding is bad, pretend pad=1 so the rest of the pipeline
    // still runs over (garbage) bytes of a valid length.
    let eff_pad = ct_select(pad_ok, pad, 1) as usize;
    let plain = &buf[..n - eff_pad];

    // Strip optional whitespace + `0x`. (Small data-dependent loop — see
    // module docs.)
    let trimmed = trim_ascii_ws(plain);
    let body = if trimmed.len() >= 2 && trimmed[0] == b'0' && (trimmed[1] | 0x20) == b'x' {
        &trimmed[2..]
    } else {
        trimmed
    };
    ok &= (body.len() == 64) as u8;

    // Always decode exactly 64 chars (from the body if it has them,
    // else from a zero window) so parse cost is constant.
    let zero_window = [b'0'; 64];
    let window: &[u8] = if body.len() == 64 { body } else { &zero_window };
    let (pk, pk_ok) = ct_hex_decode(window);
    ok &= pk_ok;

    let mut out = Zeroizing::new([0u8; 32]);
    if pk.len() == 32 {
        out.copy_from_slice(&pk);
    } else {
        ok = 0;
    }
    buf.iter_mut().for_each(|b| *b = 0);

    if std::hint::black_box(ok) == 1 {
        Ok(out)
    } else {
        Err(anyhow!(V1_OPEN_FAILED))
    }
}

// ─── branch-free helpers (u8 masks: 1 = true, 0 = false) ────────────

#[inline]
fn ct_eq(a: u8, b: u8) -> u8 {
    let x = (a ^ b) as u16;
    (((x.wrapping_sub(1)) >> 8) & 1) as u8
}
#[inline]
fn ct_ne_zero(a: u8) -> u8 {
    1 ^ ct_eq(a, 0)
}
#[inline]
fn ct_lt(a: u8, b: u8) -> u8 {
    (((a as u16).wrapping_sub(b as u16) >> 8) & 1) as u8
}
#[inline]
fn ct_le(a: u8, b: u8) -> u8 {
    1 ^ ct_lt(b, a)
}
#[inline]
fn ct_select(cond: u8, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(cond & 1);
    (a & mask) | (b & !mask)
}

/// Value of one hex digit and a validity flag, without branches on the
/// character value.
#[inline]
fn ct_hex_nibble(c: u8) -> (u8, u8) {
    let is_digit = ct_le(b'0', c) & ct_le(c, b'9');
    let lc = c | 0x20;
    let is_alpha = ct_le(b'a', lc) & ct_le(lc, b'f');
    let v_digit = c.wrapping_sub(b'0');
    let v_alpha = lc.wrapping_sub(b'a').wrapping_add(10);
    let v = ct_select(is_digit, v_digit, ct_select(is_alpha, v_alpha, 0));
    (v, is_digit | is_alpha)
}

/// Decode hex over the WHOLE input without early exit. Output length is
/// `len / 2` (a function of public length only); the flag says whether
/// every char was hex and the length even.
fn ct_hex_decode(s: &[u8]) -> (Zeroizing<Vec<u8>>, u8) {
    let mut ok = s.len().is_multiple_of(2) as u8;
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for pair in s.chunks_exact(2) {
        let (hi, ok_hi) = ct_hex_nibble(pair[0]);
        let (lo, ok_lo) = ct_hex_nibble(pair[1]);
        ok &= ok_hi & ok_lo;
        out.push((hi << 4) | lo);
    }
    (out, ok)
}

fn trim_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    const PK_HEX: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn seal(dek: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> String {
        let enc = Aes256CbcEnc::new(dek.into(), iv.into());
        hex::encode(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
    }

    fn expected_pk() -> [u8; 32] {
        hex::decode(PK_HEX).unwrap().try_into().unwrap()
    }

    /// Same crypto as backend keyEncryption.ts: AES-256-CBC/PKCS#7 over
    /// the UTF-8 "0x…" private key string.
    #[test]
    fn round_trip_0x_prefixed() {
        let dek = [0xAB; 32];
        let iv = [0xCD; 16];
        let ct = seal(&dek, &iv, format!("0x{PK_HEX}").as_bytes());
        let pk = open_v1_private_key(&dek, &hex::encode(iv), &ct).unwrap();
        assert_eq!(*pk, expected_pk());
    }

    #[test]
    fn round_trip_bare_hex_whitespace_and_0x_inputs() {
        let dek = [0x11; 32];
        let iv = [0x22; 16];
        for pt in [PK_HEX.to_string(), format!(" 0x{PK_HEX}\n"), format!("0X{}", PK_HEX.to_uppercase())] {
            let ct = seal(&dek, &iv, pt.as_bytes());
            let pk = open_v1_private_key(&dek, &format!("0x{}", hex::encode(iv)), &format!("0x{ct}")).unwrap();
            assert_eq!(*pk, expected_pk(), "{pt:?}");
        }
    }

    /// Every failure class must produce the byte-identical error string.
    #[test]
    fn all_failures_are_indistinguishable() {
        let dek = [0xAB; 32];
        let iv = [0xCD; 16];
        let iv_hex = hex::encode(iv);
        let good = seal(&dek, &iv, format!("0x{PK_HEX}").as_bytes());

        let mut bad_pad = hex::decode(&good).unwrap();
        let n = bad_pad.len();
        bad_pad[n - 17] ^= 0x01; // flips last plaintext byte → pad byte invalid
        let not_hex_pt = seal(&dek, &iv, b"0xzz0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        let short_pt = seal(&dek, &iv, b"0xabcd");
        let not_utf8_pt = seal(&dek, &iv, &[0xff; 66]);

        let cases: Vec<(&str, Vec<u8>, String, String)> = vec![
            ("wrong dek len", vec![0u8; 31], iv_hex.clone(), good.clone()),
            ("wrong dek", vec![0x01; 32], iv_hex.clone(), good.clone()),
            ("bad padding", dek.to_vec(), iv_hex.clone(), hex::encode(&bad_pad)),
            ("iv not hex", dek.to_vec(), "zz".repeat(16), good.clone()),
            ("iv wrong len", dek.to_vec(), "00".repeat(15), good.clone()),
            ("ct not hex", dek.to_vec(), iv_hex.clone(), "zz".repeat(48)),
            ("ct not block multiple", dek.to_vec(), iv_hex.clone(), "00".repeat(17)),
            ("ct empty", dek.to_vec(), iv_hex.clone(), String::new()),
            ("plaintext not hex", dek.to_vec(), iv_hex.clone(), not_hex_pt),
            ("plaintext too short", dek.to_vec(), iv_hex.clone(), short_pt),
            ("plaintext not utf8", dek.to_vec(), iv_hex.clone(), not_utf8_pt),
        ];
        for (name, k, ivh, cth) in cases {
            let err = open_v1_private_key(&k, &ivh, &cth).unwrap_err();
            assert_eq!(format!("{err:#}"), V1_OPEN_FAILED, "{name}");
        }
    }

    #[test]
    fn helper_masks() {
        for a in 0..=255u8 {
            for b in [0u8, 1, 15, 16, 17, 200, 255] {
                assert_eq!(ct_eq(a, b), (a == b) as u8);
                assert_eq!(ct_lt(a, b), (a < b) as u8);
                assert_eq!(ct_le(a, b), (a <= b) as u8);
            }
            let (v, ok) = ct_hex_nibble(a);
            let expect = (a as char).to_digit(16);
            assert_eq!(ok == 1, expect.is_some(), "{a}");
            if let Some(d) = expect {
                assert_eq!(v as u32, d);
            }
        }
    }
}
