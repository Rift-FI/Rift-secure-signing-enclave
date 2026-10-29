//! Vsock wire framing shared by both directions of the parent↔enclave
//! channel.
//!
//! Frame format (FROZEN — must match `enclave/src/vsock_server.rs`):
//!   - 4-byte big-endian `u32` length prefix
//!   - that many bytes of UTF-8 JSON
//!
//! One request frame → one response frame per connection.
//!
//! Generic over `AsyncRead` / `AsyncWrite` so the framing logic compiles
//! and is unit-tested on every platform, not just on the Linux host
//! where `tokio_vsock::VsockStream` exists.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame body we accept from a peer. Matches the enclave's own
/// limit so neither side can be made to allocate unbounded memory.
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// Read one length-prefixed frame. Rejects frames above
/// [`MAX_FRAME_LEN`] before allocating the body buffer.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame too large: {len} bytes (max 1 MiB)");
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read frame body")?;
    Ok(body)
}

/// Write one length-prefixed frame and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(stream: &mut W, body: &[u8]) -> Result<()> {
    // Previously `body.len() as u32`, which would silently truncate the
    // prefix for a >4 GiB body and desynchronise the stream. Unreachable
    // in practice, but there is no reason to keep a truncating cast on a
    // wire boundary.
    let len = u32::try_from(body.len())
        .with_context(|| format!("frame body too large to encode: {} bytes", body.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("write length prefix")?;
    stream.write_all(body).await.context("write frame body")?;
    stream.flush().await.context("flush")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let payload = br#"{"hello":"enclave"}"#.to_vec();
        write_frame(&mut a, &payload).await.unwrap();
        let got = read_frame(&mut b).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn wire_layout_is_big_endian_length_prefix() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"abc").await.unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        assert_eq!(raw, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[tokio::test]
    async fn empty_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"").await.unwrap();
        assert!(read_frame(&mut b).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let too_big = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        a.write_all(&too_big).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("frame too large"), "{err}");
    }

    #[tokio::test]
    async fn accepts_frame_at_exact_limit() {
        let (mut a, mut b) = tokio::io::duplex(MAX_FRAME_LEN + 8);
        let body = vec![b'x'; MAX_FRAME_LEN];
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &body).await.unwrap();
        });
        let got = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got.len(), MAX_FRAME_LEN);
    }

    #[tokio::test]
    async fn truncated_body_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"short").await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}
