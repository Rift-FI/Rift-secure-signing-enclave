//! Parent → enclave request forwarding over vsock.

use anyhow::Result;
use serde_json::Value;

/// Where the enclave's listeners live. Each operation has its own vsock
/// port so a hung request of one kind cannot starve the others (the
/// enclave runs an independent accept loop per port).
#[derive(Clone, Copy, Debug)]
pub struct EnclaveEndpoints {
    pub cid: u32,
    pub sign_port: u32,
    pub generate_wallet_port: u32,
    pub migrate_port: u32,
    pub reseal_port: u32,
    /// Health / canary port (5010). Additive: older enclave images
    /// don't listen here, so `/health/enclave` returns 502 against them.
    pub health_port: u32,
}

/// Send one JSON request frame to the enclave on `port` and return its
/// JSON response frame.
#[cfg(target_os = "linux")]
pub async fn forward(cid: u32, port: u32, body: &Value) -> Result<Value> {
    use anyhow::Context;
    use tokio_vsock::{VsockAddr, VsockStream};

    use crate::framing::{read_frame, write_frame};

    let mut stream = VsockStream::connect(VsockAddr::new(cid, port))
        .await
        .with_context(|| format!("vsock connect to enclave at cid={cid} port={port}"))?;
    let payload = serde_json::to_vec(body)?;
    write_frame(&mut stream, &payload).await?;
    let resp_bytes = read_frame(&mut stream).await?;
    Ok(serde_json::from_slice(&resp_bytes)?)
}

/// Non-Linux builds have no vsock; every forward fails. This keeps the
/// HTTP layer compiling (and unit-testable) on dev laptops.
#[cfg(not(target_os = "linux"))]
pub async fn forward(_cid: u32, _port: u32, _body: &Value) -> Result<Value> {
    anyhow::bail!("parent proxy only runs on Linux")
}
