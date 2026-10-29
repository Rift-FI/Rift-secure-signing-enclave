# Multi-stage build for the Rift signing enclave.
#
# Stage 1 compiles the enclave binary from the Cargo workspace.
# Stage 2 is the minimal runtime image that becomes the enclave: just
# the enclave binary on a slim glibc base. Nothing is apt-installed in
# the runtime stage, so the measured image (PCR0) depends only on the
# pinned base image + our binary.
#
# DETERMINISM NOTES
#   - The builder image tag matches rust-toolchain.toml EXACTLY
#     (1.92.0). rust-toolchain.toml is also copied in, so if the two
#     ever drift rustup would fetch 1.92.0 anyway — keep them equal so
#     no toolchain download happens at build time.
#   - `cargo build --locked`: the committed Cargo.lock is authoritative;
#     a stale lock fails the build instead of silently resolving new
#     dependency versions (which would change PCR0 without review).
#     Commit Cargo.toml + Cargo.lock together.
#   - Release profile: fat LTO, 1 codegen unit, stripped (Cargo.toml).
#   - Base images are referenced by tag. For a fully reproducible EIF,
#     pin both FROM lines by digest (`image:tag@sha256:...`); obtain the
#     digests with `docker buildx imagetools inspect <image:tag>` on the
#     build host and record them in the same commit as the approved PCR0
#     (see prod-automation/README.md "Enclave release approval").
#
# Build (on the EC2):
#   make eif && make pcr0
#
# Note the PCR0 measurement nitro-cli prints — that's what we pin in
# the KMS key policy (via the approved-PCR0 SSM parameter).

# ─── Stage 1: build ──────────────────────────────────────────────────
FROM rust:1.92.0-bookworm AS builder

# Builder-only tooling (not part of the measured runtime image). The
# enclave links OpenSSL statically (`openssl/vendored`), so these
# packages do not end up in the binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace manifests first for docker layer caching of deps.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY enclave/Cargo.toml enclave/Cargo.toml
COPY parent-proxy/Cargo.toml parent-proxy/Cargo.toml
COPY enclave/src enclave/src
COPY parent-proxy/src parent-proxy/src

# Build ONLY the enclave binary for this image — parent-proxy is built
# separately and runs on the EC2 host outside the enclave. Default
# features only: never `dev-localhost` for an EIF.
RUN cargo build --locked --release --bin rift-signer-enclave

# Verify the binary exists.
RUN ls -la /build/target/release/rift-signer-enclave

# ─── Stage 2: enclave runtime ────────────────────────────────────────
# bookworm-slim already ships glibc + libgcc_s, which is all the
# binary needs. The enclave has no network and does no TLS (JWKS are
# pinned in the binary), so no CA bundle is required; none is
# installed, which also removes the old unpinned `apt-get install` from
# the measured image.
FROM debian:bookworm-slim

COPY --from=builder /build/target/release/rift-signer-enclave /usr/local/bin/rift-signer-enclave

ENTRYPOINT ["/usr/local/bin/rift-signer-enclave"]
