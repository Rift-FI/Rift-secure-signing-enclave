# Multi-stage build for the Rift signing enclave.
#
# Stage 1 compiles the enclave binary from the Cargo workspace.
# Stage 2 is the minimal runtime image that becomes the enclave: the
# enclave binary plus CA certs.
#
# DETERMINISM NOTE: rust-toolchain.toml pins the compiler, and the
# release profile is configured for whole-program optimization + single
# codegen unit so the resulting binary is byte-for-byte reproducible
# across builds on the same architecture. That's what keeps PCR0 stable.
#
# Build (on the c6g.large EC2):
#   docker build -t rift-signer-enclave:latest -f Dockerfile .
#   nitro-cli build-enclave \
#     --docker-uri rift-signer-enclave:latest \
#     --output-file rift-signer.eif
#
# Note the PCR0 measurement nitro-cli prints — that's what we pin in
# the KMS key policy.

# ─── Stage 1: build ──────────────────────────────────────────────────
FROM rust:1.83-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace manifests first for docker layer caching of deps.
COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
COPY enclave/Cargo.toml enclave/Cargo.toml
COPY parent-proxy/Cargo.toml parent-proxy/Cargo.toml
COPY enclave/src enclave/src
COPY parent-proxy/src parent-proxy/src

# Build ONLY the enclave binary for this image — parent-proxy is built
# separately and runs on the EC2 host outside the enclave.
RUN cargo build --release --locked --bin rift-signer-enclave

# Verify the binary exists.
RUN ls -la /build/target/release/rift-signer-enclave

# ─── Stage 2: enclave runtime ────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rift-signer-enclave /usr/local/bin/rift-signer-enclave

ENTRYPOINT ["/usr/local/bin/rift-signer-enclave"]
