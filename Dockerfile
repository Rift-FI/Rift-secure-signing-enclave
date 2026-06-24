# Multi-stage build for the Rift signing enclave.
#
# Stage 1 compiles the Rust binary. Stage 2 is the minimal runtime
# image that becomes the enclave: just our static binary plus the few
# bits of /etc the Nitro Enclaves loader needs.
#
# DETERMINISM NOTE: the toolchain version is pinned in
# rust-toolchain.toml, and the release profile is configured for
# whole-program optimization + single codegen unit so the resulting
# binary is byte-for-byte reproducible across builds on the same
# architecture. That's what keeps PCR0 stable.
#
# Build (on the c6g.large EC2):
#   docker build -t rift-signer-enclave:latest .
#   nitro-cli build-enclave \
#     --docker-uri rift-signer-enclave:latest \
#     --output-file rift-signer.eif
#
# Note the PCR0 measurement nitro-cli prints — that's what we'll pin in
# the KMS key policy.

# ─── Stage 1: build ──────────────────────────────────────────────────
FROM rust:1.83-bookworm AS builder

# System deps required to compile our crates (rsa needs openssl headers
# transitively; aws-nitro-enclaves-nsm-api builds against ioctl).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first so docker can cache the dependency build layer
# when only source files change.
COPY Cargo.toml Cargo.lock* rust-toolchain.toml ./
COPY src ./src

# Build the release binary. The --locked guard fails the build if
# Cargo.lock would change — keeps PCR0 stable.
RUN cargo build --release --locked

# Sanity-check the binary is present, statically what we expect.
RUN ls -la /build/target/release/rift-signer-enclave \
    && file /build/target/release/rift-signer-enclave

# ─── Stage 2: enclave runtime ────────────────────────────────────────
# Use the smallest base that still has glibc + ca-certs. distroless/cc
# gives ~20 MiB; alpine + musl needs us to rebuild with musl-target.
# Sticking with debian-slim for simplicity; image is ~80 MiB.
FROM debian:bookworm-slim

# Just CA certs (no networking needed inside enclave — but rustls/openssl
# might still touch the trust store on init).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rift-signer-enclave /usr/local/bin/rift-signer-enclave

# The Nitro Enclaves loader invokes this as PID 1 inside the enclave.
ENTRYPOINT ["/usr/local/bin/rift-signer-enclave"]
