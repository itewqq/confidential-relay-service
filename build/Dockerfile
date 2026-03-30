# Reproducible build for Trusted Relay.
#
# To build:
#   docker build -f build/Dockerfile -t trusted-relay .
#
# To extract the binary:
#   docker cp $(docker create trusted-relay):/usr/local/bin/trusted-relay-server ./trusted-relay-server
#
# To compute measurement (MRTD) for attestation verification:
#   sha384sum trusted-relay-server

# Pin every dependency for reproducibility.
FROM rust:1.82.0-bookworm AS builder

WORKDIR /src

# Copy manifests first for better layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/relay-attest/Cargo.toml crates/relay-attest/Cargo.toml
COPY crates/relay-tls/Cargo.toml crates/relay-tls/Cargo.toml
COPY crates/relay-core/Cargo.toml crates/relay-core/Cargo.toml
COPY crates/relay-sdk/Cargo.toml crates/relay-sdk/Cargo.toml
COPY server/Cargo.toml server/Cargo.toml

# Create stub source files so cargo can resolve deps.
RUN mkdir -p crates/relay-attest/src crates/relay-tls/src crates/relay-core/src crates/relay-sdk/src server/src && \
    echo "pub fn stub(){}" > crates/relay-attest/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-tls/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-core/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-sdk/src/lib.rs && \
    echo "fn main(){}" > server/src/main.rs

# Pre-build dependencies (cached layer).
RUN cargo build --release --target x86_64-unknown-linux-gnu -p trusted-relay-server 2>/dev/null || true

# Now copy real source and build.
COPY crates/ crates/
COPY server/ server/

# Touch source files to invalidate the stub build cache.
RUN touch crates/relay-attest/src/lib.rs crates/relay-tls/src/lib.rs \
    crates/relay-core/src/lib.rs crates/relay-sdk/src/lib.rs \
    server/src/main.rs

# Deterministic build flags.
ENV RUSTFLAGS="-C link-arg=-Wl,--build-id=none -C debuginfo=0"

RUN cargo build --release --target x86_64-unknown-linux-gnu -p trusted-relay-server && \
    cp target/x86_64-unknown-linux-gnu/release/trusted-relay-server /usr/local/bin/

# --- Runtime image (minimal) ---
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /usr/local/bin/trusted-relay-server /usr/local/bin/trusted-relay-server

# No shell, no SSH, no unnecessary tools — minimal attack surface.
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/trusted-relay-server"]
