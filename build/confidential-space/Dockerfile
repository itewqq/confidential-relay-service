# Trusted Relay production container for Google Cloud Confidential Space.
# The workload identity is the immutable image digest/signature in the
# Confidential Space attestation token, not a raw SEV-SNP MEASUREMENT.

FROM mirror.gcr.io/library/rust:1.95.0-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates/relay-attest/Cargo.toml crates/relay-attest/Cargo.toml
COPY crates/relay-tls/Cargo.toml crates/relay-tls/Cargo.toml
COPY crates/relay-core/Cargo.toml crates/relay-core/Cargo.toml
COPY crates/relay-secret/Cargo.toml crates/relay-secret/Cargo.toml
COPY crates/relay-sdk/Cargo.toml crates/relay-sdk/Cargo.toml
COPY server/Cargo.toml server/Cargo.toml
COPY tools/online-check/Cargo.toml tools/online-check/Cargo.toml
COPY tools/secret-broker/Cargo.toml tools/secret-broker/Cargo.toml
COPY tools/gateway/Cargo.toml tools/gateway/Cargo.toml
COPY tools/local-proxy/Cargo.toml tools/local-proxy/Cargo.toml

RUN mkdir -p crates/relay-attest/src crates/relay-tls/src crates/relay-core/src \
    crates/relay-secret/src crates/relay-sdk/src server/src tools/online-check/src \
    tools/secret-broker/src tools/gateway/src tools/local-proxy/src && \
    echo "pub fn stub(){}" > crates/relay-attest/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-tls/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-core/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-secret/src/lib.rs && \
    echo "pub fn stub(){}" > crates/relay-sdk/src/lib.rs && \
    echo "fn main(){}" > server/src/main.rs && \
    echo "fn main(){}" > tools/online-check/src/main.rs && \
    echo "fn main(){}" > tools/secret-broker/src/main.rs && \
    echo "fn main(){}" > tools/gateway/src/main.rs && \
    echo "fn main(){}" > tools/local-proxy/src/main.rs && \
    echo "pub fn stub(){}" > tools/local-proxy/src/lib.rs

RUN cargo build --release --locked -p trusted-relay-server \
      --no-default-features --features tee-gcp-confidential-space 2>/dev/null || true

COPY crates/ crates/
COPY server/ server/
COPY tools/ tools/

ENV RUSTFLAGS="-C link-arg=-Wl,--build-id=none -C debuginfo=0"
RUN cargo build --release --locked -p trusted-relay-server \
      --no-default-features --features tee-gcp-confidential-space && \
    cp target/release/trusted-relay-server /usr/local/bin/trusted-relay-server

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /usr/local/bin/trusted-relay-server /usr/local/bin/trusted-relay-server
EXPOSE 8443
ENV TRUSTED_RELAY_GCP_CS_AUDIENCE=trusted-relay-attested-tls
ENV TRUSTED_RELAY_GCP_CONFIDENTIAL_SPACE=1
LABEL "tee.launch_policy.allow_env_override"="TRUSTED_RELAY_UPSTREAM,TRUSTED_RELAY_ALLOWED_UPSTREAM,TRUSTED_RELAY_MAX_REQUEST_BYTES,TRUSTED_RELAY_UPSTREAM_TIMEOUT_SECS,TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST,TRUSTED_RELAY_SECRET_BROKER_URL,TRUSTED_RELAY_SECRET_BROKER_CA_PEM,TRUSTED_RELAY_SECRET_NONCE,TRUSTED_RELAY_GCP_CS_AUDIENCE"
LABEL "tee.launch_policy.log_redirect"="always"
ENTRYPOINT ["/usr/local/bin/trusted-relay-server"]
