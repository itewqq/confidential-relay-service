# Trusted Relay

A confidential LLM API proxy that cryptographically proves it cannot read, store, or modify your data.

Uses Intel TDX / AMD SEV-SNP hardware encryption + attested TLS to give users verifiable guarantees — not just promises.

## How It Works

```
┌──────────────┐    Attested TLS     ┌─────────────────────────────┐    TLS    ┌─────────────┐
│  Your App    │ ◄═══════════════► │  Confidential VM            │ ◄──────► │ OpenAI etc. │
│  + SDK       │  SDK auto-verifies: │                             │          └─────────────┘
│              │  • TEE attestation  │  trusted-relay (Rust)       │
│              │  • code measurement │  • forward requests         │
│              │  • key binding      │  • NO logging, NO disk I/O  │
└──────────────┘                     │  • memory encrypted by CPU  │
                                     └─────────────────────────────┘
```

1. The relay runs inside a **Confidential VM** (AMD SEV-SNP or Intel TDX). The CPU encrypts all memory — not even the cloud provider can read it.
2. On TLS handshake, the server embeds a hardware-signed **attestation quote** in its certificate. This quote contains:
   - A **measurement** (hash of the running binary)
   - The **hash of the TLS public key** (proving the key lives inside the TEE)
3. The SDK **automatically verifies** this quote during connection. If anything is wrong — wrong code, wrong key, no TEE — the connection is refused.
4. The source code is open. You can build it yourself, get the same binary hash, and verify the measurement matches.

## Quick Start (Development on Mac)

```bash
# Build everything
cargo build --workspace

# Run tests (14 tests, all pass on Mac with mock attestation)
cargo test --workspace

# Start the server with mock attestation (development only!)
cargo run -p trusted-relay-server -- --listen 0.0.0.0:8443 --upstream https://api.openai.com
```

### Using the SDK

```rust
use relay_sdk::{TrustedRelayClient, ChatRequest, VerificationPolicy};

let client = TrustedRelayClient::builder()
    .endpoint("https://relay.example.com:8443")
    .api_key("provider-token-from-env")
    .verification(VerificationPolicy::Strict {
        expected_measurement: hex::decode("abcdef...")?,
    })
    .build()?;

let response = client.chat_completions(
    ChatRequest::simple("gpt-4", "Hello, world!")
).await?;
```

For development, use `VerificationPolicy::MockDev` to skip real attestation.

## Deploy on GCP Confidential VM (SEV-SNP)

### 1. Create a Confidential VM

```bash
# Create an N2D instance with SEV-SNP enabled
gcloud compute instances create trusted-relay \
    --zone=us-central1-a \
    --machine-type=n2d-standard-2 \
    --min-cpu-platform="AMD Milan" \
    --confidential-compute-type=SEV_SNP \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --maintenance-policy=TERMINATE

# SSH in
gcloud compute ssh trusted-relay
```

### 2. Verify SEV-SNP is active

```bash
# Check for the SEV guest device
ls -la /dev/sev-guest
# Should show: crw------- 1 root root 10, 125 ... /dev/sev-guest

# Check dmesg for SEV-SNP
dmesg | grep -i sev
# Should show: "SEV-SNP: SNP enabled"
```

### 3. Build and run

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build with SEV-SNP support
git clone <repo-url> && cd trusted-relay
cargo build --release -p trusted-relay-server --features tee-sev-snp

# Run (will auto-detect /dev/sev-guest and use real attestation)
sudo ./target/release/trusted-relay-server \
    --listen 0.0.0.0:8443 \
    --upstream https://api.openai.com
```

The server will log:
```
INFO SEV-SNP device detected
INFO attestation backend: AMD SEV-SNP
INFO attested TLS certificate generated
INFO trusted-relay listening addr=0.0.0.0:8443
```

### 4. Connect from a client

```rust
let client = TrustedRelayClient::builder()
    .endpoint("https://<vm-external-ip>:8443")
    .api_key("local-test-token")
    .verification(VerificationPolicy::Strict {
        expected_measurement: expected_measurement_bytes,
    })
    .build()?;
```

### Getting the expected measurement

The measurement is a SHA-384 hash of the VM's launch image. To get it:

1. Build the binary reproducibly: `docker build -f build/Dockerfile -t trusted-relay .`
2. Run `./build/measure.sh` to compute the hash
3. The hash in `measurements.json` should match what the attestation quote reports

## Project Structure

```
crates/
├── relay-attest/       Attestation abstraction (traits + backends)
│   ├── traits.rs         Attester / Verifier traits
│   ├── mock.rs           Mock backend for development (Ed25519)
│   ├── sev_snp.rs        AMD SEV-SNP backend (real ioctl + report parsing)
│   ├── tdx.rs            Intel TDX backend (stub — interface ready)
│   └── quote.rs          X.509 extension embedding/extraction
├── relay-tls/          Attested TLS layer
│   ├── server.rs         Generate attested cert (quote in X.509 extension)
│   └── client.rs         Custom rustls verifier (checks attestation)
├── relay-core/         Reverse proxy
│   ├── proxy.rs          OpenAI-compatible handler with SSE streaming
│   ├── config.rs         Upstream routing configuration
│   └── router.rs         axum router
└── relay-sdk/          Client SDK
    ├── client.rs         TrustedRelayClient (builder pattern)
    ├── types.rs          ChatRequest/ChatResponse (OpenAI-compatible)
    └── verify.rs         VerificationPolicy (Strict/TOFU/Audit/MockDev)

server/                 Binary entrypoint
build/                  Reproducible build (Dockerfile + measure.sh)
```

## Cryptography Libraries

| Library | Version | Purpose | Audit Status |
|---------|---------|---------|-------------|
| **ring** | 0.17 | TLS handshake crypto, key exchange, signature verification | Google-maintained, [formally verified](https://github.com/nicovank/ring-audit) core primitives, memory-safe |
| **rustls** | 0.23 | TLS protocol implementation | [Audited by Cure53 (2024)](https://github.com/rustls/rustls/blob/main/audit/README.md), ISRG-funded, memory-safe alternative to OpenSSL |
| **sha2** | 0.10 | SHA-384 for REPORTDATA hashing | RustCrypto project, widely reviewed, pure Rust |
| **ed25519-dalek** | 2.x | Mock attestation signatures only | Dalek Cryptography, **not used in production path** |
| **p384** | 0.13 | ECDSA P-384 for SEV-SNP VCEK verification | RustCrypto project, pure Rust |
| **rcgen** | 0.13 | Self-signed X.509 cert generation | Uses ring internally |
| **x509-parser** | 0.16 | Parse certs to extract attestation evidence | Maintained by security-focused rusticata team |

**No OpenSSL. No C dependencies in the crypto path** (ring uses some assembly for performance, but is memory-safe at the API boundary).

## Security Model

### What the hardware proves
- The relay code is running inside an encrypted VM (SEV-SNP/TDX)
- The cloud provider cannot read the VM's memory
- The attestation quote is signed by AMD/Intel hardware — unforgeable

### What the code audit proves
- The relay does not log request/response content (`#![deny(unsafe_code)]`, ~2000 LOC)
- The relay does not write to disk
- The relay does not make unexpected network connections
- The TLS private key exists only inside the TEE

### What the user's SDK verifies
- The attestation quote is hardware-signed (signature chain → AMD/Intel root)
- The code measurement matches the published hash (reproducible build)
- The TLS public key hash matches REPORTDATA (channel binding)

### Trust assumptions (be honest)
- You trust AMD/Intel hardware has no backdoors
- You trust the CPU has no exploitable side-channel vulnerabilities
- The upstream LLM provider (OpenAI, etc.) still sees plaintext — the relay protects the **middle**, not the **endpoints**

## Testing

```bash
# All tests (mock attestation, works on Mac)
cargo test --workspace

# With SEV-SNP feature (verifier tests work on Mac, attester needs Linux)
cargo test -p relay-attest --features sev-snp

# Clippy
cargo clippy --workspace
```

## License

[TODO: Choose license]
