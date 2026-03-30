# Confidential LLM Proxy — Implementation Plan

## Overview

Build a Trusted LLM API proxy (like OpenRouter) that cryptographically proves to users it cannot view, store, or modify their data. Uses Confidential Computing (Intel TDX / AMD SEV-SNP) with attested TLS.

---

## Architecture

```
                        Attested TLS (quote in X.509 cert)
┌──────────────┐       ════════════════════════════════       ┌────────────────────────────────────┐
│  User App    │  ──►  SDK verifies:                    ──►  │  Confidential VM (TDX or SEV-SNP)  │
│  + our SDK   │       • quote signature (HW root)           │                                    │
│              │  ◄──  • MRTD == published hash          ◄── │  ┌──────────────────────────────┐  │
│              │       • REPORTDATA == hash(TLS pubkey)       │  │  trusted-relay (Rust binary)  │  │
└──────────────┘       ════════════════════════════════       │  │                              │  │
                                                              │  │  • receive user request       │  │
                                                              │  │  • forward to upstream LLM    │  │
                                                              │  │  • stream response back       │  │
                                                              │  │  • NO logging / NO disk I/O   │  │
                                                              │  └──────────────────────────────┘  │
                                                              │                                    │
                                                              │  Memory encrypted by HW            │
                                                              │  Code measurement = public hash    │
                                                              └──────────┬───────────────────────┘
                                                                         │
                                                                         │ standard TLS
                                                                         ▼
                                                              ┌──────────────────────┐
                                                              │  Upstream LLM APIs   │
                                                              │  (OpenAI, Anthropic) │
                                                              └──────────────────────┘
```

---

## Answers to Key Questions

### Q1: How to develop/test on a MacBook?

**Layer the abstraction. 95% of development happens locally with zero TEE hardware.**

1. **Application logic (proxy)** — Pure Rust code (axum, reqwest, SSE streaming). Runs anywhere.
2. **Attestation layer** — Trait-based with swappable backends:
   - `MockAttester` / `MockVerifier` for local dev — generates fake quotes, but exercises the full X.509 embedding + verification flow
   - `TdxAttester` / `SevSnpAttester` for production
3. **Integration with real TEE** — CI runner on a cloud Confidential VM (Azure DCesv5 for TDX, DCasv5 for SEV-SNP). Run on merge, not every commit.

**Result**: `cargo run --features tee-mock` gives you a fully functional attested TLS system on Mac. The only thing that's fake is the cryptographic attestation evidence itself.

### Q2: How to let users easily deploy & verify?

**Two deployment models:**

- **SaaS (you operate it)**: Users only need the SDK. Verification is automatic:
  1. Code is open source → anyone can read/audit
  2. Reproducible build → same code = same binary = same measurement hash
  3. SDK connects → verifies attestation quote → checks measurement → checks pubkey binding
  4. If anything fails → connection refused. User doesn't need to understand TEE internals.

- **Self-hosted**: User deploys the same Docker/VM image on their own Confidential VM. Attestation proves it's actually running in TEE mode.

**For non-Rust users**: SDK includes a local proxy mode:
```bash
trusted-relay-proxy --listen 127.0.0.1:8080 --remote relay.example.com
```
Then point any OpenAI SDK at `http://localhost:8080`. The local proxy handles attestation verification.

### Q3: How to prove the system cannot view/store/modify plaintext?

**It's a two-part proof:**

| What | How |
|------|-----|
| The binary in the TEE matches public source | Reproducible build → measurement hash → attestation quote → SDK verifies |
| Platform operator can't read TEE memory | Hardware memory encryption (TDX/SEV-SNP CPU feature) |
| TLS terminates inside the TEE | Pubkey hash in REPORTDATA, verified by SDK during handshake |
| Code doesn't exfiltrate/log/modify data | Open source, ~2000 LOC, auditable. No fs writes, no payload logging |
| Intel/AMD hardware is trustworthy | **Trust assumption** — must be disclosed honestly |
| Upstream LLM sees plaintext | **Out of scope** — user accepts this (they'd send it there anyway) |

---

## Project Structure

```
trusted-relay/
├── crates/
│   ├── relay-core/           # Proxy logic (axum server, upstream client, SSE)
│   ├── relay-attest/         # Attestation abstraction layer
│   │   ├── src/
│   │   │   ├── lib.rs        # Attester / Verifier traits
│   │   │   ├── tdx.rs        # TDX attestation (calls /dev/tdx_guest)
│   │   │   ├── sev_snp.rs    # SEV-SNP attestation (calls /dev/sev-guest)
│   │   │   ├── mock.rs       # Mock attestation for local dev
│   │   │   └── quote.rs      # Quote parsing, X.509 embedding/extraction
│   │   └── Cargo.toml
│   ├── relay-tls/            # Attested TLS: cert generation + verification
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── server.rs     # Self-signed cert with quote in X.509 extension
│   │   │   └── client.rs     # Custom rustls verifier that checks quote
│   │   └── Cargo.toml
│   └── relay-sdk/            # Client SDK (what users import)
│       ├── src/
│       │   ├── lib.rs
│       │   ├── client.rs     # OpenAI-compatible API client
│       │   └── verify.rs     # Verification policy config
│       └── Cargo.toml
├── server/                   # Binary entrypoint for the relay server
│   ├── src/main.rs
│   └── Cargo.toml
├── build/
│   ├── Dockerfile            # Reproducible build
│   └── measure.sh            # Compute expected MRTD from built image
├── tests/
│   ├── mock_e2e.rs           # Full flow with mock attestation (runs on Mac)
│   └── ci_tdx_e2e.rs         # Real attestation test (CI with TDX VM)
├── Cargo.toml                # Workspace
└── measurements.json         # Published measurement hashes per release
```

---

## Step-by-Step Implementation

### Phase 1: Core Proxy (runs anywhere, no TEE) ✅ Mac testable

**Step 1.1 — Workspace setup**
- Init Cargo workspace with crates: `relay-core`, `relay-attest`, `relay-tls`, `relay-sdk`
- Binary crate: `server/`
- Dependencies: axum, hyper, reqwest, rustls, tokio, serde, serde_json

**Step 1.2 — relay-core: reverse proxy**
- axum HTTP server: POST `/v1/chat/completions` (OpenAI-compatible)
- Forward request to configurable upstream URL
- Stream SSE responses back (non-streaming also supported)
- **Security invariants enforced in code:**
  - No filesystem writes of request/response data
  - No payload content in logs (only metadata: timestamp, model, status code)
  - Request/response buffers dropped after each request
- Test: cargo test on Mac with wiremock-rs mock upstream

**Step 1.3 — relay-core: multi-provider routing**
- Model name → upstream URL mapping via config
- Provider-specific auth header handling
- Test: unit tests with mock upstreams

### Phase 2: Attestation Abstraction ✅ Mac testable

**Step 2.1 — relay-attest: traits and types**
```rust
pub struct Evidence { pub data: Vec<u8>, pub tee_type: TeeType }
pub enum TeeType { Tdx, SevSnp, Mock }

/// Runs inside TEE — generates hardware-signed evidence
pub trait Attester: Send + Sync {
    /// user_data (64 bytes) goes into REPORTDATA — use hash(TLS pubkey)
    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence>;
}

/// Runs on client — verifies evidence
pub trait Verifier: Send + Sync {
    /// Returns REPORTDATA from the verified evidence
    fn verify(&self, evidence: &Evidence, expected_measurement: &[u8]) -> Result<[u8; 64]>;
}
```

**Step 2.2 — relay-attest: mock backend**
- `MockAttester`: fake quote signed with local test key
- `MockVerifier`: verify fake signature, extract REPORTDATA
- Full attested TLS flow works on Mac with fake quotes

**Step 2.3 — relay-attest: X.509 embedding**
- Embed attestation quote in X.509 certificate extension
- Use Gramine RA-TLS OID convention (`1.2.840.113741.1337.6`) for compatibility
- Crates: `rcgen` (generate certs), `x509-parser` (parse certs)
- Test: generate cert → embed quote → parse back → verify round-trip

### Phase 3: Attested TLS ✅ Mac testable

**Step 3.1 — relay-tls: server-side**
- On startup:
  1. Generate ephemeral TLS key pair (ECDSA P-384)
  2. `reportdata = SHA-384(public_key_bytes)` (fits in 64-byte REPORTDATA)
  3. `Attester::attest(reportdata)` → get evidence
  4. Generate self-signed X.509 cert: TLS pubkey + evidence in extension
  5. Configure `rustls::ServerConfig` with this cert
- Cert rotation: regenerate every 24h

**Step 3.2 — relay-tls: client-side (custom rustls verifier)**
- Implement `rustls::client::danger::ServerCertVerifier`:
  1. Parse server X.509 cert
  2. Extract attestation evidence from extension
  3. Extract TLS public key
  4. `expected_reportdata = SHA-384(public_key_bytes)`
  5. `Verifier::verify(evidence, expected_measurement)` → returns REPORTDATA
  6. Check REPORTDATA == expected_reportdata
  7. Accept or reject

**Step 3.3 — End-to-end test on Mac**
- Server with MockAttester → Client with MockVerifier → proxied request succeeds
- Verify rejection when: wrong measurement, wrong REPORTDATA, invalid signature

### Phase 4: Real TEE Backends ❌ Needs cloud VM

**Step 4.1 — TDX backend**
- `TdxAttester`: open `/dev/tdx_guest`, ioctl `TDX_CMD_GET_REPORT`, convert via configfs-tsm or QGS
- `TdxVerifier`: send quote to Intel Trust Authority API (simplest), or DCAP local verification
- Reference: `confidential-containers/guest-components` for ioctl interfaces
- Test: Azure DCesv5 (TDX) Confidential VM

**Step 4.2 — SEV-SNP backend**
- `SevSnpAttester`: open `/dev/sev-guest`, ioctl `SNP_GET_REPORT`
- `SevSnpVerifier`: fetch VCEK from AMD KDS, verify report → VCEK → ASK → ARK chain
- Use `virtee/sev` crate (Rust native, ~200 stars, CCC-adjacent maintainers)
- Test: Azure DCasv5 or GCP N2D Confidential VM

**Step 4.3 — Feature flags & runtime detection**
- Cargo features: `tee-tdx`, `tee-sev-snp`, `tee-mock`
- Runtime: check which `/dev/` device exists → auto-select

### Phase 5: Client SDK ✅ Mac testable (mock mode)

**Step 5.1 — relay-sdk: Rust client**
```rust
let client = TrustedRelayClient::builder()
    .endpoint("https://relay.example.com")
    .upstream_api_key("provider-token-from-env")
    .verification(VerificationPolicy::Strict {
        expected_measurement: "sha384:abcdef...",
    })
    .build()?;

let resp = client.chat_completions(request).await?;
```

**Step 5.2 — relay-sdk: local proxy mode (for non-Rust users)**
```bash
# User runs this locally
trusted-relay-proxy --listen 127.0.0.1:8080 --remote relay.example.com

# Then use any OpenAI SDK pointed at localhost
OPENAI_BASE_URL=http://localhost:8080/v1 python my_app.py
```

**Step 5.3 — Verification policies**
- `Strict`: exact measurement match (user provides or fetches from auditor)
- `TOFU` (Trust On First Use): pin on first connect, alert on change
- `Audit`: verify TEE is real, but trust operator's code

### Phase 6: Reproducible Build & Measurement Publishing ✅ Mac testable

**Step 6.1 — Reproducible build**
- Dockerfile: pinned Rust toolchain, `Cargo.lock`, deterministic flags
- Two independent builds from same commit → same measurement
- Publish: `measurements.json` per release, GPG-signed

**Step 6.2 — measurements.json**
```json
{
  "version": "0.1.0",
  "git_commit": "abc123...",
  "measurements": {
    "tdx_mrtd": "sha384:...",
    "sev_snp_measurement": "sha384:..."
  }
}
```

### Phase 7: Hardening

- `zeroize` crate: zero request/response buffers after use
- `prctl(PR_SET_DUMPABLE, 0)`: no core dumps
- Minimal VM image (distroless): no shell, no SSH, no unnecessary services
- Network policy: outbound only to upstream LLM API endpoints
- `#[deny(unsafe_code)]` in proxy crate

---

## Key Dependencies

| Crate | Purpose | Maturity |
|-------|---------|----------|
| `axum` | HTTP server | Tokio ecosystem, very mature |
| `reqwest` | HTTP client for upstream | Mature |
| `rustls` | TLS implementation | Memory-safe, widely used |
| `rcgen` | X.509 cert generation | Well-maintained |
| `x509-parser` | X.509 parsing | Security team maintained |
| `ring` / `aws-lc-rs` | Crypto primitives | Production quality |
| `virtee/sev` | AMD SEV-SNP attestation | CCC-adjacent, Rust native |
| `zeroize` | Secure memory clearing | RustCrypto project |
| `serde` / `serde_json` | Serialization | De facto standard |

For TDX: reference `confidential-containers/guest-components` (CNCF, Rust, multi-vendor).

---

## Milestone Summary

| Phase | What | Mac testable? |
|-------|------|:---:|
| 1 | Working reverse proxy | ✅ |
| 2 | Attestation abstraction + mock | ✅ |
| 3 | Attested TLS end-to-end (mock) | ✅ |
| 4 | Real TDX / SEV-SNP backends | ❌ cloud VM |
| 5 | Client SDK | ✅ mock mode |
| 6 | Reproducible build | ✅ |
| 7 | Hardening | ✅ code-level |

**Phases 1–3 get you a fully functional demo on your MacBook.
Phase 4 makes it real. Everything else is polish.**
