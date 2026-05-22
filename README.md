# Trusted Relay

A relay that tries to prove it is **not** reading your prompts in the boring old
"just trust us" way. The practical point is simple: if a middleman must exist,
the user should be able to verify the exact relay image/config before sending
anything sensitive. The less practical point is that this is fun, and it gives
CVM side-channel researchers a target that is not yet another unprotected AES
loop or ML kernel.

![Trusted Relay architecture](assets/architecture.svg)

Trusted Relay is an OpenAI-compatible LLM API relay built around attested TLS.
The current production path is **Google Cloud Confidential Space**: the user-side
local proxy verifies a Google-signed attestation token, pins the workload
container digest or signature, checks the relay config hash, and only then sends
prompts through an encrypted channel that terminates inside the private CVM.

## Security Model

### What It Protects

- **Prompt/API traffic from the relay operator, gateway, cloud host, and network path.** They can route packets, but they should not see plaintext before the attested TLS endpoint.
- **Provider credentials from users and public gateways.** The provider key is injected after attestation by `trusted-relay-secret-broker`; local user tokens are stripped by `trusted-relay-local`.
- **Trusted-code drift.** A tiny code change creates a new Confidential Space image digest, so clients and brokers pinned to the old digest reject it.
- **Config drift.** `RelayConfig::config_hash()` is bound into the attestation nonce/reportdata, covering upstream allowlists, routing, limits, timeout, and release metadata.
- **TLS key substitution.** The attestation nonce/reportdata includes `SHA-384(TLS SPKI)`, so the accepted TLS private key must correspond to the attested certificate.

### What It Does Not Protect

- The upstream provider still receives plaintext. That is the point of using the provider.
- A malicious image that users choose to pin can still exfiltrate prompts. Pin reviewed releases, not vibes.
- Side channels, traffic analysis, DoS, compromised user machines, provider-side logging, and bugs in Google/AMD firmware remain out of scope.
- The gateway/control plane still sees user identity, IPs, timing, and byte counts.
- Raw GCP SEV-SNP `MEASUREMENT` alone is **not** used as the GCP workload identity here; our A/B test showed it did not change for custom image payload changes.

### Trust Roots

- **Google Confidential Space issuer:** `https://confidentialcomputing.googleapis.com` signs the attestation token.
- **Workload identity pin:** `submods.container.image_digest` and/or `submods.container.image_signatures` is checked by the local proxy, online checker, and secret broker.
- **Runtime safety pins:** `swname == CONFIDENTIAL_SPACE`, `dbgstat == disabled-since-boot`, `secboot == true`, plus optional service account, project, zone, and instance pins.
- **Attested TLS binding:** token nonces encode `SHA-384(TLS SPKI)[0..48] || RelayConfig::config_hash()[0..16]`.
- **Secret release gate:** the broker releases the provider token only after attestation, config, TLS binding, and one-time nonce checks pass.

## Components

- `trusted-relay-local`: local OpenAI-compatible proxy; verifies attestation and strips local `Authorization` before forwarding.
- `trusted-relay-gateway`: blind HTTP CONNECT gateway; authenticates users but never terminates attested TLS.
- `trusted-relay-server`: private CVM relay; terminates attested TLS and forwards to allowed upstream providers.
- `trusted-relay-secret-broker`: verifies the CVM's attested cert and releases the provider credential once.
- `trusted-relay-online-check`: live audit/strict verifier for real endpoints.

## Quick Start

### 1. Keep Secrets Out Of Git

```bash
cp .env.example .env
$EDITOR .env
set -a
. ./.env
set +a
```

`.env` is ignored. Put real `TRUSTED_RELAY_PROVIDER_TOKEN` and
`TRUSTED_RELAY_GATEWAY_TOKEN` only there or in a real secret manager. The repo
keeps `.env.example` as placeholders only.

### 2. Run Local Tests

```bash
cargo test --workspace --all-features
```

Useful focused checks:

```bash
cargo test -p trusted-relay-local --features mock --test gateway_local_proxy
cargo test -p trusted-relay-local --features gcp-confidential-space --test gateway_local_proxy \
  local_proxy_rejects_changed_confidential_space_container_digest
```

### 3. Build And Push A Confidential Space Image

```bash
tools/gcp/build-confidential-space-image.sh \
  --project "$GCP_PROJECT" \
  --region "$GCP_REGION" \
  --repo trusted-relay
```

Record the printed `image_ref_with_digest` and `image_digest`, then update your
local `.env` pins.

### 4. Launch A Private Relay VM

```bash
tools/gcp/launch-confidential-space.sh \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --name trusted-relay-cs \
  --image-ref "$IMAGE_REF_WITH_DIGEST" \
  --env TRUSTED_RELAY_UPSTREAM="$TRUSTED_RELAY_UPSTREAM" \
  --env TRUSTED_RELAY_ALLOWED_UPSTREAM="$TRUSTED_RELAY_ALLOWED_UPSTREAM" \
  --env TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST="$TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST" \
  --env TRUSTED_RELAY_SECRET_BROKER_URL="$TRUSTED_RELAY_SECRET_BROKER_URL" \
  --env TRUSTED_RELAY_SECRET_BROKER_CA_PEM="$TRUSTED_RELAY_SECRET_BROKER_CA_PEM" \
  --env TRUSTED_RELAY_SECRET_NONCE="$(uuidgen)" \
  --duration 2h
```

The VM has no public IP. Provider keys are not passed in metadata; they come from
the broker after attestation.

### 5. Run The Broker And Local Proxy

```bash
trusted-relay-secret-broker \
  --backend gcp-confidential-space \
  --expected-config-hash "$TRUSTED_RELAY_EXPECTED_CONFIG_HASH" \
  --gcp-cs-image-digest "$TRUSTED_RELAY_GCP_CS_IMAGE_DIGEST" \
  --gcp-cs-service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --gcp-cs-project-id "$TRUSTED_RELAY_GCP_CS_PROJECT_ID" \
  --gcp-cs-zone "$TRUSTED_RELAY_GCP_CS_ZONE" \
  --tls-cert-pem "$TRUSTED_RELAY_SECRET_BROKER_TLS_CERT_PEM" \
  --tls-key-pem "$TRUSTED_RELAY_SECRET_BROKER_TLS_KEY_PEM" \
  --provider-token "$TRUSTED_RELAY_PROVIDER_TOKEN"

trusted-relay-local \
  --backend gcp-confidential-space \
  --relay-endpoint https://RELAY_PRIVATE_IP:8443 \
  --gateway-addr GATEWAY_PUBLIC_IP:443 \
  --expected-config-hash "$TRUSTED_RELAY_EXPECTED_CONFIG_HASH" \
  --gcp-cs-image-digest "$TRUSTED_RELAY_GCP_CS_IMAGE_DIGEST"
```

Point local apps at:

```bash
OPENAI_BASE_URL=http://127.0.0.1:11434/v1
OPENAI_API_KEY=$TRUSTED_RELAY_LOCAL_TOKEN
```

## Real Release Test

The real negative test must be a trusted-code change, not just a wrong token:

1. Build image `A`, publish and pin its digest/config hash.
2. Verify a positive request through local proxy -> gateway -> private CVM -> provider.
3. Make a tiny compiled code change, build image `B`, and launch it.
4. Keep the local proxy and broker pinned to `A`.
5. Expected result: attestation reaches Google token verification, then fails on `container.image_digest` mismatch; no prompt is forwarded and the broker does not release the provider key.

See `docs/confidential-space.md` and `docs/real-online-test.md` for the detailed
GCP runbook and the May 21, 2026 A/B result.

## Project Layout

```text
assets/                 README architecture assets
build/confidential-space/  GCP Confidential Space container image
docs/                   Production architecture and online test runbooks
crates/relay-attest/    Mock, SEV-SNP, and GCP Confidential Space attestation
crates/relay-tls/       Attested TLS certificate generation and verifier
crates/relay-core/      Reverse proxy, routing config, allowlist, request limits
crates/relay-secret/    Attestation-gated provider secret protocol
crates/relay-sdk/       Rust SDK and verification policies
server/                 trusted-relay-server
tools/local-proxy/      User-side local proxy
tools/gateway/          Blind CONNECT gateway
tools/secret-broker/    Provider key broker
tools/online-check/     Live endpoint verifier
tools/gcp/              Low-cost GCP build/launch/cleanup scripts
```

## Security Notes

- `tee-mock` requires `TRUSTED_RELAY_DEV_MOCK=1` and is development-only.
- Strict production use requires workload identity pins and `expected_config_hash`.
- `TrustOnFirstUse` intentionally fails until persistent pinning is implemented.
- Request and response bodies are not logged; error logs redact token-like text.
- `tools/gcp/cleanup.sh` removes named throwaway GCP resources; still verify the cloud console before going to sleep.

## License

TODO: Choose license.
