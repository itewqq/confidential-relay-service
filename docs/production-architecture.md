# Production Architecture

Trusted Relay's production architecture keeps the CVM private and pushes dynamic
user entitlement outside the prompt-confidentiality boundary. The public edge can
authenticate users and meter usage, but it does not terminate attested TLS.

## Components

- `trusted-relay-local`: user-side OpenAI-compatible proxy. It verifies remote
  attestation and config pins, then opens a CONNECT tunnel through the gateway.
- `trusted-relay-gateway`: public blind CONNECT gateway. It authenticates tunnel
  tokens and forwards opaque bytes to one private relay address.
- `trusted-relay-server`: private Confidential Space workload. It terminates
  attested TLS, injects the broker-provided provider credential, and forwards
  only to allowed upstreams.
- `trusted-relay-secret-broker`: operator-side broker holding provider keys. It
  releases them only after workload identity, TLS binding, config hash, and
  nonce checks pass.
- Upstream provider: OpenAI, Anthropic, or another configured API. It sees
  plaintext by design.

## Trust Boundaries

- The local proxy is user trust code. It must pin the expected image digest or
  image signature key and `RelayConfig::config_hash()`.
- The gateway/control plane is not trusted with prompt plaintext. It may enforce
  users, billing, quotas, abuse controls, and revocation.
- The CVM is the prompt-handling TCB. It must be private-only and run the pinned
  image/config.
- The broker is trusted with provider credentials, not prompt plaintext.
- User-facing relay tokens are unrelated to provider API keys.

## Measurement And Report Data

For GCP production, use Confidential Space claims as workload identity:

- `submods.container.image_digest` or `submods.container.image_signatures` proves
  which container image ran.
- `eat_nonce` carries the attested TLS binding and config binding.
- `dbgstat`, `secboot`, service account, project, and zone constrain runtime.

Raw SEV-SNP `MEASUREMENT` and `REPORTDATA` are different things:

- `MEASUREMENT` is a launch digest chosen by the platform. Our GCP custom-image
  A/B test showed it did not identify custom payload changes, so it is not the
  GCP production identity in this repo.
- `REPORTDATA` is guest-supplied data signed in the report. It binds TLS SPKI and
  config to the attested guest, but it is not a standalone code measurement.

## Secret Handling

1. No provider key is baked into the image or VM metadata.
2. On startup, the relay creates an ephemeral TLS key and attested certificate.
3. The relay calls the broker with the cert, config hash, and a fresh nonce.
4. The broker verifies attestation, workload identity, TLS SPKI binding, config
   hash, and nonce uniqueness.
5. The broker returns the provider credential once.
6. The relay overwrites any incoming local `Authorization` header with the
   provider credential when calling upstream.

## User Auth Model

The CVM does not need to know whether an end user paid their bill. It is
private-only, and only the gateway or private control-plane path can reach it.
The gateway can reject unauthorized users without decrypting prompts because the
user-to-CVM connection is attested TLS inside the CONNECT tunnel.

## Minimum Deployment Controls

- Relay VM has no external IP.
- Firewall allows relay port only from the gateway/control-plane subnet.
- Gateway only supports CONNECT to the configured relay address.
- Local proxy and broker fail closed without workload identity/config pins.
- Broker requires HTTPS by default; cleartext requires explicit dev-only override.
- Broker requires one-time nonces.
- Logs remain metadata-only; prompt, response, provider token, and local user
  token are not logged.
- Release automation includes the image A/B negative test.

## Tests

Local topology test:

```bash
cargo test -p trusted-relay-local --features mock --test gateway_local_proxy
```

Confidential Space workload-identity negative test:

```bash
cargo test -p trusted-relay-local --features gcp-confidential-space --test gateway_local_proxy \
  local_proxy_rejects_changed_confidential_space_container_digest
```

Real GCP runbook: `docs/real-online-test.md`.
