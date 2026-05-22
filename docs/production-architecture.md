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
  attested TLS, accepts provider credential injection on a private admin port,
  overwrites local `Authorization`, and forwards only to allowed upstreams.
- Private operator service: VPC-local service, IAP/SSH tunnel, or equivalent
  control-plane host that can reach the relay admin port and push the provider
  credential after launch.
- Upstream provider: OpenAI, Anthropic, or another configured API. It sees
  plaintext by design.

## Trust Boundaries

- The local proxy is user trust code. It must pin the expected image digest or
  image signature key and `RelayConfig::config_hash()`.
- The gateway/control plane is not trusted with prompt plaintext. It may enforce
  users, billing, quotas, abuse controls, and revocation.
- The CVM is the prompt-handling TCB. It must be private-only and run the pinned
  image/config.
- The private operator service is trusted with provider credentials, but it is
  outside the user's prompt-confidentiality proof. It must not be on a path that
  can decrypt attested TLS.
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

## Provider Credential Handling

1. No provider key is baked into the image, VM metadata, launch env, docs, or Git.
2. On startup, the relay creates an ephemeral TLS key and attested certificate.
3. The relay exposes the user data-plane on attested TLS (`8443` by default).
4. If configured, the relay also exposes plain HTTP private admin on
   `TRUSTED_RELAY_ADMIN_LISTEN`, for example `0.0.0.0:8788` inside a private VPC.
5. A private operator service pushes the provider credential once:

```bash
curl -fsS -X POST http://RELAY_PRIVATE_IP:8788/admin/provider-credential \
  -H 'content-type: application/json' \
  -d '{"auth_scheme":"Bearer","token":"..."}'
```

6. Until a credential is loaded, production-mode relay requests fail closed with
   `503 provider credential not loaded`.
7. After injection, the relay overwrites any incoming local `Authorization` header
   with the provider credential when calling upstream.
8. A second injection returns `409 Conflict`; rotate by restarting a fresh CVM
   or adding an explicit future rotation protocol.

The admin port is deliberately boring private plumbing. It is not authenticated
by the relay application and it is not attested TLS. Protect it with network
controls: no public IP, firewall source ranges or tags, private subnet only, IAP
or SSH tunnel for manual tests, and metadata/log hygiene.

## User Auth Model

The CVM does not need to know whether an end user paid their bill. It is
private-only, and only the gateway or private control-plane path can reach it.
The gateway can reject unauthorized users without decrypting prompts because the
user-to-CVM connection is attested TLS inside the CONNECT tunnel.

## Minimum Deployment Controls

- Relay VM has no external IP.
- Firewall allows relay data port only from the gateway/control-plane subnet.
- Firewall allows relay admin port only from the private operator service.
- Gateway only supports CONNECT to the configured relay address.
- Local proxy and online checker fail closed without workload identity/config pins.
- Provider credential injection is one-shot and never logged.
- Logs remain metadata-only; prompt, response, provider token, and local user
  token are not logged.
- Release automation includes the image A/B negative test.

## Tests

Local topology test:

```bash
cargo test -p trusted-relay-local --features mock --test gateway_local_proxy
```

Private injection regression:

```bash
cargo test -p trusted-relay-server --features tee-mock --test mock_e2e \
  private_admin_injection_loads_provider_credential_once
```

Confidential Space workload-identity negative test:

```bash
cargo test -p trusted-relay-local --features gcp-confidential-space --test gateway_local_proxy \
  local_proxy_rejects_changed_confidential_space_container_digest
```

Real GCP runbook: `docs/real-online-test.md`.
