# Google Cloud Confidential Space Deployment

Confidential Space is the chosen GCP production path for Trusted Relay. The
release identity is the Google-signed workload-container claim
`submods.container.image_digest` or `submods.container.image_signatures`, not raw
GCP SEV-SNP `MEASUREMENT`.

## Attestation Binding

The relay asks the Confidential Space launcher for an OIDC token whose custom
nonces encode the attested TLS binding:

```text
nonce/reportdata[0..48]  = SHA-384(TLS certificate SPKI)[0..48]
nonce/reportdata[48..64] = RelayConfig::config_hash()[0..16]
```

Because the launcher limits nonce size, this is sent as two nonce strings:

```text
trr1s.<base64url(reportdata[0..48])>
trr1c.<base64url(reportdata[48..64])>
```

The verifier checks:

- Google OIDC signature and `iss`/`aud`/`exp`/`nbf`.
- `eat_nonce` equals the expected TLS SPKI/config binding.
- `swname == CONFIDENTIAL_SPACE`.
- `dbgstat == disabled-since-boot`.
- `secboot == true`.
- Optional service account, project ID, zone, and instance name pins.
- Container image digest and/or allowed image signature key ID.

## Build And Push

```bash
tools/gcp/build-confidential-space-image.sh \
  --project "$GCP_PROJECT" \
  --region "$GCP_REGION" \
  --repo trusted-relay \
  --require-pinned-bases \
  --rust-base "$TRUSTED_RELAY_RUST_BASE_IMAGE" \
  --runtime-base "$TRUSTED_RELAY_RUNTIME_BASE_IMAGE"
```

Record the printed `image_ref_with_digest` and `image_digest`.

## Launch Private VM

```bash
tools/gcp/launch-confidential-space.sh \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --name trusted-relay-cs \
  --service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --image-ref "$IMAGE_REF_WITH_DIGEST" \
  --env TRUSTED_RELAY_UPSTREAM="$TRUSTED_RELAY_UPSTREAM" \
  --env TRUSTED_RELAY_ALLOWED_UPSTREAM="$TRUSTED_RELAY_ALLOWED_UPSTREAM" \
  --env TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256="$TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256" \
  --env TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST="${IMAGE_DIGEST#sha256:}" \
  --env TRUSTED_RELAY_ADMIN_LISTEN="0.0.0.0:8788" \
  --duration 2h
```

Do not pass provider keys through metadata. The image allowlists only non-secret
runtime configuration and the private admin listener address. Provider keys are
pushed later from a private operator service to the private admin port.
`TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256` is non-secret config in
`ORIGIN=sha256:<64-hex>` form; it is folded into `RelayConfig::config_hash()`.
The config hash also covers security-relevant runtime policy: whether client
provider auth is allowed, whether the private admin endpoint is enabled, the
provider auth scheme, and the relay-owned body logging policy. It deliberately
excludes deploy-only addresses and secret token material.

## Inject Provider Credential

Run this only from a host that reaches the relay private IP. For throwaway tests,
that can be a temporary IAP/SSH tunnel or private control host.

```bash
curl -fsS -X POST "http://RELAY_PRIVATE_IP:8788/admin/provider-credential" \
  -H 'content-type: application/json' \
  -d '{"auth_scheme":"Bearer","token":"'"$TRUSTED_RELAY_PROVIDER_TOKEN"'"}'
```

Check private admin readiness without exposing secrets:

```bash
curl -fsS "http://RELAY_PRIVATE_IP:8788/admin/health"
```

The admin listener is not public and not user-facing. Protect it with VPC and
firewall controls. The user-facing proof remains the attested TLS connection on
the relay data port.

## Online Verification

Audit mode prints claims without enforcing image identity:

```bash
cargo run -p trusted-relay-online-check --no-default-features \
  --features gcp-confidential-space -- \
  --backend gcp-confidential-space \
  --endpoint https://RELAY_PRIVATE_IP:8443 \
  --mode audit \
  --print-only
```

Strict mode enforces image/config pins:

```bash
cargo run -p trusted-relay-online-check --no-default-features \
  --features gcp-confidential-space -- \
  --backend gcp-confidential-space \
  --endpoint https://RELAY_PRIVATE_IP:8443 \
  --mode strict \
  --gcp-cs-image-digest "$IMAGE_DIGEST" \
  --gcp-cs-service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --gcp-cs-project-id "$GCP_PROJECT" \
  --gcp-cs-zone "$GCP_ZONE" \
  --expected-config-hash "$TRUSTED_RELAY_EXPECTED_CONFIG_HASH" \
  --upstream-tls-leaf-sha256 "$TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256" \
  --private-admin-enabled \
  --provider-auth-scheme Bearer \
  --body-log-policy metadata-only \
  --health
```

The local proxy uses the same policy:

```bash
trusted-relay-local \
  --backend gcp-confidential-space \
  --relay-endpoint https://RELAY_PRIVATE_IP:8443 \
  --gateway-addr GATEWAY_PUBLIC_IP:443 \
  --expected-config-hash "$TRUSTED_RELAY_EXPECTED_CONFIG_HASH" \
  --gcp-cs-service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --gcp-cs-project-id "$GCP_PROJECT" \
  --gcp-cs-zone "$GCP_ZONE" \
  --gcp-cs-image-digest "$IMAGE_DIGEST"
```

## Negative Test

Build image `B` after a small trusted-code change and keep verifiers pinned to
image `A`. Expected failure is `container.image_digest` mismatch after signature
and nonce validation. No prompt should be forwarded.
