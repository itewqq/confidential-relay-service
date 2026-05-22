# Real Online Test Runbook

Use this runbook for a low-cost production-path test on GCP Confidential Space.
It uses one small private Confidential Space VM, an optional blind gateway or IAP
TCP tunnel, and the local proxy on the user's machine. Delete cloud resources
immediately after the smoke test.

## Cost Controls

- Use one `n2d-standard-2` Confidential Space VM at a time.
- Use `--duration 2h` / `--max-run-duration=2h` for throwaway VMs.
- Keep the relay private with `--no-address`.
- Use Cloud NAT only while the relay needs provider egress.
- Use a low-limit provider key from `.env` and inject it through the private admin endpoint only.
- Run `tools/gcp/cleanup.sh` when done.

## Production Positive Test

1. Build and push image `A`:

```bash
tools/gcp/build-confidential-space-image.sh \
  --project "$GCP_PROJECT" \
  --region "$GCP_REGION" \
  --repo trusted-relay \
  --tag release-a
```

2. Record:

```text
IMAGE_A_REF_WITH_DIGEST=...
IMAGE_A_DIGEST=sha256:...
TRUSTED_RELAY_EXPECTED_CONFIG_HASH=...
```

3. Launch a private relay:

```bash
tools/gcp/launch-confidential-space.sh \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --name trusted-relay-cs-a \
  --service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --image-ref "$IMAGE_A_REF_WITH_DIGEST" \
  --env TRUSTED_RELAY_UPSTREAM="$TRUSTED_RELAY_UPSTREAM" \
  --env TRUSTED_RELAY_ALLOWED_UPSTREAM="$TRUSTED_RELAY_ALLOWED_UPSTREAM" \
  --env TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256="$TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256" \
  --env TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST="${IMAGE_A_DIGEST#sha256:}" \
  --env TRUSTED_RELAY_ADMIN_LISTEN="0.0.0.0:8788" \
  --duration 2h
```

4. Run strict online verification from a host that can reach the private relay.
If your local network needs a proxy for Google JWKS, set `HTTPS_PROXY` and
`ALL_PROXY` before running the command.

```bash
cargo run -p trusted-relay-online-check --no-default-features \
  --features gcp-confidential-space -- \
  --backend gcp-confidential-space \
  --endpoint https://RELAY_PRIVATE_IP:8443 \
  --mode strict \
  --gcp-cs-image-digest "$IMAGE_A_DIGEST" \
  --gcp-cs-service-account "$TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT" \
  --gcp-cs-project-id "$GCP_PROJECT" \
  --gcp-cs-zone "$GCP_ZONE" \
  --upstream-tls-leaf-sha256 "$TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256" \
  --expected-config-hash "$TRUSTED_RELAY_EXPECTED_CONFIG_HASH" \
  --health
```

5. Inject the provider credential from a private operator host or temporary
private tunnel:

```bash
curl -fsS -X POST "http://RELAY_PRIVATE_IP:8788/admin/provider-credential" \
  -H 'content-type: application/json' \
  -d '{"auth_scheme":"Bearer","token":"'"$TRUSTED_RELAY_PROVIDER_TOKEN"'"}'
```

6. Start `trusted-relay-local`, then send a normal OpenAI-compatible request to
`http://127.0.0.1:11434/v1/chat/completions`.

Expected result:

- local proxy accepts only after online Google JWKS verification succeeds;
- gateway or IAP tunnel sees only opaque TCP metadata;
- CVM overwrites local `Authorization` with the injected provider credential;
- CVM verifies WebPKI/hostname and the configured upstream leaf certificate pin before sending upstream bytes;
- upstream returns a normal response;
- logs remain metadata-only.

## Required Negative Test

The negative test must prove trusted-code identity, not merely wrong credentials.

1. Keep image `A` pins in the local proxy and online checker.
2. Make a tiny compiled trusted-code change, for example changing the `/health` response body.
3. Build and launch image `B`.
4. Connect to `B` while still pinned to `A`.

Expected result:

- TLS reaches attestation verification;
- Google token signature and nonce are valid;
- strict verification fails on `container.image_digest` mismatch;
- no prompt is forwarded.

Local regression coverage:

```bash
cargo test -p trusted-relay-local --features gcp-confidential-space --test gateway_local_proxy \
  local_proxy_rejects_changed_confidential_space_container_digest
```

Provider-injection regression coverage:

```bash
cargo test -p trusted-relay-server --features tee-mock --test mock_e2e \
  private_admin_injection_loads_provider_credential_once
```

## May 22, 2026 Evidence

Real GCP tests used private no-external-IP `n2d-standard-2` relay VMs in
`us-central1-a` with Cloud NAT for provider egress and IAP local tunnels for
`8443` and `8788`.

Pinned image `A`:

```text
image_digest=sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be
relay_config_hash=ba482176c844b171307e90af40fe34cb5a178f3a6c0a886360827980e5072226
```

Changed image `B` used one compiled code change: `/health` returned `ok-b`
instead of `ok`.

```text
image_digest=sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
relay_config_hash=bcd3a9b2a2a113db3e92e55631d3eec8b6da543927174d2346d37c5189c2b96a
```

Strict verification accepted live `A` with online Google JWKS:

```text
token.issuer=https://confidentialcomputing.googleapis.com
token.audience=trusted-relay-attested-tls
token.swname=CONFIDENTIAL_SPACE
token.dbgstat=disabled-since-boot
token.container.image_digest=sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be
token.gce.project_id=stone-botany-277908
token.gce.zone=us-central1-a
RESULT: OK - GcpConfidentialSpace/Strict verification succeeded
health.status=HTTP/1.1 200 OK
health.body=ok
```

Pinned to `A`, live `B` was rejected before forwarding:

```text
token.container.image_digest=sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
token.gce.instance_name=trusted-relay-cs-b
Error: attestation evidence verification failed
Caused by:
    Confidential Space image digest mismatch: expected sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be, got sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
```

The local proxy pinned to `A` also rejected live `B` before forwarding a prompt:

```text
HTTP/1.1 502 Bad Gateway
{"error":{"message":"relay request failed: client error (Connect)","type":"local_proxy_error"}}
```

Before provider injection, the relay failed closed:

```text
HTTP/1.1 503 Service Unavailable
{"error":{"message":"provider credential not loaded","type":"relay_error"}}
```

After private admin injection, a real OpenAI provider request returned `200 OK`
in an earlier smoke test. A later online-JWKS run used a deliberately fake
provider credential and reached the real OpenAI endpoint, which returned `401
invalid_api_key`; relay logs showed only metadata. Current relay builds sanitize
injected-provider `401/403` bodies before returning them to local users, because
some providers echo invalid key fragments in auth errors.

```text
provider credential injected through private admin endpoint
proxied request model=gpt-4o-mini upstream=https://api.openai.com/v1/chat/completions status=401 latency_ms=241
```

## May 22, 2026 Final GCP E2E With Upstream TLS Pinning

A final smoke test built the current Confidential Space image with upstream TLS
leaf-certificate pinning enabled, launched a private no-external-IP relay in
`us-central1-a`, injected the provider credential over a private operator path,
and sent a real OpenAI request through `trusted-relay-local`. Cloud NAT was used
only for provider egress, then all throwaway Compute and Artifact Registry
resources were deleted.

```text
image_digest=sha256:0d1cbc39e26b9ea274f3ee1de52a48ad05febbaba08f7998239ef693a15c4365
relay_config_hash=d9b26e9a8086b56724c006b39b9e499ccb11a90395d905485625c5ec838678f5
upstream_tls_leaf_sha256=https://api.openai.com=sha256:46b4925a67f673d37d085a90cffd2adc685ce51df10d626a641cd0e5479df229
service_account=365884490266-compute@developer.gserviceaccount.com
provider_injection=204 No Content
admin_health_after_injection={"ok":true,"provider_credential_loaded":true}
```

Strict verification used live Google JWKS through the local proxy and accepted
the endpoint only after checking the image digest, service account, project,
zone, and config hash:

```text
token.issuer=https://confidentialcomputing.googleapis.com
token.audience=trusted-relay-attested-tls
token.swname=CONFIDENTIAL_SPACE
token.dbgstat=disabled-since-boot
token.service_accounts=["365884490266-compute@developer.gserviceaccount.com"]
token.container.image_digest=sha256:0d1cbc39e26b9ea274f3ee1de52a48ad05febbaba08f7998239ef693a15c4365
token.gce.project_id=stone-botany-277908
token.gce.zone=us-central1-a
RESULT: OK - GcpConfidentialSpace/Strict verification succeeded
health.status=HTTP/1.1 200 OK
health.body=ok
```

The local proxy then forwarded a normal OpenAI-compatible request through
attested TLS to the private relay, and the relay reached the real OpenAI
upstream after validating WebPKI/hostname and the configured leaf pin:

```text
HTTP/1.1 200 OK
model=gpt-4o-mini-2024-07-18
content=relay-ok
usage={prompt_tokens: 13, completion_tokens: 2, total_tokens: 15}
relay_log=proxied request model=gpt-4o-mini upstream=https://api.openai.com/v1/chat/completions status=200 latency_ms=1513
```

A live negative smoke check pinned the verifier to a wrong image digest while
connecting to the same relay. Google token signature verification and nonce
parsing completed, then policy failed before forwarding a prompt:

```text
token.container.image_digest=sha256:0d1cbc39e26b9ea274f3ee1de52a48ad05febbaba08f7998239ef693a15c4365
Error: attestation evidence verification failed
Caused by:
    Confidential Space image digest mismatch: expected sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, got sha256:0d1cbc39e26b9ea274f3ee1de52a48ad05febbaba08f7998239ef693a15c4365
```

## Cleanup

```bash
tools/gcp/cleanup.sh
gcloud artifacts repositories list --project "$GCP_PROJECT" --location "$GCP_REGION"
gcloud compute instances list --project "$GCP_PROJECT" --filter="name ~ 'trusted|relay|cvm|confidential'"
gcloud compute disks list --project "$GCP_PROJECT" --filter="name ~ 'trusted|relay|cvm|confidential'"
```
