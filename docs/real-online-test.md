# Real Online Test Runbook

Use this runbook for a low-cost production-path test on GCP Confidential Space.
It uses one small private Confidential Space VM, an optional tiny gateway, and a
local proxy on the user's machine. Delete cloud resources immediately after the
smoke test.

## Cost Controls

- Use `n2d-standard-2` for the Confidential Space relay.
- Use `--duration 2h` / `--max-run-duration=2h` for throwaway VMs.
- Keep the relay private with `--no-address`; use a gateway, IAP tunnel, or SSH
  tunnel from a cheap control host.
- Use a low-limit provider key in `.env` and inject it through the private admin
  endpoint only.
- Run `tools/gcp/cleanup.sh` and verify Artifact Registry/Compute are empty when done.

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
```

3. Launch a private relay:

```bash
tools/gcp/launch-confidential-space.sh \
  --project "$GCP_PROJECT" \
  --zone "$GCP_ZONE" \
  --name trusted-relay-cs-a \
  --image-ref "$IMAGE_A_REF_WITH_DIGEST" \
  --env TRUSTED_RELAY_UPSTREAM="$TRUSTED_RELAY_UPSTREAM" \
  --env TRUSTED_RELAY_ALLOWED_UPSTREAM="$TRUSTED_RELAY_ALLOWED_UPSTREAM" \
  --env TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST="${IMAGE_A_DIGEST#sha256:}" \
  --env TRUSTED_RELAY_ADMIN_LISTEN="0.0.0.0:8788" \
  --duration 2h
```

4. Run strict online verification from a host that can reach the private relay:

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

- local proxy accepts only after attested TLS succeeds;
- gateway sees only CONNECT metadata;
- CVM injects the provider credential and strips the local key;
- upstream returns a normal response;
- logs remain metadata-only.

## Required Negative Test

The negative test must prove trusted-code identity, not merely wrong credentials.

1. Keep image `A` pins in the local proxy and online checker.
2. Make a tiny compiled trusted-code change, for example changing the `/health`
   response body.
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

## May 22, 2026 Confidential Space A/B Evidence

A real GCP Confidential Space A/B test used private no-external-IP
`n2d-standard-2` relay VMs in `us-central1-a`. Image `B` differed from image
`A` by a tiny compiled trusted-code change: `/health` returned `ok-b` instead
of `ok`. The private admin port was also exercised through IAP after adding
`EXPOSE 8788` to the Confidential Space image. No provider key was available in
the environment, so this run verified the production attestation path, private
admin reachability, and fail-closed behavior before injection; it did not make a
paid upstream provider request.

```text
A image_digest=sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be
A relay_config_hash=ba482176c844b171307e90af40fe34cb5a178f3a6c0a886360827980e5072226
B image_digest=sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
B relay_config_hash=bcd3a9b2a2a113db3e92e55631d3eec8b6da543927174d2346d37c5189c2b96a
```

Pinned to `A`, the strict verifier accepted live `A`:

```text
token.swname=CONFIDENTIAL_SPACE
token.dbgstat=disabled-since-boot
token.container.image_digest=sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be
token.gce.project_id=stone-botany-277908
token.gce.zone=us-central1-a
RESULT: OK - GcpConfidentialSpace/Strict verification succeeded
health.status=HTTP/1.1 200 OK
health.body=ok
```

Live `B` reported the changed digest and changed behavior:

```text
token.container.image_digest=sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
token.gce.instance_name=trusted-relay-cs-b
health.status=HTTP/1.1 200 OK
health.body=ok-b
```

Pinned to `A`, the policy check rejected live `B` after validating the
Google-signed token fields. The local network could not reach Google's JWKS
endpoint reliably during this phase, so the JWT signature was verified with the
Google JWKS fetched out-of-band for the run; the attested token still came from
the live Confidential Space VM.

```text
jwt.signature=valid
jwt.issuer=https://confidentialcomputing.googleapis.com
jwt.audience=trusted-relay-attested-tls
jwt.swname=CONFIDENTIAL_SPACE
jwt.dbgstat=disabled-since-boot
jwt.secboot=true
jwt.container.image_digest=sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
Error: image digest mismatch: expected sha256:d6ecd42ffacd6b07b9d8e17be4665e925f9d61b42f198d40f076812e5f2a70be, got sha256:5254bf562b5fe4cbc8130bca45a10a4fdb61b228832f14f527494f0903147213
```

The user-side local proxy pinned to `A` also failed before forwarding a request
to live `B`:

```text
HTTP/1.1 502 Bad Gateway
{"error":{"message":"relay request failed: client error (Connect)","type":"local_proxy_error"}}
```

Before provider credential injection, the relay failed closed instead of
forwarding a local user token upstream:

```text
HTTP/1.1 503 Service Unavailable
{"error":{"message":"provider credential not loaded","type":"relay_error"}}
```

## Cleanup

```bash
tools/gcp/cleanup.sh
gcloud artifacts repositories list --project "$GCP_PROJECT"
gcloud compute instances list --project "$GCP_PROJECT" --filter='name~(trusted|relay|cvm|confidential)'
gcloud compute disks list --project "$GCP_PROJECT" --filter='name~(trusted|relay|cvm|confidential)'
```

If you created an Artifact Registry repo only for the test, delete it too:

```bash
gcloud artifacts repositories delete trusted-relay \
  --location "$GCP_REGION" \
  --project "$GCP_PROJECT" \
  --quiet
```
