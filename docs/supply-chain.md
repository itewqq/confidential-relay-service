# Supply Chain Hardening

This repo is still a research prototype, but release candidates should be built
as if the image digest will become a user-pinned security boundary.

## Current Controls

- `cargo build --locked` uses `Cargo.lock` during the Confidential Space build.
- The local verifier pins the final Confidential Space `container.image_digest`
  or accepted image signature key IDs.
- `RelayConfig::config_hash()` binds reviewed runtime policy and upstream config
  into attested TLS.
- `tools/gcp/build-confidential-space-image.sh` supports digest-pinned builder and
  runtime base images via `--rust-base`, `--runtime-base`, and
  `--require-pinned-bases`.

## Recommended Release Build

Resolve the base-image digests for the target platform, then build with immutable
base references:

```bash
RUST_BASE='mirror.gcr.io/library/rust:1.95.0-bookworm@sha256:...'
RUNTIME_BASE='gcr.io/distroless/cc-debian12@sha256:...'

tools/gcp/build-confidential-space-image.sh \
  --project "$GCP_PROJECT" \
  --region "$GCP_REGION" \
  --repo trusted-relay \
  --tag "$(git rev-parse --short=12 HEAD)" \
  --rust-base "$RUST_BASE" \
  --runtime-base "$RUNTIME_BASE" \
  --require-pinned-bases
```

Record the printed base refs, final image digest, config hash, commit SHA, and
negative-test result in `docs/real-online-test.md` or release notes.

## Still To Add

- Generate and publish an SBOM, for example SPDX or CycloneDX.
- Sign release images and verify `submods.container.image_signatures`, not only
  `container.image_digest`.
- Publish provenance/SLSA-style build attestations.
- Make release builds reproducible enough that reviewers can rebuild and compare
  artifacts, or at least compare source commit, lockfile, base digests, and final
  image digest.
