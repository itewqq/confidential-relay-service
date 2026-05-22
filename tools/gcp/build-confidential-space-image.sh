#!/usr/bin/env bash
# Build and push the Trusted Relay Confidential Space container to Artifact Registry.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/gcp/build-confidential-space-image.sh [options]

Options:
  --project PROJECT      GCP project (default: active gcloud project).
  --region REGION        Artifact Registry region (default: us-central1).
  --repo REPO            Artifact Registry repository (default: trusted-relay).
  --tag TAG              Image tag (default: git short SHA or timestamp).
  --no-push              Build locally but do not push.
  --platform PLATFORM    Container platform (default: linux/amd64 for GCP N2D).
  -h, --help             Show this help.

Outputs:
  image_ref=REGION-docker.pkg.dev/PROJECT/REPO/trusted-relay-confidential-space:TAG
  image_digest=sha256:...
  image_ref_with_digest=REGION-docker.pkg.dev/PROJECT/REPO/trusted-relay-confidential-space@sha256:...
USAGE
}

PROJECT=$(gcloud config get-value project 2>/dev/null || true)
REGION=us-central1
REPO=trusted-relay
TAG=$(git rev-parse --short=12 HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
PUSH=1
PLATFORM=linux/amd64

while [ "$#" -gt 0 ]; do
  case "$1" in
    --project) PROJECT=${2:?missing --project value}; shift 2 ;;
    --region) REGION=${2:?missing --region value}; shift 2 ;;
    --repo) REPO=${2:?missing --repo value}; shift 2 ;;
    --tag) TAG=${2:?missing --tag value}; shift 2 ;;
    --no-push) PUSH=0; shift ;;
    --platform) PLATFORM=${2:?missing --platform value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$PROJECT" ]; then
  echo "no GCP project configured; pass --project" >&2
  exit 1
fi

HOST="$REGION-docker.pkg.dev"
IMAGE="$HOST/$PROJECT/$REPO/trusted-relay-confidential-space:$TAG"

gcloud services enable artifactregistry.googleapis.com --project="$PROJECT" >/dev/null
if ! gcloud artifacts repositories describe "$REPO" --location="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPO" \
    --repository-format=docker \
    --location="$REGION" \
    --project="$PROJECT" \
    --description="Trusted Relay Confidential Space images"
fi

gcloud auth configure-docker "$HOST" --quiet >/dev/null

docker build --platform "$PLATFORM" -f build/confidential-space/Dockerfile -t "$IMAGE" .

if [ "$PUSH" = "1" ]; then
  docker push "$IMAGE"
  DIGEST=$(gcloud artifacts docker images describe "$IMAGE" \
    --project="$PROJECT" \
    --format='value(image_summary.digest)')
  if [ -z "$DIGEST" ]; then
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" | sed 's/^.*@//')
  fi
else
  DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null | sed 's/^.*@//' || true)
fi

echo "image_ref=$IMAGE"
if [ -n "${DIGEST:-}" ]; then
  echo "image_digest=$DIGEST"
  echo "image_ref_with_digest=$HOST/$PROJECT/$REPO/trusted-relay-confidential-space@$DIGEST"
else
  echo "image_digest="
fi
