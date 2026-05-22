#!/usr/bin/env bash
# Best-effort cleanup for low-cost Trusted Relay GCP test resources.

set -euo pipefail

PROJECT=$(gcloud config get-value project 2>/dev/null || true)
ZONE=${ZONE:-us-central1-a}
REGION=${REGION:-us-central1}
DELETE_BUCKET=${DELETE_BUCKET:-0}
DELETE_ARTIFACT_REPO=${DELETE_ARTIFACT_REPO:-1}
DELETE_CLOUDBUILD_OBJECTS=${DELETE_CLOUDBUILD_OBJECTS:-0}
ARTIFACT_REPO=${ARTIFACT_REPO:-trusted-relay}

if [ -z "$PROJECT" ]; then
  echo "no GCP project configured" >&2
  exit 1
fi

delete_instance() {
  local name=$1
  if gcloud compute instances describe "$name" --zone="$ZONE" --project="$PROJECT" >/dev/null 2>&1; then
    gcloud compute instances delete "$name" --zone="$ZONE" --project="$PROJECT" --quiet
  fi
}

delete_firewall() {
  local name=$1
  if gcloud compute firewall-rules describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
    gcloud compute firewall-rules delete "$name" --project="$PROJECT" --quiet
  fi
}

delete_instance trusted-relay-capacity-probe
delete_instance trusted-relay-cvm-test
delete_instance trusted-relay-cs
delete_instance trusted-relay-cs-a
delete_instance trusted-relay-cs-b
delete_instance trusted-relay-builder

delete_firewall trusted-relay-builder-ssh-alt
delete_firewall trusted-relay-gateway-connect
delete_firewall trusted-relay-cvm-private

for image in $(gcloud compute images list --project="$PROJECT" --no-standard-images --filter='name~^trusted-relay' --format='value(name)'); do
  gcloud compute images delete "$image" --project="$PROJECT" --quiet
done

if [ "$DELETE_ARTIFACT_REPO" = "1" ]; then
  if gcloud artifacts repositories describe "$ARTIFACT_REPO" --location="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
    gcloud artifacts repositories delete "$ARTIFACT_REPO" --location="$REGION" --project="$PROJECT" --quiet
  fi
fi

project_number=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null || true)
if [ "$DELETE_BUCKET" = "1" ] && [ -n "$project_number" ]; then
  bucket="trusted-relay-$project_number"
  if gcloud storage buckets describe "gs://$bucket" >/dev/null 2>&1; then
    gcloud storage rm --recursive "gs://$bucket" || true
  fi
fi

if [ "$DELETE_CLOUDBUILD_OBJECTS" = "1" ]; then
  cloudbuild_bucket="gs://${PROJECT}_cloudbuild"
  if gcloud storage buckets describe "$cloudbuild_bucket" >/dev/null 2>&1; then
    gcloud storage rm --recursive "$cloudbuild_bucket/artifacts/**" "$cloudbuild_bucket/source/**" || true
  fi
fi

echo "cleanup complete"
