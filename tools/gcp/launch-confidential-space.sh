#!/usr/bin/env bash
# Launch a low-cost private Confidential Space VM running Trusted Relay.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/gcp/launch-confidential-space.sh --image-ref IMAGE [options]

Options:
  --image-ref IMAGE       Container image ref, preferably ...@sha256:...
  --name NAME             Instance name (default: trusted-relay-cs)
  --project PROJECT       GCP project (default: active gcloud project)
  --zone ZONE             Zone (default: us-central1-a)
  --machine-type TYPE     Machine type (default: n2d-standard-2)
  --service-account SA    Runtime service account email
  --duration DURATION     Max run duration (default: 2h)
  --env KEY=VALUE         tee-env-* variable for the workload. Repeatable.
  --serial                Enable serial console output.
  --log-redirect          Ask Confidential Space to redirect workload logs to serial.
  -h, --help              Show this help.

Required env usually includes non-secret relay config only. Provider keys should
come from --secret-broker-url or another post-attestation injection path, not be
baked into the image or metadata.
USAGE
}

PROJECT=$(gcloud config get-value project 2>/dev/null || true)
ZONE=us-central1-a
NAME=trusted-relay-cs
MACHINE_TYPE=n2d-standard-2
SERVICE_ACCOUNT=
DURATION=2h
IMAGE_REF=
SERIAL=false
LOG_REDIRECT=false
ENV_VARS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image-ref) IMAGE_REF=${2:?missing --image-ref value}; shift 2 ;;
    --name) NAME=${2:?missing --name value}; shift 2 ;;
    --project) PROJECT=${2:?missing --project value}; shift 2 ;;
    --zone) ZONE=${2:?missing --zone value}; shift 2 ;;
    --machine-type) MACHINE_TYPE=${2:?missing --machine-type value}; shift 2 ;;
    --service-account) SERVICE_ACCOUNT=${2:?missing --service-account value}; shift 2 ;;
    --duration) DURATION=${2:?missing --duration value}; shift 2 ;;
    --env) ENV_VARS+=("${2:?missing --env value}"); shift 2 ;;
    --serial) SERIAL=true; shift ;;
    --log-redirect) LOG_REDIRECT=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$PROJECT" ]; then
  echo "no GCP project configured; pass --project" >&2
  exit 1
fi
if [ -z "$IMAGE_REF" ]; then
  echo "--image-ref is required" >&2
  usage >&2
  exit 2
fi
if [[ "$IMAGE_REF" != *@sha256:* ]]; then
  echo "warning: --image-ref is not digest-pinned; attestation policy should pin the reported digest" >&2
fi

METADATA="^~^tee-image-reference=$IMAGE_REF~block-project-ssh-keys=TRUE"
if [ "$LOG_REDIRECT" = true ]; then
  METADATA+="~tee-container-log-redirect=true"
fi
for kv in "${ENV_VARS[@]+${ENV_VARS[@]}}"; do
  key=${kv%%=*}
  val=${kv#*=}
  if [ -z "$key" ] || [ "$key" = "$kv" ]; then
    echo "--env must be KEY=VALUE, got '$kv'" >&2
    exit 2
  fi
  METADATA+="~tee-env-$key=$val"
done
if [ "$SERIAL" = true ]; then
  METADATA+="~serial-port-enable=true"
fi

ARGS=(
  compute instances create "$NAME"
  --project="$PROJECT"
  --zone="$ZONE"
  --machine-type="$MACHINE_TYPE"
  --confidential-compute-type=SEV_SNP
  --maintenance-policy=TERMINATE
  --image-project=confidential-space-images
  --image-family=confidential-space
  --boot-disk-size=11GB
  --boot-disk-type=pd-balanced
  --network-interface=network=default,subnet=default,no-address,nic-type=GVNIC
  --no-address
  --shielded-secure-boot
  --shielded-vtpm
  --metadata="$METADATA"
  --max-run-duration="$DURATION"
  --instance-termination-action=DELETE
  --quiet
)
if [ -n "$SERVICE_ACCOUNT" ]; then
  ARGS+=(--service-account="$SERVICE_ACCOUNT" --scopes=cloud-platform)
fi

gcloud "${ARGS[@]}"

gcloud compute instances describe "$NAME" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --format='table(name,zone,status,machineType.basename(),networkInterfaces[0].networkIP,serviceAccounts[0].email)'
