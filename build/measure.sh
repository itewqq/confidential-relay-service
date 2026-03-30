#!/usr/bin/env bash
# Compute the expected measurement hash for the built binary.
# This hash should match the MRTD value reported in TDX attestation quotes,
# or the MEASUREMENT in SEV-SNP reports.
#
# Usage:
#   ./build/measure.sh
#
# Prerequisites:
#   - Docker (to build reproducibly)

set -euo pipefail

echo "=== Building reproducible image ==="
docker build -f build/Dockerfile -t trusted-relay-measure .

echo "=== Extracting binary ==="
CONTAINER_ID=$(docker create trusted-relay-measure)
docker cp "$CONTAINER_ID:/usr/local/bin/trusted-relay-server" /tmp/trusted-relay-server
docker rm "$CONTAINER_ID" > /dev/null

echo "=== Computing measurements ==="
SHA256=$(sha256sum /tmp/trusted-relay-server | cut -d' ' -f1)
SHA384=$(sha384sum /tmp/trusted-relay-server | cut -d' ' -f1)

echo ""
echo "Binary SHA-256: $SHA256"
echo "Binary SHA-384: $SHA384"
echo ""
echo "Update measurements.json with these values."

rm /tmp/trusted-relay-server
