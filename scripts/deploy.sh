#!/usr/bin/env bash
# ==============================================================================
# SaltaX — EigenCompute Deployment Script
#
# Builds the Docker image, pushes to EigenCloud registry, and deploys (or
# upgrades) the application on EigenCompute with Intel TDX TEE.
#
# Usage:
#   ./scripts/deploy.sh
#
# Prerequisites:
#   - Docker installed and authenticated to registry.eigencloud.xyz
#   - ecloud CLI installed and configured
#   - Git repository with at least one commit
#
# Resource targets (documented; CLI flags may vary by ecloud version):
#   CPU:     4 vCPU
#   Memory:  8 GB
#   Storage: 20 GB
# ==============================================================================

set -euo pipefail

APP_NAME="saltax-sovereign"
REGISTRY="registry.eigencloud.xyz/saltax"
GIT_SHA="$(git rev-parse --short HEAD)"
IMAGE_TAG="saltax:${GIT_SHA}"
IMAGE_REF="${REGISTRY}/${IMAGE_TAG}"

echo "==> Building Docker image: ${IMAGE_REF}"
docker build -t "${IMAGE_REF}" .

echo "==> Pushing to EigenCloud registry..."
docker push "${IMAGE_REF}"

echo "==> Checking deployment status..."
if ecloud compute app status --name "${APP_NAME}" > /dev/null 2>&1; then
    echo "==> App exists — upgrading..."
    ecloud compute app upgrade \
        --name "${APP_NAME}" \
        --image-ref "${IMAGE_REF}"
else
    echo "==> First deployment — deploying..."
    ecloud compute app deploy \
        --name "${APP_NAME}" \
        --image-ref "${IMAGE_REF}"
fi

DIGEST="$(docker inspect --format='{{.Id}}' "${IMAGE_REF}")"
echo ""
echo "==> Deployment complete."
echo "    Image ref:    ${IMAGE_REF}"
echo "    Image digest: ${DIGEST}"
echo ""
echo "Next steps:"
echo "  1. Verify attestation:  ecloud compute app attestation --name ${APP_NAME}"
echo "  2. Check health:        curl https://<your-domain>/api/v1/status"
echo "  3. Seal secrets (if first deploy): ./scripts/kms-init.sh"
