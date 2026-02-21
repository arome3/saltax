#!/usr/bin/env bash
# ==============================================================================
# SaltaX — EigenCloud KMS Secret Sealing
#
# Seals sensitive environment variables via EigenCloud KMS so they can only be
# decrypted by the exact Docker image running inside the TEE.
#
# Usage:
#   export SALTAX_EIGENAI_WALLET_PRIVATE_KEY="0x..."
#   export SALTAX_GITHUB_APP_PRIVATE_KEY="..."
#   export SALTAX_GITHUB_WEBHOOK_SECRET="..."
#   export KMS_ENDPOINT="https://kms.eigencloud.xyz"
#   ./scripts/kms-init.sh
#
# Prerequisites:
#   - ecloud CLI installed and configured
#   - KMS endpoint reachable
#   - Secret values set as environment variables (never hardcoded)
# ==============================================================================

set -euo pipefail

APP_NAME="saltax-sovereign"
KMS_ENDPOINT="${KMS_ENDPOINT:-https://kms.eigencloud.xyz}"

SECRETS=(
    "SALTAX_EIGENAI_WALLET_PRIVATE_KEY"
    "SALTAX_GITHUB_APP_PRIVATE_KEY"
    "SALTAX_GITHUB_WEBHOOK_SECRET"
)

sealed=0
skipped=0
failed=0

echo "==> SaltaX KMS Secret Sealing"
echo "    App:      ${APP_NAME}"
echo "    Endpoint: ${KMS_ENDPOINT}"
echo ""

for secret_name in "${SECRETS[@]}"; do
    echo "--- ${secret_name}"

    # Check if already sealed
    if ecloud kms status --key "${secret_name}" --endpoint "${KMS_ENDPOINT}" > /dev/null 2>&1; then
        echo "    Already sealed — skipping."
        skipped=$((skipped + 1))
        continue
    fi

    # Verify the env var is set
    secret_value="${!secret_name:-}"
    if [[ -z "${secret_value}" ]]; then
        echo "    ERROR: Environment variable ${secret_name} is not set."
        failed=$((failed + 1))
        continue
    fi

    # Seal the secret
    if echo "${secret_value}" | ecloud kms seal \
        --key "${secret_name}" \
        --app "${APP_NAME}" \
        --endpoint "${KMS_ENDPOINT}" \
        --stdin; then
        echo "    Sealed successfully."
        sealed=$((sealed + 1))
    else
        echo "    ERROR: Failed to seal ${secret_name}."
        failed=$((failed + 1))
    fi
done

echo ""
echo "==> Summary: ${sealed} sealed, ${skipped} skipped, ${failed} failed"

if [[ "${failed}" -gt 0 ]]; then
    echo "    One or more secrets failed to seal. Check errors above."
    exit 1
fi

echo "==> All secrets sealed successfully."
