"""x402 payment verification for the paid audit service.

Implements the x402 V2 protocol for USDC payments on Base (EIP-155:8453).
Verification is delegated to an external facilitator service (default:
``https://x402.org/facilitator``).

All monetary amounts are stored as **integer atomic units** (1 USDC = 10^6
atomic) to avoid IEEE 754 float precision issues.  The ``amount_usdc``
property converts to ``float`` only at the JSON-response boundary.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

USDC_DECIMALS = 6
USDC_CONTRACT_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
X402_VERSION = 2
BASE_NETWORK = "eip155:8453"

_FACILITATOR_TIMEOUT = 10.0
_MAX_PAYMENT_HEADER_BYTES = 8192  # 8 KB — generous for any real x402 payload


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PaymentVerification:
    """Result of x402 payment header verification."""

    valid: bool
    amount_atomic: int  # USDC atomic units (1 USDC = 10^6)
    payer_address: str
    tx_hash: str
    payment_id: str
    error: str

    @property
    def amount_usdc(self) -> float:
        """Amount in USDC for JSON serialization / display."""
        return self.amount_atomic / 10**USDC_DECIMALS


@dataclass(frozen=True)
class PaymentRequirements:
    """x402 payment requirements for a resource."""

    amount_atomic: int  # USDC atomic units (1 USDC = 10^6)
    resource: str
    description: str
    pay_to: str
    max_timeout_seconds: int = 600

    @property
    def amount_usdc(self) -> float:
        """Amount in USDC for JSON serialization / display."""
        return self.amount_atomic / 10**USDC_DECIMALS

    def to_header_value(self) -> str:
        """Encode requirements as a Base64 JSON string for the ``PAYMENT-REQUIRED`` header."""
        payload: dict[str, Any] = {
            "x402Version": X402_VERSION,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": BASE_NETWORK,
                    "maxAmountRequired": str(self.amount_atomic),
                    "resource": self.resource,
                    "description": self.description,
                    "mimeType": "application/json",
                    "payTo": self.pay_to,
                    "maxTimeoutSeconds": self.max_timeout_seconds,
                    "asset": USDC_CONTRACT_ADDRESS,
                    "extra": {},
                }
            ],
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()


def build_payment_response_header(payment_id: str, tx_hash: str) -> str:
    """Build the Base64 ``PAYMENT-RESPONSE`` header value."""
    return base64.b64encode(
        json.dumps({
            "x402Version": X402_VERSION,
            "success": True,
            "paymentId": payment_id,
            "transactionHash": tx_hash,
        }).encode()
    ).decode()


# ── Verifier ──────────────────────────────────────────────────────────────────


class PaymentVerifier:
    """Verify x402 payment proofs via an external facilitator service.

    The HTTP client is created lazily on first use and can be safely
    re-created after ``close()`` is called.
    """

    def __init__(self, facilitator_url: str, pay_to_address: str) -> None:
        if not facilitator_url.startswith("https://"):
            raise ValueError(
                f"Facilitator URL must use HTTPS for payment security, got: {facilitator_url!r}"
            )
        self._facilitator_url = facilitator_url.rstrip("/")
        self._pay_to_address = pay_to_address
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=_FACILITATOR_TIMEOUT)
        return self._client

    def build_requirements(
        self,
        amount_usdc: float,
        resource: str,
        description: str,
    ) -> PaymentRequirements:
        """Build ``PaymentRequirements``, converting USDC float to atomic int.

        Uses ``Decimal`` for the conversion to avoid float precision loss
        (e.g. ``0.1 + 0.2 != 0.3`` in IEEE 754).
        """
        amount_atomic = int(Decimal(str(amount_usdc)) * 10**USDC_DECIMALS)
        return PaymentRequirements(
            amount_atomic=amount_atomic,
            resource=resource,
            description=description,
            pay_to=self._pay_to_address,
        )

    async def verify(
        self,
        payment_header: str,
        requirements: PaymentRequirements,
    ) -> PaymentVerification:
        """Verify a payment header against the facilitator service.

        Returns a ``PaymentVerification`` — never raises for expected
        failure modes (missing header, bad base64, facilitator errors).
        """
        if not payment_header:
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="missing_payment_header",
            )

        if len(payment_header) > _MAX_PAYMENT_HEADER_BYTES:
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="payment_header_too_large",
            )

        # Decode Base64 payload
        try:
            decoded_bytes = base64.b64decode(payment_header, validate=True)
        except Exception:  # noqa: BLE001
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="invalid_base64",
            )

        if not decoded_bytes:
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="empty_payload",
            )

        # Parse JSON payload
        try:
            payment_payload = json.loads(decoded_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="invalid_json_payload",
            )

        # Build facilitator request
        facilitator_body: dict[str, Any] = {
            "paymentPayload": payment_payload,
            "paymentRequirements": {
                "scheme": "exact",
                "network": BASE_NETWORK,
                "maxAmountRequired": str(requirements.amount_atomic),
                "resource": requirements.resource,
                "description": requirements.description,
                "mimeType": "application/json",
                "payTo": requirements.pay_to,
                "maxTimeoutSeconds": requirements.max_timeout_seconds,
                "asset": USDC_CONTRACT_ADDRESS,
                "extra": {},
            },
        }

        # Call facilitator
        try:
            client = self._get_client()
            response = await client.post(
                f"{self._facilitator_url}/verify",
                json=facilitator_body,
            )
        except httpx.TimeoutException:
            logger.warning("Facilitator request timed out")
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="facilitator_timeout",
            )
        except httpx.TransportError as exc:
            logger.warning("Facilitator transport error: %s", exc)
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="facilitator_unreachable",
            )

        # Handle non-success status codes
        if response.status_code >= 500:
            logger.warning("Facilitator returned %d", response.status_code)
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="facilitator_unavailable",
            )

        if response.status_code >= 400:
            logger.info("Facilitator rejected payment: %d", response.status_code)
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="payment_rejected",
            )

        # Parse facilitator response
        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            logger.warning("Facilitator returned non-JSON response")
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="facilitator_response_invalid",
            )

        return self._parse_facilitator_response(data, requirements)

    @staticmethod
    def _parse_facilitator_response(
        data: dict[str, Any],
        requirements: PaymentRequirements,
    ) -> PaymentVerification:
        """Parse the facilitator response defensively (V2 then V1 keys)."""
        # Check verification status — V2 uses "verified", V1 uses "valid"
        is_verified = data.get("verified")
        if is_verified is None:
            is_verified = data.get("valid")
        if is_verified is None:
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="facilitator_response_invalid",
            )

        if not is_verified:
            return PaymentVerification(
                valid=False,
                amount_atomic=0,
                payer_address="",
                tx_hash="",
                payment_id="",
                error="payment_not_verified",
            )

        # Extract fields — V2 keys first, then V1 fallbacks
        tx_hash = data.get("transactionHash") or data.get("tx_hash") or ""
        payer = data.get("payer") or data.get("from") or ""
        payment_id = data.get("paymentId") or ""

        # Defense-in-depth: if the facilitator returns an amount, verify it
        raw_amount = data.get("settledAmount") or data.get("amount")
        if raw_amount is not None:
            try:
                settled = int(raw_amount)
            except (ValueError, TypeError):
                settled = 0
            if settled < requirements.amount_atomic:
                logger.warning(
                    "Facilitator verified=true but amount %d < required %d",
                    settled,
                    requirements.amount_atomic,
                )
                return PaymentVerification(
                    valid=False,
                    amount_atomic=settled,
                    payer_address=payer,
                    tx_hash=tx_hash,
                    payment_id=payment_id,
                    error="insufficient_amount",
                )

        return PaymentVerification(
            valid=True,
            amount_atomic=requirements.amount_atomic,
            payer_address=payer,
            tx_hash=tx_hash,
            payment_id=payment_id,
            error="",
        )

    async def close(self) -> None:
        """Close the HTTP client and allow lazy re-creation."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
