"""x402 payment verification for the paid audit service."""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PaymentVerification:
    """Result of x402 payment header verification."""

    valid: bool
    amount_usdc: float
    payer_address: str
    tx_hash: str
    error: str


async def verify_x402_payment(
    payment_header: str,
    required_amount: float,
) -> PaymentVerification:
    """Verify an ``X-PAYMENT`` header against the x402 protocol.

    Current implementation is a stub that accepts any non-empty Base64 payload.

    .. todo::
        Replace with a real HTTP call to ``https://facilitator.x402.org/verify``
        to validate the payment proof on-chain.
    """
    if not payment_header:
        return PaymentVerification(
            valid=False,
            amount_usdc=0.0,
            payer_address="",
            tx_hash="",
            error="Missing X-PAYMENT header",
        )

    try:
        decoded = base64.b64decode(payment_header, validate=True)
    except Exception:  # noqa: BLE001
        return PaymentVerification(
            valid=False,
            amount_usdc=0.0,
            payer_address="",
            tx_hash="",
            error="Invalid Base64 in X-PAYMENT header",
        )

    if not decoded:
        return PaymentVerification(
            valid=False,
            amount_usdc=0.0,
            payer_address="",
            tx_hash="",
            error="Empty payment payload",
        )

    # Stub: accept any non-empty payload as valid
    logger.info(
        "x402 payment stub accepted",
        extra={"required_amount": required_amount, "payload_len": len(decoded)},
    )
    return PaymentVerification(
        valid=True,
        amount_usdc=required_amount,
        payer_address="0x" + "a" * 40,
        tx_hash="0x" + "b" * 64,
        error="",
    )
