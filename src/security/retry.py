"""Async retry with exponential backoff and jitter."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from typing import TypeVar

    T = TypeVar("T")

logger = logging.getLogger(__name__)


async def with_retry(
    fn: Callable[..., Awaitable[T]],
    *args: object,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: object,
) -> T:
    """Call *fn* with retries on transient failures.

    Parameters
    ----------
    fn:
        Async callable to invoke.
    max_retries:
        Total attempts (including the first).  Default 3.
    base_delay:
        Initial delay in seconds.  Doubles each attempt.
    max_delay:
        Delay cap in seconds.
    retryable_exceptions:
        Exception types eligible for retry.  ``CancelledError``
        (a ``BaseException``) is always re-raised immediately.

    Backoff formula::

        delay = min(base_delay * 2^(attempt-1), max_delay)
              + random.uniform(0, base_delay * 0.1)
    """
    last_exc: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            # Non-retryable → propagate immediately
            if not isinstance(exc, retryable_exceptions):
                raise

            last_exc = exc

            if attempt == max_retries:
                break

            delay = min(base_delay * 2 ** (attempt - 1), max_delay)
            jitter = random.uniform(0, base_delay * 0.1)  # noqa: S311
            total_delay = delay + jitter

            logger.warning(
                "Retry %d/%d for %s after %.2fs: %s",
                attempt,
                max_retries,
                getattr(fn, "__qualname__", getattr(fn, "__name__", repr(fn))),
                total_delay,
                exc,
            )
            await asyncio.sleep(total_delay)

    # All retries exhausted — raise the last exception
    raise last_exc  # type: ignore[misc]
