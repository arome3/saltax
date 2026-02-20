"""Component-level health endpoint.

Returns per-component health status with latency and detail, plus an
overall system status.  HTTP 200 for healthy/degraded, 503 for unhealthy.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.observability.health import ComponentStatus

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(request: Request) -> JSONResponse:
    """Deep health check with per-component probe results."""
    checker = getattr(request.app.state, "health_checker", None)
    if checker is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "detail": "health checker not configured",
            },
        )

    result = await checker.check()

    components = {
        name: {
            "status": comp.status.value,
            "latency_ms": comp.latency_ms,
            "detail": comp.detail,
        }
        for name, comp in result.components.items()
    }

    status_code = 200 if result.status != ComponentStatus.UNHEALTHY else 503

    content: dict[str, object] = {
        "status": result.status.value,
        "components": components,
        "cached": result.cached,
    }

    budget_tracker = getattr(request.app.state, "budget_tracker", None)
    if budget_tracker is not None:
        content["budget_utilisation"] = budget_tracker.get_summary()

    return JSONResponse(
        status_code=status_code,
        content=content,
    )
