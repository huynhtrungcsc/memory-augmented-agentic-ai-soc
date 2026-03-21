"""
POST /decide

Lightweight endpoint that applies the decision policy to any risk score,
independent of the full analysis pipeline.  Useful for testing thresholds
or integrating external scoring systems into the same policy engine.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.models.schemas import DecideRequest, DecideResponse
from app.services.decision_engine import apply_policy

router = APIRouter(prefix="/decide", tags=["decision"])


@router.post("", response_model=DecideResponse)
async def decide(request: DecideRequest) -> DecideResponse:
    """
    Apply the SOC decision policy to a given risk score.

    Decision rules:
    - score > BLOCK_THRESHOLD  → block
    - score > ALERT_THRESHOLD  → alert_analyst
    - otherwise                → log_only
    """
    return apply_policy(
        risk_score=request.risk_score,
        entity_id=request.entity_id,
        context=request.context,
    )
