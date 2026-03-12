"""
Decision engine — applies the SOC decision policy to a risk score.

Policy:
  risk_score > BLOCK_THRESHOLD (default 80)
    AND minimum evidence satisfied              → block
    AND within cooldown window                 → block (sustained)
  risk_score > BLOCK_THRESHOLD
    BUT minimum evidence NOT satisfied         → review_required
  REVIEW_LOWER_BOUND < risk_score ≤ BLOCK_THRESHOLD → review_required (if uncertainty present)
  risk_score > ALERT_THRESHOLD (default 50)   → alert_analyst
  otherwise                                   → log_only

Decision states:
  review_required — for high-risk cases without sufficient multi-signal evidence.
    Requires explicit human analyst sign-off before any automated blocking action.
    Sits between alert_analyst and block.
  minimum evidence gate — BLOCK requires at least `min_signals_for_block`
    strong independent signals (chain, baseline, anomaly>0.8, history>0.7).
    A single sensor firing cannot trigger automatic block.
  evidence_count — count of strong signals that fired (passed in from analyze.py).

Thresholds are configurable via environment variables.
"""

from __future__ import annotations

from app.config import get_settings
from app.models.schemas import Decision, DecideResponse

settings = get_settings()

# Decision rank for ordering (used by hysteresis in analyze.py)
DECISION_RANK: dict[str, int] = {
    "block": 3,
    "review_required": 2,
    "alert_analyst": 1,
    "log_only": 0,
}


def _count_strong_signals(
    anomaly_score: float,
    history_score: float,
    has_chain: bool,
    has_baseline_deviation: bool,
) -> int:
    """
    Count how many strong, independent signals fired.

    A "strong signal" is one that independently suggests high risk.
    The minimum evidence gate requires at least 2 of these before BLOCK.

    Signals counted:
      • Chain detected   — algorithmic MITRE chain match (at least 2-phase)
      • Baseline spike   — behavioral deviation has_sufficient_baseline + is elevated
      • Anomaly outlier  — rule-based detector fired strongly (>0.8)
      • History pattern  — entity has an established high-risk history (>0.7)
    """
    count = 0
    if has_chain:
        count += 1
    if has_baseline_deviation:
        count += 1
    if anomaly_score > 0.8:
        count += 1
    if history_score > 0.7:
        count += 1
    return count


def apply_policy(
    risk_score: int,
    entity_id: str | None = None,
    context: str | None = None,
    evidence_count: int = 2,   # strong signal count from scoring context
    contradictory_flagged: bool = False,  # new: force review_required for contradictory evidence
) -> DecideResponse:
    """
    Map a risk score to a Decision and produce a human-readable rationale.

    Parameters
    ----------
    risk_score:
        Integer 0–100 (composite or calibrated score from scoring engine).
    entity_id:
        Optional entity label for the rationale message.
    context:
        Optional free-text context forwarded from the caller.
    evidence_count:
        Number of strong signals that fired.  BLOCK requires at least
        settings.min_signals_for_block (default 2).

    Returns
    -------
    DecideResponse with decision + rationale.
    """
    s = get_settings()
    entity_label = entity_id or "entity"

    if risk_score > s.block_threshold:
        # Minimum evidence gate — if we don't have enough strong independent
        # signals, demote from BLOCK to REVIEW_REQUIRED to prevent single-sensor FP.
        if evidence_count >= s.min_signals_for_block:
            decision = Decision.block
            rationale = (
                f"Risk score {risk_score} exceeds block threshold ({s.block_threshold}). "
                f"Multi-signal confirmation: {evidence_count} independent strong signal(s). "
                f"Automated blocking recommended for {entity_label}. "
                "Initiate incident response and forensic evidence collection."
            )
        else:
            decision = Decision.review_required
            rationale = (
                f"Risk score {risk_score} exceeds block threshold ({s.block_threshold}), "
                f"but only {evidence_count} strong signal(s) detected "
                f"(minimum {s.min_signals_for_block} required for automated block). "
                f"Human analyst review required for {entity_label} before any blocking action. "
                "Single-sensor alerts carry elevated false-positive risk."
            )

    elif risk_score > s.review_lower_bound:
        # Scores in the review band — high enough to warrant analyst attention,
        # not sufficient for automated action.
        decision = Decision.review_required
        rationale = (
            f"Risk score {risk_score} is in the review band "
            f"({s.review_lower_bound}–{s.block_threshold}). "
            f"Analyst review required for {entity_label}. "
            "Investigate the triggering events before deciding on escalation."
        )

    elif risk_score > s.alert_threshold:
        # Contradiction override: mixed signals in the alert band → review_required
        if contradictory_flagged:
            decision = Decision.review_required
            rationale = (
                f"Risk score {risk_score} is in alert band "
                f"({s.alert_threshold}–{s.review_lower_bound}), "
                f"but evidence is contradictory (anomaly and false-positive signals disagree). "
                f"Human analyst review required for {entity_label} before escalation. "
                "Contradictory evidence increases false-positive risk significantly."
            )
        else:
            decision = Decision.alert_analyst
            rationale = (
                f"Risk score {risk_score} is between alert threshold "
                f"({s.alert_threshold}) and review threshold "
                f"({s.review_lower_bound}). "
                f"Alert analyst for investigation of {entity_label}. "
                "Consider temporary network segmentation while investigating."
            )
    else:
        decision = Decision.log_only
        rationale = (
            f"Risk score {risk_score} is below alert threshold "
            f"({s.alert_threshold}). "
            f"Activity for {entity_label} logged for audit trail. "
            "No immediate action required; continue passive monitoring."
        )

    return DecideResponse(
        risk_score=risk_score,
        decision=decision,
        rationale=rationale,
        entity_id=entity_id,
    )
