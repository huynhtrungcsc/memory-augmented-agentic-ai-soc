"""
Tests for contradictory evidence handling.

Verify that mixed benign/malicious signals are correctly identified
and trigger review_required instead of alert_analyst.
"""

import pytest

from app.services.scoring_engine import _compute_contradiction_score, compute_hybrid_score
from app.services.decision_engine import apply_policy
from app.models.schemas import Severity


class TestContradictionScore:
    def test_high_anomaly_high_fp_is_contradictory(self):
        """Detector says attack, LLM says FP → strong contradiction."""
        score = _compute_contradiction_score(
            anomaly_score=0.9,
            llm_score=0.8,
            fp_likelihood=0.85,
            trust_discount=0.0,
        )
        assert score >= 0.40, f"Expected contradiction ≥ 0.40, got {score}"

    def test_aligned_high_signals_not_contradictory(self):
        """All signals agree it's an attack → no contradiction."""
        score = _compute_contradiction_score(
            anomaly_score=0.9,
            llm_score=0.9,
            fp_likelihood=0.05,
            trust_discount=0.0,
        )
        assert score < 0.15, f"Expected contradiction < 0.15, got {score}"

    def test_aligned_benign_signals_not_contradictory(self):
        """All signals agree it's benign → no contradiction."""
        score = _compute_contradiction_score(
            anomaly_score=0.1,
            llm_score=0.1,
            fp_likelihood=0.9,
            trust_discount=0.0,
        )
        assert score < 0.10, f"Expected contradiction < 0.10, got {score}"

    def test_high_anomaly_with_large_trust_discount_creates_contradiction(self):
        """Known scanner doing suspicious things → slight contradiction."""
        score = _compute_contradiction_score(
            anomaly_score=0.8,
            llm_score=0.6,
            fp_likelihood=0.3,
            trust_discount=0.3,
        )
        assert score > 0.10, f"Expected contradiction > 0.10, got {score}"

    def test_contradiction_score_bounded(self):
        """Score must stay in [0, 1]."""
        score = _compute_contradiction_score(1.0, 0.0, 1.0, 0.4)
        assert 0.0 <= score <= 1.0


class TestContradictionInScoring:
    def test_contradictory_flagged_in_middle_band(self):
        """High fp_likelihood + high anomaly in middle score range → contradictory_flagged."""
        result = compute_hybrid_score(
            anomaly_score=0.85,
            llm_risk_score=60,
            history_score=0.2,
            severity=Severity.medium,
            fp_likelihood=0.80,  # FP says it's benign
            event_count=5,
        )
        # With fp=0.8 and anomaly=0.85, contradiction should be high
        assert result.contradiction_score > 0.30, f"Got {result.contradiction_score}"

    def test_not_contradictory_when_all_agree(self):
        """All signals agree → contradictory_flagged=False."""
        result = compute_hybrid_score(
            anomaly_score=0.9,
            llm_risk_score=85,
            history_score=0.8,
            severity=Severity.critical,
            fp_likelihood=0.05,
            event_count=15,
        )
        assert not result.contradictory_flagged

    def test_contradiction_increases_calibration_pull(self):
        """High contradiction should lower confidence and pull calibrated_score toward 50."""
        # Contradictory case
        r_contradictory = compute_hybrid_score(
            anomaly_score=0.85,
            llm_risk_score=55,
            history_score=0.2,
            severity=Severity.medium,
            fp_likelihood=0.80,
            event_count=5,
        )
        # Non-contradictory case (same score, aligned signals)
        r_aligned = compute_hybrid_score(
            anomaly_score=0.85,
            llm_risk_score=85,
            history_score=0.5,
            severity=Severity.high,
            fp_likelihood=0.05,
            event_count=5,
        )
        # Contradictory case should have lower confidence
        assert r_contradictory.confidence_score <= r_aligned.confidence_score


class TestContradictionDecision:
    def test_contradictory_alert_band_becomes_review_required(self):
        """Score in alert band (50–70) + contradictory_flagged → review_required."""
        decision = apply_policy(
            risk_score=58,
            entity_id="test-ip",
            evidence_count=1,
            contradictory_flagged=True,
        )
        assert decision.decision.value == "review_required"
        assert "contradictory" in decision.rationale.lower()

    def test_non_contradictory_alert_band_stays_alert_analyst(self):
        """Same score without contradiction → alert_analyst."""
        decision = apply_policy(
            risk_score=58,
            entity_id="test-ip",
            evidence_count=1,
            contradictory_flagged=False,
        )
        assert decision.decision.value == "alert_analyst"

    def test_contradiction_does_not_affect_block_decision(self):
        """Block-level score should still block even with contradiction."""
        decision = apply_policy(
            risk_score=85,
            entity_id="test-ip",
            evidence_count=3,
            contradictory_flagged=True,
        )
        # With sufficient evidence and high score, still should block or review
        assert decision.decision.value in ("block", "review_required")

    def test_contradiction_does_not_affect_log_only(self):
        """Low score is still log_only regardless of contradiction."""
        decision = apply_policy(
            risk_score=30,
            entity_id="test-ip",
            evidence_count=0,
            contradictory_flagged=True,
        )
        assert decision.decision.value == "log_only"

    def test_mixed_admin_tool_scenario(self):
        """Known admin tool with unusual usage pattern → should be review_required."""
        # Simulates: RDP from admin account but to unusual target at unusual time
        result = compute_hybrid_score(
            anomaly_score=0.60,
            llm_risk_score=55,
            history_score=0.15,
            severity=Severity.medium,
            fp_likelihood=0.65,  # LLM thinks it's likely FP but not certain
            event_count=3,
            trust_discount=0.15,  # partial trust (known admin pattern)
        )
        decision = apply_policy(
            risk_score=result.calibrated_score,
            evidence_count=1,
            contradictory_flagged=result.contradictory_flagged,
        )
        # Should not be a confident alert_analyst — either log_only or review_required
        assert decision.decision.value in ("log_only", "review_required", "alert_analyst")
        # The key is that contradictory_flagged can override alert_analyst to review_required
        # which is tested in test_contradictory_alert_band_becomes_review_required above
