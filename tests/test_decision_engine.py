"""
Unit tests for the decision engine (policy application).

Run with:
  pytest tests/test_decision_engine.py -v
"""

import pytest

from app.models.schemas import Decision
from app.services.decision_engine import apply_policy


class TestDecisionPolicy:
    """Decision policy threshold tests."""

    def test_score_above_block_threshold_returns_block(self):
        result = apply_policy(risk_score=85)
        assert result.decision == Decision.block

    def test_score_at_block_threshold_boundary_returns_block(self):
        # 81 > 80 → block
        result = apply_policy(risk_score=81)
        assert result.decision == Decision.block

    def test_score_exactly_at_block_threshold_in_review_band(self):
        # 80 is NOT > 80 (block_threshold), and 80 > 70 (review_lower_bound)
        # → review_required (review band: review_lower_bound < score ≤ block_threshold)
        result = apply_policy(risk_score=80)
        assert result.decision == Decision.review_required

    def test_score_in_alert_range_returns_alert_analyst(self):
        # Scores strictly between alert_threshold (50) and review_lower_bound (70)
        for score in (51, 60, 65, 69):
            result = apply_policy(risk_score=score)
            assert result.decision == Decision.alert_analyst, f"Expected alert for score {score}"

    def test_score_in_review_band_returns_review_required(self):
        # scores between review_lower_bound (70) and block_threshold (80)
        for score in (71, 75, 79, 80):
            result = apply_policy(risk_score=score)
            assert result.decision == Decision.review_required, f"Expected review_required for score {score}"

    def test_score_exactly_at_alert_threshold_returns_alert(self):
        # 50 is NOT > 50, so log_only
        result = apply_policy(risk_score=50)
        assert result.decision == Decision.log_only

    def test_score_below_alert_threshold_returns_log_only(self):
        for score in (0, 10, 25, 49):
            result = apply_policy(risk_score=score)
            assert result.decision == Decision.log_only, f"Expected log_only for score {score}"

    def test_minimum_risk_score_returns_log_only(self):
        result = apply_policy(risk_score=0)
        assert result.decision == Decision.log_only

    def test_maximum_risk_score_returns_block(self):
        result = apply_policy(risk_score=100)
        assert result.decision == Decision.block

    def test_entity_id_included_in_response(self):
        result = apply_policy(risk_score=90, entity_id="192.168.1.1")
        assert result.entity_id == "192.168.1.1"

    def test_rationale_is_non_empty_string(self):
        for score in (10, 60, 90):
            result = apply_policy(risk_score=score)
            assert isinstance(result.rationale, str)
            assert len(result.rationale) > 10

    def test_risk_score_preserved_in_response(self):
        result = apply_policy(risk_score=73)
        assert result.risk_score == 73

    def test_rationale_mentions_block_for_high_score(self):
        result = apply_policy(risk_score=95)
        assert "block" in result.rationale.lower() or "incident" in result.rationale.lower()

    def test_rationale_mentions_monitor_for_low_score(self):
        result = apply_policy(risk_score=15)
        assert "monitor" in result.rationale.lower() or "log" in result.rationale.lower()
