"""
Unit tests for the hybrid risk scoring engine.

Tests verify that:
- Component scores are correctly normalised
- Weights are applied proportionally
- Composite score is clamped to [0, 100]
- Score breakdown fields are populated correctly
- Different severity values produce expected results

Run with:
  pytest tests/test_hybrid_scoring.py -v
"""

import pytest

from app.models.schemas import Severity
from app.services.scoring_engine import compute_hybrid_score


class TestHybridScoringBasics:
    """Composite score range and structure."""

    def test_all_zero_inputs_produce_low_score(self):
        result = compute_hybrid_score(
            anomaly_score=0.0,
            llm_risk_score=0,
            history_score=0.0,
            severity=Severity.low,
        )
        # low severity = 0.10 × weight_severity → small but non-zero
        assert 0 <= result.composite_score <= 10

    def test_all_max_inputs_produce_100(self):
        result = compute_hybrid_score(
            anomaly_score=1.0,
            llm_risk_score=100,
            history_score=1.0,
            severity=Severity.critical,
        )
        assert result.composite_score == 100

    def test_composite_score_always_between_0_and_100(self):
        for anomaly in (0.0, 0.5, 1.0):
            for llm in (0, 50, 100):
                for history in (0.0, 0.5, 1.0):
                    for sev in Severity:
                        r = compute_hybrid_score(anomaly, llm, history, sev)
                        assert 0 <= r.composite_score <= 100

    def test_score_breakdown_fields_present(self):
        result = compute_hybrid_score(0.6, 70, 0.4, Severity.high)
        assert hasattr(result, "anomaly_score")
        assert hasattr(result, "llm_score")
        assert hasattr(result, "history_score")
        assert hasattr(result, "severity_score")
        assert hasattr(result, "weights")
        assert hasattr(result, "composite_score")

    def test_weights_dict_has_four_keys(self):
        result = compute_hybrid_score(0.5, 60, 0.3, Severity.medium)
        assert set(result.weights.keys()) == {"anomaly", "llm", "history", "severity"}

    def test_component_scores_are_normalised_0_to_1(self):
        result = compute_hybrid_score(0.8, 75, 0.6, Severity.high)
        assert 0.0 <= result.anomaly_score <= 1.0
        assert 0.0 <= result.llm_score <= 1.0
        assert 0.0 <= result.history_score <= 1.0
        assert 0.0 <= result.severity_score <= 1.0


class TestSeverityContribution:
    """Severity levels produce expected normalised scores."""

    def test_critical_severity_score_is_1(self):
        result = compute_hybrid_score(0.0, 0, 0.0, Severity.critical)
        assert result.severity_score == 1.0

    def test_high_severity_score_is_0_75(self):
        result = compute_hybrid_score(0.0, 0, 0.0, Severity.high)
        assert result.severity_score == 0.75

    def test_medium_severity_score_is_0_40(self):
        result = compute_hybrid_score(0.0, 0, 0.0, Severity.medium)
        assert result.severity_score == 0.40

    def test_low_severity_score_is_0_10(self):
        result = compute_hybrid_score(0.0, 0, 0.0, Severity.low)
        assert result.severity_score == 0.10

    def test_higher_severity_produces_higher_composite(self):
        base = dict(anomaly_score=0.5, llm_risk_score=50, history_score=0.3)
        low = compute_hybrid_score(**base, severity=Severity.low)
        medium = compute_hybrid_score(**base, severity=Severity.medium)
        high = compute_hybrid_score(**base, severity=Severity.high)
        critical = compute_hybrid_score(**base, severity=Severity.critical)
        assert low.composite_score <= medium.composite_score
        assert medium.composite_score <= high.composite_score
        assert high.composite_score <= critical.composite_score


class TestWeightApplication:
    """Higher signal values in one component increase the composite score."""

    def test_higher_anomaly_raises_score(self):
        low = compute_hybrid_score(0.1, 50, 0.3, Severity.medium)
        high = compute_hybrid_score(0.9, 50, 0.3, Severity.medium)
        assert high.composite_score > low.composite_score

    def test_higher_llm_score_raises_composite(self):
        low = compute_hybrid_score(0.5, 10, 0.3, Severity.medium)
        high = compute_hybrid_score(0.5, 90, 0.3, Severity.medium)
        assert high.composite_score > low.composite_score

    def test_higher_history_score_raises_composite(self):
        low = compute_hybrid_score(0.5, 60, 0.0, Severity.medium)
        high = compute_hybrid_score(0.5, 60, 1.0, Severity.medium)
        assert high.composite_score > low.composite_score

    def test_llm_score_normalisation(self):
        result = compute_hybrid_score(0.0, 100, 0.0, Severity.low)
        assert result.llm_score == 1.0

        result_zero = compute_hybrid_score(0.0, 0, 0.0, Severity.low)
        assert result_zero.llm_score == 0.0


class TestKnownScenarios:
    """End-to-end scenarios with expected composite score ranges."""

    def test_benign_scenario_produces_low_score(self):
        # Low anomaly, low LLM risk, no history, low severity
        result = compute_hybrid_score(0.05, 10, 0.0, Severity.low)
        assert result.composite_score < 30, f"Expected low score, got {result.composite_score}"

    def test_suspicious_scenario_produces_mid_score(self):
        result = compute_hybrid_score(0.5, 55, 0.3, Severity.medium)
        assert 30 <= result.composite_score <= 75

    def test_critical_attack_chain_produces_high_score(self):
        # High anomaly, high LLM risk, strong history, critical severity
        result = compute_hybrid_score(0.9, 88, 0.8, Severity.critical)
        assert result.composite_score >= 80, f"Expected high score, got {result.composite_score}"

    def test_high_llm_with_no_history_still_produces_alert_range(self):
        # Strong LLM signal even without memory context
        result = compute_hybrid_score(0.6, 75, 0.0, Severity.high)
        assert result.composite_score >= 50
