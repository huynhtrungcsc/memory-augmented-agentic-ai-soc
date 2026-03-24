"""
Tests for the behavioral baseline comparison module.

Key accuracy requirements being tested:
  1. Legitimate scanners (Nessus, Nmap) with consistent behavior ≠ high deviation
  2. Sudden activity spike from quiet entity = high deviation
  3. Severity escalation is detected
  4. New event types not seen in baseline are flagged
  5. Entities with no baseline history return deviation=0 (not flagged as dangerous)

These tests directly address the "học vẹt" (rote learning) problem:
  The system should NOT flag a legitimate internal scanner just because it
  matches "scan" keywords — it should compare behavior against baseline.

Run with:
  pytest tests/test_baseline.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.services.baseline import BaselineDeviation, compute_baseline_deviation
from app.services.history_scorer import SimpleEvent


# ─── Helpers ──────────────────────────────────────────────────────────────────


def make_event(
    event_type: str = "SCAN",
    severity: str = "medium",
    anomaly_score: float = 0.5,
    minutes_ago: int = 60,
) -> SimpleEvent:
    return SimpleEvent(
        event_type=event_type,
        severity=severity,
        anomaly_score=anomaly_score,
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
    )


def make_events(n: int, event_type: str = "SCAN", severity: str = "medium",
                minutes_start: int = 1440, minutes_step: int = 60) -> list:
    """Create n evenly-spaced events over a time window."""
    return [
        make_event(event_type, severity, 0.5, minutes_start - i * minutes_step)
        for i in range(n)
    ]


# ─── No baseline tests ────────────────────────────────────────────────────────


class TestNoBaseline:
    """Entities with insufficient history must NOT produce false positives."""

    def test_no_baseline_events_returns_zero_deviation(self):
        result = compute_baseline_deviation(
            recent_events=[make_event(minutes_ago=30)],
            baseline_events=[],
        )
        assert result.deviation == 0.0

    def test_single_baseline_event_returns_zero_deviation(self):
        result = compute_baseline_deviation(
            recent_events=[make_event(minutes_ago=30)],
            baseline_events=[make_event(minutes_ago=120)],
        )
        # Only 1 event < min_baseline_size=3 → insufficient
        assert result.deviation == 0.0
        assert result.has_sufficient_baseline is False

    def test_first_seen_entity_not_flagged_as_dangerous(self):
        """A brand new entity with 0 baseline events must have deviation=0."""
        result = compute_baseline_deviation(
            recent_events=[make_event("SSH Scan", "high", 0.9, 5)],
            baseline_events=[],
        )
        assert result.deviation == 0.0, (
            "New entities should not be flagged as deviating — they have no baseline to compare against"
        )


# ─── Normal behavior tests ────────────────────────────────────────────────────


class TestNormalBehavior:
    """Consistent legitimate activity should produce low deviation."""

    def test_consistent_scanner_low_deviation(self):
        """
        Critical accuracy test: A Nessus/Qualys-style scanner that consistently
        runs the same scan patterns should have LOW deviation.

        This prevents false positives on legitimate security tooling.
        """
        # 24h baseline: 24 scan events (one per hour) — consistent scanner
        baseline = make_events(24, event_type="Vulnerability Scan", severity="medium",
                               minutes_start=1440, minutes_step=60)
        # Last 1h: 1 scan event — normal rate
        recent = [make_event("Vulnerability Scan", "medium", 0.5, 30)]

        result = compute_baseline_deviation(recent, baseline)

        assert result.deviation < 0.3, (
            f"Consistent scanner should have low deviation, got {result.deviation}. "
            "This would cause false positives on Nessus/Qualys scans."
        )

    def test_steady_rate_rate_ratio_near_one(self):
        baseline = make_events(24, minutes_start=1440, minutes_step=60)
        recent = make_events(1, minutes_start=30, minutes_step=10)
        result = compute_baseline_deviation(recent, baseline)
        # rate_ratio near 1.0 = same activity rate
        assert 0.5 <= result.rate_ratio <= 3.0

    def test_no_escalation_when_severity_stable(self):
        baseline = make_events(10, severity="medium", minutes_start=600, minutes_step=60)
        recent = make_events(1, severity="medium", minutes_start=30, minutes_step=10)
        result = compute_baseline_deviation(recent, baseline)
        assert result.is_escalating is False


# ─── Anomalous behavior tests ─────────────────────────────────────────────────


class TestAnomalousBehavior:
    """Sudden behavioral changes should produce high deviation."""

    def test_sudden_spike_produces_high_deviation(self):
        """
        An entity that normally has 1 event/hour but suddenly has 10 events in
        one hour should be flagged with high deviation.
        """
        # Baseline: 5 events in 24h (quiet entity — 1 event per ~5 hours)
        baseline = make_events(5, minutes_start=1440, minutes_step=288)
        # Recent 1h: 10 events (10× the normal rate)
        recent = make_events(10, minutes_start=59, minutes_step=5)

        result = compute_baseline_deviation(recent, baseline)

        assert result.deviation > 0.4, (
            f"Sudden 10x spike should produce high deviation, got {result.deviation}"
        )
        assert result.rate_ratio > 5.0

    def test_severity_escalation_detected(self):
        """
        An entity that went from medium-severity events to critical-severity
        events should have is_escalating=True.
        """
        baseline = make_events(10, severity="low", minutes_start=1440, minutes_step=144)
        recent = [make_event("Critical Alert", "critical", 0.95, 10)]

        result = compute_baseline_deviation(recent, baseline)
        assert result.is_escalating is True
        assert result.sev_delta > 0

    def test_new_event_types_detected(self):
        """
        An entity that historically only generates SCAN events but now shows
        BRUTE_FORCE events should have new_event_types populated.
        """
        baseline = make_events(10, event_type="Port Scan", severity="medium",
                               minutes_start=1440, minutes_step=144)
        recent = [make_event("SSH BruteForce", "high", 0.8, 15)]

        result = compute_baseline_deviation(recent, baseline)
        assert "SSH BruteForce" in result.new_event_types

    def test_extreme_spike_caps_at_one(self):
        """Deviation is capped at 1.0 regardless of how extreme the spike is."""
        baseline = make_events(3, minutes_start=1440, minutes_step=480)
        recent = make_events(100, minutes_start=59, minutes_step=0)  # 100 events in 1h

        result = compute_baseline_deviation(recent, baseline)
        assert result.deviation <= 1.0

    def test_deviation_increases_with_spike_magnitude(self):
        """Larger spikes should produce higher deviation."""
        # Baseline: 20 events over 24h → ~0.83 events/hour
        baseline = make_events(20, minutes_start=1440, minutes_step=72)

        # Small spike: 2 events in last 1h (≈2.4× baseline rate — within threshold)
        small_spike = make_events(2, minutes_start=59, minutes_step=30)
        # Large spike: 10 events in last 1h (≈12× baseline rate — at ceiling)
        large_spike = make_events(10, minutes_start=59, minutes_step=6)

        result_small = compute_baseline_deviation(small_spike, baseline)
        result_large = compute_baseline_deviation(large_spike, baseline)

        assert result_large.deviation > result_small.deviation, (
            f"Larger activity spikes must produce higher deviation scores. "
            f"Got small={result_small.deviation}, large={result_large.deviation}"
        )


# ─── Rate ratio tests ─────────────────────────────────────────────────────────


class TestRateRatio:
    def test_zero_recent_events_rate_ratio_zero(self):
        baseline = make_events(10, minutes_start=1440, minutes_step=144)
        result = compute_baseline_deviation([], baseline)
        assert result.rate_ratio == 0.0

    def test_rate_ratio_matches_expected_value(self):
        # Baseline: 24 events in 24h = 1 per hour
        # Recent 1h: 5 events = 5×
        baseline = make_events(24, minutes_start=1440, minutes_step=60)
        recent = make_events(5, minutes_start=59, minutes_step=12)
        result = compute_baseline_deviation(recent, baseline)
        # Expected rate_ratio ≈ 5 (5 events/hour vs 1 event/hour baseline)
        assert 3.0 <= result.rate_ratio <= 7.0


# ─── Data completeness tests ──────────────────────────────────────────────────


class TestDataCompleteness:
    def test_result_has_all_required_fields(self):
        baseline = make_events(5, minutes_start=1440, minutes_step=288)
        recent = [make_event(minutes_ago=30)]
        result = compute_baseline_deviation(recent, baseline)

        assert hasattr(result, "deviation")
        assert hasattr(result, "rate_ratio")
        assert hasattr(result, "sev_delta")
        assert hasattr(result, "is_escalating")
        assert hasattr(result, "new_event_types")
        assert hasattr(result, "baseline_event_count")
        assert hasattr(result, "recent_event_count")
        assert hasattr(result, "has_sufficient_baseline")

    def test_event_counts_correct(self):
        baseline = make_events(8, minutes_start=1440, minutes_step=180)
        recent = make_events(3, minutes_start=50, minutes_step=15)
        result = compute_baseline_deviation(recent, baseline)
        assert result.baseline_event_count == 8
        assert result.recent_event_count == 3
