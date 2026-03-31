"""
Tests for low-and-slow attack persistence detection (baseline.compute_slow_persistence).

Verify that gradual, sustained suspicious activity is detected even when
no single burst threshold is triggered.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.baseline import SlowPersistence, compute_slow_persistence
from app.services.history_scorer import SimpleEvent

_UTC = timezone.utc


def _evt(hours_ago: float, anomaly: float = 0.6, severity: str = "high", event_type: str = "BRUTE_FORCE") -> SimpleEvent:
    return SimpleEvent(
        event_type=event_type,
        severity=severity,
        anomaly_score=anomaly,
        timestamp=datetime.now(_UTC) - timedelta(hours=hours_ago),
        message=f"event {hours_ago}h ago",
    )


class TestSlowPersistenceEmpty:
    def test_empty_events_returns_zero(self):
        result = compute_slow_persistence([])
        assert result.persistence_score == 0.0
        assert not result.is_persistent

    def test_events_older_than_72h_are_excluded(self):
        events = [_evt(73, anomaly=0.9)] * 30
        result = compute_slow_persistence(events)
        assert result.suspicious_72h == 0
        assert result.persistence_score == 0.0

    def test_fewer_than_3_suspicious_events_no_persistence(self):
        events = [_evt(5, 0.8), _evt(10, 0.8)]
        result = compute_slow_persistence(events)
        assert result.suspicious_72h == 2
        assert result.persistence_score == 0.0
        assert not result.is_persistent


class TestSlowPersistenceDetection:
    def test_spread_over_many_hours_flags_persistent(self):
        """2 suspicious events every 4 hours over 48h = 24 events spread over 12 distinct hour buckets."""
        events = []
        for h in range(2, 50, 4):  # 12 events spread at hours 2,6,10,...,46
            events.append(_evt(h, anomaly=0.6))
        result = compute_slow_persistence(events)
        assert result.suspicious_72h >= 10
        assert result.distinct_hours_active >= 5
        assert result.is_persistent

    def test_benign_low_anomaly_events_not_flagged(self):
        """Many events but all with low anomaly score — should not count as suspicious."""
        events = [_evt(i, anomaly=0.2, event_type="DNS_QUERY") for i in range(1, 60)]
        result = compute_slow_persistence(events)
        assert result.suspicious_72h == 0  # 0.2 < _SLOW_ANOMALY_THRESHOLD (0.45)
        assert not result.is_persistent

    def test_burst_events_in_one_hour_not_flagged_by_persistence(self):
        """50 events all in the last 30 min — burst, not spread. distinct_hours should be 1."""
        # Use sub-minute offsets (0.005h = 18 seconds) — all within same hour bucket
        events = [_evt(0.005 * i, anomaly=0.8) for i in range(1, 51)]
        result = compute_slow_persistence(events)
        # All events within <30 min → distinct_hours_active = 1
        assert result.distinct_hours_active == 1
        # spread_factor = 1/36 ≈ 0.028 < 0.05
        spread = result.distinct_hours_active / 36.0
        assert spread < 0.05

    def test_trend_increasing_flagged(self):
        """More events in the recent 36h than in the older 36h → trend_increasing=True."""
        older = [_evt(40 + i, anomaly=0.6) for i in range(3)]   # 3 events 40-42h ago
        newer = [_evt(5 + i, anomaly=0.6) for i in range(15)]   # 15 events 5-19h ago
        result = compute_slow_persistence(older + newer)
        assert result.trend_increasing is True

    def test_trend_stable_not_flagged(self):
        """Equal events in both halves → trend_increasing=False."""
        older = [_evt(40 + i, anomaly=0.6) for i in range(10)]
        newer = [_evt(5 + i, anomaly=0.6) for i in range(10)]
        result = compute_slow_persistence(older + newer)
        assert result.trend_increasing is False

    def test_window_counts_are_correct(self):
        """Events in 6h, 24h, 72h windows are counted correctly."""
        events = [
            _evt(2, 0.7),   # within 6h
            _evt(4, 0.7),   # within 6h
            _evt(10, 0.7),  # within 24h, not 6h
            _evt(20, 0.7),  # within 24h, not 6h
            _evt(50, 0.7),  # within 72h, not 24h
            _evt(60, 0.7),  # within 72h
        ]
        result = compute_slow_persistence(events)
        assert result.suspicious_6h == 2
        assert result.suspicious_24h == 4
        assert result.suspicious_72h == 6

    def test_persistence_score_increases_with_spread(self):
        """More spread → higher persistence score."""
        concentrated = [_evt(i * 0.1, anomaly=0.7) for i in range(1, 20)]  # all <2h
        spread_out = [_evt(i * 3, anomaly=0.7) for i in range(1, 20)]      # 3h apart
        r_conc = compute_slow_persistence(concentrated)
        r_spread = compute_slow_persistence(spread_out)
        assert r_spread.persistence_score > r_conc.persistence_score


class TestSlowPersistenceIntegration:
    def test_slow_brute_force_pattern(self):
        """Simulate slow brute-force: 1-2 attempts/hour over 48 hours."""
        events = []
        for h in range(1, 49):
            for attempt in range(2):
                events.append(_evt(h + attempt * 0.1, anomaly=0.65, event_type="AUTH_FAILURE"))
        result = compute_slow_persistence(events)
        assert result.is_persistent
        assert result.distinct_hours_active >= 20

    def test_slow_recon_pattern(self):
        """APT reconnaissance: one port scan every 3 hours for 3 days."""
        events = [_evt(i * 3, anomaly=0.55, event_type="PORT_SCAN") for i in range(24)]
        result = compute_slow_persistence(events)
        assert result.is_persistent
        assert result.suspicious_72h >= 20

    def test_low_rate_beaconing(self):
        """C2 beaconing every 4 hours = 18 events in 72h, each with high anomaly."""
        events = [_evt(i * 4, anomaly=0.80, event_type="C2_BEACON") for i in range(18)]
        result = compute_slow_persistence(events)
        assert result.is_persistent
        assert result.suspicious_72h == 18
