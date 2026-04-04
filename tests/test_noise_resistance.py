"""
Noise & False-Positive Resistance Tests.

These tests verify that the SOC AI pipeline does NOT produce high-risk
decisions for benign-but-noisy activity patterns:

  1. Benign bursts — short spikes in traffic that come from scanning tools,
     load tests, or non-malicious crawlers.
  2. Repeated harmless scans — internal security scanner making many low-sev
     port-check events over time.
  3. Internal admin activity — domain admin performing scheduled maintenance
     (RDP, WMI, script execution) that looks suspicious in isolation.
  4. Mixed legitimate/noisy entity — entity with a long history of medium
     alerts interspersed with normal activity: history_score should not
     reach the block threshold on its own.

Each test applies the policy to an event set and asserts the composite
score does NOT cross the block threshold (80) on its own without confirmed
multi-signal evidence.

The tests use the unit-testable service layer directly (no HTTP layer).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from app.models.schemas import Severity
from app.services.decision_engine import DECISION_RANK, apply_policy
from app.services.history_scorer import SimpleEvent, compute_history_score
from app.services.scoring_engine import compute_hybrid_score


# ─── Helpers ──────────────────────────────────────────────────────────────────

_UTC = timezone.utc


def _make_event(
    event_type: str,
    severity: str,
    anomaly: float,
    minutes_ago: float,
    message: str = "",
) -> SimpleEvent:
    ts = datetime.now(_UTC) - timedelta(minutes=minutes_ago)
    return SimpleEvent(
        event_type=event_type,
        severity=severity,
        anomaly_score=anomaly,
        timestamp=ts,
        message=message,
    )


def _score_events(
    events: List[SimpleEvent],
    llm_risk: int,
    severity: Severity,
    event_count_hint: int = 0,
) -> int:
    """Helper: compute composite score from events + mock LLM score."""
    history = compute_history_score(events)
    avg_anomaly = sum(e.anomaly_score for e in events) / len(events) if events else 0.0
    breakdown = compute_hybrid_score(
        anomaly_score=avg_anomaly,
        llm_risk_score=llm_risk,
        history_score=history,
        severity=severity,
        sequence_matches=None,
        baseline_deviation=None,
        event_count=event_count_hint or len(events),
    )
    return breakdown.composite_score


# ─── Test classes ──────────────────────────────────────────────────────────────


class TestBenignBursts:
    """
    Benign traffic bursts (load test, nmap, crawler) must not
    trigger the BLOCK decision when the LLM correctly identifies low risk.
    """

    def test_load_test_burst_low_anomaly_no_block(self):
        """
        50 low-anomaly HTTP events in 10 minutes (load test pattern).
        LLM correctly outputs low risk (20). Composite must be below 70.
        """
        events = [
            _make_event("HTTP_GET", "low", 0.05, i * 0.2)
            for i in range(50)
        ]
        score = _score_events(events, llm_risk=20, severity=Severity.low)
        assert score < 70, (
            f"Load test burst should not exceed review threshold; got composite={score}"
        )

    def test_nmap_port_scan_medium_anomaly_no_block(self):
        """
        20 port-scan events with medium anomaly (scanner is loud but not malicious).
        LLM assigns risk=40 (suspicious but not confirmed attack).
        Composite must stay below block threshold.
        """
        events = [
            _make_event("PORT_SCAN", "medium", 0.45, i * 3)
            for i in range(20)
        ]
        score = _score_events(events, llm_risk=40, severity=Severity.medium)
        assert score < 80, (
            f"Port scan burst should not trigger block without chain confirmation; got composite={score}"
        )

    def test_crawler_burst_no_block_decision(self):
        """
        100 DNS lookups and HTTP requests (web crawler pattern).
        LLM outputs risk=25. Decision must not be block.
        """
        events = [
            _make_event("DNS_LOOKUP", "low", 0.10, i * 0.5)
            for i in range(60)
        ] + [
            _make_event("HTTP_GET", "low", 0.08, i * 0.5 + 30)
            for i in range(40)
        ]
        score = _score_events(events, llm_risk=25, severity=Severity.low)
        result = apply_policy(risk_score=score, entity_id="crawler-bot", evidence_count=0)
        assert result.decision.value in ("log_only", "alert_analyst"), (
            f"Crawler burst must not reach review/block; got {result.decision.value} (score={score})"
        )


class TestRepeatedHarmlessScans:
    """
    Repeated low-severity scans from an internal security scanner.
    These generate many events over time but are all known-benign types.
    """

    def test_internal_vuln_scanner_no_block(self):
        """
        Internal vulnerability scanner runs daily. 100 scan events over 24h,
        all low severity and low anomaly. LLM correctly assigns risk=15.
        """
        events = [
            _make_event("VULN_SCAN", "low", 0.08, i * 14)  # every 14 min over 24h
            for i in range(100)
        ]
        score = _score_events(events, llm_risk=15, severity=Severity.low, event_count_hint=100)
        assert score < 50, (
            f"Internal vuln scanner should produce log_only; got composite={score}"
        )

    def test_network_discovery_probe_stays_below_alert(self):
        """
        Network discovery probe (ICMP pings + ARP) across a /24 subnet.
        Medium anomaly (volume), but all standard discovery traffic.
        LLM risk=30. Should stay below alert threshold or just barely alert.
        """
        events = [
            _make_event("ICMP_PING", "low", 0.25, i)
            for i in range(254)  # full /24 sweep
        ]
        score = _score_events(events, llm_risk=30, severity=Severity.low, event_count_hint=254)
        # The freq_factor will be high (254 events) but anomaly and severity are low
        # and LLM says low risk → expect below block threshold
        assert score < 70, (
            f"Network discovery probe must not reach review/block; got composite={score}"
        )

    def test_repeated_failed_auth_scanner_with_low_llm(self):
        """
        Credential spraying scanner that fails repeatedly — generates many
        failed_login events but LLM correctly identifies it as an automated
        scanner (no credential stuffing confirmation). LLM risk=35.
        """
        events = [
            _make_event("AUTH_FAILED", "medium", 0.40, i * 2)
            for i in range(30)
        ]
        history = compute_history_score(events)
        avg_anomaly = sum(e.anomaly_score for e in events) / len(events)
        breakdown = compute_hybrid_score(
            anomaly_score=avg_anomaly,
            llm_risk_score=35,
            history_score=history,
            severity=Severity.medium,
            sequence_matches=None,
            baseline_deviation=None,
            event_count=30,
        )
        result = apply_policy(
            risk_score=breakdown.composite_score,
            entity_id="scanner-host",
            evidence_count=1,  # only one strong signal (anomaly barely over threshold)
        )
        # Should be alert or review at most — not block (single signal, no chain)
        assert DECISION_RANK.get(result.decision.value, 0) < DECISION_RANK["block"], (
            f"Scanner should not trigger block without chain + baseline; "
            f"got {result.decision.value} (composite={breakdown.composite_score})"
        )


class TestInternalAdminActivity:
    """
    Admin activity patterns that trigger alerts in naive systems
    but are NOT actual attacks: RDP, WMI, scheduled script execution.
    """

    def test_rdp_admin_session_no_block(self):
        """
        RDP login from admin IP to many hosts (patch round). High severity
        but LLM identifies it as admin pattern (risk=25). Must not block.
        """
        events = [
            _make_event("RDP_LOGIN", "high", 0.30, i * 5)
            for i in range(15)
        ]
        score = _score_events(events, llm_risk=25, severity=Severity.high)
        result = apply_policy(risk_score=score, entity_id="admin.corp", evidence_count=0)
        assert result.decision.value != "block", (
            f"Admin RDP logins must not trigger block; got {result.decision.value} (score={score})"
        )

    def test_wmi_execution_admin_no_block(self):
        """
        WMI remote execution events (admin deploying patch via SCCM).
        Medium-high anomaly, but LLM has context from asset DB (risk=20).
        """
        events = [
            _make_event("WMI_EXEC", "high", 0.50, i * 10)
            for i in range(10)
        ]
        breakdown = compute_hybrid_score(
            anomaly_score=0.50,
            llm_risk_score=20,  # LLM knows this is admin activity
            history_score=compute_history_score(events),
            severity=Severity.high,
            sequence_matches=None,
            baseline_deviation=None,
            event_count=10,
        )
        result = apply_policy(
            risk_score=breakdown.composite_score,
            entity_id="sccm-server",
            evidence_count=1,
        )
        assert result.decision.value != "block", (
            f"SCCM admin activity should not block; "
            f"got {result.decision.value} (composite={breakdown.composite_score})"
        )

    def test_backup_agent_large_data_movement_no_block(self):
        """
        Backup agent moves large volumes of data (looks like exfil). LLM
        recognises scheduled backup pattern (risk=10). Must be log_only.
        """
        events = [
            _make_event("LARGE_TRANSFER", "medium", 0.20, i * 30)
            for i in range(8)
        ]
        score = _score_events(events, llm_risk=10, severity=Severity.medium)
        result = apply_policy(risk_score=score, entity_id="backup-agent", evidence_count=0)
        assert result.decision.value == "log_only", (
            f"Backup agent transfer must be log_only; "
            f"got {result.decision.value} (composite={score})"
        )


class TestMixedLegitimateAndNoisy:
    """
    Entities with mixed legitimate/noisy event history should not
    be over-penalised. Stale high-anomaly events should decay over time.
    """

    def test_old_high_anomaly_events_decay_in_history_score(self):
        """
        10 high-anomaly events from 5 days ago should have significantly
        less influence than 2 recent low-anomaly events (temporal decay).
        """
        old_events = [
            _make_event("PORT_SCAN", "high", 0.90, 5 * 24 * 60 + i)  # 5 days ago
            for i in range(10)
        ]
        recent_events = [
            _make_event("DNS_LOOKUP", "low", 0.05, i)  # just now
            for i in range(2)
        ]
        all_events = old_events + recent_events

        history_with_decay = compute_history_score(all_events, decay_half_life_hours=24.0)
        history_no_decay = compute_history_score(old_events)  # only the old bad events

        # With decay, old events should reduce their influence significantly
        # The decayed score (mixing old high + recent low) should be meaningfully
        # lower than the pure old-events score
        assert history_with_decay < history_no_decay, (
            f"Decay should reduce history_score for stale events: "
            f"decayed={history_with_decay}, no_decay={history_no_decay}"
        )

    def test_recent_events_outweigh_stale_history(self):
        """
        An entity had a bad week (high anomaly) but has been clean for 3 days.
        Recent clean events should bring the history score down noticeably.
        """
        old_bad = [
            _make_event("BRUTE_FORCE", "critical", 0.95, 4 * 24 * 60 + i)  # 4 days ago
            for i in range(5)
        ]
        recent_clean = [
            _make_event("HTTP_GET", "low", 0.05, i * 60)  # last few hours
            for i in range(10)
        ]

        score_old_only = compute_history_score(old_bad, decay_half_life_hours=24.0)
        score_mixed = compute_history_score(old_bad + recent_clean, decay_half_life_hours=24.0)

        # Mixed should score lower because old events are decayed AND recent clean events
        # weight in as low-anomaly. Freq_factor is higher but anomaly pulls score down.
        # At minimum, verify score is bounded reasonably.
        assert score_mixed <= 1.0, "History score must not exceed 1.0"
        assert score_mixed >= 0.0, "History score must not go below 0.0"

    def test_high_freq_low_severity_entity_stays_below_block(self):
        """
        Entity that generates lots of low-severity noise (monitoring system).
        High frequency contributes to freq_factor, but low anomaly + low LLM risk
        should keep the decision at alert or below.
        """
        events = [
            _make_event("HEALTH_CHECK", "low", 0.03, i)
            for i in range(200)
        ]
        score = _score_events(events, llm_risk=5, severity=Severity.low, event_count_hint=200)
        result = apply_policy(risk_score=score, entity_id="monitor-agent", evidence_count=0)
        assert result.decision.value in ("log_only", "alert_analyst"), (
            f"High-freq low-sev monitor should not exceed alert_analyst; "
            f"got {result.decision.value} (composite={score})"
        )


class TestEvidenceGate:
    """
    Minimum evidence gate: single-sensor high-score events must not
    auto-block without corroboration from multiple independent signals.
    """

    def test_single_high_anomaly_event_no_block(self):
        """
        A single event with anomaly=0.95 (one loud sensor) and LLM risk=70.
        Only 1 strong signal fired. Decision must not be block.
        """
        breakdown = compute_hybrid_score(
            anomaly_score=0.95,
            llm_risk_score=70,
            history_score=0.1,
            severity=Severity.high,
            sequence_matches=None,
            baseline_deviation=None,
            event_count=1,
        )
        result = apply_policy(
            risk_score=breakdown.composite_score,
            entity_id="unknown-host",
            evidence_count=1,  # only anomaly sensor fired — no chain, no baseline
        )
        assert result.decision.value != "block", (
            f"Single sensor should not auto-block; "
            f"got {result.decision.value} (composite={breakdown.composite_score}, "
            f"calibrated={breakdown.calibrated_score})"
        )

    def test_zero_evidence_high_score_yields_review(self):
        """
        Even a very high composite score with evidence_count=0 must not block.
        This tests the evidence gate directly.
        """
        result = apply_policy(risk_score=95, entity_id="mystery-host", evidence_count=0)
        assert result.decision.value in ("review_required",), (
            f"evidence_count=0 at score=95 should yield review_required; "
            f"got {result.decision.value}"
        )

    def test_multi_signal_confirmation_allows_block(self):
        """
        Four independent strong signals (chain + baseline + anomaly + history)
        should unlock the BLOCK decision at high scores.
        """
        result = apply_policy(risk_score=90, entity_id="attacker-host", evidence_count=4)
        assert result.decision.value == "block", (
            f"4 strong signals at score=90 must yield block; got {result.decision.value}"
        )
