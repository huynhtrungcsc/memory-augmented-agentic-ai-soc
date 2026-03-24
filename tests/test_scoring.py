"""
Unit tests for the anomaly scoring module.

Run with:
  pytest tests/test_scoring.py -v
"""

from datetime import datetime

import pytest

from app.models.schemas import RawLog, LogSource, Severity
from app.services.anomaly_detector import compute_score, _is_rfc1918


def _make_log(**kwargs) -> RawLog:
    defaults = {
        "source": LogSource.generic,
        "timestamp": datetime.utcnow(),
        "event_type": "TEST_EVENT",
        "severity": Severity.low,
        "message": "Test event",
    }
    defaults.update(kwargs)
    return RawLog(**defaults)


class TestAnomalyScoring:
    """Anomaly score range and heuristic tests."""

    def test_score_always_between_0_and_1(self):
        log = _make_log(severity=Severity.critical, message="exploit brute bruteforce")
        score = compute_score(log)
        assert 0.0 <= score <= 1.0

    def test_low_severity_no_keywords_gives_low_score(self):
        log = _make_log(severity=Severity.low, message="routine check")
        score = compute_score(log)
        assert score <= 0.35

    def test_critical_severity_gives_high_base_score(self):
        log = _make_log(severity=Severity.critical, message="routine check")
        score = compute_score(log)
        assert score >= 0.8

    def test_brute_force_keyword_boosts_score(self):
        log_low = _make_log(severity=Severity.medium, message="routine event")
        log_brute = _make_log(severity=Severity.medium, message="SSH brute force detected")
        assert compute_score(log_brute) > compute_score(log_low)

    def test_multiple_keywords_bump_score_further(self):
        log_one = _make_log(severity=Severity.medium, message="brute force attempt")
        log_many = _make_log(severity=Severity.medium, message="brute force exploit injection backdoor")
        assert compute_score(log_many) >= compute_score(log_one)

    def test_keyword_boost_capped(self):
        log = _make_log(
            severity=Severity.low,
            message="brute scan exploit injection backdoor exfiltration c2 lateral mimikatz dump credential",
        )
        score = compute_score(log)
        assert score <= 1.0

    def test_suspicious_port_boosts_score(self):
        log_normal = _make_log(severity=Severity.medium, message="connection", dst_port=80)
        log_suspicious = _make_log(severity=Severity.medium, message="connection", dst_port=4444)
        assert compute_score(log_suspicious) > compute_score(log_normal)

    def test_non_suspicious_port_no_boost(self):
        log = _make_log(severity=Severity.medium, message="routine", dst_port=80)
        score_no_port = compute_score(_make_log(severity=Severity.medium, message="routine"))
        score_with_port = compute_score(log)
        assert score_with_port == score_no_port

    def test_internal_to_internal_lateral_boost(self):
        log_internal = _make_log(
            severity=Severity.medium,
            message="lateral movement smb",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
        )
        log_external = _make_log(
            severity=Severity.medium,
            message="lateral movement smb",
            src_ip="8.8.8.8",
            dst_ip="10.0.0.5",
        )
        assert compute_score(log_internal) > compute_score(log_external)

    def test_high_severity_ssh_bruteforce_is_anomalous(self):
        log = _make_log(
            severity=Severity.high,
            event_type="ET SCAN SSH BruteForce",
            message="SSH brute force attempt detected",
            dst_port=22,
        )
        score = compute_score(log)
        assert score >= 0.5, f"Expected anomalous, got score {score}"

    def test_low_severity_benign_message_not_anomalous(self):
        log = _make_log(
            severity=Severity.low,
            event_type="SCHEDULED_TASK",
            message="Backup completed successfully",
        )
        score = compute_score(log)
        assert score < 0.5


class TestRFC1918:
    """RFC-1918 private address detection."""

    def test_10_block_is_private(self):
        assert _is_rfc1918("10.0.0.1")
        assert _is_rfc1918("10.255.255.255")

    def test_172_16_31_block_is_private(self):
        assert _is_rfc1918("172.16.0.1")
        assert _is_rfc1918("172.31.255.255")

    def test_172_15_not_private(self):
        assert not _is_rfc1918("172.15.0.1")

    def test_192_168_block_is_private(self):
        assert _is_rfc1918("192.168.0.1")
        assert _is_rfc1918("192.168.255.255")

    def test_public_addresses_not_private(self):
        for ip in ("8.8.8.8", "1.1.1.1", "52.0.0.1", "185.220.101.47"):
            assert not _is_rfc1918(ip), f"{ip} should not be RFC-1918"

    def test_malformed_ip_returns_false(self):
        assert not _is_rfc1918("not-an-ip")
        assert not _is_rfc1918("")
        assert not _is_rfc1918("999.999.999.999")
