"""
Tests for category-specific calibration factors.

Verify that event categories receive correct risk multipliers:
- Admin activity: 0.75× (reduce false positives from legitimate admin ops)
- Network scanner: 0.60× (further reduce scanner false positives)
- C2/exfiltration: 1.20× (amplify high-severity threat categories)
- Noisy benign: 0.90× (moderate reduction for known noisy events)
- Unknown: 1.00× (neutral)
"""

import pytest

from app.services.category_calibration import CalibrationResult, get_category_factor


class TestCategoryFactorOutput:
    def test_returns_calibration_result(self):
        result = get_category_factor(event_type="BRUTE_FORCE", message="failed login")
        assert isinstance(result, CalibrationResult)
        assert hasattr(result, "factor")
        assert hasattr(result, "category_label")

    def test_factor_is_float(self):
        result = get_category_factor(event_type="PORT_SCAN", message="port scan")
        assert isinstance(result.factor, float)

    def test_factor_is_positive(self):
        for event_type in ["DNS_QUERY", "BRUTE_FORCE", "C2_BEACON", "PORT_SCAN", "FILE_ACCESS"]:
            result = get_category_factor(event_type=event_type, message="test")
            assert result.factor > 0.0, f"{event_type} should have positive factor"


class TestAdminActivityCalibration:
    def test_admin_login_gets_reduced_factor(self):
        result = get_category_factor(event_type="ADMIN_LOGIN", message="admin user login")
        assert result.factor <= 0.80, f"Admin login factor should be ≤ 0.80, got {result.factor}"
        assert "admin" in result.category_label.lower()

    def test_privileged_access_gets_reduced_factor(self):
        result = get_category_factor(event_type="PRIVILEGED_ACCESS", message="sudo command executed")
        assert result.factor <= 0.85

    def test_config_change_gets_reduced_factor(self):
        result = get_category_factor(event_type="CONFIG_CHANGE", message="firewall rule modified by admin")
        assert result.factor <= 0.85

    def test_rdp_admin_message_gets_reduced_factor(self):
        result = get_category_factor(event_type="REMOTE_ACCESS", message="rdp session from admin workstation")
        assert result.factor <= 0.90


class TestScannerCalibration:
    def test_port_scan_gets_reduced_factor(self):
        result = get_category_factor(event_type="PORT_SCAN", message="nmap port scan detected")
        assert result.factor <= 0.70, f"Scanner factor should be ≤ 0.70, got {result.factor}"
        assert any(k in result.category_label.lower() for k in ("scan", "network"))

    def test_vuln_scan_gets_reduced_factor(self):
        result = get_category_factor(event_type="VULN_SCAN", message="nessus vulnerability scan")
        assert result.factor <= 0.70

    def test_network_discovery_gets_reduced_factor(self):
        result = get_category_factor(event_type="NETWORK_SCAN", message="host discovery scan")
        assert result.factor <= 0.75


class TestC2Calibration:
    def test_c2_beacon_gets_amplified_factor(self):
        result = get_category_factor(event_type="C2_BEACON", message="command and control beacon")
        assert result.factor >= 1.10, f"C2 factor should be ≥ 1.10, got {result.factor}"
        assert result.category_label != "neutral"  # must be categorized, not default

    def test_data_exfiltration_gets_amplified_factor(self):
        result = get_category_factor(event_type="DATA_EXFIL", message="large data transfer to external")
        assert result.factor >= 1.10

    def test_lateral_movement_gets_amplified_factor(self):
        result = get_category_factor(event_type="LATERAL_MOVEMENT", message="pass-the-hash lateral movement")
        assert result.factor >= 1.10

    def test_ransomware_gets_amplified_factor(self):
        result = get_category_factor(event_type="RANSOMWARE", message="encrypted files detected")
        assert result.factor >= 1.15


class TestNoisyBenignCalibration:
    def test_dns_query_gets_slight_reduction(self):
        result = get_category_factor(event_type="DNS_QUERY", message="normal dns lookup")
        assert result.factor <= 1.0

    def test_http_normal_traffic_slight_reduction(self):
        result = get_category_factor(event_type="HTTP_REQUEST", message="normal web request")
        assert result.factor <= 1.0


class TestUnknownCategory:
    def test_unknown_event_type_returns_neutral(self):
        result = get_category_factor(event_type="TOTALLY_UNKNOWN_TYPE", message="unknown event")
        assert result.factor == 1.0
        assert result.category_label == "neutral"

    def test_empty_event_type_returns_neutral(self):
        result = get_category_factor(event_type="", message="")
        assert result.factor == 1.0
        assert result.category_label == "neutral"


class TestCalibrationIntegration:
    def test_scanner_factor_lower_than_admin_factor(self):
        """Scanner should get more reduction than generic admin activity."""
        scanner = get_category_factor(event_type="PORT_SCAN", message="nmap scan")
        admin = get_category_factor(event_type="ADMIN_LOGIN", message="admin login")
        assert scanner.factor <= admin.factor

    def test_c2_factor_highest_of_all_categories(self):
        """C2/exfil category should produce highest risk multiplier."""
        c2 = get_category_factor(event_type="C2_BEACON", message="c2 beacon detected")
        scanner = get_category_factor(event_type="PORT_SCAN", message="scan")
        admin = get_category_factor(event_type="ADMIN_LOGIN", message="admin")
        dns = get_category_factor(event_type="DNS_QUERY", message="dns")
        assert c2.factor > scanner.factor
        assert c2.factor > admin.factor
        assert c2.factor > dns.factor

    def test_scoring_engine_accepts_category_factor(self):
        """compute_hybrid_score should accept and apply category_factor without error."""
        from app.models.schemas import Severity
        from app.services.scoring_engine import compute_hybrid_score

        result = compute_hybrid_score(
            anomaly_score=0.75,
            llm_risk_score=70,
            history_score=0.5,
            severity=Severity.high,
            event_count=8,
            category_factor=1.20,
            category_label="c2_exfiltration",
        )
        assert result.composite_score > 0
        assert result.category_label == "c2_exfiltration"
        assert result.category_factor == 1.20

    def test_category_factor_increases_score_for_c2(self):
        """Higher category factor should produce higher calibrated score."""
        from app.models.schemas import Severity
        from app.services.scoring_engine import compute_hybrid_score

        base_kwargs = dict(
            anomaly_score=0.70,
            llm_risk_score=60,
            history_score=0.4,
            severity=Severity.high,
            event_count=5,
        )
        r_c2 = compute_hybrid_score(**base_kwargs, category_factor=1.20, category_label="c2")
        r_scanner = compute_hybrid_score(**base_kwargs, category_factor=0.60, category_label="scanner")
        assert r_c2.calibrated_score > r_scanner.calibrated_score
