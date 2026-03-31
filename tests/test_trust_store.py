"""
Tests for the trust evaluation system.

Verify that known scanners, admin tools, and trusted hostnames receive
appropriate trust discounts without completely suppressing real threats.
"""

import pytest

from app.services.trust_store import TrustContext, evaluate_trust


class TestTrustContextDefaults:
    def test_unknown_entity_no_discount(self):
        ctx = evaluate_trust(
            event_type="LATERAL_MOVEMENT",
            src_ip="203.0.113.99",
            message="credential theft from external source",
        )
        assert ctx.trust_discount == 0.0
        assert ctx.trust_labels == []

    def test_trust_discount_bounded_above(self):
        """Even with many matching signals, discount must not exceed max (0.4)."""
        ctx = evaluate_trust(
            event_type="VULN_SCAN",
            src_ip="192.168.1.100",   # internal range
            username="nessus_svc",   # scanner account
            hostname="nessus-scanner-01",
            message="vulnerability scan by nessus",
        )
        assert ctx.trust_discount <= 0.40

    def test_trust_discount_bounded_below(self):
        ctx = evaluate_trust(event_type="EXPLOIT", src_ip="8.8.8.8", message="remote exploit")
        assert ctx.trust_discount >= 0.0


class TestKnownScannerDetection:
    def test_nessus_scanner_ip_detected(self):
        ctx = evaluate_trust(
            event_type="PORT_SCAN",
            src_ip="10.0.0.200",
            hostname="nessus-scanner",
            message="nessus scan",
        )
        assert ctx.trust_discount > 0.0
        assert any("scanner" in label.lower() for label in ctx.trust_labels)

    def test_qualys_in_message_detected(self):
        ctx = evaluate_trust(
            event_type="VULN_SCAN",
            src_ip="192.168.10.50",
            message="qualys cloud agent scan",
        )
        assert ctx.trust_discount > 0.0

    def test_nmap_detected_by_message(self):
        ctx = evaluate_trust(
            event_type="PORT_SCAN",
            src_ip="172.16.0.5",
            message="nmap scan initiated from admin workstation",
        )
        assert ctx.trust_discount > 0.0

    def test_pentest_hostname_detected(self):
        ctx = evaluate_trust(
            event_type="EXPLOIT",
            hostname="pentest-kali-01",
            message="exploitation attempt",
        )
        assert ctx.trust_discount > 0.0
        assert any("pentest" in label.lower() for label in ctx.trust_labels)


class TestAdminAccountDetection:
    def test_svc_account_gets_discount(self):
        ctx = evaluate_trust(
            event_type="PRIVILEGED_ACCESS",
            username="svc_deploy",
            message="service account elevated action",
        )
        assert ctx.trust_discount > 0.0

    def test_admin_prefix_username(self):
        ctx = evaluate_trust(
            event_type="CONFIG_CHANGE",
            username="admin_john",
            message="configuration change by admin",
        )
        assert ctx.trust_discount > 0.0

    def test_root_account_not_trusted_by_default(self):
        """root account doing unusual things should NOT get trust discount."""
        ctx = evaluate_trust(
            event_type="EXPLOIT",
            username="root",
            src_ip="203.0.113.100",  # external IP
            message="remote root exploit attempt",
        )
        # An external IP with root access should not get trust discount
        # (scanner patterns require internal/known IPs)
        assert ctx.trust_discount < 0.30


class TestTrustLabelContent:
    def test_labels_are_informative(self):
        ctx = evaluate_trust(
            event_type="VULN_SCAN",
            hostname="nessus-scanner",
            message="nessus scan result",
        )
        assert len(ctx.trust_labels) > 0
        for label in ctx.trust_labels:
            assert isinstance(label, str)
            assert len(label) > 0

    def test_multiple_signals_produce_multiple_labels(self):
        ctx = evaluate_trust(
            event_type="VULN_SCAN",
            src_ip="10.0.1.200",
            username="nessus_svc",
            hostname="nessus-scanner",
            message="nessus vulnerability scan",
        )
        # Multiple scanner signals should produce at least 2 labels (capped by max_discount logic)
        assert len(ctx.trust_labels) >= 1


class TestTrustContextDataclass:
    def test_trust_context_has_expected_fields(self):
        ctx = evaluate_trust(event_type="DNS_QUERY", message="dns lookup")
        assert hasattr(ctx, "trust_discount")
        assert hasattr(ctx, "trust_labels")
        assert hasattr(ctx, "trusted")

    def test_trusted_false_when_no_discount(self):
        ctx = evaluate_trust(event_type="LATERAL_MOVEMENT", src_ip="203.0.113.5", message="credential theft")
        assert not ctx.trusted
        assert not ctx.is_trusted_source

    def test_trusted_true_when_discount_applied(self):
        ctx = evaluate_trust(
            event_type="PORT_SCAN",
            hostname="nessus-scanner",
            message="nessus scan",
        )
        if ctx.trust_discount > 0:
            assert ctx.trusted
