"""
Tests for the attack sequence / MITRE ATT&CK chain detector.

Key accuracy requirements being tested:
  1. Real attack chains are detected (no false negatives for clear patterns)
  2. Isolated events do NOT match chains (no false positives)
  3. Phase order is enforced (recon after brute-force ≠ recon before brute-force)
  4. Partial chains only match at the correct completion threshold
  5. The classify_phase function generalises across different log formats

Run with:
  pytest tests/test_sequence_detector.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.services.history_scorer import SimpleEvent
from app.services.sequence_detector import (
    build_phase_timeline,
    classify_phase,
    detect_sequences,
    best_sequence_score,
    _count_ordered_matches,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def make_event(event_type: str, message: str = "", severity: str = "medium", minutes_ago: int = 10) -> SimpleEvent:
    return SimpleEvent(
        event_type=event_type,
        severity=severity,
        anomaly_score=0.5,
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        message=message,
    )


# ─── Phase classifier tests ───────────────────────────────────────────────────


class TestClassifyPhase:
    """Phase classification generalises across log format variations."""

    def test_nmap_scan_is_reconnaissance(self):
        e = make_event("ET SCAN Nmap TCP SYN Scan", "port scan detected")
        assert classify_phase(e) == "reconnaissance"

    def test_sweep_is_reconnaissance(self):
        e = make_event("Host Discovery Sweep", "ping sweep")
        assert classify_phase(e) == "reconnaissance"

    def test_brute_force_is_credential_access(self):
        e = make_event("SSH BruteForce Attempt", "72 failed auth")
        assert classify_phase(e) == "credential_access"

    def test_password_spray_is_credential_access(self):
        e = make_event("Password Spray Detected", "authentication failure repeated")
        assert classify_phase(e) == "credential_access"

    def test_authenticated_is_initial_access(self):
        e = make_event("Successful SSH Auth After BruteForce", "user authenticated after brute")
        assert classify_phase(e) == "initial_access"

    def test_session_opened_is_initial_access(self):
        e = make_event("Session Opened", "session opened for user root")
        assert classify_phase(e) == "initial_access"

    def test_smb_is_lateral_movement(self):
        e = make_event("SMB Lateral Movement Detected", "smb share access")
        assert classify_phase(e) == "lateral_movement"

    def test_rdp_is_lateral_movement(self):
        e = make_event("RDP Login", "remote desktop connection")
        assert classify_phase(e) == "lateral_movement"

    def test_sudo_is_privilege_escalation(self):
        e = make_event("Sudo Abuse", "privilege escalation via sudo")
        assert classify_phase(e) == "privilege_escalation"

    def test_c2_beacon_is_exfiltration_or_c2(self):
        e = make_event("C2 Beacon Detected", "beacon to known c2 server")
        phase = classify_phase(e)
        assert phase in ("exfiltration", "command_and_control")

    def test_data_exfiltration_is_exfiltration(self):
        e = make_event("Data Exfiltration Beacon", "exfil to tor exit node")
        assert classify_phase(e) == "exfiltration"

    def test_unknown_event_returns_none(self):
        e = make_event("DHCP_LEASE_RENEWAL", "normal dhcp renewal")
        assert classify_phase(e) is None

    def test_benign_ntp_returns_none(self):
        e = make_event("NTP_SYNC", "time synchronization")
        assert classify_phase(e) is None


# ─── Phase timeline tests ─────────────────────────────────────────────────────


class TestBuildPhaseTimeline:
    """Timeline construction and deduplication."""

    def test_empty_events_return_empty_timeline(self):
        assert build_phase_timeline([]) == []

    def test_consecutive_same_phases_are_deduplicated(self):
        # 50 brute-force events should produce ONE credential_access phase
        events = [
            make_event("SSH BruteForce", "failed auth", minutes_ago=60 - i)
            for i in range(50)
        ]
        timeline = build_phase_timeline(events)
        assert timeline.count("credential_access") == 1

    def test_timeline_preserves_order(self):
        events = [
            make_event("Nmap Scan", "scan", minutes_ago=30),       # recon (oldest)
            make_event("BruteForce SSH", "brute", minutes_ago=20), # credential_access
            make_event("SSH Authenticated", "success", minutes_ago=10),  # initial_access
        ]
        timeline = build_phase_timeline(events)
        assert timeline == ["reconnaissance", "credential_access", "initial_access"]

    def test_unknown_events_excluded_from_timeline(self):
        events = [
            make_event("DHCP_RENEWAL", "dhcp", minutes_ago=30),  # unknown phase
            make_event("Nmap Scan", "scan", minutes_ago=20),
        ]
        timeline = build_phase_timeline(events)
        assert "reconnaissance" in timeline
        # No unknown placeholder
        assert None not in timeline


# ─── Ordered matches tests ────────────────────────────────────────────────────


class TestCountOrderedMatches:
    def test_exact_match_returns_full_count(self):
        timeline = ["reconnaissance", "credential_access", "initial_access"]
        required = ["reconnaissance", "credential_access", "initial_access"]
        assert _count_ordered_matches(timeline, required) == 3

    def test_out_of_order_returns_partial(self):
        # Brute force then recon is backwards — only first (recon) should match
        timeline = ["credential_access", "reconnaissance"]
        required = ["reconnaissance", "credential_access"]
        # recon comes after credential_access in timeline, so only credential_access matches? No.
        # _count_ordered_matches scans left to right through timeline looking for required[0] first
        # timeline: credential_access → not "reconnaissance" → skip. Then "reconnaissance" → matches req[0].
        # req_idx now 1 → looking for "credential_access" → already passed. Result: 1.
        result = _count_ordered_matches(timeline, required)
        assert result == 1  # only gets "reconnaissance" but not "credential_access" after it

    def test_subset_returns_partial_count(self):
        timeline = ["reconnaissance", "credential_access"]
        required = ["reconnaissance", "credential_access", "initial_access", "lateral_movement"]
        assert _count_ordered_matches(timeline, required) == 2

    def test_empty_timeline_returns_zero(self):
        assert _count_ordered_matches([], ["reconnaissance", "credential_access"]) == 0


# ─── Full chain detection tests ───────────────────────────────────────────────


class TestDetectSequences:
    """End-to-end chain detection — the most critical accuracy tests."""

    def test_empty_events_no_matches(self):
        assert detect_sequences([]) == []

    def test_isolated_scan_no_chain(self):
        # A single port scan MUST NOT trigger a chain match (false positive prevention)
        events = [make_event("Nmap SYN Scan", "port scan", minutes_ago=10)]
        matches = detect_sequences(events)
        assert len(matches) == 0, (
            "Single port scan should NOT match any chain — would cause FP for legitimate scanners"
        )

    def test_isolated_brute_force_no_chain(self):
        # Isolated brute force without recon or success should not match chains
        # requiring recon or initial_access
        events = [make_event("SSH BruteForce", "failed auth x50", minutes_ago=10)]
        matches = detect_sequences(events)
        # The "Recon + Brute Force" chain requires both phases — should not match
        for m in matches:
            assert "reconnaissance" not in m.phases_detected, (
                "Brute force alone should not show reconnaissance phase in match"
            )

    def test_recon_then_brute_force_matches_chain(self):
        events = [
            make_event("Nmap Scan", "tcp scan", minutes_ago=30),
            make_event("SSH BruteForce", "72 failed auth", minutes_ago=20),
        ]
        matches = detect_sequences(events)
        assert len(matches) >= 1
        chain_names = [m.chain_name for m in matches]
        assert "Recon + Brute Force" in chain_names

    def test_full_breach_chain_detected(self):
        events = [
            make_event("Nmap SYN Scan", "port scan", severity="medium", minutes_ago=60),
            make_event("SSH BruteForce Attempt", "72 failed auth", severity="high", minutes_ago=45),
            make_event("Successful SSH Auth After BruteForce", "user authenticated after brute", severity="critical", minutes_ago=30),
            make_event("SMB Lateral Movement", "lateral smb access", severity="critical", minutes_ago=15),
        ]
        matches = detect_sequences(events)
        chain_names = [m.chain_name for m in matches]
        assert "Classic Breach Chain" in chain_names

        classic = next(m for m in matches if m.chain_name == "Classic Breach Chain")
        assert classic.completion_ratio >= 0.75

    def test_smash_and_grab_detected(self):
        events = [
            make_event("Nmap Discovery", "host discovery", minutes_ago=30),
            make_event("Webshell Deployed", "shell opened for attacker", minutes_ago=20),
            make_event("Data Exfiltration to Tor", "exfil beacon detected", minutes_ago=5),
        ]
        matches = detect_sequences(events)
        chain_names = [m.chain_name for m in matches]
        assert any("Smash" in n or "Exfil" in n or "Grab" in n for n in chain_names)

    def test_order_enforcement_reversed_events_no_full_match(self):
        # Events in WRONG order: exfil first, then scan → should not match chains
        # that require scan before exfil
        events = [
            make_event("Data Exfiltration", "exfil beacon", minutes_ago=30),  # exfil first
            make_event("Nmap Scan", "port scan", minutes_ago=10),              # recon later
        ]
        matches = detect_sequences(events)
        # "Smash-and-Grab" requires reconnaissance → initial_access → exfiltration in order
        # With exfil first and recon last, this chain should NOT be matched
        smash_and_grab = [m for m in matches if "Smash" in m.chain_name]
        assert len(smash_and_grab) == 0 or smash_and_grab[0].completion_ratio < 0.67

    def test_completion_ratio_correct_for_partial_chain(self):
        # Only 2 of 4 phases for Classic Breach Chain (no initial_access or lateral_movement)
        events = [
            make_event("Nmap Scan", "scan", minutes_ago=30),
            make_event("SSH BruteForce", "brute force", minutes_ago=20),
        ]
        matches = detect_sequences(events)
        # The "Classic Breach Chain" (4 phases) should be 50% complete at most
        classic = next((m for m in matches if m.chain_name == "Classic Breach Chain"), None)
        if classic:
            # 2 of 4 phases = 50%
            assert classic.completion_ratio <= 0.51
        # The "Recon + Brute Force" chain (2 phases) should be 100% complete
        recon_brute = next((m for m in matches if m.chain_name == "Recon + Brute Force"), None)
        assert recon_brute is not None, "Recon + BruteForce chain should be detected"
        assert recon_brute.completion_ratio == 1.0

    def test_matches_sorted_by_completion_descending(self):
        events = [
            make_event("Nmap Scan", "scan", minutes_ago=60),
            make_event("SSH BruteForce", "brute", minutes_ago=45),
            make_event("SSH Auth Success After BruteForce", "authenticated after brute", minutes_ago=30),
            make_event("Data Exfil Beacon", "exfil to c2", minutes_ago=15),
        ]
        matches = detect_sequences(events)
        if len(matches) >= 2:
            for i in range(len(matches) - 1):
                assert matches[i].completion_ratio >= matches[i + 1].completion_ratio

    def test_best_sequence_score_empty(self):
        assert best_sequence_score([]) == 0.0

    def test_best_sequence_score_returns_max(self):
        from app.services.sequence_detector import SequenceMatch
        m1 = SequenceMatch("A", "high", ["recon"], 4, 0.25, 0.25)
        m2 = SequenceMatch("B", "critical", ["recon", "cred"], 4, 0.5, 0.5)
        assert best_sequence_score([m1, m2]) == 0.5

    def test_credential_theft_exfil_chain(self):
        events = [
            make_event("Failed Auth Repeated", "credential brute force", minutes_ago=40),
            make_event("SSH Session Opened", "authenticated, access granted", minutes_ago=30),
            make_event("Encrypted Data Upload", "data exfiltration exfil beacon", minutes_ago=10),
        ]
        matches = detect_sequences(events)
        assert len(matches) >= 1
        chain_names = [m.chain_name for m in matches]
        assert any("Exfil" in n or "Credential" in n for n in chain_names)
