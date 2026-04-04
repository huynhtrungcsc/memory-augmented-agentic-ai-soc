"""
Realistic SOC benchmark test pack.

Unlike the synthetic "SSH Brute Force / SMB Lateral Movement" labels used in
unit tests, these tests use real-world event signatures:

  - Suricata ET rule names (ET SCAN, ET EXPLOIT, ET POLICY)
  - Windows Security Event IDs (4625 = failed logon, 4624 = success, 4648 = explicit creds)
  - Wazuh rule IDs and groups (brute_force, authentication_success, recon)
  - Zeek conn/notice log descriptors

The benchmark validates three capabilities:

  A. Phase classification — classify_phase() maps real-world signals to MITRE phases.
  B. Chain detection    — detect_sequences() fires for realistic multi-stage sequences.
  C. Scoring sanity     — compute_hybrid_score() produces expected score ranges for
                          clearly benign vs. clearly malicious event sets.

These tests exercise the system with the kinds of logs a production SOC would
actually ingest, catching regressions that synthetic tests miss.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.history_scorer import SimpleEvent
from app.services.sequence_detector import classify_phase, detect_sequences


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ev(
    event_type: str,
    message: str,
    severity: str = "medium",
    anomaly_score: float = 0.7,
    minutes_ago: int = 5,
) -> SimpleEvent:
    """Build a SimpleEvent with realistic field values."""
    ts = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
    return SimpleEvent(
        event_type=event_type,
        message=message,
        severity=severity,
        anomaly_score=anomaly_score,
        timestamp=ts,
    )


# ─── A. Phase classification with real-world event signatures ─────────────────


class TestRealisticPhaseClassification:
    """
    classify_phase() must correctly map real-world event signatures to the
    correct MITRE ATT&CK tactic phase.

    These are the log signatures that actually appear in Suricata, Zeek, Wazuh,
    and Splunk — NOT the sanitised labels used in other unit tests.
    """

    # Reconnaissance
    def test_et_scan_portscan_classified_as_recon(self):
        ev = _ev(
            "ET SCAN Nmap Scripting Engine User-Agent",
            "Nmap NSE script scan detected from 10.0.0.5",
        )
        assert classify_phase(ev) == "reconnaissance"

    def test_et_scan_sshscan_classified_as_recon(self):
        ev = _ev(
            "ET SCAN SSH BruteForce Tool",
            "SSH scan tool detected attempting multiple hosts",
        )
        assert classify_phase(ev) == "reconnaissance"

    def test_wazuh_recon_group_classified_as_recon(self):
        ev = _ev(
            "Wazuh Rule 100200",
            "recon activity detected host enumeration",
        )
        assert classify_phase(ev) == "reconnaissance"

    # Brute force / credential access
    def test_win_4625_brute_force_classified_as_credential_access(self):
        ev = _ev(
            "Windows Security Event ID 4625",
            "An account failed to log on. Reason: Unknown user or bad password. 200 attempts in 60s.",
            severity="high",
            anomaly_score=0.85,
        )
        assert classify_phase(ev) == "credential_access"

    def test_wazuh_brute_force_group_classified_as_credential_access(self):
        ev = _ev(
            "Wazuh Rule 5712 (sshd_brute_force)",
            "brute force attack: 512 attempts from same IP",
            severity="critical",
        )
        assert classify_phase(ev) == "credential_access"

    def test_rdp_brute_force_classified_as_credential_access(self):
        ev = _ev(
            "ET POLICY RDP brute force attempt",
            "Multiple RDP login failures detected — possible credential stuffing",
            severity="high",
        )
        assert classify_phase(ev) == "credential_access"

    # Initial access / successful login
    def test_win_4624_after_brute_classified_as_initial_access(self):
        ev = _ev(
            "Windows Security Event ID 4624",
            "An account was successfully logged on. Logon Type: 3. Network logon success after repeated failures.",
            severity="high",
            anomaly_score=0.75,
        )
        assert classify_phase(ev) == "initial_access"

    def test_wazuh_auth_success_after_brute_classified_as_initial_access(self):
        ev = _ev(
            "Wazuh Rule 5715 (authentication_success)",
            "Successful SSH login after brute force activity detected",
            severity="high",
        )
        assert classify_phase(ev) == "initial_access"

    def test_ssh_accepted_password_classified_as_initial_access(self):
        ev = _ev(
            "Accepted password for root",
            "SSH login accepted for privileged account from external IP",
            severity="critical",
        )
        assert classify_phase(ev) == "initial_access"

    # Lateral movement
    def test_et_smb_lateral_classified_as_lateral_movement(self):
        ev = _ev(
            "ET EXPLOIT PsExec Lateral Movement",
            "PsExec-style command execution via SMB ADMIN$ share detected",
            severity="critical",
            anomaly_score=0.95,
        )
        assert classify_phase(ev) == "lateral_movement"

    def test_zeek_smb_pivot_classified_as_lateral_movement(self):
        ev = _ev(
            "Zeek SMB connection via hidden share",
            "SMB pivot to admin share from authenticated session lateral movement",
            severity="high",
        )
        assert classify_phase(ev) == "lateral_movement"

    # Exfiltration
    def test_et_policy_data_exfil_classified_as_exfiltration(self):
        ev = _ev(
            "ET POLICY Large DNS TXT response — possible data exfiltration",
            "Outbound DNS TXT payload 512 bytes — potential DNS tunnel exfil",
            severity="high",
        )
        assert classify_phase(ev) == "exfiltration"

    def test_zeek_large_upload_classified_as_exfiltration(self):
        ev = _ev(
            "Zeek Conn Large Upload Detected",
            "data exfiltration upload 500MB to external IP",
            severity="critical",
        )
        assert classify_phase(ev) == "exfiltration"

    # C2 / Command and Control
    def test_et_trojan_c2_classified_as_c2(self):
        ev = _ev(
            "ET TROJAN Generic CnC Beacon",
            "C2 beacon detected — periodic outbound connections to known C&C IP",
            severity="critical",
            anomaly_score=0.99,
        )
        assert classify_phase(ev) == "command_and_control"

    def test_wazuh_c2_rule_classified_as_c2(self):
        ev = _ev(
            "Wazuh Rule 87001 (malware_c2)",
            "Outbound C2 connection to threat intelligence IP command control",
            severity="critical",
        )
        assert classify_phase(ev) == "command_and_control"


# ─── B. Chain detection with realistic multi-stage sequences ──────────────────


class TestRealisticChainDetection:
    """
    detect_sequences() must fire for realistic multi-stage attack sequences
    as they would actually appear in a SOC log stream.

    Events are ordered newest-first (descending timestamp) as they come from
    the memory store.  The detector must handle this ordering correctly.
    """

    def _timeline(self, events_oldest_first: list) -> list:
        """Return events sorted newest-first (as memory store delivers them)."""
        return list(reversed(events_oldest_first))

    def test_et_scan_to_brute_to_login_chain(self):
        """ET SCAN → Windows 4625 failures → 4624 success is a canonical initial-access chain."""
        events = self._timeline([
            _ev("ET SCAN Nmap Scripting Engine", "Nmap scan recon", minutes_ago=60),
            _ev("Windows Security Event ID 4625", "Failed logon attempt brute force", "high", 0.85, minutes_ago=40),
            _ev("Windows Security Event ID 4624", "Successful logon after failures initial access", "high", 0.8, minutes_ago=20),
        ])
        chains = detect_sequences(events)
        phases = {p for m in chains for p in m.phases_detected}
        assert "reconnaissance" in phases or "credential_access" in phases, (
            "Expected recon or credential_access phase in chain for ET SCAN + 4625 + 4624 sequence."
        )
        assert "initial_access" in phases, (
            f"Expected initial_access for 4624 success after brute force. Phases: {phases}"
        )

    def test_brute_force_to_lateral_movement_chain(self):
        """SSH brute force → successful login → lateral SMB is a typical APT pattern."""
        events = self._timeline([
            _ev("Wazuh Rule 5712 (sshd_brute_force)", "brute force 200 attempts", "high", 0.9, minutes_ago=90),
            _ev("Wazuh Rule 5715 (authentication_success)", "Successful SSH login after brute force initial access", "high", 0.75, minutes_ago=60),
            _ev("ET EXPLOIT PsExec Lateral Movement", "PsExec-style lateral movement SMB pivot", "critical", 0.95, minutes_ago=30),
        ])
        chains = detect_sequences(events)
        assert chains, "No chains detected for brute→login→lateral sequence"
        phases = {p for m in chains for p in m.phases_detected}
        assert "lateral_movement" in phases, (
            f"Expected lateral_movement phase in realistic APT chain. Phases: {phases}"
        )

    def test_c2_beacon_alone_is_not_a_full_chain(self):
        """A single C2 beacon without preceding phases should not fire a multi-phase chain."""
        events = [
            _ev("ET TROJAN Generic CnC Beacon", "C2 beacon command control", "critical", 0.99, minutes_ago=5),
        ]
        chains = detect_sequences(events)
        multi_phase = [m for m in chains if m.phases_total > 1 and m.completion_ratio >= 0.8]
        assert not multi_phase, (
            "A single C2 event should not fire a nearly-complete multi-phase attack chain."
        )

    def test_full_kill_chain_recon_to_exfil(self):
        """Full kill chain: recon → brute → login → lateral → exfil detects multiple phases."""
        events = self._timeline([
            _ev("ET SCAN Nmap Scripting Engine", "Nmap scan port recon", "medium", 0.6, minutes_ago=300),
            _ev("Wazuh Rule 5712 (sshd_brute_force)", "brute force attack credential", "high", 0.9, minutes_ago=250),
            _ev("Wazuh Rule 5715 (authentication_success)", "SSH login success initial access after brute", "high", 0.8, minutes_ago=200),
            _ev("ET EXPLOIT PsExec Lateral Movement", "PsExec lateral movement SMB", "critical", 0.95, minutes_ago=150),
            _ev("Zeek Conn Large Upload Detected", "data exfiltration upload 200MB exfil", "critical", 0.95, minutes_ago=60),
        ])
        chains = detect_sequences(events)
        assert chains, "No chains detected for full recon→brute→login→lateral→exfil kill chain"
        all_phases = {p for m in chains for p in m.phases_detected}
        # At minimum lateral movement + exfiltration should be detected
        assert len(all_phases) >= 2, (
            f"Expected ≥2 distinct phases detected for full kill chain. Got: {all_phases}"
        )


# ─── C. Scoring sanity with realistic event sets ──────────────────────────────


class TestRealisticScoringSanity:
    """
    compute_hybrid_score() must produce sensible ranges for clearly-benign
    vs. clearly-malicious realistic event sets.

    These are sanity bounds — not exact values — because the scorer is
    deliberately multi-signal and context-dependent.
    """

    def _simple_events(self, event_type, message, severity, score, n=5):
        return [_ev(event_type, message, severity, score, minutes_ago=i * 2) for i in range(n)]

    def test_benign_windows_logons_score_below_50(self):
        from app.services.scoring_engine import compute_hybrid_score
        from app.models.schemas import Severity

        events = self._simple_events(
            "Windows Security Event ID 4624",
            "Normal daily workstation logon Type 2 interactive",
            "low",
            0.1,
        )
        result = compute_hybrid_score(
            anomaly_score=0.1,
            llm_risk_score=20,
            history_score=0.2,
            severity=Severity.low,
            sequence_matches=[],
            baseline_deviation=None,
        )
        assert result.composite_score < 50, (
            f"Benign Windows logons scored {result.composite_score} — expected < 50."
        )

    def test_full_kill_chain_scores_above_70(self):
        from app.services.scoring_engine import compute_hybrid_score
        from app.services.sequence_detector import detect_sequences
        from app.services.baseline import BaselineDeviation
        from app.models.schemas import Severity

        kill_chain_events = [
            _ev("ET SCAN Nmap Scripting Engine", "Nmap recon scan", "high", 0.8, 30),
            _ev("Wazuh Rule 5712 (sshd_brute_force)", "brute force credential attack", "critical", 0.95, 20),
            _ev("Wazuh Rule 5715 (authentication_success)", "SSH login success initial access after brute force", "high", 0.85, 10),
            _ev("ET EXPLOIT PsExec Lateral Movement", "PsExec lateral movement SMB pivot", "critical", 0.98, 5),
        ]
        # Newest first (as memory store delivers)
        kill_chain_events.sort(key=lambda e: e.timestamp, reverse=True)
        chains = detect_sequences(kill_chain_events)

        high_baseline = BaselineDeviation(
            deviation=0.8,
            rate_ratio=4.0,
            sev_delta=0.6,
            is_escalating=True,
            new_event_types=["Lateral Movement"],
            baseline_event_count=10,
            recent_event_count=40,
            has_sufficient_baseline=True,
        )

        result = compute_hybrid_score(
            anomaly_score=0.92,
            llm_risk_score=85,
            history_score=0.85,
            severity=Severity.critical,
            sequence_matches=chains,
            baseline_deviation=high_baseline,
        )
        assert result.composite_score >= 70, (
            f"Full kill chain should score >= 70. Got {result.composite_score}."
        )

    def test_single_c2_beacon_scores_above_60(self):
        """A single high-confidence C2 beacon is always a high-severity signal."""
        from app.services.scoring_engine import compute_hybrid_score
        from app.models.schemas import Severity

        result = compute_hybrid_score(
            anomaly_score=0.98,
            llm_risk_score=80,
            history_score=0.5,
            severity=Severity.critical,
            sequence_matches=[],
            baseline_deviation=None,
        )
        assert result.composite_score >= 60, (
            f"High-confidence C2 beacon scored {result.composite_score} — expected >= 60."
        )
