"""
Regression tests for fixed bugs and architectural constraints.

Each test targets a specific behaviour that was incorrect or incomplete
in an earlier iteration, ensuring it cannot regress silently.

Coverage:
  - Phase classification: message-field propagation, priority tie-breaking
  - Baseline deviation: recent-event window exclusion
  - Anomaly detector: keyword specificity (multi-word phrases, port list)
  - History scorer: log₂ frequency scaling beyond 20-event saturation point
  - Chain detection: 24h temporal window enforcement
  - LLM timeline: chain-anchor event inclusion when outside top-20 window
  - Decision hysteresis: deferred downgrade during active threat windows
  - Context summary: qualitative anomaly label (no raw float exposure)
  - Ingest endpoint: token authentication and per-IP rate limiting

Run with:
  pytest tests/test_regression.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.schemas import RawLog, Severity
from app.services.anomaly_detector import compute_score
from app.services.baseline import compute_baseline_deviation
from app.services.history_scorer import SimpleEvent, compute_history_score
from app.services.sequence_detector import (
    PHASE_PRIORITY,
    classify_phase,
    detect_sequences,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def make_event(event_type: str, message: str = "", severity: str = "medium",
               minutes_ago: int = 5, anomaly_score: float = 0.5) -> SimpleEvent:
    ts = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
    return SimpleEvent(
        event_type=event_type,
        message=message,
        severity=severity,
        anomaly_score=anomaly_score,
        timestamp=ts,
    )


def make_log(event_type: str, message: str = "", severity: str = "medium",
             src_ip: str | None = None, dst_ip: str | None = None,
             dst_port: int | None = None, source: str = "suricata") -> RawLog:
    return RawLog(
        source=source,
        src_ip=src_ip or "10.1.1.1",
        event_type=event_type,
        severity=Severity(severity),
        message=message,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


# ─── Regression: classify_phase() uses event_type + message ──────────────────


class TestMessagePropagation:
    """
    _to_simple() was not copying the message field from MemoryEvents.
    classify_phase() uses f"{event_type} {message}" — without message, half
    the signal is lost and phase classification degrades silently.
    """

    def test_classify_phase_uses_message_content(self):
        """Phase classification must read message, not just event_type."""
        # event_type alone is vague; message makes intent clear
        event = make_event("Security Event", "user logged in successfully", minutes_ago=1)
        phase = classify_phase(event)
        assert phase == "initial_access", (
            "classify_phase() must use message='user logged in successfully'; "
            "if message is dropped, this event gets no phase."
        )

    def test_classify_phase_message_adds_signal(self):
        """An event type alone that would match credential_access but whose
        message clearly says it was a successful session gets initial_access."""
        event = make_event(
            "SSH Event",  # ambiguous type
            "session opened for user root after brute force",  # unambiguous message
        )
        phase = classify_phase(event)
        assert phase == "initial_access", (
            "Message 'session opened ... after brute force' must dominate; "
            "without message propagation this event gets no classification."
        )

    def test_empty_message_still_classifies_from_event_type(self):
        """When message is truly empty, event_type alone must still classify."""
        event = make_event("SSH BruteForce Attack", message="")
        phase = classify_phase(event)
        assert phase == "credential_access", (
            "Event type 'SSH BruteForce Attack' contains 'brute' — must "
            "classify as credential_access even with empty message."
        )

    def test_chain_fires_when_message_provides_initial_access_signal(self):
        """
        Full chain detection should work when the initial_access signal
        is in the message, not just the event_type.
        """
        events = [
            make_event("SSH Scan", "nmap syn scan detected", minutes_ago=60),
            make_event("Auth Failures", "72 authentication failures brute force", minutes_ago=30),
            make_event("SSH Session", "session opened for root accepted password", minutes_ago=10),
            make_event("SMB Pivot", "smb lateral movement detected", minutes_ago=5),
        ]
        matches = detect_sequences(events)
        assert matches, (
            "Classic Breach Chain (recon→cred→access→lateral) must fire; "
            "if messages are dropped, 'session opened' is never classified as initial_access."
        )
        chain_names = [m.chain_name for m in matches]
        assert any("Breach" in n or "Credential" in n for n in chain_names)


# ─── Regression: classify_phase() priority tie-breaking ──────────────────────


class TestPhaseClassificationPriorityTieBreaking:
    """
    "Successful SSH Login After BruteForce" was classified as
    credential_access because "brute" appeared in the text and credential_access
    was evaluated first with strict > comparison.  initial_access must win
    when both phase keywords appear in the same event.
    """

    def test_confirmed_compromise_beats_brute_force_classification(self):
        """
        An event that says "brute force" AND "session opened" must be
        classified as initial_access, not credential_access.
        initial_access has higher priority (10 vs 3) in PHASE_PRIORITY.
        """
        event = make_event(
            "Successful SSH Login After BruteForce",
            "session opened for root",
        )
        phase = classify_phase(event)
        assert phase == "initial_access", (
            f"Got {phase!r}. 'session opened' (initial_access, priority=10) "
            "must beat 'brute' (credential_access, priority=3) in priority tie-break."
        )

    def test_initial_access_priority_is_higher_than_credential_access(self):
        """Verify the priority table is correctly configured."""
        assert PHASE_PRIORITY["initial_access"] > PHASE_PRIORITY["credential_access"]
        assert PHASE_PRIORITY["exfiltration"] > PHASE_PRIORITY["credential_access"]
        assert PHASE_PRIORITY["lateral_movement"] > PHASE_PRIORITY["reconnaissance"]

    def test_classic_breach_chain_fires_with_combined_event(self):
        """
        When the 'login after brute' event is correctly classified as
        initial_access, the Classic Breach Chain must complete.
        """
        events = [
            make_event("Nmap Scan", "nmap scan", minutes_ago=40),
            make_event("SSH BruteForce Attempt", "brute force authentication failure", minutes_ago=20),
            make_event("Successful SSH Login After BruteForce", "session opened root", minutes_ago=5),
            make_event("SMB Lateral Movement", "smb pivot to fileserver", minutes_ago=1),
        ]
        matches = detect_sequences(events)
        assert matches, (
            "Classic Breach Chain must fire when brute→success→lateral sequence is present. "
            "Misclassifying the success event would suppress this chain."
        )

    def test_pure_brute_force_no_success_stays_credential_access(self):
        """Pure failed brute force without any success indicator = credential_access."""
        event = make_event(
            "SSH Authentication Failure",
            "invalid password attempt brute force",
        )
        phase = classify_phase(event)
        assert phase == "credential_access"

    def test_wazuh_style_user_authenticated_classifies_as_initial_access(self):
        """Wazuh-style 'User authenticated' events must map to initial_access."""
        event = make_event(
            "PAM Authentication",
            "User admin authenticated successfully",
        )
        phase = classify_phase(event)
        assert phase == "initial_access"

    def test_openssh_accepted_password_is_initial_access(self):
        """OpenSSH-style 'Accepted password for root' must map to initial_access."""
        event = make_event(
            "sshd",
            "Accepted password for root from 10.1.1.5 port 52341 ssh2",
        )
        phase = classify_phase(event)
        assert phase == "initial_access"


# ─── Regression: baseline window must exclude recent events ──────────────────


class TestBaselineWindowExclusion:
    """
    compute_baseline_deviation() was called with simple_baseline = simple_all
    (all 48h events).  This means the current 1h attack events were included in
    the baseline, artificially inflating the baseline rate and underestimating
    the deviation.

    Correct behaviour: baseline_events should be events from 1h–25h ago (not
    including recent). These tests verify that the baseline function handles
    the case where recent events are NOT in the baseline set.
    """

    def _make_events(self, count: int, hours_ago_range, severity: str = "low") -> list:
        """Create `count` events spaced within the given hours_ago range."""
        events = []
        start_h, end_h = hours_ago_range
        for i in range(count):
            frac = i / max(count - 1, 1)
            hours = start_h + frac * (end_h - start_h)
            ts = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
            events.append(SimpleEvent(
                event_type="scan",
                severity=severity,
                anomaly_score=0.3,
                timestamp=ts,
            ))
        return events

    def test_deviation_zero_when_rate_matches_baseline(self):
        """No deviation when recent rate equals baseline rate."""
        # 1 event in the last hour vs ~1/hour baseline (24 in 24h) → no deviation
        baseline = self._make_events(24, (1.5, 25))  # 1h–25h ago
        recent = self._make_events(1, (0, 1))         # last 1h

        result = compute_baseline_deviation(recent, baseline)
        assert result.deviation < 0.3, (
            f"Expected low deviation, got {result.deviation}. "
            "Rate should be approximately matching the baseline."
        )

    def test_deviation_high_when_attack_events_excluded_from_baseline(self):
        """
        When recent attack events are correctly NOT included in the baseline,
        the deviation is high.  If attack events WERE in the baseline
        (the BUG), deviation would be artificially low.
        """
        # 2 baseline events per hour over 24h → baseline_rate = 2 events/hour
        baseline = self._make_events(48, (1.5, 25), severity="low")
        # Sudden spike: 20 high-severity events in the last hour
        recent = self._make_events(20, (0, 1), severity="high")

        result = compute_baseline_deviation(recent, baseline)
        assert result.has_sufficient_baseline
        assert result.deviation > 0.5, (
            f"Expected high deviation, got {result.deviation}. "
            "20 events vs 2/hr baseline should show strong anomaly."
        )
        assert result.rate_ratio >= 5.0, (
            f"Expected rate_ratio >= 5, got {result.rate_ratio}. "
            "20 events/hr vs 2 events/hr baseline = 10× ratio."
        )

    def test_baseline_includes_recent_inflates_denominator(self):
        """
        Demonstrate the baseline calculation error when recent events are included.

        If recent events are included in the baseline (the bug), the baseline
        rate denominator is inflated, reducing the rate_ratio and understating
        the deviation.  If excluded (the fix), the ratio is higher.

        We deliberately stay below the 5× rate cap so the difference is visible.
        Numbers:
          recent = 2 events (attacker's recent burst)
          baseline_correct = 12 events over 24h → rate = 0.5/hr → ratio = 4× (not capped)
          baseline_bugged  = 14 events over 24h → rate = 0.583/hr → ratio = 3.4× (not capped)
          → correct deviation (0.75 rate_dev) > bugged deviation (0.61 rate_dev)
        """
        baseline_correct = self._make_events(12, (1.5, 25))  # 1h–25h ago only
        # Bugged: also includes the recent 2 events, inflating the denominator
        recent = self._make_events(2, (0, 1))
        baseline_bugged = self._make_events(12, (1.5, 25)) + recent

        result_correct = compute_baseline_deviation(recent, baseline_correct)
        result_bugged = compute_baseline_deviation(recent, baseline_bugged)

        assert result_correct.rate_ratio > result_bugged.rate_ratio, (
            "Correct baseline (excluding recent) must have a HIGHER rate_ratio "
            "than bugged baseline (including recent). "
            f"correct_ratio={result_correct.rate_ratio:.2f}, bugged_ratio={result_bugged.rate_ratio:.2f}"
        )
        assert result_correct.deviation > result_bugged.deviation, (
            "Correct baseline must show HIGHER deviation than bugged baseline. "
            f"correct_dev={result_correct.deviation:.3f}, bugged_dev={result_bugged.deviation:.3f}"
        )


# ─── Regression: anomaly detector keyword specificity ────────────────────────


class TestAnomalyDetectorKeywords:
    """
    Anomaly detector keywords were too generic. Port 22 was in the
    suspicious port list despite SSH being ubiquitous. Single words like
    "scan", "credential", "privilege" matched legitimate activity names.
    """

    def test_port_22_does_not_trigger_suspicious_port_boost(self):
        """SSH on port 22 must NOT add the suspicious port bonus."""
        log = make_log(
            "SSH Connection", "developer ssh session",
            severity="low", dst_port=22,
        )
        score = compute_score(log)
        # low severity = 0.1, no keyword hits, no port boost (22 removed)
        assert score <= 0.1, (
            f"Port 22 (SSH) added a suspicious port boost: score={score}. "
            "Port 22 is normal DevOps infrastructure and must not inflate scores."
        )

    def test_port_4444_still_triggers_suspicious_port_boost(self):
        """Metasploit default port 4444 must still be flagged."""
        log = make_log("Connection", severity="medium", dst_port=4444)
        score_with_port = compute_score(log)
        log_no_port = make_log("Connection", severity="medium", dst_port=None)
        score_no_port = compute_score(log_no_port)
        assert score_with_port > score_no_port, "Port 4444 must add a suspicious port boost"

    def test_vulnerability_scan_word_alone_does_not_trigger_keyword(self):
        """'vulnerability assessment scan completed' should NOT match keyword 'scan'."""
        log = make_log(
            "Tenable Nessus vulnerability assessment scan completed",
            message="Routine security assessment completed successfully",
            severity="low",
        )
        score = compute_score(log)
        # low severity = 0.1, generic word "scan" alone is NOT in the keyword list
        assert score <= 0.1, (
            f"'scan' alone should not be a keyword anymore. Got score={score}. "
            "Vulnerability scanner events should not trigger anomaly keywords."
        )

    def test_credential_dump_specific_phrase_triggers(self):
        """Multi-word 'credential dump' must trigger but 'credential' alone must not."""
        log_specific = make_log(
            "Credential Dump via LSASS",
            "mimikatz credential dump detected",
            severity="critical",
        )
        log_generic = make_log(
            "Credential Update",
            "User successfully updated credential",
            severity="low",
        )
        score_specific = compute_score(log_specific)
        score_generic = compute_score(log_generic)

        # The specific phrase must score much higher than the generic one
        assert score_specific > score_generic + 0.2, (
            f"Specific='credential dump' should score significantly higher than "
            f"generic='credential update'. Got specific={score_specific}, generic={score_generic}"
        )

    def test_privilege_escalation_phrase_triggers_not_word_alone(self):
        """
        'privilege escalation' as a phrase must trigger, but 'privilege' alone
        in a context like 'privilege review' should not.
        """
        log_phrase = make_log(
            "Windows Event: Privilege Escalation via Token Impersonation",
            "token impersonation privilege escalation detected",
            severity="critical",
        )
        log_word = make_log(
            "Privilege Review Completed",
            "Annual privilege access review completed for user",
            severity="low",
        )
        score_phrase = compute_score(log_phrase)
        score_word = compute_score(log_word)
        assert score_phrase > score_word, (
            f"Phrase 'privilege escalation' should score higher than 'privilege' alone. "
            f"Got phrase={score_phrase}, word={score_word}"
        )


# ─── Regression: history_score log-scale frequency ───────────────────────────


class TestHistoryScoreLogScale:
    """
    history_score uses log₂ frequency scaling instead of min(total/20.0, 1.0),
    which saturated at 20 events. An entity generating 20 events must not score
    identically to one generating 500. The log₂ curve differentiates between
    low-noise (1–10), medium-noise (10–50), and high-noise (50+) entities.

    Formula: freq_factor = log₂(total+1) / log₂(51)
    Approximate values:
        1 event  → 0.18
        5 events → 0.45
       10 events → 0.63
       20 events → 0.79  (previously saturated at 1.00)
       50 events → 1.00
      100 events → 1.00 (capped)
    """

    def _make_n_events(self, n: int, severity: str = "low") -> list:
        return [
            SimpleEvent(
                event_type="normal_event",
                severity=severity,
                anomaly_score=0.1,
                timestamp=datetime.now(tz=timezone.utc) - timedelta(minutes=i),
            )
            for i in range(n)
        ]

    def test_log_scale_differentiates_beyond_20_events(self):
        """20 events must score LOWER than 100 events (no saturation at 20)."""
        score_20 = compute_history_score(self._make_n_events(20))
        score_100 = compute_history_score(self._make_n_events(100))
        assert score_20 < score_100, (
            f"Log₂ scaling should give score_20 < score_100. "
            f"Got score_20={score_20}, score_100={score_100}. "
            "The old min(total/20, 1.0) formula may have re-appeared."
        )

    def test_log_scale_differentiates_at_50_boundary(self):
        """50 events should reach near-maximum freq_factor, 10 events should be clearly lower."""
        score_10 = compute_history_score(self._make_n_events(10))
        score_50 = compute_history_score(self._make_n_events(50))
        assert score_50 > score_10, (
            f"50 events should score higher than 10. Got {score_10=}, {score_50=}"
        )

    def test_ascending_property_preserved(self):
        """More events should always produce equal or higher score."""
        prev = 0.0
        for n in (1, 3, 5, 10, 20, 30, 50, 75, 100):
            score = compute_history_score(self._make_n_events(n))
            assert score >= prev, (
                f"Score at n={n} ({score}) is less than score at previous checkpoint ({prev}). "
                "History score must be monotonically non-decreasing with more events."
            )
            prev = score

    def test_score_bounded_zero_to_one(self):
        """Score must stay in [0, 1] for any event count."""
        for n in (0, 1, 20, 100, 500):
            score = compute_history_score(self._make_n_events(n))
            assert 0.0 <= score <= 1.0, f"score={score} out of bounds for n={n}"

    def test_new_entity_produces_zero_history_score(self):
        """Empty event list must return 0.0."""
        assert compute_history_score([]) == 0.0

    def test_fewer_events_produce_lower_frequency_score(self):
        """Within the log-scale region, more events should produce a higher score."""
        score_5 = compute_history_score(self._make_n_events(5))
        score_15 = compute_history_score(self._make_n_events(15))
        assert score_15 > score_5, (
            "More events should produce a higher history score in the log-scale region."
        )


# ─── Phase priority coverage ──────────────────────────────────────────────────


class TestPhaseClassificationCoverage:
    """
    Verify that the full set of MITRE ATT&CK phases can be classified
    using realistic log event text. These are the minimum viable keyword
    coverage tests for real-world accuracy.
    """

    def test_openssh_recon(self):
        e = make_event("ET SCAN Potential SSH Scan OUTBOUND", "nmap tcp syn scan detected")
        assert classify_phase(e) == "reconnaissance"

    def test_wazuh_brute_force(self):
        e = make_event("Multiple auth failures", "authentication failure 10 times brute force")
        assert classify_phase(e) == "credential_access"

    def test_wazuh_successful_login(self):
        e = make_event("sshd", "Accepted password for admin from 10.0.0.1 port 38274 ssh2")
        assert classify_phase(e) == "initial_access"

    def test_suricata_smb_lateral(self):
        e = make_event("ET LATERAL MOVEMENT SMB Logon to Multiple Hosts", "smb lateral movement")
        assert classify_phase(e) == "lateral_movement"

    def test_wazuh_privilege_escalation(self):
        e = make_event("Windows Event 4672", "token impersonation privilege escalation to SYSTEM")
        assert classify_phase(e) == "privilege_escalation"

    def test_zeek_dns_exfil(self):
        e = make_event("DNS Tunneling Detected", "large dns transfer dns tunneling data exfil")
        assert classify_phase(e) == "exfiltration"

    def test_zeek_c2_beacon(self):
        e = make_event("Periodic C2 Beacon", "c2 beacon command and control callback")
        assert classify_phase(e) == "command_and_control"

    def test_wazuh_log_deletion(self):
        e = make_event("Event Log Cleared", "clear log windows event log deleted tamper")
        assert classify_phase(e) == "defense_evasion"

    def test_unknown_event_returns_none(self):
        e = make_event("Normal Web Request", "GET /api/users HTTP/1.1 200 OK")
        assert classify_phase(e) is None, "Benign web request must not match any phase"

    def test_mimikatz_is_credential_access(self):
        e = make_event("Mimikatz Detected", "mimikatz lsass credential dump memory access")
        assert classify_phase(e) == "credential_access"

# ─── Regression: temporal window on chain detection ──────────────────────────


class TestTemporalChainWindow:
    """
    detect_sequences() enforces a max_chain_window_hours parameter (default 24h).
    A chain assembled from events spanning more than 24 hours is rejected because
    events that far apart are unlikely to be from the same incident.

    Example of the original defect:
      A brute-force on Monday + a lateral movement on Thursday would have been
      reported as a "Brute Force to Breach" chain — implausible and misleading.

    Fix: after ordered-subsequence matching, compute the time span between
    the first and last matched-phase timestamps. Reject if span > window.
    """

    def _make_chain_events(self, *specs) -> list:
        """
        Build events from (event_type, message, hours_ago) tuples.
        hours_ago is how many hours in the past the event occurred.
        """
        events = []
        for event_type, message, hours_ago in specs:
            ts = datetime.now(tz=timezone.utc) - timedelta(hours=hours_ago)
            events.append(SimpleEvent(
                event_type=event_type,
                message=message,
                severity="high",
                anomaly_score=0.8,
                timestamp=ts,
            ))
        return events

    def test_recent_chain_within_window_is_detected(self):
        """A chain where all phases occur within 2 hours must be detected."""
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 1.5),
            ("SSH Login", "accepted password session opened", 1.0),
            ("SMB Pivot", "smb lateral movement detected", 0.5),
        )
        matches = detect_sequences(events, max_chain_window_hours=24.0)
        assert matches, (
            "Brute Force to Breach chain spanning 1h must be detected within 24h window."
        )
        chain_names = [m.chain_name for m in matches]
        assert any("Brute" in n or "Breach" in n for n in chain_names)

    def test_stale_chain_spanning_48h_is_rejected(self):
        """
        A chain where phases span 48h must be REJECTED with the 24h default window.
        Without temporal enforcement, this returned a match — the key regression this test guards.
        """
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 48),  # 2 days ago
            ("SSH Login", "accepted password session opened", 24),          # 1 day ago
            ("SMB Pivot", "smb lateral movement detected", 1),              # 1h ago
        )
        matches = detect_sequences(events, max_chain_window_hours=24.0)
        # The "Brute Force to Breach" chain spans 47h (48h→1h) → must be rejected by the window
        brute_breach = [m for m in matches if "Brute Force to Breach" == m.chain_name]
        assert not brute_breach, (
            "Brute Force to Breach chain spanning 47h must be REJECTED with 24h window. "
            "Stale events must not be chained as if from the same incident."
        )

    def test_chain_window_hours_field_populated(self):
        """chain_window_hours on a SequenceMatch must reflect actual time span."""
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 2.0),
            ("SSH Login", "accepted password session opened", 1.0),
        )
        matches = detect_sequences(events, max_chain_window_hours=24.0)
        # Recon+BruteForce or Brute Force to Breach should appear
        for m in matches:
            # window should be approximately 1h (2h ago to 1h ago)
            assert m.chain_window_hours >= 0.0, "chain_window_hours must be non-negative"
            # Should not exceed the total span of the events (~1h)
            assert m.chain_window_hours <= 2.5, (
                f"chain_window_hours={m.chain_window_hours} for 1h-span events seems too large"
            )

    def test_custom_window_parameter_enforced(self):
        """Setting max_chain_window_hours=1.0 must reject a 6h-old chain."""
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 6.0),
            ("SSH Login", "accepted password session opened", 5.0),
            ("SMB Pivot", "smb lateral movement detected", 0.1),
        )
        # With 1h window, the 5.9h span should be rejected
        matches_tight = detect_sequences(events, max_chain_window_hours=1.0)
        # With 24h window, the same chain should be accepted
        matches_wide = detect_sequences(events, max_chain_window_hours=24.0)
        breach_tight = [m for m in matches_tight if "Brute Force to Breach" == m.chain_name]
        breach_wide = [m for m in matches_wide if "Brute Force to Breach" == m.chain_name]
        assert not breach_tight, (
            "Breach chain spanning 5.9h must be rejected with max_chain_window_hours=1h"
        )
        assert breach_wide, (
            "Breach chain spanning 5.9h must be accepted with max_chain_window_hours=24h"
        )

    def test_inf_window_accepts_any_chain(self):
        """float('inf') window must disable temporal filtering entirely."""
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 200),
            ("SSH Login", "accepted password session opened", 100),
            ("SMB Pivot", "smb lateral movement detected", 1),
        )
        matches = detect_sequences(events, max_chain_window_hours=float("inf"))
        chain_names = [m.chain_name for m in matches]
        assert any("Breach" in n or "Brute" in n for n in chain_names), (
            "Infinite window must disable temporal filtering and detect the chain."
        )

    def test_single_phase_events_have_zero_window(self):
        """A single-phase match (e.g. Recon+BruteForce with one phase) has 0h window."""
        events = self._make_chain_events(
            ("SSH BruteForce", "authentication failure brute force", 0.5),
        )
        matches = detect_sequences(events, max_chain_window_hours=24.0)
        for m in matches:
            if len(m.phases_detected) == 1:
                assert m.chain_window_hours == 0.0, (
                    f"Single-phase match must have chain_window_hours=0, got {m.chain_window_hours}"
                )


# ─── Regression: LLM timeline includes chain-triggering events ───────────────


class TestLLMEventAlignment:
    """
    The LLM context timeline always includes events that triggered chain
    detection, even when those events fall outside the primary top-20
    recent-timeline window.

    Original defect: a chain is detected using event #21 (older), the LLM
    receives only events #1-#20 and reasons about a pattern it cannot see.
    Fix: the chain-anchor event is merged into the LLM timeline.

    These tests verify the _build_llm_timeline helper directly.
    """

    def _make_memory_event(self, event_type: str, message: str, minutes_ago: int):
        from app.models.schemas import MemoryEvent
        ts = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
        return MemoryEvent(
            log_id=0,
            timestamp=ts,
            event_type=event_type,
            severity="high",
            message=message,
            source="suricata",
            anomaly_score=0.8,
        )

    def _make_simple(self, event_type: str, message: str, minutes_ago: int):
        ts = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes_ago)
        return SimpleEvent(
            event_type=event_type,
            message=message,
            severity="high",
            anomaly_score=0.8,
            timestamp=ts,
        )

    def test_chain_anchor_event_added_when_missing_from_primary(self):
        """
        An event that triggered chain detection but isn't in primary_timeline
        must be added to the merged LLM timeline.
        """
        from app.routes.analyze import _build_llm_timeline
        from app.services.sequence_detector import detect_sequences, SequenceMatch

        # Primary timeline: 20 recent benign events (no chain phases)
        primary = [
            self._make_memory_event("Web Request", "GET /api/data HTTP 200", i)
            for i in range(20)
        ]

        # Chain-anchor: a lateral movement event that is NOT in primary (older)
        chain_anchor = self._make_memory_event(
            "SMB Lateral Movement", "smb lateral movement detected pivot", 120
        )
        simple_anchor = self._make_simple(
            "SMB Lateral Movement", "smb lateral movement detected pivot", 120
        )

        # Simulate: all_events = primary + chain_anchor (chain_anchor is outside top-20)
        all_events = primary + [chain_anchor]
        simple_all = [self._make_simple("Web Request", "GET /api/data HTTP 200", i) for i in range(20)]
        simple_all.append(simple_anchor)

        # Build a fake sequence that detected lateral_movement
        fake_seq = SequenceMatch(
            chain_name="Test Chain",
            chain_severity="critical",
            phases_detected=["lateral_movement"],
            phases_total=2,
            completion_ratio=0.5,
            sequence_score=0.5,
            phase_timeline=["lateral_movement"],
        )

        merged = _build_llm_timeline(
            primary_timeline=primary,
            all_events=all_events,
            simple_all=simple_all,
            sequences=[fake_seq],
            max_events=20,
        )

        # The chain anchor must appear in the merged timeline
        event_types_in_merged = {e.event_type for e in merged}
        assert "SMB Lateral Movement" in event_types_in_merged, (
            "Chain-anchor event (SMB Lateral Movement) not present "
            "in LLM timeline despite being a detected chain phase."
        )

    def test_no_duplication_when_anchor_already_in_primary(self):
        """If the chain-anchor event is already in primary_timeline, it must not appear twice."""
        from app.routes.analyze import _build_llm_timeline
        from app.services.sequence_detector import SequenceMatch

        anchor = self._make_memory_event("SMB Lateral", "smb lateral movement", 10)
        primary = [anchor]
        all_events = [anchor]
        simple_all = [self._make_simple("SMB Lateral", "smb lateral movement", 10)]

        fake_seq = SequenceMatch("X", "critical", ["lateral_movement"], 2, 0.5, 0.5)
        merged = _build_llm_timeline(primary, all_events, simple_all, [fake_seq], 20)

        # Should appear exactly once
        smb_events = [e for e in merged if "SMB" in e.event_type]
        assert len(smb_events) == 1, (
            f"Chain-anchor event duplicated in LLM timeline: {len(smb_events)} copies"
        )

    def test_empty_sequences_returns_primary_unchanged(self):
        """With no detected sequences, the LLM timeline must be the primary timeline."""
        from app.routes.analyze import _build_llm_timeline

        primary = [self._make_memory_event("Web Request", "GET /", i) for i in range(5)]
        result = _build_llm_timeline(primary, primary, [], [], 20)
        assert result == primary, "With no sequences, _build_llm_timeline must return primary unchanged"


# ─── Regression: decision hysteresis ─────────────────────────────────────────


class TestDecisionHysteresis:
    """
    _apply_hysteresis() prevents rapid oscillation when an entity's score
    momentarily dips below a threshold during an ongoing attack.

    Rules:
      - Upgrades are always immediate.
      - Downgrades are deferred until hysteresis_hours have elapsed.
      - Exception: score <= hysteresis_score_floor → immediate downgrade (threat gone).
    """

    def _make_prior(self, decision: str, hours_ago: float) -> object:
        """Create a mock EntityDecisionRecord."""
        from unittest.mock import MagicMock
        rec = MagicMock()
        rec.last_decision = decision
        rec.last_score = 85
        ts = datetime.now(tz=timezone.utc) - timedelta(hours=hours_ago)
        rec.last_decided_at = ts.replace(tzinfo=None)  # stored as naive UTC in DB
        rec.cooldown_until = None  # no active block cooldown for these tests
        return rec

    def _make_decide_response(self, decision: str, score: int) -> object:
        from app.models.schemas import Decision, DecideResponse
        return DecideResponse(
            risk_score=score,
            decision=Decision(decision),
            rationale="test",
            entity_id="10.1.1.1",
        )

    def test_upgrade_is_immediate(self):
        """block upgrade from alert_analyst must be applied immediately."""
        from app.routes.analyze import _apply_hysteresis
        prior = self._make_prior("alert_analyst", 0.1)  # only 6 minutes ago
        new_dec = self._make_decide_response("block", 85)
        result = _apply_hysteresis(new_dec, prior, 85, datetime.now(tz=timezone.utc))
        assert result.decision.value == "block", (
            "Upgrade from alert_analyst to block must be immediate regardless of hysteresis."
        )

    def test_downgrade_deferred_within_window(self):
        """Downgrade from block to alert_analyst within hysteresis_hours must be deferred."""
        from app.routes.analyze import _apply_hysteresis
        prior = self._make_prior("block", 0.5)  # blocked 30min ago
        new_dec = self._make_decide_response("alert_analyst", 70)
        result = _apply_hysteresis(new_dec, prior, 70, datetime.now(tz=timezone.utc))
        assert result.decision.value == "block", (
            "Downgrade from block must be deferred — only 30min elapsed, hysteresis is 4h. "
            f"Got {result.decision.value!r} instead."
        )
        assert "HYSTERESIS" in result.rationale, (
            "Rationale must mention HYSTERESIS when a downgrade is deferred."
        )

    def test_downgrade_allowed_after_hysteresis_window(self):
        """Downgrade is allowed once hysteresis_hours have elapsed."""
        from app.routes.analyze import _apply_hysteresis
        prior = self._make_prior("block", 5.0)  # blocked 5h ago (> default 4h)
        new_dec = self._make_decide_response("alert_analyst", 70)
        result = _apply_hysteresis(new_dec, prior, 70, datetime.now(tz=timezone.utc))
        assert result.decision.value == "alert_analyst", (
            "Downgrade from block should be allowed after 5h (> 4h hysteresis window). "
            f"Got {result.decision.value!r} instead."
        )

    def test_immediate_reset_when_score_below_floor(self):
        """If score drops below hysteresis_score_floor, downgrade immediately."""
        from app.routes.analyze import _apply_hysteresis
        prior = self._make_prior("block", 0.1)  # only 6 min ago
        new_dec = self._make_decide_response("log_only", 15)  # well below floor=30
        result = _apply_hysteresis(new_dec, prior, 15, datetime.now(tz=timezone.utc))
        assert result.decision.value == "log_only", (
            "Score=15 is below hysteresis_score_floor=30 — must allow immediate downgrade. "
            f"Got {result.decision.value!r}."
        )

    def test_no_prior_record_uses_raw_decision(self):
        """With no prior record, _apply_hysteresis must return the raw decision unchanged."""
        from app.routes.analyze import _apply_hysteresis
        new_dec = self._make_decide_response("alert_analyst", 65)
        result = _apply_hysteresis(new_dec, None, 65, datetime.now(tz=timezone.utc))
        assert result.decision.value == "alert_analyst"

    def test_same_level_is_not_a_downgrade(self):
        """Repeated same-level decision must pass through without triggering hysteresis."""
        from app.routes.analyze import _apply_hysteresis
        prior = self._make_prior("block", 0.1)
        new_dec = self._make_decide_response("block", 88)
        result = _apply_hysteresis(new_dec, prior, 88, datetime.now(tz=timezone.utc))
        assert result.decision.value == "block"


# ─── Regression: qualitative anomaly label in context summary ────────────────


class TestAnomalyLabel:
    """
    build_context_summary must not expose the raw numeric anomaly float to the
    LLM. Instead, a qualitative label is shown:
      CRITICAL (>=0.80), HIGH (>=0.60), MODERATE (>=0.40), LOW (>=0.20),
      MINIMAL (<0.20).

    Exposing the raw float causes the LLM to anchor on it and ignore other
    contextual signals — especially harmful when the anomaly subsystem and
    the chain detector disagree.
    """

    def _make_events(self, n: int, anomaly_score: float):
        """Return n MemoryEvents with a fixed anomaly_score."""
        from app.models.schemas import MemoryEvent
        now = datetime.now(tz=timezone.utc)
        return [
            MemoryEvent(
                log_id=i,
                timestamp=now - timedelta(minutes=i),
                event_type="SSH_LOGIN",
                severity="medium",
                message="login attempt",
                source="wazuh",
                anomaly_score=anomaly_score,
            )
            for i in range(n)
        ]

    def test_critical_label_emitted_for_high_scores(self):
        from app.services.context_builder import build_context_summary
        events = self._make_events(3, anomaly_score=0.90)
        summary = build_context_summary("10.1.1.1", events)
        assert "Anomaly level    : CRITICAL" in summary, (
            f"Expected CRITICAL label for avg_anomaly=0.90. Summary:\n{summary}"
        )

    def test_high_label_emitted_for_moderate_high_scores(self):
        from app.services.context_builder import build_context_summary
        events = self._make_events(3, anomaly_score=0.70)
        summary = build_context_summary("10.1.1.1", events)
        assert "Anomaly level    : HIGH" in summary, (
            f"Expected HIGH label for avg_anomaly=0.70. Summary:\n{summary}"
        )

    def test_moderate_label_emitted_for_mid_scores(self):
        from app.services.context_builder import build_context_summary
        events = self._make_events(3, anomaly_score=0.50)
        summary = build_context_summary("10.1.1.1", events)
        assert "Anomaly level    : MODERATE" in summary, (
            f"Expected MODERATE label for avg_anomaly=0.50. Summary:\n{summary}"
        )

    def test_minimal_label_emitted_for_near_zero_scores(self):
        from app.services.context_builder import build_context_summary
        events = self._make_events(3, anomaly_score=0.05)
        summary = build_context_summary("10.1.1.1", events)
        assert "Anomaly level    : MINIMAL" in summary, (
            f"Expected MINIMAL label for avg_anomaly=0.05. Summary:\n{summary}"
        )

    def test_raw_numeric_score_not_in_summary(self):
        """
        The raw float must never appear in the context summary.

        Regression guard: ensures no code path re-introduces numeric anchoring.
        Checks for the exact old string 'Avg anomaly score' as well as any
        raw float pattern like '0.73' or '0.90'.
        """
        import re
        from app.services.context_builder import build_context_summary
        events = self._make_events(3, anomaly_score=0.73)
        summary = build_context_summary("10.1.1.1", events)
        assert "Avg anomaly score" not in summary, (
            "Numeric anchoring line 'Avg anomaly score' must not appear in context summary."
        )
        # No bare decimal like '0.73' should appear in the entity overview section
        overview_lines = summary.split("\n")[:8]
        for line in overview_lines:
            found = re.findall(r"\b0\.\d{2}\b", line)
            assert not found, (
                f"Raw anomaly float {found} found in overview line: {line!r}"
            )


# ─── Regression: ingest endpoint auth + rate limiting ────────────────────────


class TestIngestSecurity:
    """
    The /ingest-log endpoint validates X-SOC-Ingest-Token and enforces a
    sliding-window rate limit per client IP.

    Tests exercise the pure functions (_verify_ingest_token, _check_rate_limit)
    directly to avoid async/HTTP overhead in the unit test suite.
    """

    # ── Token validation ───────────────────────────────────────────────────────

    def test_missing_token_raises_401_when_configured(self, monkeypatch):
        from fastapi import HTTPException
        from app.routes.ingest import _verify_ingest_token
        monkeypatch.setattr("app.routes.ingest.settings.soc_ingest_token", "mysecret")
        with pytest.raises(HTTPException) as exc_info:
            _verify_ingest_token(None)
        assert exc_info.value.status_code == 401

    def test_wrong_token_raises_401(self, monkeypatch):
        from fastapi import HTTPException
        from app.routes.ingest import _verify_ingest_token
        monkeypatch.setattr("app.routes.ingest.settings.soc_ingest_token", "correct")
        with pytest.raises(HTTPException) as exc_info:
            _verify_ingest_token("wrong")
        assert exc_info.value.status_code == 401

    def test_correct_token_passes(self, monkeypatch):
        from app.routes.ingest import _verify_ingest_token
        monkeypatch.setattr("app.routes.ingest.settings.soc_ingest_token", "correct")
        _verify_ingest_token("correct")  # must not raise

    def test_empty_config_token_skips_auth(self, monkeypatch):
        """Dev mode: no token configured → auth skipped, no exception raised."""
        from app.routes.ingest import _verify_ingest_token
        monkeypatch.setattr("app.routes.ingest.settings.soc_ingest_token", "")
        _verify_ingest_token(None)   # must not raise
        _verify_ingest_token("any")  # must not raise

    # ── Rate limiter ───────────────────────────────────────────────────────────

    def test_rate_limit_allows_requests_within_window(self, monkeypatch):
        """Requests within the rate limit must not raise."""
        from app.routes.ingest import _check_rate_limit, _rate_buckets
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_limit", 5)
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_window_seconds", 60)
        _rate_buckets.pop("test_allow_ip", None)
        for _ in range(5):
            _check_rate_limit("test_allow_ip")  # must not raise

    def test_rate_limit_blocks_on_excess(self, monkeypatch):
        """Request exceeding the rate limit must raise HTTP 429."""
        from fastapi import HTTPException
        from app.routes.ingest import _check_rate_limit, _rate_buckets
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_limit", 3)
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_window_seconds", 60)
        _rate_buckets.pop("test_block_ip", None)
        for _ in range(3):
            _check_rate_limit("test_block_ip")  # OK — fills the bucket
        with pytest.raises(HTTPException) as exc_info:
            _check_rate_limit("test_block_ip")  # 4th request → 429
        assert exc_info.value.status_code == 429

    def test_rate_limit_independent_per_ip(self, monkeypatch):
        """Rate limit counters are independent per client IP."""
        from app.routes.ingest import _check_rate_limit, _rate_buckets
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_limit", 2)
        monkeypatch.setattr("app.routes.ingest.settings.ingest_rate_window_seconds", 60)
        _rate_buckets.pop("ip_a", None)
        _rate_buckets.pop("ip_b", None)
        _check_rate_limit("ip_a")
        _check_rate_limit("ip_b")
        _check_rate_limit("ip_a")   # 2nd for ip_a — still OK
        _check_rate_limit("ip_b")   # 2nd for ip_b — still OK
        # Both are now at the limit; a third for ip_a must fail
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _check_rate_limit("ip_a")
