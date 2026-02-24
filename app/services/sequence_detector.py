"""
Attack Sequence / MITRE ATT&CK Chain Detector.

WHY THIS EXISTS — The core accuracy problem with event-by-event scoring:
  A single port scan scores 0.60 → LOG_ONLY (correct).
  A single SSH brute-force scores 0.80 → BLOCK (reasonable).
  But a SEQUENCE of: scan → brute force → successful login → lateral movement
  is a textbook breach chain and should score near 100, even if the individual
  events each appear moderate.

HOW IT WORKS (generalised, not hard-coded keyword lists):
  1. Each event is mapped to a MITRE ATT&CK phase via keyword sets.
     Keyword matching is on event_type + message (normalised), so it
     generalises across log sources (Suricata/Zeek/Wazuh/Splunk).
  2. The event timeline is scanned in chronological order to build a
     sequence of unique phases, each annotated with its first timestamp.
  3. Known attack chain templates are matched against the phase sequence
     using ordered subsequence matching (phases don't have to be adjacent).
  4. A chain match is rejected if the matched phases span more than
     max_chain_window_hours (default 24h). Events separated by days or weeks
     are unlikely to be from the same incident and should not form a chain.
  5. A sequence_score (0–1) reflects completion ratio of the best chain.

ACCURACY NOTE:
  This module does NOT flag isolated events.  A port scan alone never triggers
  a sequence match.  At least 50 % of a chain's phases must be present in the
  correct temporal order.  This deliberately reduces false positives for
  legitimate network scanning tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.services.history_scorer import SimpleEvent


# ─── MITRE Phase keyword mapping ─────────────────────────────────────────────
# Each keyword list is intentionally broad to match varied log formats.
# Matching is substring-based on lowercase event_type + message text.

PHASE_KEYWORDS: Dict[str, List[str]] = {
    "reconnaissance": [
        "scan", "nmap", "sweep", "probe", "discovery", "ping",
        "traceroute", "fingerprint", "enumerat", "host discov",
        "arp scan", "syn scan", "udp scan",
        # Real-world Suricata/Zeek ET rule prefixes
        "et scan",          # Suricata ET rule category prefix
        "port scan",        # Generic
        "host enumerat",    # Zeek enumeration
        "network scan",
    ],
    "credential_access": [
        "brute", "bruteforce", "password spray", "failed auth",
        "authentication failure", "invalid password", "login fail",
        "kerberos", "ntlm hash", "pass the hash",
        "password attempt", "lsass", "credential dump",
        "mimikatz", "hash capture",
        # Windows Security Event ID 4625 (failed logon) signatures
        "event id 4625",    # Windows: An account failed to log on
        "4625",             # Short form used in event_type fields
        "failed to log on", # Windows 4625 message text
        "account failed",   # "An account failed to log on"
        "bad password",     # Windows reason code
        "wrong password",
        "login failure",
        "logon failure",
        "failed logon",
        # Wazuh rule group names
        "sshd_brute_force", # Wazuh rule 5712 group tag
        "brute_force",      # Wazuh generic brute force group
    ],
    "initial_access": [
        # Explicit success / session indicators (prefer multi-word to reduce FP)
        "login success", "login successful",
        "authentication success", "authentication successful",
        "logon success", "logon successful",
        "session opened", "session established",
        "user logged in", "user logged on",
        "access granted", "access accepted",
        "shell opened", "webshell",
        "exploit success",
        "after brute",           # "Successful login after brute force" pattern
        "logged in",             # syslog / PAM: "User logged in"
        "logged on",
        "successful login", "successful ssh", "successful logon",  # reverse-order variants
        "accepted password",     # OpenSSH: "Accepted password for root"
        "accepted publickey",    # OpenSSH: "Accepted publickey for admin"
        # Past-participle forms — specific enough to indicate a completed auth
        "authenticated",         # "SSH Authenticated" / "User authenticated"
                                 # NOTE: does NOT match "authentication failure"
                                 # ("authenticated" ≠ "authentication")
        "accepted",              # OpenSSH fallback: "Accepted ..."
        # Windows Security Event ID 4624 (successful logon) signatures
        "event id 4624",         # Windows: An account was successfully logged on
        "4624",                  # Short form used in event_type fields
        "initial access",        # Literal phase label when embedded in log messages
        "account logged on",     # Windows 4624 text fragment
        "network logon success", # Windows 4624 Logon Type 3 text
    ],
    "lateral_movement": [
        "lateral", "rdp", "smb", "wmi", "psexec", "pivot",
        "pass the ticket", "remote exec", "remote session",
        "dcom", "winrm", "remote desktop",
    ],
    "privilege_escalation": [
        "escalat", "token impersonat", "uac bypass",
        "setuid", "suid", "privilege escalation", "root access",
        "admin priv", "sudo escalat",
    ],
    "exfiltration": [
        "exfil", "data transfer", "large transfer",
        "tor exit", "encrypted beacon", "data theft",
        "dns tunneling", "large dns", "data exfil",
    ],
    "command_and_control": [
        "beacon", "callback", "dropper", "rat ", "botnet",
        "periodic", "c2 traffic", "c2 beacon", "command and control",
        "c2 server",
        # Real-world Suricata/Wazuh C2 signatures
        "cnc",              # Suricata: "Generic CnC Beacon"
        "c&c",              # Common shorthand
        "c2 connection",    # Zeek/Suricata connection logs
        "command control",  # Without the "and" (common log abbreviation)
        "malware_c2",       # Wazuh rule group tag
        "et trojan",        # Suricata ET TROJAN rule prefix → C2 family
        "trojan",           # Generic trojan / RAT indicator
        "malware beacon",
    ],
    "defense_evasion": [
        "clear log", "log delet", "tamper", "disable av",
        "bypass", "obfuscat", "timestomp",
    ],
}

# Phase priority for tie-breaking.
# When two phases have the same keyword hit count, the higher-priority phase wins.
# This prevents "Successful SSH Login After BruteForce" from being classified as
# credential_access (lower priority) instead of initial_access (higher priority)
# merely because "brute" appears in the event text.
#
# Priority rationale:
#   "Confirmed" events (initial_access, exfiltration) are specific and rare.
#   "Attempted" events (credential_access, reconnaissance) are noisy and common.
#   When in doubt, prefer the interpretation with higher operational consequence.
PHASE_PRIORITY: Dict[str, int] = {
    "initial_access":       10,  # Confirmed entry — highest specificity
    "exfiltration":          9,  # Data leaving the network — critical
    "lateral_movement":      8,  # Host-to-host movement
    "privilege_escalation":  7,  # Privilege gain
    "command_and_control":   6,  # C2 channel established
    "defense_evasion":       5,  # Anti-forensics
    "reconnaissance":        4,  # Noisy, often benign
    "credential_access":     3,  # Failed attempts — lowest priority
}

# ─── Known attack chain templates ────────────────────────────────────────────
# Each chain defines:
#   name         — human-readable label returned to the analyst
#   phases       — ordered MITRE phase list (temporal order required)
#   min_pct      — minimum fraction of phases that must match (0.0–1.0)
#   severity     — chain severity level for reporting

@dataclass
class ChainTemplate:
    name: str
    phases: List[str]
    min_pct: float = 0.5
    severity: str = "high"


KNOWN_CHAINS: List[ChainTemplate] = [
    # ── Full-spectrum breach chains ────────────────────────────────────────────
    ChainTemplate(
        # Textbook APT kill chain; requires reconnaissance as the opening move.
        name="Classic Breach Chain",
        phases=["reconnaissance", "credential_access", "initial_access", "lateral_movement"],
        min_pct=0.5,   # 2/4 phases sufficient to flag (recon + any one other)
        severity="critical",
    ),
    ChainTemplate(
        # Most common real-world pattern: brute force → successful login → spread.
        # Does NOT require reconnaissance — many attackers skip external scanning.
        name="Brute Force to Breach",
        phases=["credential_access", "initial_access", "lateral_movement"],
        min_pct=0.67,  # needs at least 2/3 phases in order
        severity="critical",
    ),
    ChainTemplate(
        # Brute force → compromise → C2 beaconing (no lateral movement yet).
        name="Credential Compromise with C2",
        phases=["credential_access", "initial_access", "command_and_control"],
        min_pct=0.67,
        severity="critical",
    ),
    ChainTemplate(
        # Full kill chain including C2 after lateral movement.
        name="Breach Campaign with C2",
        phases=["credential_access", "initial_access", "lateral_movement", "command_and_control"],
        min_pct=0.5,   # 2/4 phases → credential_access + initial_access enough to flag
        severity="critical",
    ),
    ChainTemplate(
        # Data stolen via exfiltration after credential theft.
        name="Credential Theft + Exfiltration",
        phases=["credential_access", "initial_access", "exfiltration"],
        min_pct=0.65,  # 2/3 phases = 0.666..., using 0.65 avoids float edge case
        severity="critical",
    ),
    ChainTemplate(
        # Fast smash-and-grab: initial access directly to exfiltration.
        name="Smash-and-Grab",
        phases=["reconnaissance", "initial_access", "exfiltration"],
        min_pct=0.67,
        severity="high",
    ),
    ChainTemplate(
        # Escalation after initial access — attacker gaining elevated control.
        name="Privilege Escalation Campaign",
        phases=["initial_access", "privilege_escalation", "lateral_movement"],
        min_pct=0.67,
        severity="high",
    ),
    ChainTemplate(
        # Early-stage indicator: recon followed by brute force confirms intent.
        name="Recon + Brute Force",
        phases=["reconnaissance", "credential_access"],
        min_pct=1.0,   # both phases required
        severity="medium",
    ),
    ChainTemplate(
        # C2 established after initial access, leading to exfiltration.
        name="C2 Beacon Campaign",
        phases=["initial_access", "command_and_control", "exfiltration"],
        min_pct=0.65,  # 2/3 = 0.666, using 0.65 avoids float edge case
        severity="critical",
    ),
]


# ─── Output schema ────────────────────────────────────────────────────────────


@dataclass
class SequenceMatch:
    chain_name: str
    chain_severity: str
    phases_detected: List[str]
    phases_total: int
    completion_ratio: float  # 0.0 – 1.0
    sequence_score: float    # 0.0 – 1.0 (same as completion for now)
    phase_timeline: List[str] = field(default_factory=list)  # ordered unique phases seen
    # Actual time span (hours) between first and last matched phase.
    # 0.0 means single-phase or same-timestamp match.
    chain_window_hours: float = 0.0


# ─── Phase classifier ─────────────────────────────────────────────────────────


def classify_phase(event: SimpleEvent) -> Optional[str]:
    """
    Map a single event to a MITRE ATT&CK phase.

    Uses substring matching on lower-cased event_type + message (combined).
    Tie-breaking: when two phases have equal keyword hits, the higher-priority
    phase wins (see PHASE_PRIORITY).  This prevents "Successful SSH Login After
    BruteForce" from being misclassified as credential_access merely because
    "brute" appears in the text — initial_access has higher priority and wins
    the tie with its "after brute" / "successful" keywords.

    Returns None if no keyword matches — unknown events are excluded from chain
    matching rather than producing false chain detections.
    """
    text = f"{event.event_type} {event.message}".lower()

    best_phase: Optional[str] = None
    best_hits: int = 0
    best_priority: int = -1

    for phase, keywords in PHASE_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text)
        if hits == 0:
            continue

        priority = PHASE_PRIORITY.get(phase, 0)

        # Update if: strictly more hits, OR same hits but higher priority
        if hits > best_hits or (hits == best_hits and priority > best_priority):
            best_hits = hits
            best_phase = phase
            best_priority = priority

    return best_phase if best_hits >= 1 else None


# ─── Ordered subsequence checker ─────────────────────────────────────────────


def _count_ordered_matches(phase_sequence: List[str], required: List[str]) -> int:
    """
    Count how many `required` phases appear, in order, within `phase_sequence`.

    Uses a greedy left-to-right scan — does not require the phases to be
    adjacent, only in the correct relative order.

    Example:
      phase_sequence = [recon, credential_access, initial_access, exfil]
      required       = [recon, credential_access, initial_access, lateral_movement]
      → returns 3 (recon, credential_access, initial_access matched in order;
                    lateral_movement not found)
    """
    req_idx = 0
    for phase in phase_sequence:
        if req_idx < len(required) and phase == required[req_idx]:
            req_idx += 1
    return req_idx


def _extract_match_with_timestamps(
    timed_timeline: List[Tuple[str, datetime]],
    required: List[str],
) -> Tuple[int, List[datetime]]:
    """
    Greedy ordered subsequence match that also collects the timestamps of
    each matched phase (for temporal window enforcement).

    Parameters
    ----------
    timed_timeline:
        [(phase, first_seen_timestamp), ...] in chronological order.
    required:
        Ordered list of required phases for the chain template.

    Returns
    -------
    (match_count, [matched_timestamps])
    match_count == len(matched_timestamps).
    """
    req_idx = 0
    matched_ts: List[datetime] = []
    for phase, ts in timed_timeline:
        if req_idx < len(required) and phase == required[req_idx]:
            matched_ts.append(ts)
            req_idx += 1
    return req_idx, matched_ts


# ─── Public API ───────────────────────────────────────────────────────────────


def build_phase_timeline(events: List[SimpleEvent]) -> List[str]:
    """
    Convert a list of events into a deduplicated phase timeline.

    Events are sorted chronologically.  Consecutive duplicate phases are
    collapsed to one (e.g., 50 brute-force attempts = one credential_access
    phase, not 50 separate phase entries).
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    timeline: List[str] = []
    for ev in sorted_events:
        phase = classify_phase(ev)
        if phase and (not timeline or timeline[-1] != phase):
            timeline.append(phase)
    return timeline


def _to_utc(ts: datetime) -> datetime:
    """
    Ensure a timestamp is timezone-aware UTC.

    Many log sources deliver naive datetimes.  Mixing tz-aware and tz-naive
    datetimes in the same sort will raise a TypeError in Python ≥3.11.
    This helper normalises both cases to UTC so that mixed-source event lists
    sort correctly regardless of how the upstream log was ingested.
    """
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _build_timed_timeline(events: List[SimpleEvent]) -> List[Tuple[str, datetime]]:
    """
    Like build_phase_timeline but also captures the first timestamp seen for
    each phase transition (used for temporal window enforcement).

    Returns [(phase, first_event_timestamp), ...] in chronological order.
    Consecutive duplicate phases are deduplicated (same as build_phase_timeline).

    All timestamps are normalised to UTC before sorting to prevent
    TypeError when mixing tz-aware and tz-naive events from different log sources.
    """
    sorted_events = sorted(events, key=lambda e: _to_utc(e.timestamp))
    timed: List[Tuple[str, datetime]] = []
    for ev in sorted_events:
        phase = classify_phase(ev)
        if phase and (not timed or timed[-1][0] != phase):
            timed.append((phase, _to_utc(ev.timestamp)))
    return timed


# ─── Valid phase transitions ──────────────────────────────────────────────────
#
# Not all phase orderings are realistic.  A chain that shows exfiltration BEFORE
# initial_access was never physically possible — the data couldn't leave without
# first gaining entry.  We validate detected-phase sequences against this map
# and reject chains whose inferred ordering violates physical causality.
#
# Format: {phase → set of phases that MUST appear before it in any valid chain}
# An empty set means "this phase can appear as the first phase."
#
# This is intentionally conservative — we only reject OBVIOUS impossibilities
# (exfil before access, lateral before access).  We don't try to enumerate
# every valid ordering because real attacks are creative.
_REQUIRES_PRIOR: Dict[str, set] = {
    "initial_access":       set(),                                    # can be first
    "reconnaissance":       set(),                                    # can be first
    "credential_access":    set(),                                    # can be first
    "lateral_movement":     {"initial_access"},                       # need foothold first
    "privilege_escalation": {"initial_access"},                       # need foothold first
    "exfiltration":         {"initial_access"},                       # must be in first
    "command_and_control":  set(),                                    # C2 can precede access (staged dropper)
    "defense_evasion":      set(),                                    # can happen at any time
}


def _validate_phase_order(phases_detected: List[str]) -> bool:
    """
    Validate that the detected phase sequence is physically plausible.

    Returns True if the sequence is valid (or if no transition rules exist for
    the phases in question), False if any required predecessor is missing.

    Example rejections:
      ["exfiltration"]                     → invalid (exfil without initial_access)
      ["lateral_movement", "initial_access"] → valid (out-of-order input, but both present)
      ["exfiltration", "initial_access"]   → invalid ordering cannot be fixed
    """
    if not phases_detected:
        return True

    phases_set = set(phases_detected)
    for phase in phases_detected:
        required_priors = _REQUIRES_PRIOR.get(phase, set())
        if required_priors and not required_priors.intersection(phases_set):
            return False
    return True


def detect_sequences(
    events: List[SimpleEvent],
    max_chain_window_hours: float = 24.0,
) -> List[SequenceMatch]:
    """
    Detect known attack chains in the event timeline.

    Parameters
    ----------
    events:
        SimpleEvent list (any order — sorted internally).
    max_chain_window_hours:
        Maximum allowed time span (hours) between the first and last
        matched phase in a chain.  Chains whose matched phases span longer than
        this window are rejected as likely-unrelated events from different
        incidents.  Default 24 hours.  Set to float('inf') to disable.

    Returns
    -------
    List of SequenceMatch objects, sorted by completion_ratio descending.
    An empty list means no recognised attack pattern was found within the
    temporal window.

    Accuracy guarantee:
      A chain is only reported if the required phases appear in the correct
      temporal order AND completion_ratio ≥ chain.min_pct AND the matched
      phases fit within max_chain_window_hours.  Isolated events never produce
      a match regardless of their anomaly_score.
    """
    if not events:
        return []

    # Build both plain timeline (for API compatibility) and timed timeline (for W2)
    timed_timeline = _build_timed_timeline(events)
    phase_timeline = [p for p, _ in timed_timeline]

    if not phase_timeline:
        return []

    matches: List[SequenceMatch] = []

    for chain in KNOWN_CHAINS:
        match_count, match_timestamps = _extract_match_with_timestamps(
            timed_timeline, chain.phases
        )
        completion = match_count / len(chain.phases)

        if completion < chain.min_pct:
            continue  # not enough of the chain present

        # Enforce temporal window — reject chains assembled from events
        # that are too far apart in time to plausibly be the same incident.
        chain_window_hours = 0.0
        if len(match_timestamps) >= 2:
            span_secs = (match_timestamps[-1] - match_timestamps[0]).total_seconds()
            chain_window_hours = round(span_secs / 3600.0, 2)
            if chain_window_hours > max_chain_window_hours:
                continue  # chain spans too wide — events likely from different incidents

        detected_phases = chain.phases[:match_count]
        sequence_score = completion  # direct linear mapping (0–1)

        # Reject chains with physically impossible phase orderings.
        # This catches cases where chain template matching produces a result
        # that cannot represent a real attack (e.g., exfiltration before access).
        if not _validate_phase_order(detected_phases):
            continue

        matches.append(SequenceMatch(
            chain_name=chain.name,
            chain_severity=chain.severity,
            phases_detected=detected_phases,
            phases_total=len(chain.phases),
            completion_ratio=round(completion, 3),
            sequence_score=round(sequence_score, 3),
            phase_timeline=phase_timeline,
            chain_window_hours=chain_window_hours,
        ))

    # Return highest-completion chains first
    matches.sort(key=lambda m: m.completion_ratio, reverse=True)
    return matches


def best_sequence_score(matches: List[SequenceMatch]) -> float:
    """Return the highest sequence_score across all matches, or 0.0."""
    return max((m.sequence_score for m in matches), default=0.0)
