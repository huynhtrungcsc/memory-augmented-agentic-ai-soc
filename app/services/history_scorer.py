"""
History scorer — derives a risk contribution from an entity's event history.

MEMORY-AUGMENTED CORE INSIGHT
==============================
Memory is not just an accumulator of risk. Its primary purpose is to help the
system distinguish a KNOWN benign entity (one that routinely triggers IDS false
positives) from a NOVEL or ESCALATING threat.

Two orthogonal outputs are produced:

  compute_history_score()    — How active / high-anomaly is this entity's past?
                               Used to DETECT low-and-slow attacks that are
                               individually unremarkable but accumulate over time.

  compute_fp_pattern()       — Does this entity's history look like a STABLE,
                               RECURRING false-positive pattern?
                               Used to DISCOUNT the risk score for entities that
                               routinely generate suspicious-looking alerts that
                               have never escalated.

Together these implement the key Memory-Augmented property:

  "High history score" alone should NOT push a benign entity to alert.
  High history score WITH escalation / novelty SHOULD push it to alert.
  High history score + stable non-escalating repetition → known FP → DISCOUNT.

This module is intentionally ORM-free so it can be unit-tested with plain data.
The SQLiteMemoryStore converts ORM rows into SimpleEvent instances before calling
these helpers.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


# ─── Lightweight event representation (ORM-free) ──────────────────────────────


@dataclass
class SimpleEvent:
    """Minimal event record used by scoring helpers (no ORM dependency)."""

    event_type: str
    severity: str
    anomaly_score: float
    timestamp: datetime
    message: str = ""


# ─── Severity weights (shared) ────────────────────────────────────────────────

_SEV_WEIGHT: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.40,
    "low": 0.10,
}

_SEV_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

_FREQ_SATURATION: int = 50


# ─── FP Pattern Analysis ──────────────────────────────────────────────────────


@dataclass
class FPPatternAnalysis:
    """
    Characterises whether an entity's history reflects a stable, recurring
    false-positive (FP) pattern — i.e., the same alert types appearing
    repeatedly without severity escalation.

    fp_pattern_score:
        0.0 → history is novel, escalating, or too short to judge
        1.0 → strong evidence of a stable known-FP profile for this entity

    The scoring engine uses fp_pattern_score to DISCOUNT the history
    contribution to the composite risk score:

        effective_history = history_score × (1 - fp_pattern_score × discount_weight)

    This implements the core Memory-Augmented insight: "I've seen this entity
    trigger these alerts 40 times over 3 days with no escalation. That is
    EVIDENCE AGAINST a real attack, not evidence for one."
    """

    fp_pattern_score: float = 0.0
    repeated_event_types: List[str] = field(default_factory=list)
    escalation_detected: bool = False
    escalation_details: str = ""
    pattern_age_hours: float = 0.0
    dominant_event_type: str = ""
    repetition_count: int = 0
    summary: str = ""


def compute_fp_pattern(
    events: List[SimpleEvent],
    now: Optional[datetime] = None,
    repetition_threshold: int = 3,
    escalation_severity_jump: int = 1,
) -> FPPatternAnalysis:
    """
    Detect whether an entity's history shows a stable, non-escalating
    false-positive pattern.

    Algorithm
    ---------
    1. Repetition score   — high when the same event types recur many times.
    2. Escalation penalty — if severity is increasing over time, this is NOT a
                            benign pattern; penalty reduces fp_pattern_score.
    3. Age bonus          — a pattern that has been stable over hours/days is
                            more confidently benign than one seen only twice.

    fp_pattern_score = repetition_score × age_factor × (1 − escalation_penalty)

    Parameters
    ----------
    repetition_threshold:
        Minimum times an event type must appear to count as "repeated".
    escalation_severity_jump:
        Minimum severity rank increase (e.g., low→high = +2) to flag escalation.

    Returns
    -------
    FPPatternAnalysis
    """
    if not events:
        return FPPatternAnalysis(fp_pattern_score=0.0, summary="No events in memory.")

    now_ts = now or datetime.now(tz=timezone.utc)

    def _utc(ts: datetime) -> datetime:
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    sorted_events = sorted(events, key=lambda e: _utc(e.timestamp))
    oldest = _utc(sorted_events[0].timestamp)
    newest = _utc(sorted_events[-1].timestamp)
    span_hours = max((newest - oldest).total_seconds() / 3600.0, 0.5)

    # ── 1. Repetition score ────────────────────────────────────────────────────
    type_counts = Counter(e.event_type for e in events)
    repeated_types = [
        et for et, cnt in type_counts.items() if cnt >= repetition_threshold
    ]
    dominant_type = type_counts.most_common(1)[0][0] if type_counts else ""
    total_repeated = sum(type_counts[et] for et in repeated_types)

    if not repeated_types:
        return FPPatternAnalysis(
            fp_pattern_score=0.0,
            repeated_event_types=[],
            dominant_event_type=dominant_type,
            pattern_age_hours=span_hours,
            repetition_count=0,
            summary="Insufficient repetition to establish a known entity FP profile.",
        )

    rep_factor = min(math.log2(total_repeated + 1) / math.log2(31), 1.0)
    coverage = total_repeated / len(events)
    repetition_score = rep_factor * coverage

    # ── 2. Escalation detection ────────────────────────────────────────────────
    n = len(sorted_events)
    recent_n = max(3, min(10, n // 5))
    baseline_part = sorted_events[: n - recent_n] if n > recent_n else sorted_events
    recent_part = sorted_events[n - recent_n :] if n > recent_n else sorted_events

    baseline_sev_avg = sum(_SEV_RANK.get(e.severity, 1) for e in baseline_part) / max(len(baseline_part), 1)
    recent_sev_avg = sum(_SEV_RANK.get(e.severity, 1) for e in recent_part) / max(len(recent_part), 1)
    sev_delta = recent_sev_avg - baseline_sev_avg

    baseline_max = max((_SEV_RANK.get(e.severity, 1) for e in baseline_part), default=1)
    recent_max = max((_SEV_RANK.get(e.severity, 1) for e in recent_part), default=1)
    peak_jump = recent_max - baseline_max

    escalation_detected = (sev_delta >= escalation_severity_jump) or (peak_jump >= escalation_severity_jump)
    escalation_penalty = min(max((sev_delta / 3.0) + (peak_jump / 4.0), 0.0), 1.0)

    escalation_details = ""
    if escalation_detected:
        escalation_details = (
            f"Severity rising in recent {recent_n} events "
            f"(baseline avg={baseline_sev_avg:.1f} → recent avg={recent_sev_avg:.1f}, "
            f"peak jump={peak_jump:+d} rank). "
            "This entity's activity is ESCALATING — FP pattern discount reduced."
        )

    # ── 3. Age bonus ───────────────────────────────────────────────────────────
    age_factor = min(math.log2(span_hours + 1) / math.log2(25), 1.0)

    # ── 4. Anomaly consistency check ──────────────────────────────────────────
    repeated_events = [e for e in events if e.event_type in repeated_types]
    avg_repeated_anomaly = (
        sum(e.anomaly_score for e in repeated_events) / len(repeated_events)
        if repeated_events else 0.0
    )
    anomaly_penalty = max(0.0, (avg_repeated_anomaly - 0.75) / 0.25)

    # ── Final FP pattern score ────────────────────────────────────────────────
    raw = repetition_score * age_factor * (1.0 - escalation_penalty) * (1.0 - anomaly_penalty * 0.5)
    fp_score = round(min(max(raw, 0.0), 1.0), 3)

    if fp_score >= 0.7:
        summary = (
            f"STRONG known-FP profile: {dominant_type} seen {type_counts[dominant_type]}× "
            f"over {span_hours:.1f}h with no severity escalation. "
            "Memory strongly suggests recurring false-positive pattern for this entity."
        )
    elif fp_score >= 0.4:
        summary = (
            f"MODERATE known-FP profile: {', '.join(repeated_types[:3])} repeat "
            f"({total_repeated} occurrences over {span_hours:.1f}h). "
            "Pattern is consistent but not yet conclusively benign."
        )
    elif fp_score >= 0.2:
        summary = (
            f"WEAK FP pattern: some repetition detected but history is short or anomaly is high. "
            f"({span_hours:.1f}h span, avg_anomaly={avg_repeated_anomaly:.2f})"
        )
    else:
        summary = (
            f"No established FP pattern. "
            f"{'Escalation detected. ' if escalation_detected else ''}"
            f"History does not suggest a known benign profile for this entity."
        )

    return FPPatternAnalysis(
        fp_pattern_score=fp_score,
        repeated_event_types=repeated_types,
        escalation_detected=escalation_detected,
        escalation_details=escalation_details,
        pattern_age_hours=span_hours,
        dominant_event_type=dominant_type,
        repetition_count=total_repeated,
        summary=summary,
    )


# ─── History score (risk accumulation) ────────────────────────────────────────


def _decay_weight(event_ts: datetime, now: datetime, half_life_hours: float = 24.0) -> float:
    """
    Compute temporal decay weight for an event.

    Exponential decay with configurable half-life:
      weight = 2^(-age_hours / half_life_hours)

    Examples (half_life_hours=24):
      0h ago  → 1.00
      12h ago → 0.71
      24h ago → 0.50
      48h ago → 0.25
    """
    ts = event_ts if event_ts.tzinfo else event_ts.replace(tzinfo=timezone.utc)
    now_aware = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (now_aware - ts).total_seconds() / 3600.0)
    weight = math.pow(2.0, -age_hours / half_life_hours)
    return max(0.05, weight)


def compute_history_score(
    events: List[SimpleEvent],
    now: Optional[datetime] = None,
    decay_half_life_hours: float = 24.0,
) -> float:
    """
    Derive a normalised risk signal (0–1) from historical event patterns.

    NOTE: This score captures "how active / anomalous" the entity has been.
    It should be COMBINED with FPPatternAnalysis.fp_pattern_score to determine
    whether that activity is a KNOWN benign pattern or a genuine threat.
    Use compute_fp_pattern() to get the FP context before applying this score.

    Formula:
      score = (weighted_avg_anomaly × 0.40)
            + (freq_factor × 0.35)
            + (weighted_avg_severity × 0.25)
    """
    if not events:
        return 0.0

    now_ts = now or datetime.now(tz=timezone.utc)
    if now_ts.tzinfo is None:
        now_ts = now_ts.replace(tzinfo=timezone.utc)

    total = len(events)
    weights = [_decay_weight(e.timestamp, now_ts, decay_half_life_hours) for e in events]
    total_weight = sum(weights)

    weighted_anomaly = sum(w * e.anomaly_score for w, e in zip(weights, events)) / total_weight

    freq_factor = min(
        math.log2(total + 1) / math.log2(_FREQ_SATURATION + 1),
        1.0,
    )

    weighted_severity = sum(
        w * _SEV_WEIGHT.get(e.severity, 0.2) for w, e in zip(weights, events)
    ) / total_weight

    raw = (weighted_anomaly * 0.40) + (freq_factor * 0.35) + (weighted_severity * 0.25)
    return min(round(raw, 3), 1.0)


def compute_context_stats(
    events: List[SimpleEvent],
    observation_hours: float = 24.0,
) -> Tuple[float, Dict[str, int], Dict[str, int], float]:
    """Compute aggregate statistics from a list of SimpleEvents."""
    if not events:
        return 0.0, {}, {}, 0.0

    timestamps = [e.timestamp for e in events]
    oldest = min(timestamps)
    newest = max(timestamps)
    span_hours = max((newest - oldest).total_seconds() / 3600.0, 1.0)
    events_per_hour = round(len(events) / span_hours, 2)

    attack_dist = dict(Counter(e.event_type for e in events))
    severity_dist = dict(Counter(e.severity for e in events))
    avg_anomaly = round(sum(e.anomaly_score for e in events) / len(events), 3)

    return events_per_hour, attack_dist, severity_dist, avg_anomaly


def derive_dominant_severity(severity_distribution: Dict[str, int]) -> str:
    """Return the most severe category present in the distribution."""
    for sev in ("critical", "high", "medium", "low"):
        if severity_distribution.get(sev, 0) > 0:
            return sev
    return "low"


# ─── Semantic Memory builder ───────────────────────────────────────────────────


@dataclass
class SemanticProfileData:
    """
    Structured output of compute_semantic_profile_data().

    Represents the accumulated scoring priors derived from all episodic events
    and stored into semantic memory after each analysis.  Each analysis enriches
    the semantic memory, which then informs the next analysis — shifting the
    composite score toward lower risk for established benign entities over time.
    """
    known_good_hours: List[int]
    dominant_event_types: List[str]
    peer_entities: List[str]
    avg_anomaly_score: float
    fp_confidence: float
    risk_trend: str
    total_events_seen: int


def compute_semantic_profile_data(
    events: List[SimpleEvent],
    graph_peer_ids: Optional[List[str]] = None,
    fp_pattern: Optional["FPPatternAnalysis"] = None,
    now: Optional[datetime] = None,
) -> SemanticProfileData:
    """
    Derive SEMANTIC MEMORY content from the entity's episodic history.

    This function is the bridge between raw episodic events and the accumulated
    semantic profile.  It is called at the end of every analysis to update
    the entity's long-term memory.

    Key computations
    ----------------
    known_good_hours:
        Hours of day that appear with above-average frequency — derived from
        event timestamp distribution across the entity's full episodic history.

    dominant_event_types:
        Event types that account for ≥ 10% of total events — identified by
        frequency threshold across the entity's event history.

    fp_confidence:
        Accumulated probability that this entity generates FP alerts.
        Derived from fp_pattern.fp_pattern_score with stability weighting:
          - Higher when stable, non-escalating FP pattern is detected.
          - Lower when escalation is detected (novel / suspicious).
          - Accumulates across analyses (caller merges with prior profile).

    risk_trend:
        Compares the last 25% of events to the first 75% by avg anomaly.
        'escalating'   — recent events are significantly more anomalous.
        'deescalating' — recent events are significantly less anomalous.
        'stable'       — no significant trend.
    """
    if not events:
        return SemanticProfileData(
            known_good_hours=[],
            dominant_event_types=[],
            peer_entities=[],
            avg_anomaly_score=0.0,
            fp_confidence=0.0,
            risk_trend="stable",
            total_events_seen=0,
        )

    now_ts = now or datetime.now(tz=timezone.utc)
    if now_ts.tzinfo is None:
        now_ts = now_ts.replace(tzinfo=timezone.utc)

    def _hour(e: SimpleEvent) -> int:
        ts = e.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.hour

    # Known-good hours: hours with above-average count
    hour_counts: Counter = Counter(_hour(e) for e in events)
    if hour_counts:
        avg_hourly = len(events) / max(len(hour_counts), 1)
        known_good_hours = sorted(h for h, c in hour_counts.items() if c >= avg_hourly)
    else:
        known_good_hours = []

    # Dominant event types: those that appear in ≥ 10% of events
    type_counts: Counter = Counter(e.event_type for e in events)
    threshold = max(1, len(events) * 0.10)
    dominant_event_types = [t for t, c in type_counts.most_common(8) if c >= threshold]

    # Average anomaly across all events
    avg_anomaly = round(sum(e.anomaly_score for e in events) / len(events), 3)

    # FP confidence — derived from fp_pattern if available
    if fp_pattern is not None:
        base_confidence = fp_pattern.fp_pattern_score
        if fp_pattern.escalation_detected:
            # Escalation overrides FP confidence — not a simple FP anymore
            fp_confidence = max(0.0, base_confidence * 0.2)
        else:
            fp_confidence = base_confidence
    else:
        # No FP pattern computed yet — use low anomaly as weak prior
        fp_confidence = max(0.0, 0.5 - avg_anomaly)

    # Risk trend: compare recent quarter to earlier three-quarters
    n = len(events)
    if n >= 4:
        # Events are expected newest-first; reverse to chronological
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        split = max(1, n * 3 // 4)
        early_avg = sum(e.anomaly_score for e in sorted_events[:split]) / split
        recent_count = n - split
        recent_avg = sum(e.anomaly_score for e in sorted_events[split:]) / recent_count
        delta = recent_avg - early_avg
        if delta > 0.15:
            risk_trend = "escalating"
        elif delta < -0.15:
            risk_trend = "deescalating"
        else:
            risk_trend = "stable"
    else:
        risk_trend = "stable"

    # Peer entities from graph (if provided)
    peer_entities = list(graph_peer_ids or [])[:20]

    return SemanticProfileData(
        known_good_hours=known_good_hours,
        dominant_event_types=dominant_event_types,
        peer_entities=peer_entities,
        avg_anomaly_score=avg_anomaly,
        fp_confidence=round(fp_confidence, 3),
        risk_trend=risk_trend,
        total_events_seen=n,
    )
