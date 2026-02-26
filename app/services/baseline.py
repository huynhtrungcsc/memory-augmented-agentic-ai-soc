"""
Behavioral Baseline Comparison.

WHY THIS EXISTS — The false-positive problem with static scoring:
  A legitimate vulnerability scanner (Nessus, Qualys, Tenable) running
  nightly from an internal IP generates hundreds of "port scan" events.
  The current anomaly_score heuristic gives each one a score of 0.75+,
  which would eventually trigger a block on your own security tooling.

  Conversely, an attacker who scans slowly and deliberately might stay
  under the per-event threshold even though their RELATIVE activity is
  anomalous — they went from 0 events/day to 20 events in 1 hour.

HOW IT WORKS:
  1. Compare the entity's SHORT-TERM rate (last 1 hour) against its
     LONG-TERM baseline (last 24 hours).
  2. Compute a severity escalation signal: is average severity getting worse?
  3. Detect new event types that were never seen in the baseline window.
  4. Combine into a `deviation` score (0–1) where:
       0.0 = perfectly normal (matches baseline behaviour)
       1.0 = extreme anomaly (sudden 5x+ rate spike + escalating severity)

ACCURACY NOTES:
  - An entity with zero baseline history gets deviation = 0 (not 1).
    Unknown ≠ dangerous; first-seen events are handled by history_score instead.
  - Rate ratio is capped at 5× — beyond that the additional ratio adds nothing.
  - Severity escalation is only flagged if the delta exceeds 0.3 on a 0–3 scale.
    Small natural fluctuations don't trigger false positives.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from app.services.history_scorer import SimpleEvent


# ─── Severity numeric mapping ─────────────────────────────────────────────────
_SEV_NUM = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.0}

# Minimum anomaly score for an event to count as "suspicious" in slow-window analysis
_SLOW_ANOMALY_THRESHOLD: float = 0.45

# ─── Output schema ────────────────────────────────────────────────────────────


@dataclass
class BaselineDeviation:
    """
    Comparison of entity's short-term (1h) activity vs long-term (24h) baseline.
    """
    deviation: float         # 0–1 composite deviation score
    rate_ratio: float        # recent_rate / baseline_rate  (1.0 = same rate)
    sev_delta: float         # avg_sev_recent - avg_sev_baseline  (positive = escalating)
    is_escalating: bool      # True when severity is getting significantly worse
    new_event_types: List[str] = field(default_factory=list)
    baseline_event_count: int = 0
    recent_event_count: int = 0
    has_sufficient_baseline: bool = True  # False if baseline is too small to trust


# ─── Public API ───────────────────────────────────────────────────────────────


def compute_baseline_deviation(
    recent_events: List[SimpleEvent],    # last 1h window
    baseline_events: List[SimpleEvent],  # last 24h window (includes recent)
    min_baseline_size: int = 3,
) -> BaselineDeviation:
    """
    Compute how much the recent activity deviates from the entity's baseline.

    Parameters
    ----------
    recent_events:
        Events in the last 1 hour (short window).
    baseline_events:
        Events in the last 24 hours (long baseline window; includes recent).
    min_baseline_size:
        Minimum number of baseline events to trust the comparison.
        If the baseline has fewer than this many events, the deviation is
        returned as 0.0 to avoid false positives on new entities.

    Returns
    -------
    BaselineDeviation with composite deviation score and component signals.
    """
    # With no baseline history, we can't make a meaningful comparison.
    # Return zero deviation — the history_score (which handles new entities)
    # will carry the risk signal instead.
    if len(baseline_events) < min_baseline_size:
        return BaselineDeviation(
            deviation=0.0,
            rate_ratio=1.0,
            sev_delta=0.0,
            is_escalating=False,
            baseline_event_count=len(baseline_events),
            recent_event_count=len(recent_events),
            has_sufficient_baseline=False,
        )

    # ── Component 1: Rate ratio ───────────────────────────────────────────────
    # baseline_rate = events per hour over the 24h window
    # recent_rate   = events in the last 1 hour
    baseline_rate = len(baseline_events) / 24.0
    recent_rate = float(len(recent_events))  # events/hour in last 1h
    rate_ratio = recent_rate / max(baseline_rate, 0.1)

    # Normalise: ratio 1.0 = normal, 5.0 = max deviation (cap there)
    rate_deviation = max(0.0, min((rate_ratio - 1.0) / 4.0, 1.0))

    # ── Component 2: Severity escalation ─────────────────────────────────────
    baseline_avg_sev = _avg_severity(baseline_events)
    recent_avg_sev = _avg_severity(recent_events) if recent_events else baseline_avg_sev
    sev_delta = recent_avg_sev - baseline_avg_sev  # positive = getting worse

    # Normalise: max delta = 3 (low→critical)
    sev_deviation = max(0.0, min(sev_delta / 3.0, 1.0))
    is_escalating = sev_delta > 0.3  # require meaningful increase

    # ── Component 3: New event types ──────────────────────────────────────────
    baseline_types = {e.event_type for e in baseline_events}
    recent_types = {e.event_type for e in recent_events}
    new_types = sorted(recent_types - baseline_types)

    # Normalise: 1 new type = 0.33, 3+ new types = 1.0
    new_type_deviation = min(len(new_types) / 3.0, 1.0)

    # ── Composite ─────────────────────────────────────────────────────────────
    # Weight: rate is the strongest signal; severity and new types are supporting
    deviation = (
        rate_deviation * 0.55
        + sev_deviation * 0.30
        + new_type_deviation * 0.15
    )
    deviation = round(min(deviation, 1.0), 3)

    return BaselineDeviation(
        deviation=deviation,
        rate_ratio=round(rate_ratio, 2),
        sev_delta=round(sev_delta, 2),
        is_escalating=is_escalating,
        new_event_types=new_types,
        baseline_event_count=len(baseline_events),
        recent_event_count=len(recent_events),
        has_sufficient_baseline=True,
    )


# ─── Helper ───────────────────────────────────────────────────────────────────


def _avg_severity(events: List[SimpleEvent]) -> float:
    if not events:
        return 0.0
    return sum(_SEV_NUM.get(e.severity, 1.0) for e in events) / len(events)


# ─── Slow-persistence detection ───────────────────────────────────────────────


@dataclass
class SlowPersistence:
    """
    Multi-window analysis for detecting low-and-slow attack patterns.

    LOW_AND_SLOW attacks evade burst-rate detection by spreading anomalous
    events over many hours or days.  This dataclass captures evidence of
    sustained, sub-threshold activity that doesn't trigger 1h-vs-24h rate
    comparisons but nonetheless represents persistent threat behaviour.

    Windows compared:
      6h  — short-medium window (recent activity)
      24h — full day window (daily baseline)
      72h — three-day window (campaign persistence)

    persistence_score (0–1):
      0.0 = no suspicious persistence detected
      1.0 = high-rate suspicious activity spread across all windows with
            increasing trend (hallmark of a multi-day campaign)
    """
    persistence_score: float        # 0–1 composite slow-persistence signal
    suspicious_6h: int              # suspicious events in last 6h
    suspicious_24h: int             # suspicious events in last 24h
    suspicious_72h: int             # suspicious events in last 72h
    trend_increasing: bool          # activity level increasing across windows?
    avg_anomaly_72h: float          # avg anomaly score of all 72h events
    distinct_hours_active: int      # how many distinct hours had at least one suspicious event
    is_persistent: bool             # True when persistence_score ≥ 0.35


def compute_slow_persistence(
    events: List[SimpleEvent],
    now: Optional[datetime] = None,
    anomaly_threshold: float = _SLOW_ANOMALY_THRESHOLD,
) -> SlowPersistence:
    """
    Detect low-and-slow attack patterns from a long event window (≥ 72h).

    Unlike burst detection (1h vs 24h rate ratio), this function measures
    *sustained* suspicious activity across multi-hour windows.  An attacker
    who sends 2 suspicious events per hour for 36 hours won't trigger burst
    thresholds (rate ratio ≈ 1.0) but will show high distinct_hours_active
    and a rising 6h/24h/72h ratio.

    Parameters
    ----------
    events:
        All available events for the entity, typically from a 72h+ window.
    now:
        Reference point for window computation. Defaults to utcnow().
    anomaly_threshold:
        Minimum anomaly_score for an event to be counted as suspicious.

    Returns
    -------
    SlowPersistence with persistence_score and window-level counts.
    """
    if not events:
        return SlowPersistence(
            persistence_score=0.0,
            suspicious_6h=0, suspicious_24h=0, suspicious_72h=0,
            trend_increasing=False, avg_anomaly_72h=0.0,
            distinct_hours_active=0, is_persistent=False,
        )

    now_ts = now or datetime.now(timezone.utc)

    def _age_hours(e: SimpleEvent) -> float:
        ts = e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc)
        return max(0.0, (now_ts - ts).total_seconds() / 3600.0)

    # Filter: only events within 72h
    within_72h = [e for e in events if _age_hours(e) <= 72.0]
    if not within_72h:
        return SlowPersistence(
            persistence_score=0.0,
            suspicious_6h=0, suspicious_24h=0, suspicious_72h=0,
            trend_increasing=False, avg_anomaly_72h=0.0,
            distinct_hours_active=0, is_persistent=False,
        )

    suspicious_all = [e for e in within_72h if e.anomaly_score >= anomaly_threshold]

    s_6h = sum(1 for e in suspicious_all if _age_hours(e) <= 6.0)
    s_24h = sum(1 for e in suspicious_all if _age_hours(e) <= 24.0)
    s_72h = len(suspicious_all)

    avg_anomaly = (
        sum(e.anomaly_score for e in within_72h) / len(within_72h)
        if within_72h else 0.0
    )

    # Distinct hours with at least one suspicious event
    active_hours: set[int] = set()
    for e in suspicious_all:
        bucket = int(_age_hours(e))
        active_hours.add(bucket)
    distinct_hours = len(active_hours)

    # Trend: compare rate in first half (72h–36h ago) vs second half (36h–now)
    older_half = [e for e in suspicious_all if 36.0 <= _age_hours(e) <= 72.0]
    newer_half = [e for e in suspicious_all if _age_hours(e) < 36.0]
    trend_increasing = len(newer_half) > len(older_half) + 1  # strictly increasing

    # Persistence score components:
    #   1. Volume across full 72h window (log-scaled, saturates at 30 events)
    volume_factor = min(math.log2(s_72h + 1) / math.log2(31), 1.0) if s_72h > 0 else 0.0

    #   2. Spread: how many distinct hours had activity (max meaningful = 36)
    spread_factor = min(distinct_hours / 36.0, 1.0)

    #   3. Trend bonus (0 or 0.2)
    trend_factor = 0.2 if trend_increasing else 0.0

    #   4. Severity of sustained events
    sev_factor = min(avg_anomaly / 0.8, 1.0)

    # Require at least 3 suspicious events in 72h for any persistence signal
    if s_72h < 3:
        persistence_score = 0.0
    else:
        persistence_score = min(
            volume_factor * 0.35
            + spread_factor * 0.35
            + trend_factor * 0.15
            + sev_factor * 0.15,
            1.0,
        )

    persistence_score = round(persistence_score, 3)

    return SlowPersistence(
        persistence_score=persistence_score,
        suspicious_6h=s_6h,
        suspicious_24h=s_24h,
        suspicious_72h=s_72h,
        trend_increasing=trend_increasing,
        avg_anomaly_72h=round(avg_anomaly, 3),
        distinct_hours_active=distinct_hours,
        is_persistent=persistence_score >= 0.35,
    )
