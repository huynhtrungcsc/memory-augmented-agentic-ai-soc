"""
Context builder — turns raw memory events into an LLM-safe textual summary.

MEMORY-AUGMENTED DESIGN
========================
This module is the primary interface between the memory store and the LLM.
Its most important job is NOT just to summarise history — it is to give the
LLM the MEMORY INTELLIGENCE needed to distinguish:

  (a) An entity generating the same suspicious-looking alerts for the 30th
      time without escalation → KNOWN BENIGN PATTERN → reduce FP likelihood

  (b) An entity showing a NEW or ESCALATING pattern not seen before
      → NOVEL THREAT → raise risk score

This distinction is impossible without memory. The LLM alone sees only the
current event. Memory provides the context.

IMPORTANT: Raw log payloads are NEVER passed to the LLM. Only the structured
summary produced here is forwarded. This module is the gatekeeper.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from app.config import get_settings
from app.models.schemas import EntityEdgeSchema, MemoryEvent
from app.services.baseline import BaselineDeviation
from app.services.history_scorer import FPPatternAnalysis, SemanticProfileData
from app.services.sequence_detector import SequenceMatch

settings = get_settings()


def _anomaly_label(avg_score: float) -> str:
    """Convert an internal numeric anomaly score to a qualitative label."""
    if avg_score >= 0.80:
        return "CRITICAL"
    if avg_score >= 0.60:
        return "HIGH"
    if avg_score >= 0.40:
        return "MODERATE"
    if avg_score >= 0.20:
        return "LOW"
    return "MINIMAL"


def build_context_summary(
    entity_id: str,
    events: List[MemoryEvent],
    sequences: Optional[List[SequenceMatch]] = None,
    baseline: Optional[BaselineDeviation] = None,
    graph_edges: Optional[List[EntityEdgeSchema]] = None,
    fp_pattern: Optional[FPPatternAnalysis] = None,
    semantic_profile: Optional[SemanticProfileData] = None,
) -> str:
    """
    Produce a multi-section context summary suitable for LLM consumption.

    Parameters
    ----------
    entity_id:   The entity being analysed.
    events:      Historical events from memory (newest first).
    sequences:   Detected attack chain matches (may be None or empty list).
    baseline:    Behavioral deviation vs. 24h baseline (may be None).
    graph_edges: Known entity relationships from the graph (may be None).
    fp_pattern:  FPPatternAnalysis from history_scorer (may be None).
                 This is the core Memory-Augmented input — tells the LLM
                 whether this entity has a known FP profile in memory.

    Returns
    -------
    A structured, multi-line text summary. No raw log payloads included.
    """
    if not events:
        return (
            f"=== ENTITY CONTEXT SUMMARY ===\n"
            f"Entity ID        : {entity_id}\n"
            "STATUS           : No historical activity found in the memory store.\n"
            "MEMORY CONTEXT   : This is the first observed event for this entity.\n"
            "                   No established FP profile exists — treat with caution.\n"
            "ASSESSMENT HINT  : Without memory context, lean toward false_positive\n"
            "                   unless the current event severity is critical.\n"
            "=== END OF CONTEXT SUMMARY ==="
        )

    now = datetime.now(tz=timezone.utc)
    window_hours = settings.context_window_hours

    cutoff = now - timedelta(hours=window_hours)
    recent = []
    for e in events:
        ts = e.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff:
            recent.append(e)
    if not recent:
        recent = events

    all_count = len(events)
    recent_count = len(recent)

    severity_dist = Counter(e.severity for e in recent)
    event_type_freq = Counter(e.event_type for e in recent)
    source_freq = Counter(e.source for e in recent)
    top_event_types = event_type_freq.most_common(5)
    avg_anomaly = sum(e.anomaly_score for e in recent) / recent_count
    anomaly_level = _anomaly_label(avg_anomaly)

    timeline_events = recent[:settings.max_context_events]
    timeline_lines = []
    for ev in reversed(timeline_events):
        ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        timeline_lines.append(
            f"  [{ts_str}] [{ev.severity.upper()}] [{ev.source}] {ev.event_type}: {ev.message}"
        )

    lines = [
        "=== ENTITY CONTEXT SUMMARY ===",
        f"Entity ID        : {entity_id}",
        f"Analysis window  : last {window_hours} hours",
        f"Total events seen: {all_count} (lifetime), {recent_count} in window",
        f"Anomaly level    : {anomaly_level}",
        f"Log sources      : {', '.join(f'{s}({n})' for s, n in source_freq.items())}",
        "",
    ]

    # ── Section 1: Severity distribution ──────────────────────────────────────
    lines += ["--- Severity distribution ---"]
    for sev in ("critical", "high", "medium", "low"):
        count = severity_dist.get(sev, 0)
        if count:
            bar = "█" * min(count, 20)
            lines.append(f"  {sev.upper():8s}: {bar} ({count})")

    lines += ["", "--- Top event types ---"]
    for etype, cnt in top_event_types:
        lines.append(f"  {etype} ({cnt}x)")

    # ── Section 2: MEMORY INTELLIGENCE — core Memory-Augmented section ────────
    lines += ["", "--- MEMORY INTELLIGENCE: KNOWN ENTITY PATTERNS ---"]
    if fp_pattern is not None:
        score = fp_pattern.fp_pattern_score
        if score >= 0.7:
            lines.append(
                "  [KNOWN FP PROFILE] This entity has a STRONG established false-positive profile in memory."
            )
            lines.append(f"  Pattern: {fp_pattern.summary}")
            lines.append(
                f"  Dominant alert type: '{fp_pattern.dominant_event_type}' "
                f"({fp_pattern.repetition_count} occurrences over {fp_pattern.pattern_age_hours:.1f}h)"
            )
            if fp_pattern.repeated_event_types:
                lines.append(
                    f"  Recurring alert types: {', '.join(fp_pattern.repeated_event_types[:5])}"
                )
            if fp_pattern.escalation_detected:
                lines.append(f"  [!] ESCALATION DETECTED: {fp_pattern.escalation_details}")
                lines.append(
                    "  NOTE: Despite FP profile, escalation means this MAY be a real attack "
                    "building on top of normal activity."
                )
                lines.append(
                    "  ASSESSMENT HINT: Treat with elevated suspicion — established FP entity "
                    "showing NEW behaviour is a significant red flag."
                )
            else:
                lines.append(
                    "  ASSESSMENT HINT: Memory strongly indicates this entity ROUTINELY generates "
                    "these alerts without confirmed incident. INCREASE false_positive_likelihood "
                    "significantly (0.7–0.9) unless the current event differs from the pattern."
                )
        elif score >= 0.4:
            lines.append(
                "  [PARTIAL FP PROFILE] Moderate evidence of a recurring pattern in memory."
            )
            lines.append(f"  Pattern: {fp_pattern.summary}")
            if fp_pattern.escalation_detected:
                lines.append(f"  [!] ESCALATION DETECTED: {fp_pattern.escalation_details}")
                lines.append(
                    "  ASSESSMENT HINT: Partial FP profile with escalation — treat as MODERATE risk. "
                    "Do not dismiss as FP without careful review of the current event."
                )
            else:
                lines.append(
                    "  ASSESSMENT HINT: Some repetition in memory but pattern not fully established. "
                    "Weight the SPECIFIC characteristics of the current event heavily."
                )
        elif score >= 0.1:
            lines.append(
                "  [WEAK FP SIGNAL] Some repetition detected but insufficient to establish a profile."
            )
            lines.append(f"  {fp_pattern.summary}")
            lines.append(
                "  ASSESSMENT HINT: Memory does not conclusively support a benign pattern. "
                "Evaluate the current event on its own merits."
            )
        else:
            lines.append(
                "  [NO ESTABLISHED PATTERN] Memory does not show a known FP profile for this entity."
            )
            if fp_pattern.escalation_detected:
                lines.append(f"  [!] ESCALATION: {fp_pattern.escalation_details}")
            lines.append(
                "  ASSESSMENT HINT: No known benign pattern in memory. "
                "Novel or escalating activity — apply standard threat assessment."
            )
    else:
        lines.append("  Memory intelligence not available for this analysis.")
        lines.append(
            "  ASSESSMENT HINT: Without FP pattern context, rely on event characteristics, "
            "chain detection, and baseline deviation."
        )

    # ── Section 2b: SEMANTIC MEMORY — Learned behavioural priors ─────────────
    lines += ["", "--- SEMANTIC MEMORY: LEARNED ENTITY PROFILE ---"]
    if semantic_profile is not None:
        if semantic_profile.total_events_seen == 0:
            lines.append(
                "  [NEW ENTITY] No semantic profile yet — this is the agent's first encounter with this entity."
            )
            lines.append(
                "  ASSESSMENT HINT: No learned priors available. Weight episodic and current-event signals heavily."
            )
        else:
            trend_marker = {
                "stable": "STABLE ✓",
                "escalating": "ESCALATING ⚠",
                "deescalating": "DE-ESCALATING ↓",
            }.get(semantic_profile.risk_trend, semantic_profile.risk_trend.upper())
            lines.append(f"  Risk trend (learned): {trend_marker}")
            lines.append(f"  FP confidence (learned): {semantic_profile.fp_confidence:.2f} (0=unknown, 1=strongly FP)")
            lines.append(f"  Total events in lifetime memory: {semantic_profile.total_events_seen}")
            lines.append(f"  Avg anomaly (lifetime): {semantic_profile.avg_anomaly_score:.3f}")
            if semantic_profile.dominant_event_types:
                lines.append(
                    f"  Dominant event types (normal for this entity): "
                    f"{', '.join(semantic_profile.dominant_event_types[:5])}"
                )
            if semantic_profile.known_good_hours:
                hours_str = ", ".join(
                    f"{h:02d}:00" for h in semantic_profile.known_good_hours[:8]
                )
                lines.append(f"  Known-good hours (activity is expected): {hours_str}")
            if semantic_profile.peer_entities:
                lines.append(
                    f"  Known peer entities: {', '.join(semantic_profile.peer_entities[:5])}"
                )
            # Semantic memory assessment hints
            if semantic_profile.risk_trend == "escalating":
                lines.append(
                    "  ASSESSMENT HINT [SEMANTIC]: Despite any prior FP profile, the "
                    "accumulated profile shows ESCALATING risk — this entity is behaving outside its "
                    "historical norm. DO NOT suppress this alert as FP."
                )
            elif semantic_profile.fp_confidence >= 0.7:
                lines.append(
                    "  ASSESSMENT HINT [SEMANTIC]: Semantic memory shows HIGH confidence this entity "
                    "is a benign FP source. If the current event matches its normal profile, "
                    "increase false_positive_likelihood to 0.7+."
                )
            elif semantic_profile.fp_confidence >= 0.4:
                lines.append(
                    "  ASSESSMENT HINT [SEMANTIC]: Moderate FP confidence in semantic memory. "
                    "Check whether the current event type and timing match the learned profile."
                )
            else:
                lines.append(
                    "  ASSESSMENT HINT [SEMANTIC]: Low FP confidence — entity not established "
                    "as benign in long-term memory. Apply standard threat assessment."
                )
    else:
        lines.append("  Semantic profile not available (first analysis or memory not initialised).")

    # ── Section 3: Attack chain detection ─────────────────────────────────────
    lines += ["", "--- ATTACK CHAIN DETECTION ---"]
    if sequences:
        lines.append(
            f"  [!] {len(sequences)} KNOWN ATTACK CHAIN(S) DETECTED — "
            "this entity's activity matches a multi-stage attack pattern."
        )
        for m in sequences:
            pct = int(m.completion_ratio * 100)
            lines.append(f"  Chain : {m.chain_name} ({pct}% complete, severity={m.chain_severity})")
            lines.append(f"  Phases confirmed : {' → '.join(m.phases_detected)}")
            remaining = [
                p for p in m.phase_timeline[len(m.phases_detected):]
                if p not in m.phases_detected
            ]
            if remaining:
                lines.append(f"  Phases not yet seen: {' → '.join(remaining)}")
        lines.append(
            "  ASSESSMENT HINT: Multi-stage attack chains have much higher true-positive"
            " rates than isolated events. Raise risk score accordingly."
        )
        if fp_pattern and fp_pattern.fp_pattern_score >= 0.5:
            lines.append(
                "  NOTE: Attack chain detected on an entity with a known FP profile. "
                "Verify that the CHAIN PHASES represent genuinely different attack stages, "
                "not the same repeated event type matching multiple pattern rules."
            )
    else:
        lines.append("  No known attack chain pattern detected in the event timeline.")
        lines.append(
            "  ASSESSMENT HINT: No chain evidence — consider whether isolated events"
            " could be legitimate (e.g., security scanner, IT admin activity)."
        )

    # ── Section 4: Behavioral baseline ────────────────────────────────────────
    lines += ["", "--- BEHAVIORAL BASELINE COMPARISON ---"]
    if baseline and baseline.has_sufficient_baseline:
        deviation_label = (
            "EXTREME" if baseline.deviation > 0.7 else
            "HIGH" if baseline.deviation > 0.4 else
            "MODERATE" if baseline.deviation > 0.2 else
            "NORMAL"
        )
        lines.append(f"  Deviation level  : {deviation_label} ({baseline.deviation:.2f})")
        lines.append(
            f"  Activity rate    : {baseline.rate_ratio:.1f}× above 24h baseline "
            f"({baseline.recent_event_count} events in last 1h vs "
            f"{baseline.baseline_event_count} in last 24h)"
        )
        if baseline.is_escalating:
            lines.append(
                f"  Severity trend   : ESCALATING (avg severity rose by {baseline.sev_delta:+.1f} points)"
            )
        else:
            lines.append("  Severity trend   : Stable")
        if baseline.new_event_types:
            lines.append(f"  New event types  : {', '.join(baseline.new_event_types)}")
            lines.append(
                "  ASSESSMENT HINT: New event types not seen in baseline are a strong"
                " anomaly indicator — attacker may have shifted TTP."
            )
        if baseline.deviation > 0.4:
            lines.append(
                "  ASSESSMENT HINT: Significant behavioral deviation from this entity's"
                " own baseline — this is NOT normal activity for this entity."
            )
    elif baseline and not baseline.has_sufficient_baseline:
        lines.append(
            f"  Insufficient baseline history (only {baseline.baseline_event_count} events)."
        )
        lines.append(
            "  ASSESSMENT HINT: Cannot establish if this is normal for this entity."
            " Weight other signals more heavily."
        )
    else:
        lines.append("  Baseline comparison not available.")

    # ── Section 5: Entity relationship graph ──────────────────────────────────
    lines += ["", "--- ENTITY RELATIONSHIPS ---"]
    if graph_edges:
        lines.append(f"  {len(graph_edges)} known connection(s) for this entity:")
        for edge in graph_edges[:10]:
            direction = "→" if edge.direction == "outbound" else "←"
            lines.append(
                f"  {direction} {edge.related_entity} "
                f"[{edge.edge_type}, {edge.event_count} event(s), last: {edge.last_seen.strftime('%H:%M:%S')}]"
            )
        if len(graph_edges) > 10:
            lines.append(f"  ... and {len(graph_edges) - 10} more connections.")
        lines.append(
            "  ASSESSMENT HINT: Multiple targeted connections may indicate"
            " lateral movement or distributed attack campaign."
        )
    else:
        lines.append("  No entity relationships recorded yet.")

    # ── Section 6: Chronological event timeline ───────────────────────────────
    lines += [
        "",
        f"--- Event timeline (last {len(timeline_events)} events, chronological) ---",
    ]
    lines.extend(timeline_lines)
    lines += ["", "=== END OF CONTEXT SUMMARY ==="]

    return "\n".join(lines)
