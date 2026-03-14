"""
POST /analyze-alert

Retrieves the entity's historical context from memory, builds a sanitised
summary (with attack chain detection, behavioral baseline, and entity graph),
sends it to the LLM for reasoning, computes the hybrid composite risk score,
and returns a full structured analysis.

Implementation notes:
  - UTC timestamp normalisation throughout.
  - Unified AnalysisContext assembled once; all subsystems share the same events.
  - Minimum evidence gate before BLOCK; review_required decision state; cooldown.
  - LLM retry with exponential back-off; falls back to heuristic mock on failure.
  - Calibrated score + confidence returned in score_breakdown.
  - Chain transition validation (sequence_detector.py).
  - LLM context always includes chain-triggering events.
  - Decision hysteresis — blocked entities don't drop in one quiet hour.
  - trace_id per request; structured pipeline logging; optional debug_info.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.memory.entity_graph import EntityGraphStore
from app.memory.sqlite_store import EntityDecisionRecord, EntitySemanticProfile
from app.memory.store import MemoryStore
from app.models.analysis_context import AnalysisContext, TimeWindow
from app.models.schemas import (
    AlertAnalysisRequest,
    AlertAnalysisResponse,
    BaselineDeviationSchema,
    Decision,
    DecideResponse,
    EntityEdgeSchema,
    MemoryAugmentationReport,
    MemoryContribution,
    MemoryEvent,
    SemanticProfileSchema,
    SequenceMatchSchema,
    Severity,
)
from app.services.baseline import BaselineDeviation, SlowPersistence, compute_baseline_deviation, compute_slow_persistence
from app.services.category_calibration import get_category_factor
from app.services.context_builder import build_context_summary
from app.services.decision_engine import apply_policy
from app.services.history_scorer import (
    FPPatternAnalysis,
    SemanticProfileData,
    SimpleEvent,
    compute_fp_pattern,
    compute_semantic_profile_data,
    derive_dominant_severity,
)
from app.services.llm_client import analyse_context
from app.services.scoring_engine import compute_hybrid_score
from app.services.sequence_detector import SequenceMatch, classify_phase, detect_sequences
from app.services.trust_store import TrustContext, evaluate_trust

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/analyze-alert", tags=["analysis"])

_IP_CHARS = set("0123456789.")

# Decision rank for hysteresis comparison — higher = more severe
_DECISION_RANK: dict[str, int] = {
    "block": 3,
    "review_required": 2,
    "alert_analyst": 1,
    "log_only": 0,
}


def _looks_like_ip(entity_id: str) -> bool:
    return all(c in _IP_CHARS for c in entity_id) and entity_id.count(".") == 3


def _dedup_events(events_lists) -> list:
    """
    Merge multiple event lists, removing duplicates.
    Deduplication key: (timestamp_isoformat, event_type, source).
    Returns events sorted by timestamp descending.
    """
    seen: set = set()
    merged = []
    for events in events_lists:
        for e in events:
            key = (e.timestamp.isoformat(), e.event_type, e.source)
            if key not in seen:
                seen.add(key)
                merged.append(e)
    merged.sort(key=lambda e: e.timestamp, reverse=True)
    return merged


def _to_utc(ts: datetime) -> datetime:
    """Normalise a potentially naive datetime to UTC-aware."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _to_simple(events) -> List[SimpleEvent]:
    """Convert MemoryEvent / ORM rows to SimpleEvent."""
    return [
        SimpleEvent(
            event_type=e.event_type,
            severity=e.severity,
            anomaly_score=e.anomaly_score,
            timestamp=_to_utc(e.timestamp),
            message=getattr(e, "message", "") or "",
        )
        for e in events
    ]


def _count_strong_signals(
    anomaly_score: float,
    history_score: float,
    chains: List[SequenceMatch],
    baseline: Optional[BaselineDeviation],
) -> int:
    """
    Count how many strong, independent signals fired.
    The minimum evidence gate requires at least 2 before BLOCK.
    """
    count = 0
    if chains:
        count += 1
    if baseline and baseline.has_sufficient_baseline and baseline.deviation > 0.4:
        count += 1
    if anomaly_score > 0.8:
        count += 1
    if history_score > 0.7:
        count += 1
    return count


def _build_llm_timeline(
    primary_timeline: List[MemoryEvent],
    all_events: List[MemoryEvent],
    simple_all: List[SimpleEvent],
    sequences: List[SequenceMatch],
    max_events: int,
) -> List[MemoryEvent]:
    """
    Build a merged LLM event timeline that always includes the events that
    triggered chain detection, even if they fall outside the standard
    top-N recent-timeline window.
    """
    if not sequences:
        return primary_timeline

    chain_phases: set = set()
    for seq in sequences:
        chain_phases.update(seq.phases_detected)

    chain_anchor_events: List[MemoryEvent] = []
    for raw_ev, simple_ev in zip(all_events, simple_all):
        phase = classify_phase(simple_ev)
        if phase in chain_phases:
            chain_anchor_events.append(raw_ev)

    if not chain_anchor_events:
        return primary_timeline

    existing_keys = {(e.timestamp.isoformat(), e.event_type) for e in primary_timeline}
    extra = [e for e in chain_anchor_events if (e.timestamp.isoformat(), e.event_type) not in existing_keys]

    if not extra:
        return primary_timeline

    merged = list(primary_timeline) + extra
    merged.sort(key=lambda e: e.timestamp, reverse=True)
    return merged[:max_events + 5]


def _apply_hysteresis(
    new_decision: DecideResponse,
    prior_record: Optional[EntityDecisionRecord],
    composite_score: int,
    now: datetime,
) -> DecideResponse:
    """
    W7+H3 — Enforce decision hysteresis + block cooldown.

    Block cooldown (H3): if an entity is within its block_cooldown_until window,
    the BLOCK decision is maintained unconditionally regardless of new score.

    Downgrade deferral (W7): downgrades are deferred until hysteresis_hours
    have elapsed at the lower risk level, unless score drops below floor.
    """
    s = get_settings()

    if prior_record is None:
        return new_decision

    # Block cooldown — if we're inside the cooldown window, maintain block
    if prior_record.cooldown_until is not None:
        cooldown_ts = prior_record.cooldown_until
        if cooldown_ts.tzinfo is None:
            cooldown_ts = cooldown_ts.replace(tzinfo=timezone.utc)
        if now < cooldown_ts:
            logger.info(
                "H3 cooldown: block maintained for entity (cooldown expires %s)",
                cooldown_ts.isoformat(),
            )
            return DecideResponse(
                risk_score=composite_score,
                decision=Decision.block,
                rationale=(
                    f"[COOLDOWN] Block decision maintained — cooldown expires "
                    f"{cooldown_ts.isoformat()}. Score={composite_score}."
                ),
                entity_id=new_decision.entity_id,
            )

    prior_rank = _DECISION_RANK.get(prior_record.last_decision, 0)
    new_rank = _DECISION_RANK.get(new_decision.decision.value, 0)

    if new_rank >= prior_rank:
        return new_decision  # same level or upgrade → apply immediately

    # Downgrade: check score floor and elapsed time
    prior_decided_at = prior_record.last_decided_at
    if prior_decided_at.tzinfo is None:
        prior_decided_at = prior_decided_at.replace(tzinfo=timezone.utc)

    hours_elapsed = (now - prior_decided_at).total_seconds() / 3600.0

    if composite_score <= s.hysteresis_score_floor:
        logger.info(
            "W7 hysteresis: immediate downgrade (score %d ≤ floor %d)",
            composite_score, s.hysteresis_score_floor,
        )
        return new_decision

    if hours_elapsed < s.hysteresis_hours:
        logger.info(
            "W7 hysteresis: downgrade deferred — %.1fh elapsed < %.1fh required",
            hours_elapsed, s.hysteresis_hours,
        )
        return DecideResponse(
            risk_score=composite_score,
            decision=Decision(prior_record.last_decision),
            rationale=(
                f"[HYSTERESIS] Decision maintained at {prior_record.last_decision.upper()}. "
                f"Score={composite_score} — entity must sustain lower risk for "
                f"{s.hysteresis_hours:.0f}h before downgrade. "
                f"Elapsed: {hours_elapsed:.1f}h."
            ),
            entity_id=new_decision.entity_id,
        )

    return new_decision


@router.post("", response_model=AlertAnalysisResponse)
async def analyze_alert(
    request: AlertAnalysisRequest,
    db: AsyncSession = Depends(get_db),
) -> AlertAnalysisResponse:
    """
    Analyse an entity's recent behaviour using memory-augmented LLM reasoning
    and a hybrid composite risk scoring engine.

    Analysis pipeline (all subsystems share a single AnalysisContext):
    1. Fetch entity context (history_score, distributions) — last 24h.
    2. Fetch extended history (last 72h, uncapped) for sequence + baseline + slow-persistence.
    3. Cross-entity merge (src_ip, username, hostname lookups).
    4. Build unified AnalysisContext.
    5. Run attack chain detection (MITRE ATT&CK phase matching, 24h window).
    6. Compute behavioral baseline deviation vs. entity's own 24h baseline.
    7. Count strong signals for minimum evidence gate.
    8. Fetch entity relationship graph edges.
    9. Build enriched context summary (includes chain-triggering events).
    10. Send to LLM for reasoning (retry with fallback to heuristic mock).
    11. Compute hybrid score: base (4 signals) + boosts + calibration.
    12. Apply decision policy with evidence gate and hysteresis.
    13. Persist the new decision with cooldown.
    """
    s = get_settings()
    now = datetime.now(tz=timezone.utc)

    # Propagate caller-supplied trace_id or generate a new one
    trace_id = request.trace_id or str(uuid.uuid4())
    debug_mode = request.debug_mode or s.debug_mode

    log_ctx = f"trace={trace_id} entity={request.entity_id}"
    logger.info("Analysis started | %s", log_ctx)

    store = MemoryStore(db)

    # ── 1. Entity context (last 24h, capped for LLM context window) ───────────
    since_24h = now - timedelta(hours=s.context_window_hours)
    entity_ctx = await store.get_entity_context(
        entity_id=request.entity_id,
        since=since_24h,
        limit=s.max_context_events,
    )

    # ── 1b. SEMANTIC MEMORY — load prior learned profile for this entity ────────
    # Semantic memory holds what the agent has LEARNED across all past analyses:
    # known-good hours, dominant event types, FP confidence, risk trend.
    # A None result means this is the first analysis for this entity.
    prior_semantic: Optional[EntitySemanticProfile] = await store.get_semantic_profile(
        request.entity_id
    )
    if prior_semantic is not None:
        prior_sem_data = SemanticProfileData(
            known_good_hours=json.loads(prior_semantic.known_good_hours_json or "[]"),
            dominant_event_types=json.loads(prior_semantic.dominant_event_types_json or "[]"),
            peer_entities=json.loads(prior_semantic.peer_entities_json or "[]"),
            avg_anomaly_score=prior_semantic.avg_anomaly_score or 0.0,
            fp_confidence=prior_semantic.fp_confidence or 0.0,
            risk_trend=prior_semantic.risk_trend or "stable",
            total_events_seen=prior_semantic.total_events_seen or 0,
        )
        logger.info(
            "Semantic memory loaded: fp_conf=%.2f trend=%s events_seen=%d | %s",
            prior_sem_data.fp_confidence, prior_sem_data.risk_trend,
            prior_sem_data.total_events_seen, log_ctx,
        )
    else:
        prior_sem_data = None
        logger.info("Semantic memory: new entity — no prior profile | %s", log_ctx)

    # ── 2. Extended events for sequence + baseline (uncapped, last 72h) ────────
    since_72h = now - timedelta(hours=72)
    since_48h = now - timedelta(hours=48)  # kept for backward compat
    all_events_primary = await store.get_events(
        entity_id=request.entity_id,
        since=since_72h,
        limit=300,
    )

    if entity_ctx.event_count == 0:
        logger.warning("No events in memory | %s", log_ctx)

    # ── 3. Cross-entity event merge (W1 fix) ──────────────────────────────────
    cross_events: list = []
    if _looks_like_ip(request.entity_id):
        cross_events = await store.get_events_by_src_ip(
            src_ip=request.entity_id,
            since=since_48h,
            limit=200,
        )
    else:
        uname_events = await store.get_events_by_username(
            username=request.entity_id, since=since_48h, limit=100,
        )
        hname_events = await store.get_events_by_hostname(
            hostname=request.entity_id, since=since_48h, limit=100,
        )
        cross_events = uname_events + hname_events

    all_events = _dedup_events([all_events_primary, cross_events])

    if len(all_events) > len(all_events_primary):
        logger.info(
            "Cross-entity merge: primary=%d merged=%d (+%d) | %s",
            len(all_events_primary), len(all_events),
            len(all_events) - len(all_events_primary), log_ctx,
        )

    # ── 4. Build unified AnalysisContext (H2) ─────────────────────────────────
    ctx = AnalysisContext(
        trace_id=trace_id,
        entity_id=request.entity_id,
        time_window=TimeWindow.build(start=since_72h, end=now),
        events=all_events,
    )

    if debug_mode:
        ctx.add_debug("event_count", len(all_events))
        ctx.add_debug("cross_entity_added", len(all_events) - len(all_events_primary))

    # ── 5. Attack chain detection (all subsystems use ctx.events) ─────────────
    simple_all = _to_simple(ctx.events)
    sequences: List[SequenceMatch] = detect_sequences(
        simple_all,
        max_chain_window_hours=24.0,
    )
    ctx.chains = sequences

    logger.info(
        "Chain detection: %d chain(s) detected | %s",
        len(sequences), log_ctx,
    )
    if debug_mode:
        ctx.add_debug("chains_detected", [m.chain_name for m in sequences])

    # ── 6. Behavioral baseline deviation ──────────────────────────────────────
    one_hour_ago = now - timedelta(hours=1)
    twenty_five_hours_ago = now - timedelta(hours=25)

    def _is_in_window(ts: datetime, lo: datetime, hi: datetime) -> bool:
        ts_utc = _to_utc(ts)
        return lo <= ts_utc < hi

    simple_recent_1h = [e for e in simple_all if _is_in_window(e.timestamp, one_hour_ago, now)]
    simple_baseline_24h = [e for e in simple_all if _is_in_window(e.timestamp, twenty_five_hours_ago, one_hour_ago)]

    baseline_dev: BaselineDeviation = compute_baseline_deviation(
        recent_events=simple_recent_1h,
        baseline_events=simple_baseline_24h,
    )
    ctx.baseline_stats = baseline_dev

    logger.info(
        "Baseline: deviation=%.2f escalating=%s sufficient=%s | %s",
        baseline_dev.deviation, baseline_dev.is_escalating,
        baseline_dev.has_sufficient_baseline, log_ctx,
    )
    if debug_mode:
        ctx.add_debug("baseline_deviation", baseline_dev.deviation)
        ctx.add_debug("baseline_escalating", baseline_dev.is_escalating)

    # ── 6b. Slow-persistence detection (low-and-slow attacks) ──────────────────
    slow_persist: SlowPersistence = compute_slow_persistence(simple_all, now=now)
    ctx.add_debug("slow_persistence_score", slow_persist.persistence_score)
    ctx.add_debug("slow_persistence_is_persistent", slow_persist.is_persistent)
    ctx.add_debug("slow_suspicious_72h", slow_persist.suspicious_72h)
    logger.info(
        "SlowPersistence: score=%.2f persistent=%s s72h=%d spread=%dh | %s",
        slow_persist.persistence_score, slow_persist.is_persistent,
        slow_persist.suspicious_72h, slow_persist.distinct_hours_active, log_ctx,
    )

    # ── 6b2. Memory-Augmented FP pattern analysis ──────────────────────────────
    # Core memory-augmented mechanism: analyse entity's history for a stable,
    # non-escalating FP pattern. When detected, the history contribution to the
    # composite score will be discounted — making memory REDUCE risk for known-benign
    # entities rather than accumulate it.
    fp_pattern: FPPatternAnalysis = compute_fp_pattern(simple_all, now=now)
    ctx.add_debug("fp_pattern_score", fp_pattern.fp_pattern_score)
    ctx.add_debug("fp_pattern_summary", fp_pattern.summary)
    ctx.add_debug("fp_escalation_detected", fp_pattern.escalation_detected)
    logger.info(
        "FP pattern: score=%.3f escalation=%s repetitions=%d | %s",
        fp_pattern.fp_pattern_score, fp_pattern.escalation_detected,
        fp_pattern.repetition_count, log_ctx,
    )

    # ── 6c. Trust evaluation + category calibration ────────────────────────────
    # Aggregate trust across recent events (use the most recent trigger event)
    trigger_event: Optional[MemoryEvent] = (
        entity_ctx.recent_timeline[0] if entity_ctx.recent_timeline else None
    )
    trust_ctx: TrustContext = evaluate_trust(
        event_type=trigger_event.event_type if trigger_event else "",
        src_ip=trigger_event.src_ip if trigger_event else None,
        username=trigger_event.username if hasattr(trigger_event, "username") else None,
        hostname=trigger_event.hostname if hasattr(trigger_event, "hostname") else None,
        message=trigger_event.message if trigger_event else "",
    )
    calib_result = get_category_factor(
        event_type=trigger_event.event_type if trigger_event else "",
        message=trigger_event.message if trigger_event else "",
    )
    ctx.add_debug("trust_discount", trust_ctx.trust_discount)
    ctx.add_debug("trust_labels", trust_ctx.trust_labels)
    ctx.add_debug("category_factor", calib_result.factor)
    ctx.add_debug("category_label", calib_result.category_label)
    logger.info(
        "Trust: discount=%.2f labels=%s | Category: %s factor=%.2f | %s",
        trust_ctx.trust_discount, trust_ctx.trust_labels,
        calib_result.category_label, calib_result.factor, log_ctx,
    )

    # ── 7. Count strong signals for minimum evidence gate (H3) ────────────────
    avg_anomaly = entity_ctx.avg_anomaly_score if entity_ctx.event_count > 0 else 0.0
    evidence_count = _count_strong_signals(
        anomaly_score=avg_anomaly,
        history_score=entity_ctx.history_score,
        chains=sequences,
        baseline=baseline_dev,
    )
    ctx.evidence_count = evidence_count

    logger.info(
        "Evidence signals: %d strong signal(s) (min for block=%d) | %s",
        evidence_count, s.min_signals_for_block, log_ctx,
    )
    if debug_mode:
        ctx.add_debug("evidence_count", evidence_count)
        ctx.add_debug("min_signals_for_block", s.min_signals_for_block)

    # ── 8. Entity relationship graph ───────────────────────────────────────────
    graph_store = EntityGraphStore(db)
    edge_records = await graph_store.get_entity_edges(request.entity_id, limit=20)

    graph_edges = [
        EntityEdgeSchema(
            related_entity=e.dst_entity if e.src_entity == request.entity_id else e.src_entity,
            direction="outbound" if e.src_entity == request.entity_id else "inbound",
            edge_type=e.edge_type,
            event_count=e.event_count,
            first_seen=e.first_seen,
            last_seen=e.last_seen,
        )
        for e in edge_records
    ]

    # ── 9. Build enriched LLM context summary (W6 fix) ─────────────────────────
    llm_timeline = _build_llm_timeline(
        primary_timeline=entity_ctx.recent_timeline,
        all_events=ctx.events,
        simple_all=simple_all,
        sequences=sequences,
        max_events=s.max_context_events,
    )

    context_summary = build_context_summary(
        entity_id=request.entity_id,
        events=llm_timeline,
        sequences=sequences,
        baseline=baseline_dev,
        graph_edges=graph_edges,
        fp_pattern=fp_pattern,
        semantic_profile=prior_sem_data,
    )

    # ── 10. LLM reasoning (with retry; falls back to heuristic mock on failure) ──
    llm_result = await analyse_context(context_summary)

    logger.info(
        "LLM: class=%s risk=%d fp=%.2f mock=%s | %s",
        llm_result.attack_classification, llm_result.risk_score,
        llm_result.false_positive_likelihood, llm_result.mock_mode, log_ctx,
    )
    if debug_mode:
        ctx.add_debug("llm_risk_score", llm_result.risk_score)
        ctx.add_debug("llm_classification", str(llm_result.attack_classification))
        ctx.add_debug("llm_mock_mode", llm_result.mock_mode)

    # ── 11. Trigger severity ───────────────────────────────────────────────────
    if request.trigger_severity:
        trigger_severity = request.trigger_severity
    elif entity_ctx.severity_distribution:
        dominant = derive_dominant_severity(entity_ctx.severity_distribution)
        trigger_severity = Severity(dominant)
    else:
        trigger_severity = Severity.medium

    # ── 12. Hybrid composite scoring (confidence + calibration) ──────────────
    # Derive current-event context for semantic memory matching
    _trigger_event_type: Optional[str] = (
        entity_ctx.recent_timeline[0].event_type
        if entity_ctx.recent_timeline else None
    )
    _current_hour: int = now.hour

    score_breakdown = compute_hybrid_score(
        anomaly_score=avg_anomaly,
        llm_risk_score=llm_result.risk_score,
        history_score=entity_ctx.history_score,
        severity=trigger_severity,
        sequence_matches=sequences,
        baseline_deviation=baseline_dev,
        event_count=entity_ctx.event_count,
        slow_persistence=slow_persist,
        trust_discount=trust_ctx.trust_discount,
        trust_labels=trust_ctx.trust_labels,
        category_factor=calib_result.factor,
        category_label=calib_result.category_label,
        fp_likelihood=llm_result.false_positive_likelihood,
        fp_pattern=fp_pattern,
        semantic_profile=prior_sem_data,
        current_event_type=_trigger_event_type,
        current_hour=_current_hour,
    )

    logger.info(
        "Scoring: composite=%d calibrated=%d confidence=%.2f agreement=%.2f | %s",
        score_breakdown.composite_score, score_breakdown.calibrated_score,
        score_breakdown.confidence_score, score_breakdown.signal_agreement, log_ctx,
    )
    if debug_mode:
        ctx.add_debug("composite_score", score_breakdown.composite_score)
        ctx.add_debug("calibrated_score", score_breakdown.calibrated_score)
        ctx.add_debug("confidence_score", score_breakdown.confidence_score)
        ctx.add_debug("signal_agreement", score_breakdown.signal_agreement)

    # ── 13. Decision policy with evidence gate (H3) ────────────────────────────
    # Use calibrated_score for the decision — this prevents overconfident blocking
    # when evidence is sparse or signals are contradictory.
    raw_decision = apply_policy(
        risk_score=score_breakdown.calibrated_score,
        entity_id=request.entity_id,
        evidence_count=evidence_count,
        contradictory_flagged=score_breakdown.contradictory_flagged,
    )

    # Apply hysteresis + cooldown
    prior_record = await store.get_decision_record(request.entity_id)
    decide_result = _apply_hysteresis(
        new_decision=raw_decision,
        prior_record=prior_record,
        composite_score=score_breakdown.calibrated_score,
        now=now,
    )

    # Set block cooldown if we're blocking
    cooldown_until = None
    if decide_result.decision == Decision.block:
        cooldown_until = now + timedelta(hours=s.block_cooldown_hours)

    # Persist the effective decision for future hysteresis checks
    await store.upsert_decision_record(
        entity_id=request.entity_id,
        decision=decide_result.decision.value,
        score=score_breakdown.calibrated_score,
        now=now,
        cooldown_until=cooldown_until,
    )

    logger.info(
        "Decision: %s (raw=%s) cooldown=%s | %s",
        decide_result.decision, raw_decision.decision,
        cooldown_until.isoformat() if cooldown_until else "none", log_ctx,
    )
    if debug_mode:
        ctx.add_debug("raw_decision", raw_decision.decision.value)
        ctx.add_debug("final_decision", decide_result.decision.value)
        ctx.add_debug("cooldown_until", cooldown_until.isoformat() if cooldown_until else None)

    # ── 14. SEMANTIC MEMORY UPDATE — learn from this analysis ─────────────────
    # Extract peer entity IDs from graph edges for the semantic profile
    _peer_ids = [e.related_entity for e in graph_edges] if graph_edges else []

    # Compute updated semantic profile data from the full 72h event set
    new_sem_data: SemanticProfileData = compute_semantic_profile_data(
        events=simple_all,
        graph_peer_ids=_peer_ids,
        fp_pattern=fp_pattern,
        now=now,
    )

    # If a prior profile exists, blend fp_confidence to accumulate knowledge
    # progressively rather than overwriting: each analysis nudges the confidence.
    if prior_sem_data is not None and prior_sem_data.total_events_seen > 0:
        blended_confidence = round(
            prior_sem_data.fp_confidence * 0.6 + new_sem_data.fp_confidence * 0.4, 3
        )
        new_sem_data = SemanticProfileData(
            known_good_hours=new_sem_data.known_good_hours,
            dominant_event_types=new_sem_data.dominant_event_types,
            peer_entities=new_sem_data.peer_entities,
            avg_anomaly_score=new_sem_data.avg_anomaly_score,
            fp_confidence=blended_confidence,
            risk_trend=new_sem_data.risk_trend,
            total_events_seen=new_sem_data.total_events_seen,
        )

    await store.upsert_semantic_profile(
        entity_id=request.entity_id,
        known_good_hours=new_sem_data.known_good_hours,
        dominant_event_types=new_sem_data.dominant_event_types,
        peer_entities=new_sem_data.peer_entities,
        avg_anomaly_score=new_sem_data.avg_anomaly_score,
        fp_confidence=new_sem_data.fp_confidence,
        risk_trend=new_sem_data.risk_trend,
        total_events_seen=new_sem_data.total_events_seen,
        now=now,
    )
    logger.info(
        "Semantic memory updated: fp_conf=%.2f trend=%s events=%d | %s",
        new_sem_data.fp_confidence, new_sem_data.risk_trend,
        new_sem_data.total_events_seen, log_ctx,
    )

    # Build the MemoryAugmentationReport — how each memory type contributed
    _ep_active = entity_ctx.event_count > 0
    _sem_active = prior_sem_data is not None
    _proc_active = prior_record is not None
    _work_active = True  # working memory is always active during analysis

    _ep_effect = "neutral"
    _ep_mag = 0.0
    if _ep_active and score_breakdown.fp_pattern_score > 0.2:
        _ep_effect = "discounted"
        _ep_mag = round(score_breakdown.fp_pattern_score * s.fp_pattern_discount_weight, 3)

    _sem_effect = "neutral"
    _sem_mag = round(score_breakdown.semantic_memory_discount, 3)
    if _sem_mag > 0.0:
        _sem_effect = "discounted"

    _proc_effect = "not_applied"
    _proc_mag = 0.0
    if _proc_active:
        _proc_effect = "neutral"
        if decide_result.decision != raw_decision.decision:
            _proc_effect = "boosted" if _DECISION_RANK.get(decide_result.decision.value, 0) > _DECISION_RANK.get(raw_decision.decision.value, 0) else "discounted"
            _proc_mag = 0.5

    _richness_score = sum([_ep_active, _sem_active, _proc_active])
    _richness = (
        "rich" if _richness_score >= 3 and entity_ctx.event_count >= 10
        else "moderate" if _richness_score >= 2
        else "sparse" if _richness_score >= 1
        else "none"
    )

    _total_discount = round(_ep_mag + _sem_mag, 3)
    _contributions = [
        MemoryContribution(
            memory_type="episodic",
            active=_ep_active,
            signal=(
                f"{entity_ctx.event_count} events in 72h window; "
                f"FP pattern score={score_breakdown.fp_pattern_score:.2f}; "
                f"{score_breakdown.fp_pattern_summary}"
            ) if _ep_active else "No historical events found.",
            score_effect=_ep_effect,
            magnitude=_ep_mag,
        ),
        MemoryContribution(
            memory_type="semantic",
            active=_sem_active,
            signal=(
                f"Learned profile: fp_conf={prior_sem_data.fp_confidence:.2f}, "
                f"trend={prior_sem_data.risk_trend}, "
                f"lifetime_events={prior_sem_data.total_events_seen}"
            ) if _sem_active else "No prior semantic profile — first analysis for this entity.",
            score_effect=_sem_effect,
            magnitude=_sem_mag,
        ),
        MemoryContribution(
            memory_type="procedural",
            active=_proc_active,
            signal=(
                f"Prior decision={prior_record.last_decision} "
                f"at score={prior_record.last_score} "
                f"(hysteresis {'applied' if decide_result.decision != raw_decision.decision else 'not triggered'})"
            ) if _proc_active else "No prior decision record — first analysis.",
            score_effect=_proc_effect,
            magnitude=_proc_mag,
        ),
        MemoryContribution(
            memory_type="working",
            active=_work_active,
            signal=(
                f"Active context: {len(llm_timeline)} events in LLM window; "
                f"context_summary_length={len(context_summary)} chars; "
                f"LLM risk={llm_result.risk_score}/100"
            ),
            score_effect="neutral",
            magnitude=0.0,
        ),
    ]

    _dominant_type = max(
        [c for c in _contributions if c.active],
        key=lambda c: c.magnitude,
        default=_contributions[-1],  # working memory if all are 0
    ).memory_type

    mem_aug_report = MemoryAugmentationReport(
        contributions=_contributions,
        total_memory_discount=min(1.0, _total_discount),
        dominant_memory_type=_dominant_type,
        memory_richness=_richness,
    )

    # Build SemanticProfileSchema for the response (updated profile)
    sem_profile_schema = SemanticProfileSchema(
        entity_id=request.entity_id,
        known_good_hours=new_sem_data.known_good_hours,
        dominant_event_types=new_sem_data.dominant_event_types,
        peer_entities=new_sem_data.peer_entities,
        avg_anomaly_score=new_sem_data.avg_anomaly_score,
        fp_confidence=new_sem_data.fp_confidence,
        risk_trend=new_sem_data.risk_trend,
        total_events_seen=new_sem_data.total_events_seen,
        last_updated=now,
        is_new_entity=(prior_sem_data is None),
    )

    # ── Serialise to Pydantic schemas ─────────────────────────────────────────
    seq_schemas = [
        SequenceMatchSchema(
            chain_name=m.chain_name,
            chain_severity=m.chain_severity,
            phases_detected=m.phases_detected,
            phases_total=m.phases_total,
            completion_ratio=m.completion_ratio,
            sequence_score=m.sequence_score,
            phase_timeline=m.phase_timeline,
            chain_window_hours=m.chain_window_hours,
        )
        for m in sequences
    ]

    baseline_schema = BaselineDeviationSchema(
        deviation=baseline_dev.deviation,
        rate_ratio=baseline_dev.rate_ratio,
        sev_delta=baseline_dev.sev_delta,
        is_escalating=baseline_dev.is_escalating,
        new_event_types=baseline_dev.new_event_types,
        baseline_event_count=baseline_dev.baseline_event_count,
        recent_event_count=baseline_dev.recent_event_count,
        has_sufficient_baseline=baseline_dev.has_sufficient_baseline,
    )

    return AlertAnalysisResponse(
        entity_id=request.entity_id,
        trace_id=trace_id,
        context_summary=context_summary,
        analysis=llm_result,
        score_breakdown=score_breakdown,
        sequences_detected=seq_schemas,
        baseline_deviation=baseline_schema,
        decision=decide_result.decision,
        events_analysed=entity_ctx.event_count,
        memory_augmentation=mem_aug_report,
        semantic_profile=sem_profile_schema,
        debug_info=dict(ctx.debug_info) if debug_mode else None,
    )
