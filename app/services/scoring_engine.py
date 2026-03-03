"""
Hybrid Risk Scoring Engine.

Combines independent signals into a single composite risk score (0–100):

  BASE SCORE (weighted sum, 0–100):
    1. anomaly_score  — rule-based anomaly detector (0–1), after trust+category adjustment
    2. llm_score      — LLM risk_score / 100  (0–1)
    3. history_score  — entity memory profile  (0–1), discounted by FP pattern
    4. severity_score — event severity         (0–1)

  ADDITIVE BOOSTS (applied after base score, capped at 100):
    5. sequence_boost      — attack chain detected       (0 to SEQUENCE_BOOST_MAX points)
    6. baseline_boost      — behavioural deviation       (0 to BASELINE_BOOST_MAX points)
    7. persistence_boost   — low-and-slow persistence    (0 to PERSISTENCE_BOOST_MAX points)

  ADJUSTMENTS (applied before scoring):
    8. trust_discount      — known scanner/admin source   (−0 to −0.4 from anomaly_score)
    9. category_factor     — category-specific calibration (×0.4 to ×1.5 on anomaly_score)

MEMORY-AUGMENTED FP PATTERN DISCOUNT:
  fp_pattern:  FPPatternAnalysis from history_scorer.
  When an entity has a known FP profile, the history contribution to the
  composite score is discounted:
    effective_history = history_score × (1 − fp_pattern_score × fp_pattern_discount_weight)

  This makes memory REDUCE risk for known-benign entities instead of accumulating it.
  Without this: benign entity with FP-rich memory → high history_score → high risk.
  With this:    benign entity with FP-rich memory → discounted history → correct low risk.

CONFIDENCE CALIBRATION:
  confidence_score — how much to trust the composite_score (0–1).
  calibrated_score — composite_score pulled toward 50 (uncertainty centre).

CONTRADICTION DETECTION:
  contradiction_score — how much the evidence contradicts itself (0–1).
  contradictory_flagged — True when contradiction ≥ 0.40 AND score in [45, 75].
"""

from __future__ import annotations

import math
from typing import List, Optional

from app.config import get_settings
from app.models.schemas import ScoreBreakdown, Severity
from app.services.baseline import BaselineDeviation, SlowPersistence
from app.services.history_scorer import FPPatternAnalysis, SemanticProfileData
from app.services.sequence_detector import SequenceMatch

# Severity → normalised risk contribution
_SEVERITY_NORM: dict[Severity, float] = {
    Severity.critical: 1.0,
    Severity.high: 0.75,
    Severity.medium: 0.40,
    Severity.low: 0.10,
}

_MIN_EVENTS_FULL_CONFIDENCE = 10
_PERSISTENCE_BOOST_MAX: float = 12.0
_CONTRADICTION_BAND_LOW: int = 45
_CONTRADICTION_BAND_HIGH: int = 75
_CONTRADICTION_FLAG_THRESHOLD: float = 0.40


def _compute_signal_agreement(signals: list[float]) -> float:
    if not signals:
        return 1.0
    n = len(signals)
    mean = sum(signals) / n
    variance = sum((s - mean) ** 2 for s in signals) / n
    std_dev = math.sqrt(variance)
    agreement = max(0.0, 1.0 - std_dev / 0.5)
    return round(agreement, 3)


def _compute_contradiction_score(
    anomaly_score: float,
    llm_score: float,
    fp_likelihood: float,
    trust_discount: float,
) -> float:
    contradiction = 0.0
    if fp_likelihood is not None:
        fp_anomaly_gap = anomaly_score * fp_likelihood
        llm_anomaly_gap = max(0.0, anomaly_score - llm_score)
        contradiction += fp_anomaly_gap * 0.5 + llm_anomaly_gap * 0.3
    if trust_discount >= 0.1 and anomaly_score > 0.6:
        contradiction += min(trust_discount * anomaly_score, 0.2)
    return round(min(contradiction, 1.0), 3)


def _compute_confidence(
    anomaly_score: float,
    llm_score: float,
    history_score: float,
    severity_score: float,
    event_count: int,
    signal_agreement: float,
    contradiction_score: float,
) -> float:
    evidence_factor = min(1.0, event_count / _MIN_EVENTS_FULL_CONFIDENCE) if event_count > 0 else 0.1
    agreement_factor = max(0.3, signal_agreement)
    history_factor = max(0.5, 0.5 + history_score * 0.5)
    contradiction_factor = max(0.4, 1.0 - contradiction_score * 0.5)
    confidence = evidence_factor * agreement_factor * history_factor * contradiction_factor
    return round(max(0.05, min(1.0, confidence)), 3)


def _calibrate_score(composite: int, confidence: float) -> int:
    calibrated = confidence * composite + (1.0 - confidence) * 50.0
    return max(0, min(100, int(round(calibrated))))


def compute_hybrid_score(
    anomaly_score: float,
    llm_risk_score: int,
    history_score: float,
    severity: Severity,
    sequence_matches: Optional[List[SequenceMatch]] = None,
    baseline_deviation: Optional[BaselineDeviation] = None,
    event_count: int = 10,
    slow_persistence: Optional[SlowPersistence] = None,
    trust_discount: float = 0.0,
    trust_labels: Optional[List[str]] = None,
    category_factor: float = 1.0,
    category_label: str = "neutral",
    fp_likelihood: Optional[float] = None,
    fp_pattern: Optional[FPPatternAnalysis] = None,
    semantic_profile: Optional[SemanticProfileData] = None,
    current_event_type: Optional[str] = None,
    current_hour: Optional[int] = None,
) -> ScoreBreakdown:
    """
    Compute the composite hybrid risk score from all available signals.

    Memory-Augmented parameters
    ---------------------------
    fp_pattern:        FPPatternAnalysis — episodic memory FP signal.
                       When a stable non-escalating FP pattern is detected, the
                       history contribution is discounted by fp_pattern_discount_weight.

    semantic_profile:  SemanticProfileData — LEARNED semantic memory priors.
                       Applies an additional discount when the current event matches
                       the entity's learned normal profile:
                         - current_event_type in dominant_event_types → familiar event
                         - current_hour in known_good_hours → normal time of day
                       Combined with fp_confidence, this shifts the composite score
                       toward lower risk for events that match established entity patterns.
    """
    settings = get_settings()

    # ── Apply trust discount + category factor to anomaly score ───────────────
    adjusted_anomaly = max(0.0, anomaly_score - trust_discount) * category_factor
    adjusted_anomaly = round(min(adjusted_anomaly, 1.0), 3)

    llm_norm = max(0.0, min(1.0, llm_risk_score / 100.0))
    sev_norm = _SEVERITY_NORM.get(severity, 0.25)

    # ── Memory-Augmented Discount Layer ───────────────────────────────────────
    # Two memory types contribute to FP discounting:
    #
    #  1. EPISODIC MEMORY (fp_pattern): Detects stable, recurring FP patterns
    #     in the entity's raw event history.  Strong, reliable signal.
    #
    #  2. SEMANTIC MEMORY (semantic_profile): Uses LEARNED priors about this entity:
    #       - Is the current event type part of its 'normal' repertoire?
    #       - Is the current hour a known-good time for this entity?
    #     Adds a contextual discount on top of the episodic discount.
    #
    # Combined effect: if both memory types agree the event is routine,
    # the history contribution is significantly reduced → true FP suppression.

    fp_discount = 0.0
    fp_pattern_score_val = 0.0
    fp_pattern_summary_val = ""
    if fp_pattern is not None:
        fp_pattern_score_val = fp_pattern.fp_pattern_score
        fp_pattern_summary_val = fp_pattern.summary
        fp_discount = fp_pattern_score_val * settings.fp_pattern_discount_weight

    # Semantic memory discount — applied to the anomaly score (not history)
    # so that a novel-looking event from a familiar entity still carries
    # some anomaly weight, but is pulled down when priors are strong.
    semantic_discount = 0.0
    if semantic_profile is not None and semantic_profile.fp_confidence > 0.3:
        # Check how 'familiar' the current event is according to semantic memory
        familiar_type = (
            current_event_type is not None
            and current_event_type in semantic_profile.dominant_event_types
        )
        familiar_hour = (
            current_hour is not None
            and current_hour in semantic_profile.known_good_hours
        )
        familiarity_bonus = (0.5 if familiar_type else 0.0) + (0.5 if familiar_hour else 0.0)
        # Scale discount by fp_confidence × familiarity (max ~0.25 reduction on anomaly)
        semantic_discount = round(
            semantic_profile.fp_confidence * familiarity_bonus * 0.25, 3
        )
        # Escalating trend overrides semantic discount — never suppress a rising threat
        if semantic_profile.risk_trend == "escalating":
            semantic_discount = 0.0

    adjusted_anomaly = max(0.0, adjusted_anomaly - semantic_discount)

    effective_history = history_score * max(0.0, 1.0 - fp_discount)

    weights = {
        "anomaly": settings.weight_anomaly,
        "llm": settings.weight_llm,
        "history": settings.weight_history,
        "severity": settings.weight_severity,
    }

    # ── Base score (weighted sum, 0–100) ──────────────────────────────────────
    base_01 = (
        weights["anomaly"] * adjusted_anomaly
        + weights["llm"] * llm_norm
        + weights["history"] * effective_history
        + weights["severity"] * sev_norm
    )
    base_score = int(round(base_01 * 100))

    # ── Additive boost 1: attack chain detection ──────────────────────────────
    sequence_boost = 0.0
    seq_names: List[str] = []
    if sequence_matches:
        best = max(sequence_matches, key=lambda m: m.completion_ratio)
        sequence_boost = round(best.completion_ratio * settings.sequence_boost_max, 1)
        seq_names = [m.chain_name for m in sequence_matches]

    # ── Additive boost 2: behavioral deviation from baseline ──────────────────
    baseline_boost = 0.0
    if baseline_deviation and baseline_deviation.has_sufficient_baseline:
        baseline_boost = round(
            baseline_deviation.deviation * settings.baseline_boost_max, 1
        )

    # ── Additive boost 3: low-and-slow persistence ────────────────────────────
    slow_persistence_score_val = 0.0
    persistence_boost_val = 0.0
    if slow_persistence and slow_persistence.is_persistent:
        slow_persistence_score_val = slow_persistence.persistence_score
        persistence_boost_val = round(
            slow_persistence.persistence_score * _PERSISTENCE_BOOST_MAX, 1
        )

    # ── Final composite (capped) ──────────────────────────────────────────────
    composite_score = max(0, min(100, int(round(
        base_score + sequence_boost + baseline_boost + persistence_boost_val
    ))))

    # ── Contradiction detection ───────────────────────────────────────────────
    contradiction_score = _compute_contradiction_score(
        anomaly_score=anomaly_score,
        llm_score=llm_norm,
        fp_likelihood=fp_likelihood if fp_likelihood is not None else 0.0,
        trust_discount=trust_discount,
    )
    contradictory_flagged = (
        contradiction_score >= _CONTRADICTION_FLAG_THRESHOLD
        and _CONTRADICTION_BAND_LOW <= composite_score <= _CONTRADICTION_BAND_HIGH
    )

    # ── Confidence + calibration ──────────────────────────────────────────────
    signal_agreement = _compute_signal_agreement([adjusted_anomaly, llm_norm, history_score, sev_norm])
    confidence = _compute_confidence(
        anomaly_score=adjusted_anomaly,
        llm_score=llm_norm,
        history_score=history_score,
        severity_score=sev_norm,
        event_count=event_count,
        signal_agreement=signal_agreement,
        contradiction_score=contradiction_score,
    )
    calibrated_score = _calibrate_score(composite_score, confidence)

    return ScoreBreakdown(
        anomaly_score=round(adjusted_anomaly, 3),
        llm_score=round(llm_norm, 3),
        history_score=round(history_score, 3),
        severity_score=round(sev_norm, 3),
        weights=weights,
        base_score=base_score,
        sequence_boost=sequence_boost,
        baseline_boost=baseline_boost,
        sequences_detected=seq_names,
        composite_score=composite_score,
        confidence_score=confidence,
        calibrated_score=calibrated_score,
        signal_agreement=signal_agreement,
        contradiction_score=contradiction_score,
        contradictory_flagged=contradictory_flagged,
        slow_persistence_score=slow_persistence_score_val,
        persistence_boost=persistence_boost_val,
        trust_discount_applied=round(trust_discount, 3),
        trust_labels=trust_labels or [],
        category_label=category_label,
        category_factor=round(category_factor, 3),
        fp_pattern_score=round(fp_pattern_score_val, 3),
        fp_pattern_summary=fp_pattern_summary_val,
        semantic_memory_discount=round(semantic_discount, 3),
    )
