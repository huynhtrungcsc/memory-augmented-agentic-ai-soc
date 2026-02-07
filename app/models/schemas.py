"""
Pydantic models (request / response contracts).

All schemas use strict typing so that invalid payloads are rejected at the
boundary before they ever reach business logic.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─── Enumerations ─────────────────────────────────────────────────────────────


class LogSource(str, Enum):
    suricata = "suricata"
    zeek = "zeek"
    wazuh = "wazuh"
    splunk = "splunk"
    generic = "generic"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, Enum):
    block = "block"
    alert_analyst = "alert_analyst"
    # review_required — for uncertain high-risk cases where evidence is present
    # but insufficient to justify automated block.  A human analyst must review
    # before escalation.  Sits between alert_analyst and block.
    review_required = "review_required"
    log_only = "log_only"


class AttackCategory(str, Enum):
    reconnaissance = "reconnaissance"
    lateral_movement = "lateral_movement"
    privilege_escalation = "privilege_escalation"
    credential_access = "credential_access"
    exfiltration = "exfiltration"
    command_and_control = "command_and_control"
    denial_of_service = "denial_of_service"
    malware = "malware"
    policy_violation = "policy_violation"
    false_positive = "false_positive"
    unknown = "unknown"


# ─── Ingest schemas ───────────────────────────────────────────────────────────


class RawLog(BaseModel):
    """Normalised security log ingested from any supported source.

    Two timestamps are stored:
      event_time   — when the event occurred on the source system (required).
                     Maps to `timestamp` for backward compatibility.
      processing_time — when the SOC pipeline received the event (auto-set).
    The gap between them identifies delayed / out-of-order logs.
    """

    source: LogSource = Field(..., description="Log originator (suricata, zeek, wazuh, …)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Processing timestamp set at ingest boundary
    processing_time: Optional[datetime] = Field(
        None,
        description=(
            "UTC time when this event was received by the SOC pipeline. "
            "Auto-set at ingest; omit in requests."
        ),
    )

    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: str = Field(..., description="Event category / alert type")
    severity: Severity = Severity.medium
    message: str = Field(..., description="Human-readable event description")
    username: Optional[str] = Field(None, description="Associated user account")
    hostname: Optional[str] = Field(None, description="Associated host / endpoint")
    raw_payload: Optional[Dict[str, Any]] = Field(
        None, description="Original log fields — NOT forwarded to the LLM"
    )

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "source": "suricata",
            "timestamp": "2026-04-12T10:00:00Z",
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 22,
            "protocol": "TCP",
            "event_type": "ET SCAN SSH BruteForce",
            "severity": "high",
            "message": "SSH brute-force attempt detected from 192.168.1.105",
            "username": None,
            "hostname": "srv-gateway",
        }
    })


class IngestResponse(BaseModel):
    log_id: int
    entity_id: str = Field(..., description="Primary entity key used for memory lookup")
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    is_anomalous: bool
    message: str
    # Ingest processing lag in seconds (processing_time - event_time)
    processing_lag_seconds: Optional[float] = Field(
        None, description="Delay (s) between event_time and ingest — >60s suggests delayed log"
    )


# ─── Analysis schemas ─────────────────────────────────────────────────────────


class AlertAnalysisRequest(BaseModel):
    entity_id: str = Field(..., description="IP, username, or hostname to analyse")
    trigger_log_id: Optional[int] = Field(None, description="Specific log that triggered this analysis")
    trigger_severity: Optional[Severity] = Field(
        None,
        description=(
            "Severity of the triggering event; used in hybrid scoring. "
            "If omitted, the highest severity in recent history is used."
        ),
    )
    # trace_id — propagated through the full analysis pipeline for request correlation
    trace_id: Optional[str] = Field(
        None,
        description="Optional trace ID for request correlation. Auto-generated if absent.",
    )
    # debug_mode — when True, the response includes full pipeline diagnostics
    debug_mode: bool = Field(False, description="Return full pipeline diagnostics in debug_info field")

    model_config = ConfigDict(json_schema_extra={"example": {"entity_id": "192.168.1.105"}})


class SequenceMatchSchema(BaseModel):
    """A detected attack chain match."""
    chain_name: str
    chain_severity: str
    phases_detected: List[str]
    phases_total: int
    completion_ratio: float = Field(..., ge=0.0, le=1.0)
    sequence_score: float = Field(..., ge=0.0, le=1.0)
    phase_timeline: List[str] = Field(default_factory=list)
    # Time span (hours) between first and last matched phase.
    chain_window_hours: float = Field(
        0.0, ge=0.0,
        description="Time (hours) between first and last matched phase — 0 for single-phase matches",
    )


class BaselineDeviationSchema(BaseModel):
    """Behavioural baseline comparison result."""
    deviation: float = Field(..., ge=0.0, le=1.0, description="Composite deviation score (0=normal, 1=extreme)")
    rate_ratio: float = Field(..., description="recent_rate / baseline_rate (>1 = accelerating)")
    sev_delta: float = Field(..., description="Severity escalation (positive = getting worse)")
    is_escalating: bool
    new_event_types: List[str] = Field(default_factory=list)
    baseline_event_count: int
    recent_event_count: int
    has_sufficient_baseline: bool = True


class EntityEdgeSchema(BaseModel):
    """One directed edge in the entity relationship graph."""
    related_entity: str
    direction: str = Field(..., description="'outbound' (this entity initiated) or 'inbound' (this entity was targeted)")
    edge_type: str
    event_count: int
    first_seen: datetime
    last_seen: datetime


class EntityGraphSchema(BaseModel):
    entity_id: str
    edges: List[EntityEdgeSchema]
    total_connections: int


class ScoreBreakdown(BaseModel):
    """Detailed breakdown of the hybrid composite risk score.

    Includes confidence_score and calibrated_score alongside the composite.
    """

    # ── Four base signals ─────────────────────────────────────────────────────
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Rule-based detector score (0–1)")
    llm_score: float = Field(..., ge=0.0, le=1.0, description="LLM risk_score / 100 (0–1)")
    history_score: float = Field(..., ge=0.0, le=1.0, description="Derived from entity historical pattern (0–1)")
    severity_score: float = Field(..., ge=0.0, le=1.0, description="Event severity normalised to 0–1")
    weights: Dict[str, float] = Field(..., description="Weight applied to each base component")
    base_score: int = Field(..., ge=0, le=100, description="Weighted base score before additive boosts")

    # ── Additive boosts ───────────────────────────────────────────────────────
    sequence_boost: float = Field(0.0, description="Score points added for detected attack chain (max +15)")
    baseline_boost: float = Field(0.0, description="Score points added for behavioral deviation (max +10)")
    sequences_detected: List[str] = Field(default_factory=list, description="Names of matched attack chains")

    # ── Final ─────────────────────────────────────────────────────────────────
    composite_score: int = Field(..., ge=0, le=100, description="Final hybrid risk score (0–100)")

    # ── Calibration ───────────────────────────────────────────────────────────
    confidence_score: float = Field(
        1.0, ge=0.0, le=1.0,
        description=(
            "Confidence in the composite score (0–1). Lower when evidence is sparse, "
            "source diversity is low, or signals disagree strongly."
        ),
    )
    calibrated_score: int = Field(
        ..., ge=0, le=100,
        description=(
            "composite_score adjusted by confidence. Low-confidence scores are pulled "
            "toward 50 (uncertain) to prevent extreme decisions on thin evidence."
        ),
    )
    signal_agreement: float = Field(
        1.0, ge=0.0, le=1.0,
        description="Agreement between the four base signals (0=contradictory, 1=unanimous).",
    )

    # ── Contradiction detection ────────────────────────────────────────────────
    contradiction_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description=(
            "How much the anomaly signals contradict each other (0=aligned, 1=strongly contradictory). "
            "High anomaly_score + high false_positive_likelihood is a contradiction."
        ),
    )
    contradictory_flagged: bool = Field(
        False,
        description=(
            "True when contradiction_score ≥ 0.40 AND the score is in the ambiguous middle band [45–75]. "
            "Triggers review_required instead of alert_analyst in the decision engine."
        ),
    )

    # ── Low-and-slow persistence ───────────────────────────────────────────────
    slow_persistence_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description="Sustained low-rate suspicious activity across 6h/24h/72h windows (0=none, 1=high).",
    )
    persistence_boost: float = Field(
        0.0,
        description="Score points added for detected slow-persistence pattern (max +12).",
    )

    # ── Trust discount ─────────────────────────────────────────────────────────
    trust_discount_applied: float = Field(
        0.0, ge=0.0, le=0.4,
        description="Anomaly score reduction applied for recognised trusted source.",
    )
    trust_labels: List[str] = Field(
        default_factory=list,
        description="Reasons for trust discount (e.g. 'scanner_event_type', 'admin_username_prefix').",
    )

    # ── Category calibration ──────────────────────────────────────────────────
    category_label: str = Field(
        "neutral",
        description="Category matched for calibration (e.g. 'admin_activity', 'authorised_scanner').",
    )
    category_factor: float = Field(
        1.0,
        description="Calibration multiplier applied to anomaly score before hybrid scoring.",
    )

    # ── Memory-Augmented FP pattern discount (EPISODIC MEMORY) ───────────────
    fp_pattern_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description=(
            "How strongly this entity's history matches a known false-positive profile (0=novel, 1=strong FP profile). "
            "When high and non-escalating, the history contribution to the composite score is discounted."
        ),
    )
    fp_pattern_summary: str = Field(
        "",
        description="Human-readable summary of the FP pattern analysis from memory.",
    )

    # ── Semantic Memory discount ───────────────────────────────────────────────
    semantic_memory_discount: float = Field(
        0.0, ge=0.0,
        description=(
            "Anomaly score reduction applied by SEMANTIC MEMORY: learned priors about this entity's "
            "normal behaviour. Applied when the current event type and hour match the entity's known profile. "
            "Max ~0.25. Zero when entity risk trend is escalating."
        ),
    )


class LLMAnalysisResult(BaseModel):
    attack_classification: AttackCategory
    false_positive_likelihood: float = Field(..., ge=0.0, le=1.0, description="0=definitely real, 1=likely FP")
    risk_score: int = Field(..., ge=0, le=100, description="Raw LLM risk score before hybrid weighting")
    recommended_action: str
    reasoning: str
    mock_mode: bool = Field(False, description="True when LLM key is absent and response is simulated")


class AlertAnalysisResponse(BaseModel):
    entity_id: str
    trace_id: str = Field(..., description="Request trace ID for log correlation")
    context_summary: str
    analysis: LLMAnalysisResult
    score_breakdown: ScoreBreakdown
    sequences_detected: List[SequenceMatchSchema]
    baseline_deviation: Optional[BaselineDeviationSchema]
    decision: Decision
    events_analysed: int
    memory_augmentation: Optional["MemoryAugmentationReport"] = Field(
        None,
        description=(
            "Full report of how all four memory types (episodic, semantic, procedural, working) "
            "contributed to this analysis and affected the risk score."
        ),
    )
    semantic_profile: Optional["SemanticProfileSchema"] = Field(
        None,
        description="Current learned semantic memory profile for this entity (updated after analysis).",
    )
    debug_info: Optional[Dict[str, Any]] = Field(
        None, description="Full pipeline diagnostics (only populated when debug_mode=True)"
    )


# ─── Memory-Augmented schemas ─────────────────────────────────────────────────


class SemanticProfileSchema(BaseModel):
    """
    SEMANTIC MEMORY — What the system has accumulated about this entity over time.

    Unlike episodic memory (raw events), semantic memory holds distilled, persistent
    scoring priors accumulated across all past analyses.  These priors shift the
    composite score toward lower risk as entity history deepens — provided the
    current event matches the learned profile (familiar type, known-good hour).
    """
    entity_id: str
    known_good_hours: List[int] = Field(
        default_factory=list,
        description="Hours of day (0–23) where activity is historically normal for this entity.",
    )
    dominant_event_types: List[str] = Field(
        default_factory=list,
        description="Top recurring event types identified by frequency threshold in this entity's episodic history.",
    )
    peer_entities: List[str] = Field(
        default_factory=list,
        description="Known communication partners (IPs / hosts) from relationship graph memory.",
    )
    avg_anomaly_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description="Rolling average anomaly score across all events ever seen for this entity.",
    )
    fp_confidence: float = Field(
        0.0, ge=0.0, le=1.0,
        description=(
            "Learned confidence (0–1) that this entity is a benign false-positive source. "
            "High values trigger an additional semantic memory discount on the risk score."
        ),
    )
    risk_trend: str = Field(
        "stable",
        description="Trend of risk over time: 'stable' | 'escalating' | 'deescalating'.",
    )
    total_events_seen: int = Field(
        0, ge=0,
        description="Cumulative event count seen for this entity across all time.",
    )
    last_updated: Optional[datetime] = None
    is_new_entity: bool = Field(
        True,
        description="True when no prior semantic profile exists — no learned priors available.",
    )


class MemoryContribution(BaseModel):
    """Describes how a single memory type contributed to the current risk assessment."""
    memory_type: str = Field(..., description="One of: episodic, semantic, procedural, working")
    active: bool = Field(..., description="Whether this memory type had data for this entity.")
    signal: str = Field(..., description="Human-readable description of what this memory provided.")
    score_effect: str = Field(
        "",
        description="How this memory affected the score: 'discounted', 'boosted', 'neutral', 'not_applied'.",
    )
    magnitude: float = Field(
        0.0, ge=0.0,
        description="Estimated magnitude of the score effect (0 = none, 1 = maximum impact).",
    )


class MemoryAugmentationReport(BaseModel):
    """
    Full report of how all four memory types contributed to this analysis.

    The Memory-Augmented Agentic AI architecture maintains four distinct memory types,
    each serving a different role in reducing false positives:

      1. EPISODIC  — Raw historical events. Used for frequency/severity patterns
                     and FP pattern detection (compute_fp_pattern).
      2. SEMANTIC  — Learned behavioural fingerprint. Persistent priors about what
                     is 'normal' for this entity. Updated after every analysis.
      3. PROCEDURAL — Decision history & hysteresis. Prevents oscillation between
                      block/alert decisions. Encodes learned response policy.
      4. WORKING   — Per-analysis active context. Holds LLM-consumed context summary,
                     current scoring signals, and intermediate analysis state.
    """
    contributions: List[MemoryContribution]
    total_memory_discount: float = Field(
        0.0, ge=0.0, le=1.0,
        description="Total score discount applied by memory augmentation (episodic FP + semantic FP).",
    )
    dominant_memory_type: str = Field(
        "",
        description="Which memory type had the largest influence on this analysis.",
    )
    memory_richness: str = Field(
        "none",
        description="Overall richness of memory for this entity: 'none' | 'sparse' | 'moderate' | 'rich'.",
    )


# ─── Memory schemas ───────────────────────────────────────────────────────────


class MemoryEvent(BaseModel):
    log_id: int
    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str
    anomaly_score: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None


class EntityContext(BaseModel):
    """
    Rich contextual snapshot of an entity's historical behaviour.

    MemPalace integration point:
      When using MemPalace as the memory back-end, populate this model from
      MemPalace's entity profile API rather than from the SQLite query.
    """

    entity_id: str
    event_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]

    # ── Derived risk signal ───────────────────────────────────────────────────
    history_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Composite history-based risk score (frequency × severity × anomaly)",
    )

    # ── Frequency & distribution ──────────────────────────────────────────────
    events_per_hour: float = Field(..., description="Average event rate over the observation window")
    attack_type_distribution: Dict[str, int] = Field(
        ..., description="Count of each event_type seen for this entity"
    )
    severity_distribution: Dict[str, int] = Field(
        ..., description="Count of events per severity level"
    )
    avg_anomaly_score: float = Field(..., ge=0.0, le=1.0)

    # ── Timeline ──────────────────────────────────────────────────────────────
    recent_timeline: List[MemoryEvent]


# Keep EntityMemory as a backward-compatible alias
EntityMemory = EntityContext


# ─── Decision schemas ─────────────────────────────────────────────────────────


class DecideRequest(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    entity_id: Optional[str] = None
    context: Optional[str] = None

    model_config = ConfigDict(json_schema_extra={"example": {"risk_score": 85, "entity_id": "192.168.1.105"}})


class DecideResponse(BaseModel):
    risk_score: int
    decision: Decision
    rationale: str
    entity_id: Optional[str]
