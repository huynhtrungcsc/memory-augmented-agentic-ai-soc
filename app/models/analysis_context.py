"""
H2 — Unified AnalysisContext.

All subsystems (sequence detector, baseline, LLM, scoring engine) must operate
on the SAME event set and share the same derived artefacts.  Before this object
existed, analyze.py passed separate event lists to each subsystem, creating the
risk that a bug in one branch could result in the LLM seeing different events
than the chain detector — undermining the coherence of the final output.

The AnalysisContext is assembled once in analyze.py and then passed (read-only)
to every downstream function.  This makes the analysis pipeline auditable and
makes any data-inconsistency bug immediately visible (there's only one place
where the events are collected).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.schemas import MemoryEvent
from app.services.baseline import BaselineDeviation
from app.services.sequence_detector import SequenceMatch


@dataclass(frozen=True)
class TimeWindow:
    """The UTC time window used for event selection."""
    start: datetime          # UTC — oldest event included
    end: datetime            # UTC — newest event included (≈ now)
    window_hours: float      # (end - start).total_seconds() / 3600

    @classmethod
    def build(cls, start: datetime, end: datetime) -> "TimeWindow":
        hours = (end - start).total_seconds() / 3600.0
        return cls(start=start, end=end, window_hours=hours)


@dataclass
class AnalysisContext:
    """
    Shared analysis context — assembled once, passed everywhere.

    Attributes
    ----------
    trace_id        Unique identifier for this analysis request (UUID4).
    entity_id       The entity being analysed.
    time_window     UTC time range for event selection.
    events          Deduplicated, time-ordered event list used by ALL subsystems.
                    Newest first (as returned by MemoryStore).
    baseline_stats  Behavioral baseline deviation (1h vs prior 24h).
    chains          Detected attack chains (from sequence_detector).
    evidence_count  Number of strong signals that fired (for minimum-evidence gate).
    debug_info      Populated during pipeline execution for debug_mode=True.
    """

    trace_id: str
    entity_id: str
    time_window: TimeWindow
    events: List[MemoryEvent]

    # ── Populated by the pipeline ──────────────────────────────────────────────
    baseline_stats: Optional[BaselineDeviation] = None
    chains: List[SequenceMatch] = field(default_factory=list)
    evidence_count: int = 0        # How many strong signals fired (chain, baseline, anomaly, history)
    debug_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def event_count(self) -> int:
        return len(self.events)

    def add_debug(self, key: str, value: Any) -> None:
        """Record a pipeline diagnostic (no-op when debug_mode=False)."""
        self.debug_info[key] = value
