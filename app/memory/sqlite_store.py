"""
SQLite-backed memory store (default implementation).

This is the concrete implementation used out-of-the-box.  It stores every
processed event in a lightweight SQLite database, keyed by entity_id, and
also by src_ip, dst_ip, username, and hostname for cross-entity retrieval.

MemPalace integration point:
  This file is the only thing you need to replace when upgrading to MemPalace.
  The rest of the codebase depends only on `AbstractMemoryStore`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

import json

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base
from app.memory.base import AbstractMemoryStore
from app.models.schemas import EntityContext, MemoryEvent
from app.services.history_scorer import (
    SimpleEvent,
    compute_context_stats,
    compute_history_score,
)


# ─── Semantic Memory ORM model ────────────────────────────────────────────────


class EntitySemanticProfile(Base):
    """
    SEMANTIC MEMORY — Learned, persistent behavioural fingerprint for each entity.

    Unlike episodic memory (which stores raw events), semantic memory stores
    WHAT THE AGENT HAS LEARNED about an entity across all past analyses.  It
    accumulates knowledge that persists beyond the analysis window:

      known_good_hours_json   — hours of day (0–23) where activity is historically normal
      dominant_event_types_json — top recurring event types (stable, expected patterns)
      peer_entities_json      — known communication partners (IPs / hosts)
      avg_anomaly_score       — rolling average anomaly across all events ever seen
      fp_confidence           — accumulated confidence (0–1) that this entity is a benign FP source
      risk_trend              — 'stable' | 'escalating' | 'deescalating'
      total_events_seen       — cumulative event count (lifetime)
      last_updated            — last time the profile was updated

    This profile is updated after every successful analysis and used in the next
    analysis to provide stronger priors about entity behaviour.

    Memory-Augmented property:
      When fp_confidence is high AND the current event_type is in
      dominant_event_types → additional semantic memory discount applied to score.
    """

    __tablename__ = "entity_semantic_profiles"

    entity_id = Column(String(256), primary_key=True, nullable=False)
    known_good_hours_json = Column(Text, default="[]")
    dominant_event_types_json = Column(Text, default="[]")
    peer_entities_json = Column(Text, default="[]")
    avg_anomaly_score = Column(Float, default=0.0)
    fp_confidence = Column(Float, default=0.0)
    risk_trend = Column(String(32), default="stable")
    total_events_seen = Column(Integer, default=0)
    last_updated = Column(DateTime, nullable=True)


# ─── Decision hysteresis ORM model ───────────────────────────────────────────


class EntityDecisionRecord(Base):
    """
    Persists the last decision made for an entity.

    Used by the hysteresis logic in the analyze route to prevent rapid
    oscillation when an entity's risk score momentarily drops below a
    threshold during an ongoing attack.

    Hysteresis contract:
      - Upgrades (block > review_required > alert_analyst > log_only) are applied immediately.
      - Downgrades are deferred until `hysteresis_hours` have elapsed at the
        lower risk level OR the composite score drops below a hard floor.

    Cooldown field:
      cooldown_until — when a BLOCK decision is issued, this is set to
        (now + block_cooldown_hours).  During the cooldown period, re-analysis
        of the same entity will maintain the BLOCK decision without requiring
        a new risk evaluation, preventing rapid block/unblock oscillation.
    """

    __tablename__ = "entity_decision_records"

    entity_id = Column(String(256), primary_key=True, nullable=False)
    last_decision = Column(String(64), nullable=False)   # 'block', 'review_required', 'alert_analyst', 'log_only'
    last_score = Column(Integer, nullable=False)
    last_decided_at = Column(DateTime, nullable=False)   # UTC naive
    cooldown_until = Column(DateTime, nullable=True)      # UTC naive — None if no active cooldown


# ─── ORM model ────────────────────────────────────────────────────────────────


class AlertRecord(Base):
    """
    Persisted alert / event record.

    Indexed by:
      - entity_id  — primary look-up key (IP / user / host)
      - src_ip     — source-IP cross-query
      - dst_ip     — destination-IP cross-query
      - username   — user-account cross-query
      - hostname   — host cross-query
    """

    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_id = Column(Integer, index=True)
    entity_id = Column(String(256), index=True, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String(256), nullable=False)
    severity = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    source = Column(String(64), nullable=False)
    anomaly_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    # ── Contextual attribute columns ──────────────────────────────────────────
    src_ip = Column(String(64), nullable=True, index=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    username = Column(String(256), nullable=True, index=True)
    hostname = Column(String(256), nullable=True, index=True)


# ─── Internal helpers ──────────────────────────────────────────────────────────


def _rows_to_events(rows: list) -> List[MemoryEvent]:
    return [
        MemoryEvent(
            log_id=r.log_id,
            timestamp=r.timestamp,
            event_type=r.event_type,
            severity=r.severity,
            message=r.message,
            source=r.source,
            anomaly_score=r.anomaly_score,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            username=r.username,
            hostname=r.hostname,
        )
        for r in rows
    ]


def _rows_to_simple(rows: list) -> List[SimpleEvent]:
    return [
        SimpleEvent(
            event_type=r.event_type,
            severity=r.severity,
            anomaly_score=r.anomaly_score,
            timestamp=r.timestamp,
            message=r.message or "",
        )
        for r in rows
    ]


def _apply_since(stmt, column, since: Optional[datetime]):
    if since:
        # Normalise to naive UTC for SQLite comparison
        naive = since.replace(tzinfo=None) if since.tzinfo else since
        stmt = stmt.where(column >= naive)
    return stmt


# ─── Store implementation ─────────────────────────────────────────────────────


class SQLiteMemoryStore(AbstractMemoryStore):
    """Async SQLite implementation of AbstractMemoryStore."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Write ─────────────────────────────────────────────────────────────────

    async def store_event(
        self,
        log_id: int,
        entity_id: str,
        timestamp: datetime,
        event_type: str,
        severity: str,
        message: str,
        source: str,
        anomaly_score: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        username: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> int:
        """Persist a single event and return its auto-generated record ID."""
        # Ensure timestamp is naive UTC for consistent SQLite storage
        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)

        record = AlertRecord(
            log_id=log_id,
            entity_id=entity_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            message=message,
            source=source,
            anomaly_score=anomaly_score,
            src_ip=src_ip,
            dst_ip=dst_ip,
            username=username,
            hostname=hostname,
        )
        self._session.add(record)
        await self._session.flush()
        return record.id

    # ── Entity reads ──────────────────────────────────────────────────────────

    async def get_events(
        self,
        entity_id: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.entity_id == entity_id)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        return _rows_to_events(result.scalars().all())

    async def get_entity_context(
        self,
        entity_id: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> EntityContext:
        """
        Build a rich contextual snapshot including history_score, frequency,
        and attack-type / severity distributions.

        MemPalace integration point:
          Replace this method with a call to the MemPalace entity profile API.
          The EntityContext schema is the stable contract.
        """
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.entity_id == entity_id)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()

        if not rows:
            return EntityContext(
                entity_id=entity_id,
                event_count=0,
                first_seen=None,
                last_seen=None,
                history_score=0.0,
                events_per_hour=0.0,
                attack_type_distribution={},
                severity_distribution={},
                avg_anomaly_score=0.0,
                recent_timeline=[],
            )

        simple_events = _rows_to_simple(rows)
        history_score = compute_history_score(simple_events)
        events_per_hour, attack_dist, severity_dist, avg_anomaly = compute_context_stats(simple_events)

        timestamps = [r.timestamp for r in rows]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        return EntityContext(
            entity_id=entity_id,
            event_count=len(rows),
            first_seen=first_seen,
            last_seen=last_seen,
            history_score=history_score,
            events_per_hour=events_per_hour,
            attack_type_distribution=attack_dist,
            severity_distribution=severity_dist,
            avg_anomaly_score=avg_anomaly,
            recent_timeline=_rows_to_events(rows),
        )

    # ── Attribute-targeted reads ──────────────────────────────────────────────

    async def get_events_by_src_ip(
        self,
        src_ip: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """All events where this IP was the source — cross-entity query."""
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.src_ip == src_ip)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        return _rows_to_events(result.scalars().all())

    async def get_events_by_dst_ip(
        self,
        dst_ip: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """All events targeting this destination IP — cross-entity query."""
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.dst_ip == dst_ip)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        return _rows_to_events(result.scalars().all())

    async def get_events_by_username(
        self,
        username: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """All events associated with this user account."""
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.username == username)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        return _rows_to_events(result.scalars().all())

    async def get_events_by_hostname(
        self,
        hostname: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """All events associated with this host or endpoint."""
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.hostname == hostname)
            .order_by(AlertRecord.timestamp.desc())
            .limit(limit)
        )
        stmt = _apply_since(stmt, AlertRecord.timestamp, since)
        result = await self._session.execute(stmt)
        return _rows_to_events(result.scalars().all())

    # ── Utility ───────────────────────────────────────────────────────────────

    async def get_entity_ids(self) -> List[str]:
        from sqlalchemy import distinct
        stmt = select(distinct(AlertRecord.entity_id))
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    # ── Semantic Memory (learned entity profiles) ─────────────────────────────

    async def get_semantic_profile(
        self, entity_id: str
    ) -> Optional[EntitySemanticProfile]:
        """Return the persisted semantic profile for entity_id, or None."""
        stmt = select(EntitySemanticProfile).where(
            EntitySemanticProfile.entity_id == entity_id
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert_semantic_profile(
        self,
        entity_id: str,
        known_good_hours: List[int],
        dominant_event_types: List[str],
        peer_entities: List[str],
        avg_anomaly_score: float,
        fp_confidence: float,
        risk_trend: str,
        total_events_seen: int,
        now: datetime,
    ) -> None:
        """
        Insert or update the semantic memory profile for entity_id.

        Called at the end of every analysis so the profile accumulates
        knowledge progressively across analyses.
        """
        naive_now = now.replace(tzinfo=None) if now.tzinfo else now
        existing = await self.get_semantic_profile(entity_id)
        if existing:
            existing.known_good_hours_json = json.dumps(known_good_hours)
            existing.dominant_event_types_json = json.dumps(dominant_event_types)
            existing.peer_entities_json = json.dumps(peer_entities)
            existing.avg_anomaly_score = avg_anomaly_score
            existing.fp_confidence = fp_confidence
            existing.risk_trend = risk_trend
            existing.total_events_seen = total_events_seen
            existing.last_updated = naive_now
        else:
            record = EntitySemanticProfile(
                entity_id=entity_id,
                known_good_hours_json=json.dumps(known_good_hours),
                dominant_event_types_json=json.dumps(dominant_event_types),
                peer_entities_json=json.dumps(peer_entities),
                avg_anomaly_score=avg_anomaly_score,
                fp_confidence=fp_confidence,
                risk_trend=risk_trend,
                total_events_seen=total_events_seen,
                last_updated=naive_now,
            )
            self._session.add(record)
        await self._session.flush()

    # ── Decision hysteresis ───────────────────────────────────────────────────

    async def get_decision_record(
        self, entity_id: str
    ) -> Optional[EntityDecisionRecord]:
        """Return the persisted decision record for entity_id, or None."""
        stmt = select(EntityDecisionRecord).where(
            EntityDecisionRecord.entity_id == entity_id
        )
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert_decision_record(
        self,
        entity_id: str,
        decision: str,
        score: int,
        now: datetime,
        cooldown_until: Optional[datetime] = None,
    ) -> None:
        """Insert or update the decision record for entity_id.

        cooldown_until is set when a BLOCK decision is issued.
        """
        # Normalise to naive UTC for SQLite
        naive_now = now.replace(tzinfo=None) if now.tzinfo else now
        naive_cooldown = None
        if cooldown_until is not None:
            naive_cooldown = cooldown_until.replace(tzinfo=None) if cooldown_until.tzinfo else cooldown_until

        existing = await self.get_decision_record(entity_id)
        if existing:
            existing.last_decision = decision
            existing.last_score = score
            existing.last_decided_at = naive_now
            existing.cooldown_until = naive_cooldown
        else:
            record = EntityDecisionRecord(
                entity_id=entity_id,
                last_decision=decision,
                last_score=score,
                last_decided_at=naive_now,
                cooldown_until=naive_cooldown,
            )
            self._session.add(record)
        await self._session.flush()
