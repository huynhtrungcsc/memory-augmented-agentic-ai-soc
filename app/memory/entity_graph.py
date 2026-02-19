"""
Entity Relationship Graph — SQLite ORM + query layer.

WHY THIS EXISTS — The lateral movement blind spot:
  When attacker IP 10.3.7.42 port-scans server A, brute-forces server B,
  then authenticates on server C, the current memory layer treats each event
  independently.  There is no data structure that says:
    "10.3.7.42 → server-A (targeted), 10.3.7.42 → server-B (targeted)"
  
  This means an analyst querying "who attacked server-B?" can find the answer,
  but the system itself cannot automatically:
    - Propagate risk from a confirmed attacker to related entities
    - Build a visual attack path (IP → host → user)
    - Detect when the same entity pivoted across multiple targets

HOW IT WORKS:
  When a log is ingested, edges are created/incremented between entities:
    src_ip → dst_ip       edge_type = "traffic"
    src_ip → hostname     edge_type = "targets"
    username → hostname   edge_type = "auth"
    username → src_ip     edge_type = "connected_from"

  The edge table stores event_count and last_seen, so repeated activity
  on the same path increases confidence (not just one data point).

  At analysis time:
    - get_entity_edges(entity_id) returns all connected entities
    - The context builder includes this graph section in the LLM summary
    - Risk from confirmed attackers is visible to connected entities

MemPalace integration point:
  Replace EntityGraphStore with a MemPalace knowledge graph backend.
  The abstract interface (store_edge / get_entity_edges / get_edge_count) is
  the stable contract.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import Column, DateTime, Index, Integer, String, UniqueConstraint, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base


# ─── ORM model ────────────────────────────────────────────────────────────────


class EntityEdgeRecord(Base):
    """
    Directed edge in the entity relationship graph.

    An edge (src_entity, dst_entity, edge_type) is created once and its
    event_count is incremented on each new observation.  The composite unique
    constraint ensures there is at most one edge record per directed pair+type.
    """

    __tablename__ = "entity_edges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_entity = Column(String(256), nullable=False)
    dst_entity = Column(String(256), nullable=False)
    edge_type = Column(String(64), nullable=False)
    event_count = Column(Integer, default=1)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("src_entity", "dst_entity", "edge_type", name="uq_edge"),
        Index("ix_entity_edges_src", "src_entity"),
        Index("ix_entity_edges_dst", "dst_entity"),
    )


# ─── Store ────────────────────────────────────────────────────────────────────


class EntityGraphStore:
    """SQLite-backed entity graph — upserts edges and queries connections."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def store_edge(
        self,
        src_entity: str,
        dst_entity: str,
        edge_type: str,
        timestamp: datetime,
    ) -> None:
        """
        Create a new edge or increment event_count on an existing one.

        Idempotent: calling multiple times for the same (src, dst, type) pair
        simply increments the counter — no duplicate rows are created.
        """
        if not src_entity or not dst_entity or src_entity == dst_entity:
            return  # skip self-loops and empty entities

        # Normalise to naive UTC for SQLite
        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)

        # Attempt to find existing edge
        stmt = select(EntityEdgeRecord).where(
            EntityEdgeRecord.src_entity == src_entity,
            EntityEdgeRecord.dst_entity == dst_entity,
            EntityEdgeRecord.edge_type == edge_type,
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.event_count += 1
            existing.last_seen = timestamp
        else:
            edge = EntityEdgeRecord(
                src_entity=src_entity,
                dst_entity=dst_entity,
                edge_type=edge_type,
                event_count=1,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self._session.add(edge)

        await self._session.flush()

    async def get_entity_edges(
        self,
        entity_id: str,
        limit: int = 50,
    ) -> List[EntityEdgeRecord]:
        """
        Return all edges where entity_id is either the source or destination.

        Results are ordered by event_count descending so the most-active
        relationships appear first.
        """
        stmt = (
            select(EntityEdgeRecord)
            .where(
                (EntityEdgeRecord.src_entity == entity_id)
                | (EntityEdgeRecord.dst_entity == entity_id)
            )
            .order_by(EntityEdgeRecord.event_count.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_outbound_edges(
        self,
        src_entity: str,
        limit: int = 50,
    ) -> List[EntityEdgeRecord]:
        """Return edges where this entity is the attacker/initiator."""
        stmt = (
            select(EntityEdgeRecord)
            .where(EntityEdgeRecord.src_entity == src_entity)
            .order_by(EntityEdgeRecord.event_count.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_inbound_edges(
        self,
        dst_entity: str,
        limit: int = 50,
    ) -> List[EntityEdgeRecord]:
        """Return edges where this entity was the target/destination."""
        stmt = (
            select(EntityEdgeRecord)
            .where(EntityEdgeRecord.dst_entity == dst_entity)
            .order_by(EntityEdgeRecord.event_count.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_edge_count(self, entity_id: str) -> int:
        """Count total edges (inbound + outbound) for this entity."""
        stmt = select(EntityEdgeRecord).where(
            (EntityEdgeRecord.src_entity == entity_id)
            | (EntityEdgeRecord.dst_entity == entity_id)
        )
        result = await self._session.execute(stmt)
        return len(result.scalars().all())
