"""
Abstract memory interface.

Swap in any persistent store — MemPalace, Redis, a vector DB, or a remote
service — by subclassing AbstractMemoryStore and wiring the concrete
implementation into app/memory/store.py.

MemPalace integration point:
  1. Install the MemPalace SDK.
  2. Create `app/memory/mempalace_store.py` with a subclass of AbstractMemoryStore.
  3. Change the import in `app/memory/store.py` from SQLiteMemoryStore to MemPalaceStore.
  Everything else in the application remains untouched.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from app.models.schemas import EntityContext, MemoryEvent


class AbstractMemoryStore(ABC):
    """Contract that every memory back-end must satisfy."""

    # ── Core write ────────────────────────────────────────────────────────────

    @abstractmethod
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
        """Persist a single processed event for a given entity. Returns the new record ID."""
        ...

    # ── Entity-level reads ────────────────────────────────────────────────────

    @abstractmethod
    async def get_events(
        self,
        entity_id: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """Retrieve historical events for an entity, newest first."""
        ...

    @abstractmethod
    async def get_entity_context(
        self,
        entity_id: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> EntityContext:
        """
        Return a rich contextual snapshot of the entity's historical behaviour,
        including frequency, severity distribution, attack-type distribution,
        and derived history_score.

        MemPalace integration point:
          Replace this method body with a call to the MemPalace entity profile
          API.  The returned EntityContext shape is provider-agnostic.
        """
        ...

    # ── Attribute-targeted reads ──────────────────────────────────────────────

    @abstractmethod
    async def get_events_by_src_ip(
        self,
        src_ip: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """Return all events where this IP was observed as the source."""
        ...

    @abstractmethod
    async def get_events_by_dst_ip(
        self,
        dst_ip: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """Return all events where this IP was observed as the destination."""
        ...

    @abstractmethod
    async def get_events_by_username(
        self,
        username: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """Return all events associated with a specific user account."""
        ...

    @abstractmethod
    async def get_events_by_hostname(
        self,
        hostname: str,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[MemoryEvent]:
        """Return all events associated with a specific host/endpoint."""
        ...

    # ── Utility ───────────────────────────────────────────────────────────────

    @abstractmethod
    async def get_entity_ids(self) -> List[str]:
        """Return all known entity IDs stored in memory."""
        ...
