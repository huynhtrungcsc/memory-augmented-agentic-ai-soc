"""
Memory retrieval routes.

GET /memory/{entity_id}
  Rich entity context — frequency, attack-type distribution, history_score,
  severity distribution, and recent event timeline.

GET /memory/{entity_id}/by-src-ip
GET /memory/{entity_id}/by-dst-ip     (query param)
GET /memory/by/src-ip?ip=...
GET /memory/by/username?username=...
GET /memory/by/hostname?hostname=...
  Cross-entity attribute retrieval — returns events that share an attribute
  value regardless of which entity_id they were ingested under.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

import json

from app.config import get_settings
from app.database import get_db
from app.memory.sqlite_store import EntityDecisionRecord, EntitySemanticProfile
from app.memory.store import MemoryStore
from app.models.schemas import EntityContext, MemoryEvent, SemanticProfileSchema

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/memory", tags=["memory"])


# ─── Entity context ───────────────────────────────────────────────────────────


@router.get("/{entity_id}", response_model=EntityContext)
async def get_entity_memory(
    entity_id: str,
    hours: Optional[int] = Query(
        None,
        description="Look-back window in hours. Defaults to CONTEXT_WINDOW_HOURS.",
        gt=0,
    ),
    limit: int = Query(50, description="Max events to return.", gt=0, le=200),
    db: AsyncSession = Depends(get_db),
) -> EntityContext:
    """
    Return a rich contextual snapshot of the entity's historical behaviour.

    Includes:
    - history_score       — composite risk signal derived from memory
    - events_per_hour     — activity rate
    - attack_type_distribution — event type breakdown
    - severity_distribution    — severity breakdown
    - recent_timeline     — last N events (newest first)

    MemPalace integration point:
      Swap the MemoryStore implementation in app/memory/store.py to route
      this query through MemPalace's entity profile API.
    """
    window_hours = hours or settings.context_window_hours
    since = datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)

    store = MemoryStore(db)
    ctx = await store.get_entity_context(
        entity_id=entity_id,
        since=since,
        limit=limit,
    )

    logger.info(
        "Memory lookup | entity=%s events=%d history_score=%.3f",
        entity_id, ctx.event_count, ctx.history_score,
    )

    return ctx


# ─── Attribute-targeted queries ───────────────────────────────────────────────


@router.get("/by/src-ip", response_model=List[MemoryEvent])
async def get_events_by_src_ip(
    ip: str = Query(..., description="Source IP address to query"),
    hours: Optional[int] = Query(None, gt=0),
    limit: int = Query(50, gt=0, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[MemoryEvent]:
    """Return all stored events where the given IP was the source."""
    since = _since(hours)
    store = MemoryStore(db)
    events = await store.get_events_by_src_ip(src_ip=ip, since=since, limit=limit)
    logger.info("src-ip query | ip=%s events=%d", ip, len(events))
    return events


@router.get("/by/dst-ip", response_model=List[MemoryEvent])
async def get_events_by_dst_ip(
    ip: str = Query(..., description="Destination IP address to query"),
    hours: Optional[int] = Query(None, gt=0),
    limit: int = Query(50, gt=0, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[MemoryEvent]:
    """Return all stored events targeting the given destination IP."""
    since = _since(hours)
    store = MemoryStore(db)
    events = await store.get_events_by_dst_ip(dst_ip=ip, since=since, limit=limit)
    logger.info("dst-ip query | ip=%s events=%d", ip, len(events))
    return events


@router.get("/by/username", response_model=List[MemoryEvent])
async def get_events_by_username(
    username: str = Query(..., description="Username to query"),
    hours: Optional[int] = Query(None, gt=0),
    limit: int = Query(50, gt=0, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[MemoryEvent]:
    """Return all stored events associated with a given user account."""
    since = _since(hours)
    store = MemoryStore(db)
    events = await store.get_events_by_username(username=username, since=since, limit=limit)
    logger.info("username query | user=%s events=%d", username, len(events))
    return events


@router.get("/by/hostname", response_model=List[MemoryEvent])
async def get_events_by_hostname(
    hostname: str = Query(..., description="Hostname or endpoint to query"),
    hours: Optional[int] = Query(None, gt=0),
    limit: int = Query(50, gt=0, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[MemoryEvent]:
    """Return all stored events associated with a given host or endpoint."""
    since = _since(hours)
    store = MemoryStore(db)
    events = await store.get_events_by_hostname(hostname=hostname, since=since, limit=limit)
    logger.info("hostname query | host=%s events=%d", hostname, len(events))
    return events


# ─── Full 4-Memory-Type Entity Profile ───────────────────────────────────────


@router.get("/entity/{entity_id}/profile", tags=["memory"])
async def get_entity_full_memory_profile(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Return the complete four-memory-type profile for an entity.

    The Memory-Augmented Agentic AI maintains four distinct memory types,
    each serving a unique role in reducing SOC false positives:

    **1. EPISODIC MEMORY** — Raw historical events.
       Records every alert seen for this entity. Used to compute the history
       score and detect recurring FP patterns via `compute_fp_pattern()`.
       Source: `alert_records` table.

    **2. SEMANTIC MEMORY** — Learned behavioural fingerprint.
       Distilled, persistent knowledge about what is 'normal' for this entity:
       known-good hours, dominant event types, FP confidence, risk trend.
       Updated after every analysis. Source: `entity_semantic_profiles` table.

    **3. PROCEDURAL MEMORY** — Decision history & hysteresis.
       Remembers the last decision (block/alert/log) and enforces cooldown
       periods to prevent rapid oscillation. Source: `entity_decision_records` table.

    **4. WORKING MEMORY** — Per-analysis active context.
       The live context assembled during a `POST /analyze-alert` call:
       LLM-consumed context summary, current scoring signals, etc.
       Not persisted — this endpoint returns its last computed summary.
    """
    from sqlalchemy import select
    from app.memory.sqlite_store import AlertRecord, EntityDecisionRecord, EntitySemanticProfile

    store = MemoryStore(db)

    # ── Episodic memory — summary of stored events ─────────────────────────────
    ep_ctx = await store.get_entity_context(entity_id=entity_id, limit=200)
    episodic = {
        "memory_type": "episodic",
        "description": "Raw historical alert events stored for this entity.",
        "event_count": ep_ctx.event_count,
        "first_seen": ep_ctx.first_seen.isoformat() if ep_ctx.first_seen else None,
        "last_seen": ep_ctx.last_seen.isoformat() if ep_ctx.last_seen else None,
        "history_score": ep_ctx.history_score,
        "events_per_hour": ep_ctx.events_per_hour,
        "avg_anomaly_score": ep_ctx.avg_anomaly_score,
        "attack_type_distribution": ep_ctx.attack_type_distribution,
        "severity_distribution": ep_ctx.severity_distribution,
    }

    # ── Semantic memory — learned profile ─────────────────────────────────────
    sem_row = await store.get_semantic_profile(entity_id)
    if sem_row is not None:
        semantic = {
            "memory_type": "semantic",
            "description": "Learned, persistent behavioural fingerprint for this entity.",
            "fp_confidence": sem_row.fp_confidence,
            "risk_trend": sem_row.risk_trend,
            "avg_anomaly_score": sem_row.avg_anomaly_score,
            "total_events_seen": sem_row.total_events_seen,
            "known_good_hours": json.loads(sem_row.known_good_hours_json or "[]"),
            "dominant_event_types": json.loads(sem_row.dominant_event_types_json or "[]"),
            "peer_entities": json.loads(sem_row.peer_entities_json or "[]"),
            "last_updated": sem_row.last_updated.isoformat() if sem_row.last_updated else None,
            "is_new_entity": False,
        }
    else:
        semantic = {
            "memory_type": "semantic",
            "description": "No semantic profile yet — entity has not been analysed.",
            "is_new_entity": True,
        }

    # ── Procedural memory — decision history ──────────────────────────────────
    proc_row = await store.get_decision_record(entity_id)
    if proc_row is not None:
        procedural = {
            "memory_type": "procedural",
            "description": "Persisted decision state and hysteresis cooldown for this entity.",
            "last_decision": proc_row.last_decision,
            "last_score": proc_row.last_score,
            "last_decided_at": proc_row.last_decided_at.isoformat(),
            "cooldown_until": proc_row.cooldown_until.isoformat() if proc_row.cooldown_until else None,
            "in_cooldown": (
                proc_row.cooldown_until is not None
                and proc_row.cooldown_until > datetime.now(tz=timezone.utc).replace(tzinfo=None)
            ),
        }
    else:
        procedural = {
            "memory_type": "procedural",
            "description": "No prior decision recorded — entity has not yet been blocked or alerted.",
            "last_decision": None,
        }

    # ── Working memory — note (not persisted) ─────────────────────────────────
    working = {
        "memory_type": "working",
        "description": (
            "Per-analysis transient context (not persisted). "
            "Working memory is assembled fresh during each POST /analyze-alert call: "
            "it holds the LLM-consumed context summary, scoring signals, and intermediate "
            "analysis state for the duration of a single request."
        ),
        "is_persisted": False,
        "populated_by": "POST /analyze-alert",
    }

    return {
        "entity_id": entity_id,
        "memory_types": {
            "episodic": episodic,
            "semantic": semantic,
            "procedural": procedural,
            "working": working,
        },
        "memory_richness": (
            "rich" if ep_ctx.event_count >= 10 and sem_row is not None and proc_row is not None
            else "moderate" if ep_ctx.event_count >= 3 or sem_row is not None
            else "sparse" if ep_ctx.event_count > 0
            else "none"
        ),
        "note": (
            "Run POST /analyze-alert for this entity to populate/update semantic and "
            "procedural memory. More analyses = richer semantic profile."
        ),
    }


# ─── Helper ───────────────────────────────────────────────────────────────────


def _since(hours: Optional[int]) -> Optional[datetime]:
    if hours is None:
        return None
    return datetime.now(tz=timezone.utc) - timedelta(hours=hours)
