"""
GET /graph/{entity_id}

Returns the entity relationship graph — all known connections to and from
an entity, built automatically as logs are ingested.

This endpoint allows analysts to:
  - Trace attack paths (attacker IP → targeted servers → compromised users)
  - Identify multi-target campaigns from a single source
  - Understand the blast radius of a potential compromise
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.memory.entity_graph import EntityGraphStore
from app.models.schemas import EntityEdgeSchema, EntityGraphSchema

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/graph", tags=["entity-graph"])


@router.get("/{entity_id}", response_model=EntityGraphSchema)
async def get_entity_graph(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
) -> EntityGraphSchema:
    """
    Return all entity relationship edges for the given entity.

    Edges are created automatically during log ingestion:
      - src_ip → dst_ip   (traffic)
      - src_ip → hostname (targets)
      - username → host   (auth)
      - username → src_ip (connected_from)

    Results are sorted by event_count descending — most-active relationships first.
    """
    graph = EntityGraphStore(db)
    edge_records = await graph.get_entity_edges(entity_id, limit=100)

    edges = [
        EntityEdgeSchema(
            related_entity=e.dst_entity if e.src_entity == entity_id else e.src_entity,
            direction="outbound" if e.src_entity == entity_id else "inbound",
            edge_type=e.edge_type,
            event_count=e.event_count,
            first_seen=e.first_seen,
            last_seen=e.last_seen,
        )
        for e in edge_records
    ]

    logger.info("Graph lookup | entity=%s edges=%d", entity_id, len(edges))

    return EntityGraphSchema(
        entity_id=entity_id,
        edges=edges,
        total_connections=len(edges),
    )
