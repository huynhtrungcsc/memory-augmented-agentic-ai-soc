"""
POST /ingest-log

Accepts a normalised security log, scores it for anomaly likelihood,
persists it to the memory store, and builds entity relationship graph edges.

W9 SECURITY:
  - Token auth via X-SOC-Ingest-Token header (set SOC_INGEST_TOKEN env var).
    If the env var is empty (dev mode), auth is skipped with a warning log.
  - In-memory sliding-window rate limiter per client IP.
    Default: 500 requests / 60 s.  Override via config:
      INGEST_RATE_LIMIT / INGEST_RATE_WINDOW_SECONDS env vars.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.memory.entity_graph import EntityGraphStore
from app.memory.store import MemoryStore
from app.models.schemas import IngestResponse, RawLog
from app.services.anomaly_detector import compute_score

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/ingest-log", tags=["ingestion"])


# ─── Sliding-window rate limiter ──────────────────────────────────────────────
#
# Per client-IP accounting.  Avoids a Redis dependency by using an in-process
# deque of request timestamps.  Thread-safe via a per-IP reentrant lock.
#
# Design:
#   _rate_buckets[ip] = deque of UNIX float timestamps (request times).
#   On each request:
#     1. Prune timestamps older than now - window_seconds.
#     2. If len(deque) >= limit → 429.
#     3. Otherwise append now and proceed.
#
# Trade-off: state is lost on restart.  Acceptable for a single-process SOC
# backend.  Replace with Redis-backed sliding window if horizontal scaling is
# required.
# ──────────────────────────────────────────────────────────────────────────────

_rate_lock = Lock()
_rate_buckets: dict[str, deque] = {}


def _check_rate_limit(client_ip: str) -> None:
    """
    Raise HTTP 429 if client_ip has exceeded the configured request rate.

    Thread-safe.  O(k) where k is the number of requests in the current window.
    """
    limit: int = settings.ingest_rate_limit
    window: int = settings.ingest_rate_window_seconds
    now = time.monotonic()
    cutoff = now - window

    with _rate_lock:
        if client_ip not in _rate_buckets:
            _rate_buckets[client_ip] = deque()

        bucket = _rate_buckets[client_ip]

        # Evict stale timestamps
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded for {client_ip}: "
                    f"max {limit} requests per {window}s."
                ),
            )

        bucket.append(now)


def _verify_ingest_token(x_soc_ingest_token: str | None) -> None:
    """
    Verify the X-SOC-Ingest-Token header against settings.soc_ingest_token.

    Dev mode: if SOC_INGEST_TOKEN is not set (empty), emit a warning and skip
    verification.  This allows development without secrets management overhead.

    Production mode: token must match via constant-time comparison (secrets.compare_digest)
    to prevent timing-oracle attacks.
    """
    expected = settings.soc_ingest_token
    if not expected:
        logger.warning(
            "SOC_INGEST_TOKEN not configured — ingest endpoint is UNAUTHENTICATED "
            "(set the env var before production use)."
        )
        return  # dev mode — skip auth

    if not x_soc_ingest_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-SOC-Ingest-Token header.",
        )

    if not secrets.compare_digest(x_soc_ingest_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ingest token.",
        )


# ─── Entity ID derivation ──────────────────────────────────────────────────────


def _derive_entity_id(log: RawLog) -> str:
    """
    Derive the primary entity key for memory indexing, varying by log source.

    WHY SOURCE-AWARE DERIVATION:
      Naively picking "username > hostname > src_ip" fails for network logs:
      - Suricata/Zeek: 'hostname' usually describes the VICTIM host, not the
        attacker.  src_ip IS the attacker — it should be the primary key so
        analysts can look up all activity from a given IP.
      - Wazuh: 'hostname' is the reporting endpoint (the monitored host).
        username or hostname is the correct primary entity.
      - Splunk/generic: username > hostname > src_ip is a reasonable default.

    Result: Suricata/Zeek logs are indexed by ATTACKER IP, which is what
    analysts want when asking "what did this IP do across all targets?"
    """
    from app.models.schemas import LogSource
    if log.source in (LogSource.suricata, LogSource.zeek):
        return log.src_ip or log.dst_ip or log.username or log.hostname or "unknown"
    else:
        return log.username or log.hostname or log.src_ip or log.dst_ip or "unknown"


# ─── Ingest endpoint ───────────────────────────────────────────────────────────


@router.post("", response_model=IngestResponse, status_code=201)
async def ingest_log(
    request: Request,
    log: RawLog,
    db: AsyncSession = Depends(get_db),
    x_soc_ingest_token: str | None = Header(default=None),
) -> IngestResponse:
    """
    Ingest a single normalised security log.

    Security checks (W9):
      1. X-SOC-Ingest-Token header validation (constant-time).
      2. Sliding-window rate limit by client IP.

    Processing pipeline:
      1. Derive entity ID (source-aware: attacker IP for network logs).
      2. Score event with anomaly detector.
      3. Persist to memory store (with cross-entity attributes).
      4. Build entity relationship graph edges (src_ip→dst_ip, etc.).
      5. Return anomaly verdict.

    Raw payloads are NEVER forwarded to the LLM.
    """
    # ── Auth + rate limit ─────────────────────────────────────────────────────
    _verify_ingest_token(x_soc_ingest_token)

    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    # ── Record processing timestamp + detect delayed logs ────────────────────
    now_utc = datetime.now(tz=timezone.utc)
    log.processing_time = now_utc

    # Normalise event timestamp to UTC for consistent temporal reasoning
    event_ts = log.timestamp
    if event_ts.tzinfo is None:
        event_ts = event_ts.replace(tzinfo=timezone.utc)

    lag_seconds = (now_utc - event_ts).total_seconds()

    if lag_seconds < 0:
        # Future-dated events — clock skew on source system
        logger.warning(
            "Future-dated event received | entity_candidate=%s lag=%.1fs (clock skew?)",
            log.src_ip or log.hostname or "unknown",
            lag_seconds,
        )
        lag_seconds = 0.0

    if lag_seconds > settings.delayed_log_threshold_seconds:
        logger.warning(
            "Delayed log received | entity_candidate=%s lag=%.1fs (threshold=%ds)",
            log.src_ip or log.hostname or "unknown",
            lag_seconds,
            settings.delayed_log_threshold_seconds,
        )

    # ── Core processing ───────────────────────────────────────────────────────
    entity_id = _derive_entity_id(log)
    anomaly_score = compute_score(log)
    is_anomalous = anomaly_score >= 0.5

    store = MemoryStore(db)
    record_id = await store.store_event(
        log_id=0,
        entity_id=entity_id,
        timestamp=log.timestamp,
        event_type=log.event_type,
        severity=log.severity.value,
        message=log.message,
        source=log.source.value,
        anomaly_score=anomaly_score,
        src_ip=log.src_ip,
        dst_ip=log.dst_ip,
        username=log.username,
        hostname=log.hostname,
    )

    # ── Entity relationship graph ─────────────────────────────────────────────
    graph = EntityGraphStore(db)
    ts = log.timestamp

    if log.src_ip and log.dst_ip:
        await graph.store_edge(log.src_ip, log.dst_ip, "traffic", ts)

    if log.src_ip and log.hostname:
        await graph.store_edge(log.src_ip, log.hostname, "targets", ts)

    if log.username and log.hostname:
        await graph.store_edge(log.username, log.hostname, "auth", ts)

    if log.username and log.src_ip:
        await graph.store_edge(log.username, log.src_ip, "connected_from", ts)

    logger.info(
        "Ingested log | entity=%s score=%.3f anomalous=%s client_ip=%s lag=%.1fs",
        entity_id, anomaly_score, is_anomalous, client_ip, lag_seconds,
    )

    return IngestResponse(
        log_id=record_id,
        entity_id=entity_id,
        anomaly_score=anomaly_score,
        is_anomalous=is_anomalous,
        processing_lag_seconds=round(lag_seconds, 1),
        message=(
            f"Log ingested. Entity '{entity_id}' scored {anomaly_score:.2f}. "
            + ("⚠ Anomalous — consider running /analyze-alert." if is_anomalous else "Normal activity level.")
        ),
    )
