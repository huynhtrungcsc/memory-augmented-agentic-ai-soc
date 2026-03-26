"""
Tests for memory retrieval and history scoring.

Split into two categories:
1. Pure unit tests for history_scorer.py helpers (no DB needed)
2. Async integration tests for SQLiteMemoryStore attribute queries (in-memory SQLite)

Run with:
  pytest tests/test_memory_retrieval.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.memory.sqlite_store import SQLiteMemoryStore
from app.services.history_scorer import (
    SimpleEvent,
    compute_context_stats,
    compute_history_score,
    derive_dominant_severity,
)


# ─── Test fixtures ────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def db_session():
    """In-memory SQLite session, fresh per test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()
    await engine.dispose()


def _make_event(
    event_type: str = "TEST",
    severity: str = "medium",
    anomaly_score: float = 0.5,
    minutes_ago: int = 10,
) -> SimpleEvent:
    return SimpleEvent(
        event_type=event_type,
        severity=severity,
        anomaly_score=anomaly_score,
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
    )


# ─── History score — unit tests ───────────────────────────────────────────────


class TestComputeHistoryScore:
    """Pure unit tests — no database required."""

    def test_empty_events_returns_zero(self):
        assert compute_history_score([]) == 0.0

    def test_score_is_between_0_and_1(self):
        events = [_make_event(severity="critical", anomaly_score=1.0) for _ in range(50)]
        score = compute_history_score(events)
        assert 0.0 <= score <= 1.0

    def test_single_low_severity_event_gives_low_score(self):
        score = compute_history_score([_make_event(severity="low", anomaly_score=0.1)])
        assert score < 0.35

    def test_single_critical_event_gives_moderate_score(self):
        score = compute_history_score([_make_event(severity="critical", anomaly_score=1.0)])
        assert score >= 0.35

    def test_many_high_severity_events_give_high_score(self):
        events = [_make_event(severity="critical", anomaly_score=0.9) for _ in range(25)]
        score = compute_history_score(events)
        assert score >= 0.7

    def test_more_events_increases_score(self):
        few = [_make_event(severity="medium", anomaly_score=0.5) for _ in range(2)]
        many = [_make_event(severity="medium", anomaly_score=0.5) for _ in range(20)]
        assert compute_history_score(many) > compute_history_score(few)

    def test_higher_anomaly_score_increases_history_score(self):
        low = [_make_event(severity="medium", anomaly_score=0.1) for _ in range(5)]
        high = [_make_event(severity="medium", anomaly_score=0.9) for _ in range(5)]
        assert compute_history_score(high) > compute_history_score(low)

    def test_score_saturates_at_1(self):
        events = [_make_event(severity="critical", anomaly_score=1.0) for _ in range(100)]
        assert compute_history_score(events) <= 1.0

    def test_all_low_severity_low_anomaly_stays_below_threshold(self):
        events = [_make_event(severity="low", anomaly_score=0.05) for _ in range(3)]
        assert compute_history_score(events) < 0.5


class TestComputeContextStats:
    """Tests for aggregate statistics helper."""

    def test_empty_events_returns_zeros(self):
        eps, attack_dist, sev_dist, avg_anomaly = compute_context_stats([])
        assert eps == 0.0
        assert attack_dist == {}
        assert sev_dist == {}
        assert avg_anomaly == 0.0

    def test_attack_type_distribution_counts_correctly(self):
        events = [
            _make_event(event_type="SSH_SCAN"),
            _make_event(event_type="SSH_SCAN"),
            _make_event(event_type="SQL_INJECTION"),
        ]
        _, attack_dist, _, _ = compute_context_stats(events)
        assert attack_dist["SSH_SCAN"] == 2
        assert attack_dist["SQL_INJECTION"] == 1

    def test_severity_distribution_counts_correctly(self):
        events = [
            _make_event(severity="critical"),
            _make_event(severity="high"),
            _make_event(severity="high"),
            _make_event(severity="low"),
        ]
        _, _, sev_dist, _ = compute_context_stats(events)
        assert sev_dist["critical"] == 1
        assert sev_dist["high"] == 2
        assert sev_dist["low"] == 1

    def test_avg_anomaly_is_correct_mean(self):
        events = [
            _make_event(anomaly_score=0.2),
            _make_event(anomaly_score=0.6),
            _make_event(anomaly_score=0.4),
        ]
        _, _, _, avg = compute_context_stats(events)
        assert abs(avg - 0.4) < 0.01

    def test_events_per_hour_is_positive(self):
        events = [
            _make_event(minutes_ago=60),
            _make_event(minutes_ago=30),
            _make_event(minutes_ago=1),
        ]
        eps, _, _, _ = compute_context_stats(events)
        assert eps > 0.0


class TestDeriveDominantSeverity:
    """Tests for dominant severity extraction."""

    def test_critical_dominates_all(self):
        dist = {"critical": 1, "high": 5, "medium": 10}
        assert derive_dominant_severity(dist) == "critical"

    def test_high_dominates_medium_and_low(self):
        dist = {"high": 3, "medium": 10, "low": 20}
        assert derive_dominant_severity(dist) == "high"

    def test_empty_distribution_returns_low(self):
        assert derive_dominant_severity({}) == "low"

    def test_only_low_returns_low(self):
        assert derive_dominant_severity({"low": 5}) == "low"


# ─── SQLiteMemoryStore integration tests ─────────────────────────────────────


class TestAttributeQueries:
    """Integration tests using in-memory SQLite."""

    @pytest.mark.asyncio
    async def test_store_and_retrieve_by_src_ip(self, db_session):
        store = SQLiteMemoryStore(db_session)
        await store.store_event(
            log_id=1, entity_id="host-A",
            timestamp=datetime.utcnow(), event_type="SCAN",
            severity="high", message="port scan", source="suricata",
            anomaly_score=0.7, src_ip="10.1.1.5",
        )
        events = await store.get_events_by_src_ip("10.1.1.5")
        assert len(events) == 1
        assert events[0].src_ip == "10.1.1.5"

    @pytest.mark.asyncio
    async def test_src_ip_query_returns_multiple_entities(self, db_session):
        store = SQLiteMemoryStore(db_session)
        for entity in ("host-A", "host-B", "host-C"):
            await store.store_event(
                log_id=1, entity_id=entity,
                timestamp=datetime.utcnow(), event_type="SCAN",
                severity="medium", message="test", source="zeek",
                anomaly_score=0.4, src_ip="192.168.7.7",
            )
        events = await store.get_events_by_src_ip("192.168.7.7")
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_store_and_retrieve_by_dst_ip(self, db_session):
        store = SQLiteMemoryStore(db_session)
        await store.store_event(
            log_id=2, entity_id="attacker",
            timestamp=datetime.utcnow(), event_type="EXPLOIT",
            severity="critical", message="exploit attempt", source="suricata",
            anomaly_score=0.9, dst_ip="10.0.0.1",
        )
        events = await store.get_events_by_dst_ip("10.0.0.1")
        assert len(events) == 1
        assert events[0].dst_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_store_and_retrieve_by_username(self, db_session):
        store = SQLiteMemoryStore(db_session)
        await store.store_event(
            log_id=3, entity_id="jsmith",
            timestamp=datetime.utcnow(), event_type="PRIV_ESC",
            severity="critical", message="sudo abuse", source="wazuh",
            anomaly_score=0.95, username="jsmith",
        )
        events = await store.get_events_by_username("jsmith")
        assert len(events) == 1
        assert events[0].username == "jsmith"

    @pytest.mark.asyncio
    async def test_store_and_retrieve_by_hostname(self, db_session):
        store = SQLiteMemoryStore(db_session)
        await store.store_event(
            log_id=4, entity_id="db-prod-01",
            timestamp=datetime.utcnow(), event_type="CREDENTIAL_DUMP",
            severity="critical", message="shadow read", source="wazuh",
            anomaly_score=0.98, hostname="db-prod-01",
        )
        events = await store.get_events_by_hostname("db-prod-01")
        assert len(events) == 1
        assert events[0].hostname == "db-prod-01"

    @pytest.mark.asyncio
    async def test_attribute_query_returns_empty_for_unknown(self, db_session):
        store = SQLiteMemoryStore(db_session)
        events = await store.get_events_by_src_ip("99.99.99.99")
        assert events == []

    @pytest.mark.asyncio
    async def test_get_entity_context_includes_history_score(self, db_session):
        store = SQLiteMemoryStore(db_session)
        for i in range(5):
            await store.store_event(
                log_id=i, entity_id="attacker-ip",
                timestamp=datetime.utcnow() - timedelta(minutes=i * 5),
                event_type="SCAN", severity="high",
                message="scan", source="suricata",
                anomaly_score=0.75,
            )
        ctx = await store.get_entity_context("attacker-ip")
        assert ctx.event_count == 5
        assert ctx.history_score > 0.0
        assert ctx.history_score <= 1.0

    @pytest.mark.asyncio
    async def test_get_entity_context_distributions(self, db_session):
        store = SQLiteMemoryStore(db_session)
        await store.store_event(
            log_id=1, entity_id="e1", timestamp=datetime.utcnow() - timedelta(hours=1),
            event_type="SSH_SCAN", severity="high", message="scan", source="suricata", anomaly_score=0.7,
        )
        await store.store_event(
            log_id=2, entity_id="e1", timestamp=datetime.utcnow(),
            event_type="BRUTE_FORCE", severity="critical", message="brute", source="suricata", anomaly_score=0.9,
        )
        ctx = await store.get_entity_context("e1")
        assert ctx.attack_type_distribution["SSH_SCAN"] == 1
        assert ctx.attack_type_distribution["BRUTE_FORCE"] == 1
        assert ctx.severity_distribution["high"] == 1
        assert ctx.severity_distribution["critical"] == 1

    @pytest.mark.asyncio
    async def test_empty_entity_context_returns_zero_history_score(self, db_session):
        store = SQLiteMemoryStore(db_session)
        ctx = await store.get_entity_context("nonexistent-entity")
        assert ctx.history_score == 0.0
        assert ctx.event_count == 0
        assert ctx.recent_timeline == []

    @pytest.mark.asyncio
    async def test_context_events_per_hour_is_positive(self, db_session):
        store = SQLiteMemoryStore(db_session)
        for i in range(3):
            await store.store_event(
                log_id=i, entity_id="fast-entity",
                timestamp=datetime.utcnow() - timedelta(minutes=i * 10),
                event_type="SCAN", severity="medium", message="scan",
                source="zeek", anomaly_score=0.4,
            )
        ctx = await store.get_entity_context("fast-entity")
        assert ctx.events_per_hour > 0.0
