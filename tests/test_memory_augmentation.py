"""
Memory Augmentation Demonstration Tests
========================================

Câu hỏi cốt lõi: Bộ nhớ có thực sự giúp giảm false positive không?

Đây không phải unit test thông thường — đây là BÀI KIỂM TRA MINH CHỨNG.
Mỗi test kể một câu chuyện hoàn chỉnh:

  Kịch bản 1 (Episodic Memory): Một IP đã quét mạng 30 lần trong 3 ngày,
    toàn bộ là Nmap, không leo thang. Lần thứ 31 → hệ thống nhận ra đây là
    FP pattern, giảm điểm lịch sử → điểm rủi ro thấp hơn hẳn so với lần đầu.

  Kịch bản 2 (Semantic Memory): Hệ thống đã học được rằng IP này hay quét
    vào 9–17h và luôn dùng Nmap. Khi có sự kiện mới đúng loại, đúng giờ →
    semantic discount giảm thêm anomaly score.

  Kịch bản 3 (Combined Effect): Cả hai bộ nhớ kết hợp → cùng một sự kiện
    từ entity có lịch sử benign được chấm điểm THẤP HƠN ĐÁG KỂ so với
    entity mới hoàn toàn.

  Kịch bản 4 (Escalation Guard): Nếu entity bắt đầu leo thang (severity
    tăng dần), semantic discount bị TẮT → hệ thống không bao giờ bỏ qua
    mối đe dọa thực sự.

  Kịch bản 5 (Attack Detection): Entity thực sự tấn công (kill chain hoàn
    chỉnh: recon → brute force → lateral movement) → score phải cao, quyết
    định phải là cảnh báo hoặc chặn.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.history_scorer import (
    SimpleEvent,
    compute_fp_pattern,
    compute_history_score,
    compute_semantic_profile_data,
    SemanticProfileData,
)
from app.services.scoring_engine import compute_hybrid_score
from app.models.schemas import Severity


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _event(
    event_type: str = "ET SCAN Nmap",
    severity: str = "medium",
    anomaly_score: float = 0.30,
    hours_ago: float = 1.0,
) -> SimpleEvent:
    ts = datetime.now(tz=timezone.utc) - timedelta(hours=hours_ago)
    return SimpleEvent(
        event_type=event_type,
        message=f"{event_type} detected",
        severity=severity,
        anomaly_score=anomaly_score,
        timestamp=ts,
    )


def _nmap_history(n: int, span_hours: float = 72.0) -> list[SimpleEvent]:
    """Build n repeated Nmap scan events spread evenly over span_hours."""
    step = span_hours / max(n, 1)
    return [
        _event("ET SCAN Nmap", "medium", 0.30, hours_ago=span_hours - i * step)
        for i in range(n)
    ]


# ─── Kịch bản 1: Episodic Memory giảm điểm lịch sử ──────────────────────────


class TestEpisodicMemoryFPDiscount:
    """
    Bộ nhớ episodic phát hiện pattern lặp lại không leo thang
    và GIẢM đóng góp của lịch sử vào điểm rủi ro.
    """

    def test_no_memory_fp_pattern_score_is_zero(self):
        """
        Lần đầu tiên thấy entity — không có lịch sử,
        fp_pattern_score phải bằng 0.
        """
        result = compute_fp_pattern([])
        assert result.fp_pattern_score == 0.0, (
            "Entity mới không có lịch sử phải cho fp_pattern_score = 0."
        )

    def test_30_repeated_nmap_builds_strong_fp_pattern(self):
        """
        30 lần quét Nmap trong 3 ngày, không leo thang →
        fp_pattern_score phải cao (≥ 0.55).

        Đây là bằng chứng rằng episodic memory nhận ra được FP pattern.
        """
        events = _nmap_history(30, span_hours=72)
        result = compute_fp_pattern(events)

        assert result.fp_pattern_score >= 0.55, (
            f"30 Nmap scans không leo thang phải cho fp_pattern_score >= 0.55. "
            f"Thực tế: {result.fp_pattern_score:.3f}. Summary: {result.summary}"
        )
        assert not result.escalation_detected, (
            "Không có leo thang severity — escalation_detected phải là False."
        )
        assert "ET SCAN Nmap" in result.repeated_event_types

    def test_fp_pattern_discounts_history_score(self):
        """
        Cùng một tập sự kiện:
          - Không có FP pattern  → effective_history = history_score × 1.0
          - Có FP pattern mạnh  → effective_history = history_score × (1 - discount)

        Điểm với FP pattern PHẢI THẤP HƠN điểm không có FP pattern.
        """
        events = _nmap_history(30, span_hours=72)
        history_score = compute_history_score(events)
        fp_pattern = compute_fp_pattern(events)

        score_without_memory = compute_hybrid_score(
            anomaly_score=0.30,
            llm_risk_score=45,
            history_score=history_score,
            severity=Severity.medium,
            fp_pattern=None,
        )

        score_with_episodic_memory = compute_hybrid_score(
            anomaly_score=0.30,
            llm_risk_score=45,
            history_score=history_score,
            severity=Severity.medium,
            fp_pattern=fp_pattern,
        )

        assert score_with_episodic_memory.composite_score < score_without_memory.composite_score, (
            "Episodic memory (FP pattern) phải GIẢM điểm rủi ro cho entity có lịch sử benign. "
            f"Không có memory: {score_without_memory.composite_score:.1f} | "
            f"Có episodic memory: {score_with_episodic_memory.composite_score:.1f}"
        )

        reduction = score_without_memory.composite_score - score_with_episodic_memory.composite_score
        assert reduction >= 2.0, (
            f"Giảm điểm phải ít nhất 2 điểm. Thực tế giảm: {reduction:.1f}."
        )

    def test_escalating_entity_does_not_get_fp_discount(self):
        """
        Nếu entity đang leo thang (severity tăng từ low → critical),
        fp_pattern_score phải thấp — không được discount sự kiện leo thang.

        Đây là safety guard quan trọng nhất của hệ thống.
        """
        escalating_events = [
            _event("ET SCAN Nmap", "low",      0.10, hours_ago=24),
            _event("ET SCAN Nmap", "low",      0.15, hours_ago=20),
            _event("ET SCAN Nmap", "medium",   0.40, hours_ago=12),
            _event("ET SCAN Nmap", "high",     0.75, hours_ago=6),
            _event("ET SCAN Nmap", "critical", 0.95, hours_ago=1),
        ]
        result = compute_fp_pattern(escalating_events)

        assert result.fp_pattern_score < 0.40, (
            f"Entity đang leo thang severity KHÔNG nên có fp_pattern_score cao. "
            f"Thực tế: {result.fp_pattern_score:.3f}."
        )


# ─── Kịch bản 2: Semantic Memory giảm anomaly score ──────────────────────────


class TestSemanticMemoryDiscount:
    """
    Bộ nhớ semantic (kiến thức đã học) giảm anomaly score khi sự kiện hiện tại
    khớp với profile bình thường của entity (đúng loại, đúng giờ).
    """

    def test_familiar_event_type_and_hour_triggers_semantic_discount(self):
        """
        Entity được biết là hay gặp 'ET SCAN Nmap' vào giờ 10h, fp_confidence = 0.7.
        Khi có sự kiện mới đúng loại và đúng giờ →
        semantic_discount > 0 (anomaly score bị giảm).
        """
        learned_profile = SemanticProfileData(
            known_good_hours=[9, 10, 11, 14, 15],
            dominant_event_types=["ET SCAN Nmap"],
            peer_entities=[],
            avg_anomaly_score=0.28,
            fp_confidence=0.70,
            risk_trend="stable",
            total_events_seen=30,
        )

        result = compute_hybrid_score(
            anomaly_score=0.30,
            llm_risk_score=45,
            history_score=0.40,
            severity=Severity.medium,
            semantic_profile=learned_profile,
            current_event_type="ET SCAN Nmap",
            current_hour=10,
        )

        assert result.semantic_memory_discount > 0.0, (
            "Khi sự kiện khớp profile learned (đúng type, đúng giờ), "
            f"semantic_discount phải > 0. Thực tế: {result.semantic_memory_discount}"
        )

    def test_unfamiliar_event_type_gets_no_semantic_discount(self):
        """
        Cùng entity đó, nhưng sự kiện hiện tại là 'C2 Beacon' —
        loại chưa từng thấy trong lịch sử bình thường.
        → semantic_discount phải = 0 (không được bỏ qua sự kiện lạ).
        """
        learned_profile = SemanticProfileData(
            known_good_hours=[9, 10, 11],
            dominant_event_types=["ET SCAN Nmap"],
            peer_entities=[],
            avg_anomaly_score=0.28,
            fp_confidence=0.70,
            risk_trend="stable",
            total_events_seen=30,
        )

        result = compute_hybrid_score(
            anomaly_score=0.85,
            llm_risk_score=80,
            history_score=0.40,
            severity=Severity.high,
            semantic_profile=learned_profile,
            current_event_type="ET TROJAN Generic CnC Beacon",
            current_hour=3,  # 3h sáng — không nằm trong known_good_hours [9, 10, 11]
        )

        assert result.semantic_memory_discount == 0.0, (
            "Sự kiện lạ (C2 Beacon vào 3h sáng) không khớp event type lẫn giờ hoạt động "
            "→ KHÔNG được nhận semantic discount. "
            f"Thực tế: {result.semantic_memory_discount}"
        )

    def test_escalating_trend_disables_semantic_discount(self):
        """
        Dù sự kiện đúng type và đúng giờ, nếu risk_trend = 'escalating'
        thì semantic_discount phải = 0.

        Quy tắc: hệ thống KHÔNG BAO GIỜ che đi mối đe dọa đang leo thang.
        """
        escalating_profile = SemanticProfileData(
            known_good_hours=[9, 10, 11],
            dominant_event_types=["ET SCAN Nmap"],
            peer_entities=[],
            avg_anomaly_score=0.75,
            fp_confidence=0.70,
            risk_trend="escalating",
            total_events_seen=20,
        )

        result = compute_hybrid_score(
            anomaly_score=0.85,
            llm_risk_score=80,
            history_score=0.70,
            severity=Severity.high,
            semantic_profile=escalating_profile,
            current_event_type="ET SCAN Nmap",
            current_hour=10,
        )

        assert result.semantic_memory_discount == 0.0, (
            "Khi risk_trend = 'escalating', semantic_discount PHẢI = 0 "
            "dù event type và giờ có quen thuộc hay không."
        )


# ─── Kịch bản 3: Kết hợp hai bộ nhớ ─────────────────────────────────────────


class TestCombinedMemoryEffect:
    """
    Kịch bản so sánh trực tiếp: cùng một sự kiện, cùng mức độ nguy hiểm bề ngoài,
    nhưng một entity có bộ nhớ đầy đủ và một entity mới hoàn toàn.

    Đây là minh chứng cốt lõi cho giá trị của Memory-Augmented AI.
    """

    def test_entity_with_memory_scores_lower_than_new_entity(self):
        """
        Câu chuyện:

        Entity A (mới):   Cùng sự kiện Nmap, medium severity, anomaly 0.30.
                          Không có lịch sử. Hệ thống không biết entity này là ai.
                          → Điểm rủi ro: tương đối cao (không có context để giảm)

        Entity B (cũ):    Cùng sự kiện đó, nhưng entity này đã quét 30 lần trước,
                          toàn bộ là Nmap, không leo thang. Hệ thống đã học được
                          rằng đây là pattern bình thường.
                          → Điểm rủi ro: thấp hơn đáng kể.

        Mục tiêu: Entity B nhận được điểm THẤP HƠN Entity A cho CÙNG một sự kiện.
        """
        # ── Entity A: mới, không có bộ nhớ ────────────────────────────────────
        score_new_entity = compute_hybrid_score(
            anomaly_score=0.30,
            llm_risk_score=45,
            history_score=0.35,
            severity=Severity.medium,
            fp_pattern=None,
            semantic_profile=None,
        )

        # ── Entity B: đã có 30 lần Nmap, semantic profile đã được học ─────────
        history_events = _nmap_history(30, span_hours=72)
        fp_pattern = compute_fp_pattern(history_events)
        history_score = compute_history_score(history_events)
        semantic_data = compute_semantic_profile_data(history_events, fp_pattern=fp_pattern)

        score_known_entity = compute_hybrid_score(
            anomaly_score=0.30,
            llm_risk_score=45,
            history_score=history_score,
            severity=Severity.medium,
            fp_pattern=fp_pattern,
            semantic_profile=semantic_data,
            current_event_type="ET SCAN Nmap",
            current_hour=14,
        )

        assert score_known_entity.composite_score < score_new_entity.composite_score, (
            "Entity với 30 lần Nmap trong lịch sử (benign pattern) phải có điểm rủi ro "
            "THẤP HƠN entity mới hoàn toàn cho cùng một sự kiện.\n"
            f"Entity mới:   {score_new_entity.composite_score:.1f}\n"
            f"Entity cũ:    {score_known_entity.composite_score:.1f}"
        )

        reduction = score_new_entity.composite_score - score_known_entity.composite_score
        assert reduction >= 3.0, (
            f"Kỳ vọng giảm ít nhất 3 điểm nhờ bộ nhớ. "
            f"Thực tế giảm: {reduction:.1f} điểm."
        )

    def test_fp_pattern_score_increases_with_more_history(self):
        """
        Càng nhiều lịch sử benign → fp_pattern_score càng cao → discount càng mạnh.

        Đây chứng minh rằng hệ thống ngày càng thông minh hơn theo thời gian.
        """
        pattern_5  = compute_fp_pattern(_nmap_history(5,  span_hours=24))
        pattern_15 = compute_fp_pattern(_nmap_history(15, span_hours=48))
        pattern_30 = compute_fp_pattern(_nmap_history(30, span_hours=72))

        assert pattern_5.fp_pattern_score <= pattern_15.fp_pattern_score, (
            "5 sự kiện phải có fp_pattern_score <= 15 sự kiện. "
            f"{pattern_5.fp_pattern_score:.3f} vs {pattern_15.fp_pattern_score:.3f}"
        )
        assert pattern_15.fp_pattern_score <= pattern_30.fp_pattern_score, (
            "15 sự kiện phải có fp_pattern_score <= 30 sự kiện. "
            f"{pattern_15.fp_pattern_score:.3f} vs {pattern_30.fp_pattern_score:.3f}"
        )

    def test_memory_does_not_suppress_real_attack_from_known_entity(self):
        """
        AN TOÀN QUAN TRỌNG: Ngay cả entity đã quen thuộc, nếu đột nhiên xuất hiện
        sự kiện C2 Beacon + lateral movement (kill chain), điểm phải vẫn cao (≥ 60).

        Bộ nhớ giảm false positive — nhưng KHÔNG CHE GIẤU tấn công thực.
        """
        from app.services.sequence_detector import detect_sequences

        history_events = _nmap_history(30, span_hours=72)
        fp_pattern = compute_fp_pattern(history_events)
        history_score = compute_history_score(history_events)
        semantic_data = compute_semantic_profile_data(history_events, fp_pattern=fp_pattern)

        # Đột ngột có C2 beacon + lateral movement — loại sự kiện chưa từng thấy
        attack_events = [
            _event("ET TROJAN Generic CnC Beacon",  "critical", 0.99, hours_ago=2),
            _event("ET EXPLOIT PsExec Lateral Move", "critical", 0.95, hours_ago=1),
        ]
        chains = detect_sequences(attack_events)

        result = compute_hybrid_score(
            anomaly_score=0.99,
            llm_risk_score=88,
            history_score=history_score,
            severity=Severity.critical,
            sequence_matches=chains,
            fp_pattern=fp_pattern,
            semantic_profile=semantic_data,
            current_event_type="ET TROJAN Generic CnC Beacon",
            current_hour=14,
        )

        assert result.composite_score >= 60, (
            f"C2 + lateral movement PHẢI cho điểm ≥ 60 dù entity có lịch sử benign. "
            f"Thực tế: {result.composite_score:.1f}. "
            "Bộ nhớ không được che đi tấn công thực."
        )


# ─── Kịch bản 4: Semantic profile được học từ lịch sử ────────────────────────


class TestSemanticProfileLearning:
    """
    compute_semantic_profile_data() phải trích xuất đúng kiến thức
    từ lịch sử episodic và lưu vào semantic memory.
    """

    def test_known_good_hours_extracted_from_history(self):
        """
        Nếu entity hoạt động chủ yếu vào giờ 9, 10, 11, 14, 15 →
        known_good_hours phải chứa những giờ đó.
        """
        events = []
        for hour in [9, 10, 10, 11, 14, 14, 15]:
            ts = datetime.now(tz=timezone.utc).replace(hour=hour, minute=0, second=0)
            events.append(SimpleEvent(
                event_type="ET SCAN Nmap",
                message="Nmap scan",
                severity="medium",
                anomaly_score=0.25,
                timestamp=ts,
            ))

        profile = compute_semantic_profile_data(events)

        for h in [10, 14]:
            assert h in profile.known_good_hours, (
                f"Giờ {h}h có nhiều hoạt động nhất phải nằm trong known_good_hours. "
                f"Thực tế: {profile.known_good_hours}"
            )

    def test_dominant_event_types_extracted_correctly(self):
        """
        Event type nào xuất hiện ≥ 10% tổng số sự kiện → dominant.
        """
        events = (
            [_event("ET SCAN Nmap") for _ in range(8)]
            + [_event("ET POLICY Outbound") for _ in range(2)]
        )

        profile = compute_semantic_profile_data(events)

        assert "ET SCAN Nmap" in profile.dominant_event_types, (
            f"'ET SCAN Nmap' (80% tổng) phải là dominant event type. "
            f"Thực tế: {profile.dominant_event_types}"
        )

    def test_stable_history_gives_positive_fp_confidence(self):
        """
        30 sự kiện Nmap ổn định, không leo thang →
        fp_confidence phải > 0 (hệ thống tin đây là FP source).
        """
        events = _nmap_history(30, span_hours=72)
        fp_pattern = compute_fp_pattern(events)
        profile = compute_semantic_profile_data(events, fp_pattern=fp_pattern)

        assert profile.fp_confidence > 0.0, (
            f"Lịch sử Nmap ổn định 30 sự kiện phải cho fp_confidence > 0. "
            f"Thực tế: {profile.fp_confidence}"
        )

    def test_risk_trend_stable_for_flat_severity_history(self):
        """
        Tất cả sự kiện đều ở severity medium, không thay đổi →
        risk_trend phải là 'stable'.
        """
        events = _nmap_history(20, span_hours=48)
        profile = compute_semantic_profile_data(events)

        assert profile.risk_trend == "stable", (
            f"Severity không đổi (toàn medium) → risk_trend phải là 'stable'. "
            f"Thực tế: {profile.risk_trend}"
        )
