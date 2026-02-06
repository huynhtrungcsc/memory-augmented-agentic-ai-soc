import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    log_level: str = "INFO"

    # Use SOC_DATABASE_URL to avoid colliding with the workspace Postgres DATABASE_URL secret.
    soc_database_url: str = "sqlite+aiosqlite:///./soc_memory.db"

    # ── LLM provider ──────────────────────────────────────────────────────────
    # Priority:
    #   1. Explicit LLM_API_KEY + LLM_BASE_URL (bring your own provider)
    #   2. AI_INTEGRATIONS_OPENAI_* (Replit managed LLM — no key needed)
    #   3. Mock mode (deterministic simulation, no LLM calls)
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout: int = 30

    # Replit AI Integrations auto-provisioned credentials (set by Replit, not by user)
    ai_integrations_openai_api_key: str = ""
    ai_integrations_openai_base_url: str = ""

    # Context window for entity summarisation
    context_window_hours: int = 24
    max_context_events: int = 20

    # Decision policy thresholds
    block_threshold: int = 80
    alert_threshold: int = 50

    # Ingest endpoint authentication and rate limiting
    soc_ingest_token: str = ""
    ingest_rate_limit: int = 500
    ingest_rate_window_seconds: int = 60

    # Decision hysteresis — prevents rapid oscillation when an entity's
    # score momentarily dips below a threshold during an ongoing attack.
    hysteresis_hours: float = 4.0
    hysteresis_score_floor: int = 30

    # Decision stability — minimum evidence requirements before BLOCK.
    min_signals_for_block: int = 2
    block_cooldown_hours: float = 1.0
    review_lower_bound: int = 70

    # LLM retry + timeout
    llm_max_retries: int = 1
    llm_retry_delay_seconds: float = 1.5

    # Memory decay — older events contribute less to scoring.
    memory_decay_half_life_hours: float = 12.0

    # Observability
    debug_mode: bool = False
    delayed_log_threshold_seconds: int = 300

    # Additive boost caps (score points added after base 0-100 score)
    sequence_boost_max: float = 15.0
    baseline_boost_max: float = 10.0

    # Hybrid scoring weights (should sum to ~1.0)
    weight_anomaly: float = 0.25
    weight_llm: float = 0.45
    weight_history: float = 0.20
    weight_severity: float = 0.10

    # ── Memory-Augmented FP pattern discount ──────────────────────────────────
    # When an entity has a known false-positive pattern in memory, the history
    # contribution to the composite risk score is discounted by:
    #   effective_history = history_score × (1 − fp_pattern_score × fp_pattern_discount_weight)
    #
    # At 0.80 (default): a perfect FP pattern (score=1.0) reduces the history
    # contribution to 20% of its original value — enough to prevent benign entities
    # from accumulating risk, while still raising alerts if they escalate.
    fp_pattern_discount_weight: float = 0.80

    # ── Effective LLM credentials (auto-resolved at runtime) ──────────────────

    @property
    def effective_llm_api_key(self) -> str:
        """
        Resolve the API key in priority order:
          1. Explicit LLM_API_KEY env var
          2. Replit AI Integrations key (AI_INTEGRATIONS_OPENAI_API_KEY)
          3. Empty string → mock mode
        """
        return (
            self.llm_api_key.strip()
            or self.ai_integrations_openai_api_key.strip()
        )

    @property
    def effective_llm_base_url(self) -> str:
        """
        Resolve the API base URL in priority order:
          1. If explicit LLM_API_KEY is set → use LLM_BASE_URL (user's provider)
          2. If Replit integration is available → use AI_INTEGRATIONS_OPENAI_BASE_URL
          3. Default OpenAI base URL
        """
        if self.llm_api_key.strip():
            return self.llm_base_url
        return (
            self.ai_integrations_openai_base_url.strip()
            or self.llm_base_url
        )

    @property
    def llm_mock_mode(self) -> bool:
        """True only when no real LLM credentials are available at all."""
        return not self.effective_llm_api_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
