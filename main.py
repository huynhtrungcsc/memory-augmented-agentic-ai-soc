"""
Memory-Augmented Agentic AI for Context-Aware Log Analysis
SOC False-Positive Reduction Prototype

Entry point — run with:
  uvicorn main:app --host 0.0.0.0 --port 5000 --reload
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db
from app.routes.ingest import router as ingest_router
from app.routes.analyze import router as analyze_router
from app.routes.memory import router as memory_router
from app.routes.decide import router as decide_router
from app.routes.graph import router as graph_router

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ─── Application factory ──────────────────────────────────────────────────────

app = FastAPI(
    title="SOC Memory-Augmented AI",
    description=(
        "Context-aware log analysis and false-positive reduction for SOC teams.\n\n"
        "Uses a pluggable memory layer and a provider-agnostic LLM client to "
        "reason over historical entity behaviour before classifying alerts.\n\n"
        "**Memory-Augmented**: The system tracks each entity's alert history to "
        "distinguish known-benign FP patterns from novel threats — reducing alert fatigue.\n\n"
        f"**LLM mode**: {'🟡 MOCK (set LLM_API_KEY + LLM_BASE_URL to enable live reasoning)' if settings.llm_mock_mode else '🟢 LIVE'}"
    ),
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Lifecycle ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def on_startup() -> None:
    await init_db()
    mode = "MOCK" if settings.llm_mock_mode else f"LIVE ({settings.llm_base_url})"
    logger.info("SOC AI started | env=%s | LLM=%s", settings.app_env, mode)


# ─── Routers ──────────────────────────────────────────────────────────────────

app.include_router(ingest_router)
app.include_router(analyze_router)
app.include_router(memory_router)
app.include_router(decide_router)
app.include_router(graph_router)


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "version": "0.2.0",
        "llm_mode": "mock" if s.llm_mock_mode else "live",
        "llm_provider": s.effective_llm_base_url if not s.llm_mock_mode else None,
        "model": s.llm_model,
        "memory_backend": "sqlite",
        "fp_pattern_discount_weight": s.fp_pattern_discount_weight,
    }
