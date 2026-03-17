# Memory-Augmented Agentic AI for SOC

> **Status:** Research prototype — not production-validated.

Research-grade architecture for memory-augmented, agentic AI in Security
Operations Centre (SOC) alert analysis.

## Overview

This project implements a **four-type memory architecture** for context-aware
threat analysis and false-positive reduction:

| Memory Type | Role |
|---|---|
| **Episodic** | Per-entity event history with anomaly scores |
| **Semantic** | Extracted entity patterns and false-positive signals |
| **Procedural** | SOC response playbooks and escalation rules |
| **Working** | In-context summary assembled for each LLM query |

All four memory types update atomically after each `/analyze` request.

## Scoring Pipeline

```
RawLog ──► AnomalyDetector ──► SequenceDetector ──► BaselineDeviation
               │                                            │
               └────────────────────────────────────────────┘
                                      │
                            WorkingMemoryContext
                                      │
                             LLMClient (mock/live)
                                      │
                            HybridScoringEngine
                         w_anomaly=0.25, w_llm=0.45
                         w_history=0.20, w_severity=0.10
                                      │
                            HistoryScorer + FP Discount
                         effective = history × (1 − fp × 0.80)
                                      │
                           DecisionEngine → PolicyResponse
```

## Tech Stack

- **Backend:** FastAPI (async) + aiosqlite
- **LLM:** OpenAI-compatible endpoint (configurable) with keyword-based mock
- **Storage:** SQLite (dev); swap `DATABASE_URL` for PostgreSQL in production
- **Tests:** pytest (301 tests)

## Quick Start

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 5000 --reload
```

See `.env.example` for configuration options.
