<div align="center">

# memory-augmented-agentic-ai-soc

**Memory-Augmented Agentic AI for Security Operations Centres**

*FastAPI · aiosqlite · Python 3.12 · OpenAI-compatible LLM*

![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-aiosqlite-003B57?logo=sqlite&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-301%20passing-4CAF50?logo=pytest&logoColor=white)
![Memory Types](https://img.shields.io/badge/Memory%20Types-4-7B68EE)
![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-EF9421?logo=creativecommons&logoColor=white)
![Status](https://img.shields.io/badge/Status-Research%20Prototype-FF8C00)

</div>

A reference architecture and research prototype demonstrating how persistent entity memory can be integrated into a SOC alert analysis pipeline.

## What This Project Is

Security teams are overwhelmed by alerts. Most are false positives — the same scanner, the same admin tool, the same scheduled task triggering the same rule repeatedly. Standard detection tools evaluate each alert in isolation and cannot learn "this host always does this."

This project explores one specific design question:

> *If an AI agent that analyses security logs had four distinct types of persistent memory — Episodic, Semantic, Procedural, and Working — what would the architecture and implementation look like, and does the safety constraint hold?*

It is a **reference architecture with a working implementation**, not a production SOC tool. It demonstrates how memory augmentation can be structured, tested, and connected to a real LLM. Its primary validated property is that the memory system does not suppress genuine attacks even when an entity has a rich benign history.

## What This Project Demonstrates (Verified)

| Claim | Evidence |
|---|---|
| 4-type memory architecture runs correctly end-to-end | 301 unit tests pass; all 4 memory types update after each analysis |
| Safety constraint holds: memory does not suppress real attacks | Benchmark: Groups D+E (30 attack scenarios, worst-case benign history) — Recall 100% with full memory |
| FP pattern discount accumulates monotonically with entity history | Benchmark Table 5: fp_pattern_score 0.000 to 1.000 as n grows from 0 to 30 events |
| Memory requires at least 20 entity events before reliably reducing FPR | Benchmark Table 5: score flips below threshold at n=20, not n=5 or n=10 |
| API accepts any OpenAI-compatible LLM endpoint | Configurable via `LLM_API_KEY` and `LLM_BASE_URL` env vars |

## What This Project Does Not Demonstrate

| Claim | Why it is not demonstrated |
|---|---|
| Memory reduces false positives in a production SOC | No real SOC log data with analyst-confirmed labels was used |
| Memory improves overall FPR | Benchmark shows FPR worsens with shallow history (n less than 18): C0=48.9% to C3=53.3% |
| The LLM component performs real reasoning | Default mode is a keyword-matching heuristic, not a language model |
| Results generalise beyond the tested scenarios | All scenarios are hand-designed; no external validation |

Run the benchmark to see the full honest results: `python scripts/memory_benchmark.py`

## The Four Memory Types

This is the core of the architecture. Four distinct memory types, each playing a different role:

### 1. Episodic Memory

**What it stores:** Every raw alert event for every entity, with full context (timestamp, severity, source, anomaly score).

**What it does:** Detects recurring false-positive patterns. If entity `10.0.0.5` has triggered `ET SCAN Nmap` repeatedly with no escalation, the system accumulates an FP pattern score and discounts the history contribution accordingly.

**Key formula:** `effective_history = history_score x (1 - fp_pattern_score x 0.80)`

**Where it lives:** `alert_records` table in SQLite.

### 2. Semantic Memory

**What it stores:** A persistent learned profile for each entity, distilled across all analyses:
- `fp_confidence` — accumulated confidence that this entity is a benign FP source (blended: `new = prior x 0.6 + current x 0.4`)
- `risk_trend` — `stable` / `escalating` / `deescalating`
- `known_good_hours` — hours of day where activity is historically normal
- `dominant_event_types` — alert types that are routine (at least 10% of events)
- `peer_entities` — known communication partners from the relationship graph

**What it does:** If the current event matches the learned profile (familiar type, known-good hour) and `fp_confidence > 0.3`, a semantic discount is applied to the anomaly score before the LLM sees it.

**Where it lives:** `entity_semantic_profiles` table in SQLite.

### 3. Procedural Memory

**What it stores:** The last decision for each entity, when it was made, and any block cooldown expiry.

**What it does:** Prevents rapid oscillation between decisions. Block decisions persist for a configurable cooldown. Upgrades apply immediately; downgrades are deferred.

**Where it lives:** `entity_decision_records` table in SQLite.

### 4. Working Memory

**What it stores:** The full analysis context assembled for a single `POST /analyze-alert` request — all three other memory types synthesised into a structured prose summary for the LLM.

**What it does:** Provides the LLM with entity history and learned profile alongside the current event. Raw log payloads are never included — only sanitised, structured information.

**Where it lives:** In-process only. Assembled fresh per request, never persisted.

## How the Score is Computed

Every analysis produces a composite risk score (0–100):

```
Step 1: Anomaly score (rule-based, 0-1)
  - trust_discount     (known scanner/admin source)
  x category_factor    (admin activity = 0.75x, C2/exfil = 1.20x)
  - semantic_discount  (SEMANTIC MEMORY: familiar type + known-good hour)
  = adjusted_anomaly

Step 2: History score (from EPISODIC MEMORY, 0-1)
  x (1 - fp_pattern_score x 0.80)   (EPISODIC FP PATTERN DISCOUNT)
  = effective_history

Step 3: Base score (weighted sum, weights sum to 1.00)
  = 0.25 x adjusted_anomaly
  + 0.45 x llm_score          (LLM risk assessment: highest weight)
  + 0.20 x effective_history
  + 0.10 x severity_score

Step 4: Additive boosts
  + sequence_boost     (MITRE ATT&CK kill-chain detected)
  + baseline_boost     (activity spike above 24-hour baseline)
  + persistence_boost  (low-and-slow pattern over 72 hours)

Step 5: Calibration
  confidence      = f(event_count, signal_agreement, contradiction)
  calibrated_score = composite x confidence + 50 x (1 - confidence)
```

The `calibrated_score` drives the decision: `block` / `review_required` / `alert_analyst` / `log_only`.

## About the LLM Component

### Mock mode (default, no API key required)

When no `LLM_API_KEY` is configured, the system uses a keyword-matching heuristic (`app/services/llm_client.py`). It reads the context summary text and pattern-matches against signal words:

- "scan" in context: `risk_score = 35, fp_likelihood = 0.40`
- "brute" + "success": `risk_score = 88, fp_likelihood = 0.04`
- "exfil" + "compromise": `risk_score = 90, fp_likelihood = 0.03`

All mock responses are labelled `[MOCK — configure AI integration for real LLM reasoning]`. **This is not a language model.** It is a fast, deterministic fallback for development and testing.

**Scientific implication:** The benchmark (`scripts/memory_benchmark.py`) uses a separate formula-based proxy for the LLM score. It does not call the mock heuristic. Results therefore characterise the memory mechanisms in isolation, not the integrated system with its actual mock LLM.

### Live mode (real LLM)

Set environment variables to connect to any OpenAI-compatible endpoint:

```dotenv
LLM_API_KEY=your-api-key-here
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

With a real LLM, the system sends the full entity memory summary (episodic history, semantic profile, working context) and receives genuine reasoning about attack classification, FP likelihood, and recommended action.

## Quick Start

**Requirements:** Python 3.11 or 3.12. No API key required — runs in keyword-heuristic mock mode by default.

```bash
git clone https://github.com/huynhtrungcsc/memory-augmented-agentic-ai-soc.git
cd memory-augmented-agentic-ai-soc
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 5000 --reload
```

API docs: `http://localhost:5000/docs`

Health check: `http://localhost:5000/health`

**Optional: use a real LLM**

```bash
cp .env.example .env
# Edit .env: set LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
```

## Running the Benchmark

The scientific benchmark tests memory mechanisms across 75 controlled scenarios in 5 groups:

```bash
python scripts/memory_benchmark.py
```

The benchmark reports:
- Per-group FPR and Recall for 4 memory conditions (Cold Start, Match History, Mismatch History, Combined)
- A history generalisation test (same-type vs different-type entity history)
- A safety constraint check (attacks not suppressed by memory)
- Honest negative results (Group B and C)
- A scientific integrity audit (Table 0)

## API Reference

### Ingest a log event

```
POST /ingest-log
```

```json
{
  "source": "suricata",
  "timestamp": "2026-04-15T14:30:00Z",
  "event_type": "ET SCAN Nmap Scripting Engine",
  "message": "Nmap scan detected from 10.0.0.5",
  "severity": "medium",
  "src_ip": "10.0.0.5"
}
```

Supported sources: `suricata`, `zeek`, `wazuh`, `splunk`, `generic`

### Run a full analysis

```
POST /analyze-alert
```

```json
{ "entity_id": "10.0.0.5" }
```

Response includes: `decision`, `score_breakdown`, `memory_augmentation`, `semantic_profile`, `analysis`, `sequences_detected`, `context_summary`.

### View entity memory

| Endpoint | Description |
|---|---|
| `GET /memory/{entity_id}` | Episodic snapshot |
| `GET /memory/entity/{entity_id}/profile` | Full 4-type memory profile |
| `GET /memory/by/src-ip?ip=10.0.0.5` | Lookup by source IP |
| `GET /memory/by/username?username=admin` | Lookup by username |
| `GET /memory/by/hostname?hostname=host-01` | Lookup by hostname |
| `GET /graph/{entity_id}` | Entity relationship graph |
| `GET /health` | System status and LLM mode |

## Step-by-Step Example

```bash
BASE=http://localhost:5000

# Ingest repeated events for the same IP (simulating a recurring scanner)
for i in 1 2 3 4 5; do
  curl -s -X POST "$BASE/ingest-log" \
    -H "Content-Type: application/json" \
    -d "{\"source\":\"suricata\",\"timestamp\":\"2026-04-15T1${i}:00:00Z\",
         \"event_type\":\"ET SCAN Nmap\",\"message\":\"Nmap scan\",
         \"severity\":\"medium\",\"src_ip\":\"10.0.0.5\"}"
done

# First analysis: no semantic profile yet, episodic memory only
curl -s -X POST "$BASE/analyze-alert" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"10.0.0.5"}' | python3 -m json.tool

# Ingest more events, then analyse again.
# The second analysis loads the learned semantic profile:
# fp_confidence and known_good_hours are now populated.
curl -s -X POST "$BASE/analyze-alert" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"10.0.0.5"}' | python3 -m json.tool

# View the full 4-memory-type profile
curl -s "$BASE/memory/entity/10.0.0.5/profile" | python3 -m json.tool
```

After the first analysis `semantic_profile.is_new_entity` is `true`. After the second it is `false` and `fp_confidence` has begun accumulating. Note: reliable FPR reduction requires at least 20 entity events (see benchmark Table 5).

## Running the Tests

```bash
python -m pytest tests/ -v
```

301 tests covering: scoring engine, FP pattern detection, semantic profile computation, sequence detection, baseline deviation, trust store, decision engine, category calibration, memory retrieval, contradiction detection, and memory augmentation integration.

## Project Structure

```
.
├── main.py                          # FastAPI app entry point (port 5000)
├── requirements.txt
├── .env.example                     # Copy to .env and edit
├── scripts/
│   └── memory_benchmark.py          # Scientific benchmark (75 scenarios, 5 groups)
│
├── app/
│   ├── config.py                    # All settings (loaded from .env)
│   ├── database.py                  # Async SQLite initialisation
│   │
│   ├── memory/                      # Persistence layer
│   │   ├── sqlite_store.py          # AlertRecord, EntitySemanticProfile, EntityDecisionRecord
│   │   ├── entity_graph.py          # Directed entity relationship graph
│   │   ├── base.py                  # Abstract store interface
│   │   └── store.py                 # Factory
│   │
│   ├── models/
│   │   ├── schemas.py               # All Pydantic request/response schemas
│   │   └── analysis_context.py      # Working memory context object
│   │
│   ├── routes/
│   │   ├── ingest.py                # POST /ingest-log
│   │   ├── analyze.py               # POST /analyze-alert (full pipeline)
│   │   ├── memory.py                # GET /memory/...
│   │   ├── decide.py                # POST /decide
│   │   └── graph.py                 # GET /graph/{entity_id}
│   │
│   └── services/
│       ├── history_scorer.py        # compute_fp_pattern(), compute_semantic_profile_data()
│       ├── scoring_engine.py        # compute_hybrid_score()
│       ├── context_builder.py       # Builds working memory context for LLM
│       ├── llm_client.py            # OpenAI-compatible client and keyword-heuristic mock
│       ├── sequence_detector.py     # MITRE ATT&CK kill-chain detection
│       ├── baseline.py              # Behavioural baseline deviation
│       ├── anomaly_detector.py      # Rule-based anomaly score
│       ├── decision_engine.py       # Threshold policy with evidence gate
│       ├── trust_store.py           # Trust discount for known sources
│       └── category_calibration.py  # Per-category risk multipliers
│
└── tests/                           # 301 unit tests
```

## LLM Provider Compatibility

The LLM client speaks the OpenAI API format. Any compatible provider works:

| Provider | `LLM_BASE_URL` |
|---|---|
| OpenAI | `https://api.openai.com/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| Ollama (local) | `http://localhost:11434/v1` |
| vLLM | `http://your-vllm-host:8000/v1` |
| LiteLLM proxy | `http://localhost:4000/v1` |

## Deploying

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
```

```bash
docker build -t soc-ai .
docker run -p 5000:5000 \
  -e LLM_API_KEY=your-key \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -v $(pwd)/data:/app/data \
  soc-ai
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOC_DATABASE_URL` | `sqlite+aiosqlite:///./soc_memory.db` | SQLite path. Use a persistent volume in production. |
| `LLM_API_KEY` | *(empty)* | LLM API key. Empty activates keyword-heuristic mock mode. |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible endpoint. |
| `LLM_MODEL` | `gpt-4o-mini` | Model name for your provider. |
| `BLOCK_THRESHOLD` | `80` | Score at or above this value triggers a `block` decision. |
| `ALERT_THRESHOLD` | `50` | Score at or above this value triggers `alert_analyst`. |
| `FP_PATTERN_DISCOUNT_WEIGHT` | `0.80` | Episodic FP discount magnitude (0 = off, 1 = full). |
| `CONTEXT_WINDOW_HOURS` | `24` | Hours of history included in LLM context. |

## Limitations

**Architecture limitations (by design):**
- Cold-start: new entities have no history. The system cannot distinguish benign recurring hosts from genuine first-time attackers until at least 20 events accumulate.
- Memory depth threshold: below approximately 18 entity events, the history_score contribution can slightly increase composite score even with FP discounts applied, marginally worsening FPR vs cold start (see benchmark Table 5).
- High-anomaly FP: events with anomaly above 0.65 remain above the alert threshold even with full benign memory. They correctly escalate to human review.

**Scope limitations (honest):**
- No production validation: all benchmark results use hand-designed scenarios, not real SOC log data with analyst-confirmed labels.
- Mock LLM is not a language model: it is a deterministic keyword heuristic. Any FPR claims made with mock mode enabled do not reflect what a real LLM would produce.
- No analyst feedback loop: the system updates semantic memory based on scores, not on analyst verdicts. FP labels come from pattern accumulation, not ground truth.
- SQLite: suitable for development and single-instance use. For high-throughput production, replace `app/memory/store.py` with a PostgreSQL or Redis backend.
- Not hardened for production: no authentication by default, no multi-tenancy, no audit log. See [SECURITY.md](SECURITY.md).

## License

[CC BY-NC 4.0](LICENSE) — free for research and non-commercial use.
