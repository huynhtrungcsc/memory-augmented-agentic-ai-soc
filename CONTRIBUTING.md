# Contributing

This is an active research prototype. Contributions that improve correctness, evaluation rigour, or real-world applicability are welcome.

---

## Before You Start

1. **Understand the scope.** This is a reference architecture and research prototype, not a production SOC product. Its primary validated property is that the memory system does not suppress real attacks. FPR reduction in production conditions has not been demonstrated — see `README.md` for the full list of what is and is not proven.
2. **Open an Issue before a large PR.** Discuss the approach first to avoid wasted effort.
3. **Respect the license.** All contributions must comply with [CC BY-NC 4.0](LICENSE). By submitting a PR you agree your contribution is licensed under the same terms.

---

## What We Welcome

| Area | Examples |
|---|---|
| Bug fixes | Incorrect score calculations, edge-case crashes, logic errors in memory update |
| Test coverage | New unit tests for uncovered paths; regression tests for fixed bugs |
| Documentation | Corrections, clarifications, honest updates to capability claims |
| New log source parsers | Adapters for SIEM/log formats beyond Suricata/Zeek/Wazuh/Splunk |
| LLM prompt improvements | Better context summarisation, reduced prompt injection surface |
| Memory improvements | Better semantic profile computation, TTL/pruning strategies, profile decay |
| Benchmark improvements | More realistic scenarios, real SOC log integration, external dataset validation |
| Performance | Async query optimisation, caching, indexing |
| Real LLM validation | Results from running the benchmark with a real LLM and real or labelled SOC data |

## What We Do Not Accept

- Changes that introduce external data collection, telemetry, or data exfiltration
- Replacing the pluggable LLM client with a hard dependency on a specific provider
- Removing or weakening the keyword-heuristic mock fallback
- Overclaiming results: PRs must not assert FPR reductions that are not backed by the benchmark
- Adding dependencies that are not MIT-, Apache-2.0-, or BSD-licensed

---

## Development Setup

```bash
git clone https://github.com/huynhtrungcsc/memory-augmented-agentic-ai-soc.git
cd memory-augmented-agentic-ai-soc
pip install -r requirements.txt

# Run all tests before and after your change
python -m pytest tests/ -v

# Run the benchmark
python scripts/memory_benchmark.py

# Run the server locally
uvicorn main:app --host 0.0.0.0 --port 5000 --reload
```

All 301 tests must pass before a PR will be reviewed.

---

## Pull Request Guidelines

1. **One logical change per PR.** Split unrelated fixes into separate PRs.
2. **Write tests.** New behaviour must be covered by unit tests. Bug fixes must include a regression test.
3. **Update the benchmark if relevant.** If you change the scoring engine or memory mechanisms, re-run `scripts/memory_benchmark.py` and include the updated output in the PR description.
4. **Keep commits clean.** Use [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `fix(scoring_engine): correct contradiction threshold`
   - `feat(memory): add semantic profile decay`
   - `docs(readme): update limitations section`
5. **Do not commit secrets.** Never commit API keys, tokens, or `.env` files.
6. **Be honest about results.** If a change worsens a metric, say so and explain why the trade-off is acceptable.

---

## Code Style

- Python 3.12 with full type annotations
- `black` formatting (line length 100)
- Docstrings for all public functions and classes

---

## Reporting Issues

- **Bugs**: Open a GitHub Issue with a minimal reproducible example
- **Incorrect claims in documentation**: Open a GitHub Issue referencing the specific claim and what evidence contradicts it
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do not open a public Issue
- **Feature requests**: Open a GitHub Issue describing the use case and what gap it addresses

---

## Academic Use

If you use this project in academic research, please cite it:

```
Huynh Trung. (2026). Memory-Augmented Agentic AI for SOC Log Analysis.
GitHub: https://github.com/huynhtrungcsc/memory-augmented-agentic-ai-soc
```

Note the scope of what this prototype demonstrates vs. what requires further validation with real LLM and real labelled SOC data — see `README.md` for the full breakdown.
