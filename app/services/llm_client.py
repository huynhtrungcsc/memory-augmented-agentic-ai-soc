"""
Pluggable LLM client — real provider or context-aware mock.

Credential resolution (in priority order):
  1. LLM_API_KEY + LLM_BASE_URL    — bring your own OpenAI-compatible provider
  2. AI_INTEGRATIONS_OPENAI_*      — Replit managed LLM (auto-provisioned, no key needed)
  3. Mock mode                     — deterministic simulation when no credentials present

Model behaviour notes:
  - gpt-4o / gpt-4o-mini: supports temperature, max_tokens, response_format json_object
  - gpt-5+ series: no temperature param, use max_completion_tokens, not max_tokens
  The _build_payload() function handles these differences automatically.

The LLM NEVER receives raw log data — only the sanitised context summary
produced by context_builder.py.

MemPalace integration point:
  Replace _call_api() with a MemPalace reasoning API call while keeping
  the same LLMAnalysisResult return contract.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict

import httpx

from app.config import get_settings
from app.models.schemas import AttackCategory, LLMAnalysisResult

logger = logging.getLogger(__name__)
settings = get_settings()


# ─── System prompt ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst AI.
You will receive a structured context summary describing the recent behaviour of a
network entity (IP address, user, or host).

The context includes:
- Event statistics, anomaly level, and chronological timeline
- ATTACK CHAIN DETECTION results (algorithmic pattern matching — may contain false positives)
- BEHAVIORAL BASELINE comparison (is this unusual for THIS specific entity?)
- ENTITY RELATIONSHIPS (what other systems has this entity interacted with?)

Analyse ALL sections carefully and respond with a JSON object containing EXACTLY these fields:
{
  "attack_classification": "<one of: reconnaissance, lateral_movement, privilege_escalation, credential_access, exfiltration, command_and_control, denial_of_service, malware, policy_violation, false_positive, unknown>",
  "false_positive_likelihood": <float 0.0–1.0, where 1.0 = almost certainly a false positive>,
  "risk_score": <integer 0–100, where 100 = maximum risk>,
  "recommended_action": "<concise, specific action for the SOC analyst>",
  "reasoning": "<2–4 sentences explaining your assessment, referencing SPECIFIC signals from the context>"
}

HANDLING CONTRADICTORY EVIDENCE:
- If the event timeline contains both attack indicators AND benign/normal indicators
  (e.g., scans followed by legitimate admin access), do NOT average the signals.
  Instead, evaluate which interpretation better explains ALL the evidence together.
  State the contradiction explicitly in your reasoning and explain your conclusion.
- If the chain detection says "attack chain detected" but the event timeline shows
  only ambiguous or generic events, DISAGREE with the chain and explain why.
- If the LLM anomaly level is HIGH but the event types are all known-benign
  (e.g., scheduled vulnerability scanner), trust the event type interpretation.

HANDLING LOW-CONFIDENCE / UNCERTAIN SITUATIONS:
- If there are fewer than 5 events in the timeline, explicitly note this in reasoning.
  A false_positive_likelihood of 0.50–0.70 is appropriate unless the events are
  unambiguous (e.g., known malware C2 beacon).
- If this entity has no established baseline ("has_sufficient_baseline: False"),
  note the absence of baseline context and reflect the uncertainty in your score.
- If signals are mixed (some suggest attack, some suggest benign), your risk_score
  should reflect the uncertainty: prefer values in 40–65 rather than extremes.
- When you are genuinely uncertain, it is BETTER to output a moderate risk_score
  (40–65) and a high false_positive_likelihood (0.4–0.6) than to pick a side
  and be confidently wrong.

HANDLING NOISY OR INCOMPLETE LOGS:
- Repeated identical events (e.g., 50 identical port scans) are typically one
  event, not 50 independent attack attempts. Weight them accordingly.
- If the timeline is sparse (< 3 events) and all recent, the entity may be new
  or this may be an out-of-band alert — do not over-interpret.
- Generic event_type strings (e.g., "Generic Alert", "Unknown") reduce certainty.

Reasoning guidance (use independent judgment — these are guidelines, not overrides):
- The attack chain detection is algorithmic. Evaluate whether the detected phases
  are plausible given the full event timeline. A chain may be spurious if the
  events are separated by long time gaps or involve only generic/ambiguous keywords.
- If the chain appears genuine and ≥50% complete, this significantly raises true
  positive probability — a risk_score in the 70–85 range is usually appropriate.
- Confirmed compromise (credential brute-force followed by successful login)
  combined with subsequent activity typically warrants risk_score ≥80.
- If exfiltration indicators are present alongside access evidence, risk_score
  should reflect the potential data loss severity (typically ≥85).
- Isolated events with no chain, no baseline spike, and no relationship context:
  give significant weight to false positive likelihood (≥0.30 is reasonable).
- Behavioral deviation ≥0.4 means this entity's recent activity is statistically
  unusual compared to its own baseline — this is independent evidence of anomaly.
- Do NOT fabricate facts. Base analysis ONLY on the provided context.
- Do NOT include any text outside the JSON object.
"""


# ─── Public interface ─────────────────────────────────────────────────────────


async def analyse_context(context_summary: str) -> LLMAnalysisResult:
    """
    Analyse the sanitised context summary using the best available LLM.

    Includes one retry with a brief delay on network/timeout failures.
    If all attempts fail, falls back to the context-aware mock (heuristic-only)
    and marks the result with mock_mode=True so callers can detect the degraded
    path.  The fallback prevents the analysis pipeline from failing entirely
    due to a transient LLM API issue.

    Falls back to context-aware mock when no credentials are configured.
    """
    settings = get_settings()  # fresh read (not cached at module level)

    if settings.llm_mock_mode:
        logger.info("No LLM credentials found — using context-aware mock")
        return _mock_response(context_summary)

    logger.info(
        "Sending context to LLM | provider=%s model=%s",
        settings.effective_llm_base_url,
        settings.llm_model,
    )

    last_exc: Exception | None = None
    max_attempts = 1 + max(0, settings.llm_max_retries)

    for attempt in range(1, max_attempts + 1):
        try:
            raw = await _call_api(context_summary, settings)
            result = _parse_response(raw, mock_mode=False)
            if attempt > 1:
                logger.info("LLM succeeded on retry attempt %d", attempt)
            logger.info(
                "LLM response | classification=%s risk=%d fp=%.2f",
                result.attack_classification,
                result.risk_score,
                result.false_positive_likelihood,
            )
            return result
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts:
                logger.warning(
                    "LLM attempt %d/%d failed: %s — retrying in %.1fs",
                    attempt, max_attempts, exc, settings.llm_retry_delay_seconds,
                )
                await asyncio.sleep(settings.llm_retry_delay_seconds)
            else:
                logger.error(
                    "LLM API call failed after %d attempt(s): %s — falling back to mock",
                    attempt, exc,
                )

    # All attempts failed — fall back to heuristic mock
    result = _mock_response(context_summary)
    result.reasoning = f"[LLM API error after {max_attempts} attempt(s) — heuristic fallback: {last_exc}] " + result.reasoning
    return result


# ─── API call ─────────────────────────────────────────────────────────────────


async def _call_api(context_summary: str, settings) -> Dict[str, Any]:
    """
    Call any OpenAI-compatible chat completions endpoint.

    Automatically adapts parameters for different model generations:
      - gpt-4o series: temperature + max_tokens + response_format json_object
      - gpt-5+ series: no temperature, max_completion_tokens, response_format json_object
    """
    url = f"{settings.effective_llm_base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.effective_llm_api_key}",
        "Content-Type": "application/json",
    }
    payload = _build_payload(context_summary, settings.llm_model)

    async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

    content = data["choices"][0]["message"]["content"]
    return json.loads(content)


def _build_payload(context_summary: str, model: str) -> Dict[str, Any]:
    """
    Build the API payload adapted to the model generation.

    gpt-5+ models do not accept 'temperature' or 'max_tokens'.
    """
    is_gpt5_plus = any(
        model.startswith(prefix)
        for prefix in ("gpt-5", "o3", "o4")
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": context_summary},
    ]

    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "response_format": {"type": "json_object"},
    }

    if is_gpt5_plus:
        payload["max_completion_tokens"] = 1024
        # temperature is not supported for gpt-5+ — omit it
    else:
        payload["temperature"] = 0.1  # Low temp = consistent, deterministic analysis
        payload["max_tokens"] = 1024

    return payload


# ─── Response parser ──────────────────────────────────────────────────────────


def _parse_response(raw: Dict[str, Any], mock_mode: bool) -> LLMAnalysisResult:
    """Validate and coerce the raw LLM JSON into a typed result."""
    classification_str = raw.get("attack_classification", "unknown")
    try:
        classification = AttackCategory(classification_str)
    except ValueError:
        classification = AttackCategory.unknown

    fp = float(raw.get("false_positive_likelihood", 0.5))
    risk = int(raw.get("risk_score", 50))

    # Sanity clamps — LLMs occasionally go out of range
    fp = max(0.0, min(1.0, fp))
    risk = max(0, min(100, risk))

    return LLMAnalysisResult(
        attack_classification=classification,
        false_positive_likelihood=fp,
        risk_score=risk,
        recommended_action=raw.get("recommended_action", "Monitor the entity."),
        reasoning=raw.get("reasoning", "No reasoning provided."),
        mock_mode=mock_mode,
    )


# ─── Context-aware mock response (fallback only) ─────────────────────────────


def _mock_response(context_summary: str) -> LLMAnalysisResult:
    """
    Context-AWARE mock — reads the full context summary including attack chain
    detection and baseline sections to produce a realistic varied response.

    This is ONLY used when no real LLM credentials are available.
    Prefer configuring AI_INTEGRATIONS_OPENAI_* or LLM_API_KEY for real analysis.
    """
    text = context_summary.lower()
    signals = _extract_signals(text)
    n_active = sum(1 for v in signals.values() if v)

    if signals["exfil"] and (signals["compromise"] or signals["lateral"] or signals["chain_detected"]):
        classification = AttackCategory.exfiltration
        base_risk, fp = 90, 0.03
        action = "Immediately block all outbound connections. Activate IR playbook. Preserve forensic evidence."
        reasoning = (
            "Data exfiltration confirmed with prior access evidence. "
            "Attack chain progression detected: access → exfiltration. "
            "Near-zero false positive rate for this pattern."
        )

    elif signals["compromise"] and signals["brute_force"]:
        classification = AttackCategory.credential_access
        base_risk, fp = 88, 0.04
        action = "Disable compromised account immediately. Rotate all associated credentials. Isolate affected host."
        reasoning = (
            "Authentication success following repeated failures is a textbook credential compromise. "
            "Brute-force-to-access progression eliminates false positive scenarios."
        )

    elif signals["lateral"] and (signals["compromise"] or signals["chain_detected"]):
        classification = AttackCategory.lateral_movement
        base_risk, fp = 84, 0.06
        action = "Isolate all affected hosts. Check for additional compromised credentials."
        reasoning = "Lateral movement detected following initial access indicators."

    elif signals["privesc"] and (signals["compromise"] or signals["lateral"]):
        classification = AttackCategory.privilege_escalation
        base_risk, fp = 86, 0.05
        action = "Suspend account. Escalate to Tier-2. Review all sudo/admin logs."
        reasoning = "Privilege escalation following initial access — attacker gaining elevated control."

    elif signals["brute_force"] and signals["recon"] and signals["chain_detected"]:
        classification = AttackCategory.credential_access
        base_risk, fp = 74, 0.12
        action = "Block source IP temporarily. Alert on-call team."
        reasoning = "Attack chain detected: reconnaissance followed by active brute-force."

    elif signals["brute_force"] and not signals["compromise"]:
        classification = AttackCategory.credential_access
        base_risk, fp = 55, 0.25
        action = "Rate-limit source. Check if source IP is known internal scanner."
        reasoning = (
            "Credential brute-force detected in isolation. Without success indicators, "
            "this could be automated scanning or legitimate penetration testing."
        )

    elif signals["recon"] and not signals["brute_force"] and not signals["chain_detected"]:
        classification = AttackCategory.reconnaissance
        base_risk, fp = 35, 0.40
        action = "Add source IP to watchlist. Monitor for follow-up activity."
        reasoning = (
            "Port scan without follow-up attack behaviour. High false-positive rate: "
            "could be Nessus, Qualys, or legitimate IT tooling."
        )

    elif signals["baseline_extreme"]:
        classification = AttackCategory.unknown
        base_risk, fp = 50, 0.30
        action = "Investigate the sudden activity spike. Contact asset owner."
        reasoning = "Significant behavioural anomaly without matching attack pattern."

    elif "no historical activity" in text or "first observed event" in text:
        classification = AttackCategory.unknown
        base_risk, fp = 15, 0.75
        action = "Log event. Insufficient history for confident classification."
        reasoning = "First observed event. No baseline available. Monitor and reassess."

    else:
        classification = AttackCategory.unknown
        base_risk = 35 + (n_active * 4)
        fp = max(0.15, 0.55 - n_active * 0.08)
        action = "Flag for analyst review."
        reasoning = f"Mixed signals ({n_active} indicators). No dominant attack pattern matched."

    if signals["chain_detected"]:
        base_risk = min(100, base_risk + 8)
        fp = max(0.02, fp - 0.05)
    if signals["baseline_extreme"]:
        base_risk = min(100, base_risk + 5)

    return LLMAnalysisResult(
        attack_classification=classification,
        false_positive_likelihood=round(fp, 2),
        risk_score=max(0, min(100, base_risk)),
        recommended_action=action,
        reasoning="[MOCK — configure AI integration for real LLM reasoning] " + reasoning,
        mock_mode=True,
    )


def _extract_signals(text: str) -> Dict[str, bool]:
    return {
        "recon": any(k in text for k in ["scan", "nmap", "sweep", "reconnaissance"]),
        "brute_force": any(k in text for k in ["brute", "failed auth", "authentication failure", "spray"]),
        "compromise": any(k in text for k in ["success", "authenticated", "login success", "session opened", "after brute"]),
        "lateral": any(k in text for k in ["lateral", "smb", "rdp", "wmi", "pivot"]),
        "privesc": any(k in text for k in ["privilege", "escalat", "sudo", "root access"]),
        "exfil": any(k in text for k in ["exfil", "beacon", "c2", "tor exit", "data transfer"]),
        "chain_detected": "attack chain(s) detected" in text or "known attack chain" in text,
        "baseline_extreme": "extreme" in text and "above baseline" in text,
    }
