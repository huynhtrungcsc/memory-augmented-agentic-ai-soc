"""
Category-Specific Risk Calibration.

WHY THIS EXISTS:
  The hybrid scoring engine uses a single set of weights for all event types.
  This works reasonably well for clear attacks and benign events, but
  produces miscalibrated decisions in three specific categories:

    1. ADMIN_ACTIVITY — legitimate privileged activity looks like lateral
       movement or privilege escalation, causing false-positive storms.
       → Apply a risk reduction factor (default 0.75x).

    2. LOW_AND_SLOW — gradual attacks score low on per-event anomaly because
       no single event is alarming.  Category calibration alone won't fix
       this (slow_persistence_boost in scoring_engine does), but we can
       prevent over-suppressing any event in this category.

    3. CONTRADICTORY — when evidence is mixed, the calibrated score already
       pulls toward 50.  Category calibration does NOT further reduce scores
       here, preserving the review_required trigger.

IMPLEMENTATION:
  For each ingested log, `get_category_factor()` returns a multiplier
  applied to the raw anomaly score BEFORE hybrid scoring.  This keeps
  the calibration effect transparent and auditable.

  Multipliers are conservative:
    > 1.0 = amplify risk (e.g., known-malicious event type)
    < 1.0 = suppress risk (e.g., admin activity, scanner event)
    = 1.0 = neutral (default for unknown patterns)

  Values are bounded [0.4, 1.5] to prevent extreme suppression or amplification.

CONFIGURATION:
  CATEGORY_ADMIN_FACTOR   — risk multiplier for admin event types (default 0.75)
  CATEGORY_SCANNER_FACTOR — risk multiplier for scanner events (default 0.60)
  CATEGORY_C2_FACTOR      — risk multiplier for C2/beacon events (default 1.20)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


# ─── Event type category patterns ─────────────────────────────────────────────

# Admin / IT management event types and message patterns → lower risk
_ADMIN_EVENT_TYPES = {
    "admin_login", "admin_logon", "privileged_access", "privilege_escalation",
    "config_change", "configuration_change", "remote_access", "rdp_access",
    "group_policy_change", "user_management", "account_management",
    "software_install", "service_change", "firewall_change",
}

_ADMIN_PATTERNS = [
    "password_reset", "password reset", "account_unlock",
    "scheduled_task", "scheduled task", "service_restart",
    "patch_install", "patch_deploy", "software_update",
    "backup_job", "log_rotation", "health_check",
    "certificate_renewal", "rdp_session", "auth_success",
    "sccm", "ansible", "puppet", "gpupdate",
    "windows_update", "wsus",
    "admin user", "admin account", "admin workstation",
    "during change window", "maintenance window",
]

# Vulnerability / authorised scanning event types and patterns → lower risk
_SCANNER_EVENT_TYPES = {
    "port_scan", "network_scan", "vuln_scan", "vulnerability_scan",
    "host_discovery", "asset_scan", "service_scan",
}

_SCANNER_PATTERNS = [
    "nessus", "qualys", "openvas", "tenable",
    "vuln_scan", "vuln-scan", "vulnerability_scan",
    "portscan", "port_scan", "port scan", "masscan", "nexpose",
    "host discovery", "network discovery", "authorized scanner",
]

# High-confidence malicious event types and patterns → higher risk
_HIGH_RISK_EVENT_TYPES = {
    "c2_beacon", "c2_communication", "data_exfil", "data_exfiltration",
    "lateral_movement", "ransomware", "malware_execution",
    "credential_dump", "privilege_escalation_attack",
    "persistence_mechanism", "defense_evasion",
}

_HIGH_RISK_PATTERNS = [
    "command and control", "c2 beacon", "c2_beacon",
    "ransomware", "malware", "rootkit", "shellcode",
    "reverse shell", "reverse_shell", "lsass dump",
    "mimikatz", "credential dump", "pass the hash",
    "lateral movement", "data exfil", "exfiltration",
]

# Noisy-benign patterns → suppress slightly
_NOISY_BENIGN_EVENT_TYPES = {
    "dns_query", "dns_request", "http_request", "http_response",
    "firewall_allow", "nat_translation",
}

_NOISY_BENIGN_PATTERNS = [
    "dns_query", "dns lookup", "http_request",
    "auth_failure",  # Single failure is common noise
    "firewall_allow", "nat_translation",
]


# ─── Default calibration factors ──────────────────────────────────────────────

_DEFAULT_ADMIN_FACTOR: float = 0.75
_DEFAULT_SCANNER_FACTOR: float = 0.60
_DEFAULT_HIGH_RISK_FACTOR: float = 1.20
_DEFAULT_NOISY_BENIGN_FACTOR: float = 0.90
_DEFAULT_FACTOR: float = 1.00

_MIN_FACTOR: float = 0.40
_MAX_FACTOR: float = 1.50


# ─── Output schema ─────────────────────────────────────────────────────────────


@dataclass
class CalibrationResult:
    """
    Category-specific calibration result.

    factor:
        Multiplier applied to the anomaly score before hybrid scoring.
        1.0 = no change (default for unknown/neutral events).

    category_label:
        Human-readable label for the matched category
        (e.g., 'admin_activity', 'scanner', 'c2_beacon').
    """
    factor: float
    category_label: str


# ─── Public API ────────────────────────────────────────────────────────────────


def get_category_factor(
    event_type: str,
    message: str = "",
    source: Optional[str] = None,
) -> CalibrationResult:
    """
    Return a risk calibration factor for the given event.

    Matches event_type and message against known category patterns.
    Returns a multiplier to apply to the anomaly score.

    Parameters
    ----------
    event_type:   Event category string from the ingested log.
    message:      Human-readable event description.
    source:       Log source (suricata, zeek, wazuh, splunk, generic).

    Returns
    -------
    CalibrationResult with factor and category label.
    """
    admin_factor = _env_float("CATEGORY_ADMIN_FACTOR", _DEFAULT_ADMIN_FACTOR)
    scanner_factor = _env_float("CATEGORY_SCANNER_FACTOR", _DEFAULT_SCANNER_FACTOR)
    high_risk_factor = _env_float("CATEGORY_C2_FACTOR", _DEFAULT_HIGH_RISK_FACTOR)

    et_lower = event_type.lower().strip()
    msg_lower = message.lower()
    combined = f"{et_lower} {msg_lower}"

    # Priority order: high-risk > scanner > admin > noisy-benign > neutral
    if et_lower in _HIGH_RISK_EVENT_TYPES or any(p in combined for p in _HIGH_RISK_PATTERNS):
        return CalibrationResult(
            factor=_clamp(high_risk_factor),
            category_label="c2_exfiltration",
        )

    if et_lower in _SCANNER_EVENT_TYPES or any(p in combined for p in _SCANNER_PATTERNS):
        return CalibrationResult(
            factor=_clamp(scanner_factor),
            category_label="authorised_scanner",
        )

    if et_lower in _ADMIN_EVENT_TYPES or any(p in combined for p in _ADMIN_PATTERNS):
        return CalibrationResult(
            factor=_clamp(admin_factor),
            category_label="admin_activity",
        )

    if et_lower in _NOISY_BENIGN_EVENT_TYPES or any(p in combined for p in _NOISY_BENIGN_PATTERNS):
        return CalibrationResult(
            factor=_clamp(_DEFAULT_NOISY_BENIGN_FACTOR),
            category_label="noisy_benign",
        )

    return CalibrationResult(factor=_DEFAULT_FACTOR, category_label="neutral")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _clamp(v: float) -> float:
    return round(max(_MIN_FACTOR, min(_MAX_FACTOR, v)), 3)


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, "").strip() or default)
    except (ValueError, TypeError):
        return default
