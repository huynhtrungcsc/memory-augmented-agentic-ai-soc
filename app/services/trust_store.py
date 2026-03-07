"""
Trust Store — Source Trust Weighting & Admin-Activity Discount.

WHY THIS EXISTS:
  The anomaly detector and scoring engine are deliberately conservative:
  they flag anything that looks unusual.  This works for detecting real
  attacks, but causes false-positive storms from:
    • Legitimate vulnerability scanners (Nessus, Qualys, Tenable)
    • Known admin hosts running scheduled management tasks
    • Internal IT automation (SCCM, Ansible, Puppet) making auth bursts
    • Expected maintenance windows (patch deployments, restarts)

  Without context about who is doing what, the system over-flags these
  benign events because their signatures match attack patterns.

HOW IT WORKS:
  1. Match source IP, event_type, or username against known trusted patterns.
  2. Return a trust_discount (0.0–0.4) that is SUBTRACTED from the anomaly score.
  3. Also return a trust_label describing what was recognised.

CONFIGURATION:
  Trust patterns are configurable via environment variables (comma-separated).
  Defaults include well-known scanner patterns but no production-specific values.

  TRUSTED_SCANNER_IPS   — comma-separated IPs/CIDRs for known vuln scanners
  TRUSTED_ADMIN_HOSTS   — comma-separated hostnames for known admin machines
  TRUSTED_ADMIN_USERS   — comma-separated username prefixes for known admins
  TRUSTED_MGMT_PORTS    — comma-separated port numbers for expected mgmt traffic

DESIGN PRINCIPLES:
  - Trust discounts REDUCE anomaly score; they do NOT suppress events entirely.
  - Maximum discount is 0.4 (cannot zero out a high-anomaly event).
  - Trust is cumulative: a known scanner on a trusted host gets a larger discount.
  - All trust decisions are logged in the returned TrustContext for explainability.
  - Unknown entities get zero discount (fail-safe default).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


# ─── Default trusted patterns ──────────────────────────────────────────────────

# Known vulnerability scanner event-type substrings
_SCANNER_EVENT_PATTERNS = [
    "nessus", "qualys", "openvas", "tenable", "nmap",
    "vuln_scan", "vuln-scan", "vulnerability_scan",
    "portscan", "port_scan", "port scan",
    "masscan", "nexpose",
]

# Known management / orchestration username prefixes
_ADMIN_USER_PREFIXES = [
    "svc_", "svc-", "service-", "nessus", "qualys", "ansible",
    "puppet", "chef", "saltstack", "sccm", "ad_sync",
    "admin_", "admin-",  # generic admin prefix convention
]

# Known admin hostname substrings
_ADMIN_HOST_SUBSTRINGS = [
    "nessus", "qualys", "scanner", "mgmt", "management",
    "siem", "soar", "ansible", "jump", "bastion",
    "monitor", "health-check", "pentest", "kali",
]

# Ports that are expected in admin/management traffic and should attract lower suspicion
# (Note: these ports are still flagged by anomaly detector; we only *discount* the risk)
_MANAGEMENT_PORTS = {
    22,    # SSH — admin access, normal for DevOps
    443,   # HTTPS — management APIs
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    8443,  # Alt HTTPS — management consoles
    9100,  # Prometheus node exporter
    9090,  # Prometheus server
    161,   # SNMP — monitoring
    514,   # Syslog
    2376,  # Docker daemon API (TLS)
}

# Event types that are inherently administrative and should attract lower suspicion
_ADMIN_EVENT_TYPES = [
    "password_reset", "password reset",
    "account_unlock", "account unlock",
    "scheduled_task", "scheduled task",
    "service_restart", "service restart",
    "patch_install", "patch install",
    "software_update", "software update",
    "backup_job", "backup_completed",
    "certificate_renewal", "certificate renewal",
    "log_rotation", "log rotation",
    "health_check", "health check",
    "auth_success",  # Single successful auth is benign
    "rdp_session",   # RDP from known admin hosts
]


# ─── Output schema ─────────────────────────────────────────────────────────────


@dataclass
class TrustContext:
    """
    Trust evaluation result for a single event.

    trust_discount (0.0–0.4):
        Amount to subtract from the raw anomaly score.
        0.0 = unknown source — no discount applied (conservative default).
        0.4 = strongly trusted source (known scanner on admin host).

    trust_labels:
        List of human-readable reasons for the discount — used in explanations.

    is_trusted_source:
        True when any trust signal was recognised (discount > 0).

    trusted:
        Alias for is_trusted_source (convenience accessor).
    """
    trust_discount: float = 0.0
    trust_labels: List[str] = field(default_factory=list)
    is_trusted_source: bool = False

    @property
    def trusted(self) -> bool:
        """Alias for is_trusted_source — True when any trust signal fired."""
        return self.is_trusted_source


# ─── Public API ────────────────────────────────────────────────────────────────


def evaluate_trust(
    event_type: str,
    src_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    dst_port: Optional[int] = None,
    message: str = "",
    extra_scanner_ips: Optional[List[str]] = None,
    extra_admin_hosts: Optional[List[str]] = None,
    extra_admin_users: Optional[List[str]] = None,
) -> TrustContext:
    """
    Evaluate how much an event source can be trusted.

    Match the event against known trusted patterns and return a discount
    to apply to the anomaly score.  Matches are cumulative up to 0.4.

    Parameters
    ----------
    event_type:   Event category string from the ingested log.
    src_ip:       Source IP address (optional).
    username:     Associated user account (optional).
    hostname:     Source/destination hostname (optional).
    dst_port:     Destination port (optional).
    message:      Human-readable event description.
    extra_*:      Additional trusted IPs/hosts/users (from env config).

    Returns
    -------
    TrustContext with cumulative discount and list of trust labels.
    """
    discount = 0.0
    labels: List[str] = []

    # Load environment-configured trusted patterns
    env_scanner_ips = _parse_csv_env("TRUSTED_SCANNER_IPS") + (extra_scanner_ips or [])
    env_admin_hosts = _parse_csv_env("TRUSTED_ADMIN_HOSTS") + (extra_admin_hosts or [])
    env_admin_users = _parse_csv_env("TRUSTED_ADMIN_USERS") + (extra_admin_users or [])
    env_mgmt_ports = _parse_int_csv_env("TRUSTED_MGMT_PORTS")

    combined_text = f"{event_type} {message}".lower()

    # ── Signal 1: Scanner event type pattern (+0.20) ─────────────────────────
    if any(p in combined_text for p in _SCANNER_EVENT_PATTERNS):
        discount += 0.20
        labels.append("scanner_event_type")

    # ── Signal 2: Known admin event type (+0.10) ─────────────────────────────
    if any(p in combined_text for p in _ADMIN_EVENT_TYPES):
        discount += 0.10
        labels.append("admin_event_type")

    # ── Signal 3: Known admin username prefix (+0.10) ─────────────────────────
    if username:
        uname_lower = username.lower()
        if any(uname_lower.startswith(pfx) for pfx in _ADMIN_USER_PREFIXES):
            discount += 0.10
            labels.append(f"admin_username_prefix:{username}")
        # Exact match from environment config
        if any(uname_lower == u.lower() for u in env_admin_users):
            discount += 0.10
            labels.append(f"trusted_admin_user:{username}")

    # ── Signal 4: Known admin hostname (+0.10) ────────────────────────────────
    if hostname:
        h_lower = hostname.lower()
        if any(sub in h_lower for sub in _ADMIN_HOST_SUBSTRINGS):
            discount += 0.10
            labels.append(f"admin_host_pattern:{hostname}")
        if any(h_lower == h.lower() for h in env_admin_hosts):
            discount += 0.10
            labels.append(f"trusted_admin_host:{hostname}")

    # ── Signal 5: Trusted scanner IP (+0.15) ──────────────────────────────────
    if src_ip and env_scanner_ips:
        if any(src_ip.startswith(prefix.rstrip("*")) for prefix in env_scanner_ips):
            discount += 0.15
            labels.append(f"trusted_scanner_ip:{src_ip}")

    # ── Signal 6: Management port (+0.05) ─────────────────────────────────────
    all_mgmt_ports = _MANAGEMENT_PORTS | set(env_mgmt_ports)
    if dst_port and dst_port in all_mgmt_ports:
        # Only applies if at least one other trust signal fired
        if discount > 0.0:
            discount += 0.05
            labels.append(f"management_port:{dst_port}")

    # Cap at 0.4 — trust can never fully cancel anomaly score
    discount = round(min(discount, 0.4), 3)

    return TrustContext(
        trust_discount=discount,
        trust_labels=labels,
        is_trusted_source=discount > 0.0,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _parse_csv_env(key: str) -> List[str]:
    """Parse a comma-separated environment variable into a list of strings."""
    raw = os.environ.get(key, "").strip()
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _parse_int_csv_env(key: str) -> List[int]:
    """Parse a comma-separated environment variable of integers."""
    values = []
    for v in _parse_csv_env(key):
        try:
            values.append(int(v))
        except ValueError:
            pass
    return values
