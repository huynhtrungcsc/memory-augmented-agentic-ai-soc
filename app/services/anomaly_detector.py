"""
Rule-based anomaly detector.

Evaluates a normalised RawLog against a set of heuristics and returns an
anomaly score in [0, 1].  A score >= 0.5 marks the event as anomalous.

KNOWN LIMITATIONS (by design — this is a fast first-pass filter):
  - No ML, no statistical baseline, no environment-specific calibration.
  - Keywords must be specific enough to avoid FP on legitimate event names.
  - Port list excludes port 22 (SSH is ubiquitous in DevOps environments).
  - If you need environment-specific tuning, override via subclassing or
    replace `compute_score` with an ML-based detector.

This module is intentionally simple.  Sophisticated detection should be added
as a separate module, not by expanding these keyword lists indefinitely.
"""

from __future__ import annotations

from app.models.schemas import RawLog, Severity

# Weight table: severity → base score contribution
_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.low: 0.1,
    Severity.medium: 0.3,
    Severity.high: 0.6,
    Severity.critical: 0.9,
}

# High-risk event keywords — deliberately specific to reduce false positives.
# REMOVED: "scan" (matches legitimate vuln scans), "credential" (matches password
# changes), "privilege"/"escalation" alone (matches routine audit logs),
# "dump" alone (matches heap dumps, database dumps).
# KEPT: multi-word / highly-specific phrases that rarely appear in benign logs.
_HIGH_RISK_KEYWORDS = [
    "bruteforce",
    "brute force",
    "brute-force",
    "exploit",
    "sql injection",
    "command injection",
    "backdoor",
    "data exfiltration",
    "command and control",
    "lateral movement",
    "ransomware",
    "shellcode",
    "buffer overflow",
    "reverse shell",
    "mimikatz",
    "credential dump",
    "lsass dump",
    "pass the hash",
    "token impersonation",
    "privilege escalation",  # full phrase — not just "privilege" alone
    "uac bypass",
    "webshell",
    "dropper",
    "malware",
    "rootkit",
]

# Suspicious destination ports.
# REMOVED port 22 (SSH is normal for DevOps/admin), port 8080 (ubiquitous web),
# port 80 (HTTP is everywhere).
# KEPT: ports that are high-signal indicators even in benign environments.
_SUSPICIOUS_PORTS = {
    23,    # Telnet — plaintext, almost never legitimate
    445,   # SMB — commonly abused for lateral movement
    3389,  # RDP — remote desktop; high-value target
    4444,  # Metasploit default — extremely rarely legitimate
    5900,  # VNC — remote access; abused in RATs
    6666,  # IRC/botnet channel
    9001,  # Tor ORPORT — strong C2 indicator
    1080,  # SOCKS proxy — often used as tunnel
    31337, # "Elite" — classic backdoor port
}


def compute_score(log: RawLog) -> float:
    """
    Return an anomaly score in [0.0, 1.0].

    Scoring factors:
    1. Severity weight (mandatory, 0.1–0.9).
    2. Keyword match in event_type / message (+0.2 per match, capped at +0.4).
       Keywords are multi-word / highly-specific to reduce FP.
    3. Suspicious destination port (+0.15).
       Port 22 excluded — SSH is normal infrastructure traffic.
    4. Internal source scanning internal destination (+0.1).
       Only adds when keyword is also present (lateral movement indicator).
    """
    score: float = _SEVERITY_WEIGHTS.get(log.severity, 0.2)

    combined_text = f"{log.event_type} {log.message}".lower()
    keyword_hits = sum(1 for kw in _HIGH_RISK_KEYWORDS if kw in combined_text)
    score += min(keyword_hits * 0.2, 0.4)

    if log.dst_port and log.dst_port in _SUSPICIOUS_PORTS:
        score += 0.15

    if log.src_ip and log.dst_ip:
        src_internal = _is_rfc1918(log.src_ip)
        dst_internal = _is_rfc1918(log.dst_ip)
        if src_internal and dst_internal and keyword_hits > 0:
            score += 0.1  # Lateral-movement indicator: internal-to-internal with attack keyword

    return min(round(score, 3), 1.0)


def _is_rfc1918(ip: str) -> bool:
    """Very lightweight RFC-1918 check (no extra deps)."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
        )
    except (ValueError, IndexError):
        return False
