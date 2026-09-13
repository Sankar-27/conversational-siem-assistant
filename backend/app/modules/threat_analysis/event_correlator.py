"""
Event Correlator — detects attack patterns from retrieved log evidence.

Supports 22 threat patterns:
- Brute force & Credential stuffing
- Port scanning & Active reconnaissance
- Web attacks (SQL injection, XSS, Path traversal, Command injection)
- Endpoint execution (Suspicious PowerShell, Privilege escalation, Persistence, Ransomware)
- Network threats (Malware C2, Data exfiltration, DDoS, Lateral movement)
- Identity & Access (Impossible travel, Account takeover, Kerberoasting, Insider threat)
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional, Any
import re


# ── Thresholds ─────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 8       # failed logins from one IP → brute force
CREDENTIAL_STUFFING_MIN_IPS = 4
CREDENTIAL_STUFFING_MAX_PER_IP = 3
PORT_SCAN_THRESHOLD = 8         # distinct destination ports or probes from one IP
DOS_RPS_THRESHOLD = 30          # requests in window from one IP
EXFIL_BYTES_THRESHOLD = 1_000_000 # >1MB outbound transfer

# ── Attack signature regexes ───────────────────────────────────────────────────
SQLI_RE = re.compile(r"(union\s+select|select\s+\*|drop\s+table|insert\s+into|or\s+1=1|'|\"--|sleep\()", re.I)
TRAVERSAL_RE = re.compile(r"\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/etc/shadow", re.I)
XSS_RE = re.compile(r"<script|javascript:|onerror=|onload=|alert\(|<svg", re.I)
CMD_INJECTION_RE = re.compile(r"(;\s*(cat|whoami|id|curl|nc|sh|bash)|\bwhoami\b|`id`|\|\s*whoami)", re.I)
SCANNER_UA_RE = re.compile(r"(nmap|nikto|sqlmap|dirbuster|gobuster|masscan|hydra|medusa|nuclei)", re.I)
POWERSHELL_SUSP_RE = re.compile(r"(-enc|-nop|-w hidden|IEX|DownloadString|Win32_UserAccount|Bypass)", re.I)
RANSOMWARE_RE = re.compile(r"(vssadmin(\.exe)?\s+delete\s+shadows|\.locked|\.enc)", re.I)


class AttackPattern:
    def __init__(
        self,
        pattern_type: str,
        source_ip: Optional[str],
        confidence: float,
        evidence_count: int,
        details: dict,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
    ):
        self.pattern_type = pattern_type
        self.source_ip = source_ip
        self.confidence = confidence
        self.evidence_count = evidence_count
        self.details = details
        self.first_seen = first_seen
        self.last_seen = last_seen

    def to_dict(self) -> dict:
        return {
            "pattern_type": self.pattern_type,
            "source_ip": self.source_ip,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "details": self.details,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def _get(doc: dict, *path: str) -> Any:
    """Safely get nested field."""
    current = doc
    for p in path:
        if not isinstance(current, dict):
            return None
        current = current.get(p)
    return current


def correlate_events(hits: list[dict]) -> list[AttackPattern]:
    """Analyze a list of log hits and return detected attack patterns."""
    patterns: list[AttackPattern] = []

    if not hits:
        return patterns

    sources = [hit.get("_source", hit) for hit in hits]

    # ── Aggregations ──────────────────────────────────────────────────────────
    failed_by_ip: dict[str, list[dict]] = defaultdict(list)
    success_by_ip: dict[str, list[dict]] = defaultdict(list)
    ports_by_ip: dict[str, set] = defaultdict(set)
    requests_by_ip: dict[str, list[dict]] = defaultdict(list)
    logins_by_user: dict[str, list[dict]] = defaultdict(list)
    internal_conns_by_ip: dict[str, set] = defaultdict(set)

    # Buckets for specific attack signals
    sqli_hits: list[dict] = []
    traversal_hits: list[dict] = []
    xss_hits: list[dict] = []
    cmd_injection_hits: list[dict] = []
    scanner_hits: list[dict] = []
    powershell_hits: list[dict] = []
    priv_esc_hits: list[dict] = []
    exfil_hits: list[dict] = []
    ddos_hits: list[dict] = []
    c2_hits: list[dict] = []
    ransomware_hits: list[dict] = []
    kerberos_hits: list[dict] = []
    insider_hits: list[dict] = []
    phishing_hits: list[dict] = []
    persistence_hits: list[dict] = []
    account_mod_hits: list[dict] = []

    for src in sources:
        ip = _get(src, "source", "ip") or ""
        dest_ip = _get(src, "destination", "ip") or ""
        action = _get(src, "event", "action") or ""
        ts = src.get("@timestamp", "")
        url = _get(src, "url", "original") or ""
        ua = _get(src, "user_agent", "original") or ""
        dest_port = _get(src, "destination", "port")
        username = _get(src, "user", "name") or ""
        cmd = _get(src, "process", "command_line") or ""
        pname = _get(src, "process", "name") or ""
        threat_tag = _get(src, "threat", "indicator") or ""
        bytes_out = _get(src, "http", "response", "bytes") or _get(src, "network", "bytes") or 0

        if ip:
            requests_by_ip[ip].append(src)

        if username:
            logins_by_user[username].append(src)

        if action == "failed_login" and ip:
            failed_by_ip[ip].append(src)
        elif action == "successful_login" and ip:
            success_by_ip[ip].append(src)

        if dest_port and ip:
            ports_by_ip[ip].add(dest_port)

        # Check internal connections (lateral movement)
        if ip.startswith("192.168.") and dest_ip.startswith("192.168.") and dest_port in [445, 3389, 5985, 22]:
            internal_conns_by_ip[ip].add(dest_ip)

        # Threat tag / regex inspection
        if threat_tag == "sql_injection" or (url and SQLI_RE.search(url)):
            sqli_hits.append(src)
        if threat_tag == "path_traversal" or (url and TRAVERSAL_RE.search(url)):
            traversal_hits.append(src)
        if threat_tag == "xss" or (url and XSS_RE.search(url)):
            xss_hits.append(src)
        if threat_tag == "command_injection" or (url and CMD_INJECTION_RE.search(url)) or (cmd and CMD_INJECTION_RE.search(cmd)):
            cmd_injection_hits.append(src)
        if threat_tag == "reconnaissance" or (ua and SCANNER_UA_RE.search(ua)):
            scanner_hits.append(src)
        if threat_tag == "suspicious_powershell" or (cmd and POWERSHELL_SUSP_RE.search(cmd)):
            powershell_hits.append(src)
        if threat_tag == "privilege_escalation" or action == "privilege_escalation":
            priv_esc_hits.append(src)
        if threat_tag == "data_exfiltration" or (action == "data_transfer" and bytes_out > EXFIL_BYTES_THRESHOLD):
            exfil_hits.append(src)
        if threat_tag == "ddos" or action == "high_volume_request":
            ddos_hits.append(src)
        if threat_tag == "malware_c2" or action == "c2_beacon":
            c2_hits.append(src)
        if threat_tag == "ransomware" or action == "file_encryption" or (cmd and RANSOMWARE_RE.search(cmd)):
            ransomware_hits.append(src)
        if threat_tag == "kerberoasting" or action == "kerberos_request":
            kerberos_hits.append(src)
        if threat_tag == "insider_threat" or action == "mass_data_download":
            insider_hits.append(src)
        if threat_tag == "phishing" or action == "phishing_access":
            phishing_hits.append(src)
        if threat_tag == "persistence" or action == "scheduled_task_created":
            persistence_hits.append(src)
        if threat_tag == "account_takeover" or action == "account_modification":
            account_mod_hits.append(src)

    # ── 1. Brute Force ────────────────────────────────────────────────────────
    for ip, failed_events in failed_by_ip.items():
        if len(failed_events) >= BRUTE_FORCE_THRESHOLD:
            success_after = [s for s in success_by_ip.get(ip, [])
                             if s.get("@timestamp", "") > failed_events[-1].get("@timestamp", "")]
            ts_list = sorted(e.get("@timestamp", "") for e in failed_events)
            confidence = min(0.98, 0.6 + (len(failed_events) - BRUTE_FORCE_THRESHOLD) * 0.02)
            patterns.append(AttackPattern(
                pattern_type="brute_force",
                source_ip=ip,
                confidence=round(confidence, 2),
                evidence_count=len(failed_events),
                details={
                    "failed_count": len(failed_events),
                    "success_after_failure": len(success_after) > 0,
                    "targeted_usernames": list({_get(e, "user", "name") for e in failed_events if _get(e, "user", "name")})[:5],
                },
                first_seen=ts_list[0] if ts_list else None,
                last_seen=ts_list[-1] if ts_list else None,
            ))

    # ── 2. Credential Stuffing ────────────────────────────────────────────────
    stuffing_ips = [
        ip for ip, evts in failed_by_ip.items()
        if 1 <= len(evts) <= CREDENTIAL_STUFFING_MAX_PER_IP
    ]
    if len(stuffing_ips) >= CREDENTIAL_STUFFING_MIN_IPS:
        total = sum(len(failed_by_ip[ip]) for ip in stuffing_ips)
        patterns.append(AttackPattern(
            pattern_type="credential_stuffing",
            source_ip=None,
            confidence=0.85,
            evidence_count=total,
            details={
                "attacker_ip_count": len(stuffing_ips),
                "sample_ips": stuffing_ips[:5],
                "total_failed_attempts": total,
            },
        ))

    # ── 3. Port Scanning ──────────────────────────────────────────────────────
    for ip, ports in ports_by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            patterns.append(AttackPattern(
                pattern_type="port_scan",
                source_ip=ip,
                confidence=min(0.95, 0.5 + len(ports) * 0.03),
                evidence_count=len(ports),
                details={"distinct_ports": sorted(list(ports))[:15]},
            ))

    # ── 4. SQL Injection ──────────────────────────────────────────────────────
    if sqli_hits:
        patterns.append(AttackPattern(
            pattern_type="sql_injection",
            source_ip=_get(sqli_hits[0], "source", "ip"),
            confidence=0.92,
            evidence_count=len(sqli_hits),
            details={"sample_payloads": [_get(h, "url", "original") for h in sqli_hits[:3]]},
        ))

    # ── 5. Cross-Site Scripting (XSS) ─────────────────────────────────────────
    if xss_hits:
        patterns.append(AttackPattern(
            pattern_type="xss",
            source_ip=_get(xss_hits[0], "source", "ip"),
            confidence=0.88,
            evidence_count=len(xss_hits),
            details={"sample_payloads": [_get(h, "url", "original") for h in xss_hits[:3]]},
        ))

    # ── 6. Command Injection ──────────────────────────────────────────────────
    if cmd_injection_hits:
        patterns.append(AttackPattern(
            pattern_type="command_injection",
            source_ip=_get(cmd_injection_hits[0], "source", "ip"),
            confidence=0.95,
            evidence_count=len(cmd_injection_hits),
            details={"sample_commands": [_get(h, "url", "original") or _get(h, "process", "command_line") for h in cmd_injection_hits[:3]]},
        ))

    # ── 7. Path Traversal ─────────────────────────────────────────────────────
    if traversal_hits:
        patterns.append(AttackPattern(
            pattern_type="path_traversal",
            source_ip=_get(traversal_hits[0], "source", "ip"),
            confidence=0.90,
            evidence_count=len(traversal_hits),
            details={"sample_paths": [_get(h, "url", "original") for h in traversal_hits[:3]]},
        ))

    # ── 8. Suspicious PowerShell ──────────────────────────────────────────────
    if powershell_hits:
        patterns.append(AttackPattern(
            pattern_type="suspicious_powershell",
            source_ip=_get(powershell_hits[0], "source", "ip"),
            confidence=0.93,
            evidence_count=len(powershell_hits),
            details={"commands": [_get(h, "process", "command_line") for h in powershell_hits[:3]]},
        ))

    # ── 9. Privilege Escalation ───────────────────────────────────────────────
    if priv_esc_hits:
        patterns.append(AttackPattern(
            pattern_type="privilege_escalation",
            source_ip=_get(priv_esc_hits[0], "source", "ip"),
            confidence=0.94,
            evidence_count=len(priv_esc_hits),
            details={"user": _get(priv_esc_hits[0], "user", "name"), "command": _get(priv_esc_hits[0], "process", "command_line")},
        ))

    # ── 10. Data Exfiltration ─────────────────────────────────────────────────
    if exfil_hits:
        patterns.append(AttackPattern(
            pattern_type="data_exfiltration",
            source_ip=_get(exfil_hits[0], "source", "ip"),
            confidence=0.95,
            evidence_count=len(exfil_hits),
            details={
                "destination_ip": _get(exfil_hits[0], "destination", "ip"),
                "total_transfer_events": len(exfil_hits),
            },
        ))

    # ── 11. DDoS Volumetric Attack ────────────────────────────────────────────
    if ddos_hits or any(len(reqs) >= DOS_RPS_THRESHOLD for reqs in requests_by_ip.values()):
        ddos_ip = _get(ddos_hits[0], "source", "ip") if ddos_hits else max(requests_by_ip.keys(), key=lambda k: len(requests_by_ip[k]))
        patterns.append(AttackPattern(
            pattern_type="ddos",
            source_ip=ddos_ip,
            confidence=0.91,
            evidence_count=len(ddos_hits) or len(requests_by_ip.get(ddos_ip, [])),
            details={"request_rate": f"{len(ddos_hits) or len(requests_by_ip.get(ddos_ip, []))} requests in window"},
        ))

    # ── 12. Lateral Movement ──────────────────────────────────────────────────
    for ip, targets in internal_conns_by_ip.items():
        if len(targets) >= 2:
            patterns.append(AttackPattern(
                pattern_type="lateral_movement",
                source_ip=ip,
                confidence=0.89,
                evidence_count=len(targets),
                details={"targeted_hosts": list(targets)},
            ))

    # ── 13. Phishing Indicators ───────────────────────────────────────────────
    if phishing_hits:
        patterns.append(AttackPattern(
            pattern_type="phishing",
            source_ip=_get(phishing_hits[0], "source", "ip"),
            confidence=0.87,
            evidence_count=len(phishing_hits),
            details={"destination_ip": _get(phishing_hits[0], "destination", "ip")},
        ))

    # ── 14. Active Reconnaissance ─────────────────────────────────────────────
    if scanner_hits:
        scanner_ips = list({_get(h, "source", "ip") for h in scanner_hits if _get(h, "source", "ip")})
        patterns.append(AttackPattern(
            pattern_type="reconnaissance",
            source_ip=scanner_ips[0] if scanner_ips else None,
            confidence=0.90,
            evidence_count=len(scanner_hits),
            details={"scanner_ips": scanner_ips[:5], "user_agents": list({_get(h, "user_agent", "original") for h in scanner_hits})[:3]},
        ))

    # ── 15. Persistence via Scheduled Tasks ───────────────────────────────────
    if persistence_hits:
        patterns.append(AttackPattern(
            pattern_type="persistence",
            source_ip=_get(persistence_hits[0], "source", "ip"),
            confidence=0.92,
            evidence_count=len(persistence_hits),
            details={"command": _get(persistence_hits[0], "process", "command_line")},
        ))

    # ── 16. Malware C2 Beaconing ──────────────────────────────────────────────
    if c2_hits:
        patterns.append(AttackPattern(
            pattern_type="malware_c2",
            source_ip=_get(c2_hits[0], "source", "ip"),
            confidence=0.96,
            evidence_count=len(c2_hits),
            details={"c2_server": _get(c2_hits[0], "destination", "ip"), "beacon_count": len(c2_hits)},
        ))

    # ── 17. Ransomware Activity ───────────────────────────────────────────────
    if ransomware_hits:
        patterns.append(AttackPattern(
            pattern_type="ransomware",
            source_ip=_get(ransomware_hits[0], "source", "ip"),
            confidence=0.98,
            evidence_count=len(ransomware_hits),
            details={"command": _get(ransomware_hits[0], "process", "command_line"), "impact": "High-velocity file encryption attempt"},
        ))

    # ── 18. Kerberoasting ─────────────────────────────────────────────────────
    if kerberos_hits:
        patterns.append(AttackPattern(
            pattern_type="kerberoasting",
            source_ip=_get(kerberos_hits[0], "source", "ip"),
            confidence=0.88,
            evidence_count=len(kerberos_hits),
            details={"service_user": _get(kerberos_hits[0], "user", "name"), "ticket_requests": len(kerberos_hits)},
        ))

    # ── 19. Insider Threat ────────────────────────────────────────────────────
    if insider_hits:
        patterns.append(AttackPattern(
            pattern_type="insider_threat",
            source_ip=_get(insider_hits[0], "source", "ip"),
            confidence=0.89,
            evidence_count=len(insider_hits),
            details={"user": _get(insider_hits[0], "user", "name"), "download_records": len(insider_hits)},
        ))

    # ── 20. Impossible Travel ─────────────────────────────────────────────────
    for uname, user_events in logins_by_user.items():
        distinct_ips = list({_get(e, "source", "ip") for e in user_events if _get(e, "source", "ip")})
        # Check if user logged in from both US and RU or vastly different subnets
        if any(_get(e, "threat", "indicator") == "impossible_travel" for e in user_events) or len(distinct_ips) >= 3:
            patterns.append(AttackPattern(
                pattern_type="impossible_travel",
                source_ip=distinct_ips[0] if distinct_ips else None,
                confidence=0.93,
                evidence_count=len(user_events),
                details={"user": uname, "distinct_source_ips": distinct_ips},
            ))

    # ── 21. Account Takeover ──────────────────────────────────────────────────
    if account_mod_hits:
        patterns.append(AttackPattern(
            pattern_type="account_takeover",
            source_ip=_get(account_mod_hits[0], "source", "ip"),
            confidence=0.94,
            evidence_count=len(account_mod_hits),
            details={"user": _get(account_mod_hits[0], "user", "name"), "modifications": len(account_mod_hits)},
        ))

    return patterns
