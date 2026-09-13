"""
MITRE ATT&CK Mapper.

Maps detected attack patterns to MITRE ATT&CK techniques.
Uses a static lookup table (offline) + optional ChromaDB RAG for semantic search.

The static table guarantees that common attacks are always correctly mapped
without requiring an internet connection or vector database.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from app.modules.threat_analysis.event_correlator import AttackPattern

# ── Static MITRE mapping table ─────────────────────────────────────────────────
# pattern_type → list of technique candidates
STATIC_MITRE_MAP: dict[str, list[dict]] = {
    "brute_force": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "sub_technique_id": "T1110.001",
            "sub_technique_name": "Password Guessing",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
            "base_confidence": 0.92,
        }
    ],
    "credential_stuffing": [
        {
            "technique_id": "T1110.004",
            "technique_name": "Credential Stuffing",
            "tactic": "Credential Access",
            "sub_technique_id": "T1110.004",
            "sub_technique_name": "Credential Stuffing",
            "description": "Adversaries may use credentials obtained from breach dumps to authenticate across target accounts.",
            "base_confidence": 0.90,
        }
    ],
    "port_scan": [
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries may attempt to get a listing of services and listening ports on remote hosts.",
            "base_confidence": 0.88,
        }
    ],
    "sql_injection": [
        {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application (SQLi)",
            "tactic": "Initial Access",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries may inject malicious SQL syntax into application inputs.",
            "base_confidence": 0.94,
        }
    ],
    "xss": [
        {
            "technique_id": "T1059.007",
            "technique_name": "Cross-Site Scripting (XSS)",
            "tactic": "Execution",
            "sub_technique_id": "T1059.007",
            "sub_technique_name": "JavaScript",
            "description": "Adversaries inject client-side scripts to hijack browser sessions or steal cookies.",
            "base_confidence": 0.90,
        }
    ],
    "command_injection": [
        {
            "technique_id": "T1059.004",
            "technique_name": "Command Injection (Unix/Windows Shell)",
            "tactic": "Execution",
            "sub_technique_id": "T1059.004",
            "sub_technique_name": "Unix Shell",
            "description": "Adversaries execute arbitrary operating system commands by chaining shell separators.",
            "base_confidence": 0.95,
        }
    ],
    "path_traversal": [
        {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery (Path Traversal)",
            "tactic": "Discovery",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries enumerate and retrieve files outside web root using ../ sequences.",
            "base_confidence": 0.89,
        }
    ],
    "suspicious_powershell": [
        {
            "technique_id": "T1059.001",
            "technique_name": "Suspicious PowerShell Execution",
            "tactic": "Execution",
            "sub_technique_id": "T1059.001",
            "sub_technique_name": "PowerShell",
            "description": "Adversaries abuse PowerShell with encoded commands and web downloads.",
            "base_confidence": 0.94,
        }
    ],
    "privilege_escalation": [
        {
            "technique_id": "T1068",
            "technique_name": "Privilege Escalation",
            "tactic": "Privilege Escalation",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries exploit software vulnerabilities or sudo configurations to elevate permissions.",
            "base_confidence": 0.93,
        }
    ],
    "data_exfiltration": [
        {
            "technique_id": "T1048",
            "technique_name": "Data Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries transfer confidential data out of the environment to untrusted infrastructure.",
            "base_confidence": 0.95,
        }
    ],
    "ddos": [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service (DDoS)",
            "tactic": "Impact",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries overwhelm servers with high-frequency volumetric traffic to exhaust resources.",
            "base_confidence": 0.92,
        }
    ],
    "lateral_movement": [
        {
            "technique_id": "T1021.002",
            "technique_name": "Lateral Movement (SMB/RDP/WinRM)",
            "tactic": "Lateral Movement",
            "sub_technique_id": "T1021.002",
            "sub_technique_name": "SMB/Windows Admin Shares",
            "description": "Adversaries pivot between internal hosts using administrative remote services.",
            "base_confidence": 0.91,
        }
    ],
    "phishing": [
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "sub_technique_id": "T1566.002",
            "sub_technique_name": "Spearphishing Link",
            "description": "Adversaries send deceptive links leading to credential harvesting pages.",
            "base_confidence": 0.88,
        }
    ],
    "reconnaissance": [
        {
            "technique_id": "T1595",
            "technique_name": "Active Scanning / Perimeter Reconnaissance",
            "tactic": "Reconnaissance",
            "sub_technique_id": "T1595.002",
            "sub_technique_name": "Vulnerability Scanning",
            "description": "Adversaries probe sensitive endpoints and web perimeters with automated scanners.",
            "base_confidence": 0.90,
        }
    ],
    "persistence": [
        {
            "technique_id": "T1053",
            "technique_name": "Scheduled Task / Job Persistence",
            "tactic": "Persistence",
            "sub_technique_id": "T1053.005",
            "sub_technique_name": "Scheduled Task",
            "description": "Adversaries register recurring tasks to maintain persistence across reboots.",
            "base_confidence": 0.93,
        }
    ],
    "malware_c2": [
        {
            "technique_id": "T1204.002",
            "technique_name": "Malware Execution & C2 Beaconing",
            "tactic": "Execution",
            "sub_technique_id": "T1071.001",
            "sub_technique_name": "Web Protocols",
            "description": "Infected hosts execute malicious processes communicating periodically with C2 controllers.",
            "base_confidence": 0.96,
        }
    ],
    "ransomware": [
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact (Ransomware)",
            "tactic": "Impact",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Adversaries encrypt files and disable shadow recovery copies.",
            "base_confidence": 0.98,
        }
    ],
    "kerberoasting": [
        {
            "technique_id": "T1558.003",
            "technique_name": "Kerberoasting",
            "tactic": "Credential Access",
            "sub_technique_id": "T1558.003",
            "sub_technique_name": "Kerberoasting",
            "description": "Adversaries request Kerberos TGS tickets for SPN accounts to crack passwords offline.",
            "base_confidence": 0.91,
        }
    ],
    "insider_threat": [
        {
            "technique_id": "T1458",
            "technique_name": "Insider Threat / Anomalous Data Access",
            "tactic": "Exfiltration",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Authorized internal accounts mass-download proprietary records outside standard duties.",
            "base_confidence": 0.90,
        }
    ],
    "impossible_travel": [
        {
            "technique_id": "T1078.004",
            "technique_name": "Valid Accounts: Impossible Travel Anomaly",
            "tactic": "Defense Evasion",
            "sub_technique_id": "T1078.004",
            "sub_technique_name": "Cloud Accounts",
            "description": "Compromised account accessed from geographically impossible locations within minutes.",
            "base_confidence": 0.94,
        }
    ],
    "account_takeover": [
        {
            "technique_id": "T1078.001",
            "technique_name": "Account Takeover (ATO)",
            "tactic": "Initial Access",
            "sub_technique_id": None,
            "sub_technique_name": None,
            "description": "Unauthorized actor takes control of valid user account and changes security credentials.",
            "base_confidence": 0.95,
        }
    ],
}


@dataclass
class MITRETechniqueResult:
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: Optional[str]
    sub_technique_name: Optional[str]
    confidence: float
    evidence_count: int
    description: str
    source_pattern: str

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "sub_technique_id": self.sub_technique_id,
            "sub_technique_name": self.sub_technique_name,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "description": self.description,
            "source_pattern": self.source_pattern,
        }


def map_to_mitre(patterns: list[AttackPattern]) -> list[MITRETechniqueResult]:
    """Map a list of detected attack patterns to MITRE ATT&CK techniques."""
    results: list[MITRETechniqueResult] = []
    seen_technique_ids: set[str] = set()

    for pattern in patterns:
        candidates = STATIC_MITRE_MAP.get(pattern.pattern_type, [])
        for candidate in candidates:
            tid = candidate["technique_id"]
            sub_tid = candidate.get("sub_technique_id")
            key = f"{tid}:{sub_tid}"
            if key in seen_technique_ids:
                continue
            seen_technique_ids.add(key)

            # Adjust confidence based on evidence count
            evidence_boost = min(0.05, pattern.evidence_count * 0.001)
            final_confidence = min(0.99, candidate["base_confidence"] * pattern.confidence + evidence_boost)

            results.append(MITRETechniqueResult(
                technique_id=tid,
                technique_name=candidate["technique_name"],
                tactic=candidate["tactic"],
                sub_technique_id=sub_tid,
                sub_technique_name=candidate.get("sub_technique_name"),
                confidence=round(final_confidence, 3),
                evidence_count=pattern.evidence_count,
                description=candidate["description"],
                source_pattern=pattern.pattern_type,
            ))

    # Sort by confidence descending
    results.sort(key=lambda x: -x.confidence)
    return results
