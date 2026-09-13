"""Tests for attack chain analysis (Phase 5)."""
from app.modules.threat_analysis.event_correlator import AttackPattern
from app.modules.threat_analysis.attack_chain import (
    reconstruct_attack_chain,
    score_incident_severity,
)


def test_attack_chain_reconstruction():
    patterns = [
        AttackPattern("port_scan", "185.220.101.45", 0.9, 50, {}, "2024-01-01", "2024-01-01"),
        AttackPattern("brute_force", "185.220.101.45", 0.85, 30, {}, "2024-01-02", "2024-01-02"),
    ]
    chain = reconstruct_attack_chain(patterns, source_ip="185.220.101.45")
    assert chain["evidence_backed"] is True
    assert len(chain["chain"]) == 2
    assert chain["phase_sequence"][0] in ("Reconnaissance", "Discovery", "Credential Access")


def test_severity_scoring():
    patterns = [
        AttackPattern("sql_injection", "203.0.113.99", 0.9, 20, {}),
    ]
    severity = score_incident_severity(patterns)
    assert severity["score"] >= 60
    assert severity["level"] in ("high", "critical", "medium")
