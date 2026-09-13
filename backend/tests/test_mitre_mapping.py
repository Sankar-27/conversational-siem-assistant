import pytest
from app.modules.mitre.attack_mapper import map_to_mitre
from app.modules.threat_analysis.event_correlator import AttackPattern

def test_map_brute_force_to_mitre():
    pattern = AttackPattern(
        pattern_type="brute_force",
        source_ip="185.220.101.45",
        confidence=0.9,
        evidence_count=50,
        details={},
    )
    results = map_to_mitre([pattern])
    assert len(results) > 0
    t1110 = next((r for r in results if r.technique_id == "T1110"), None)
    assert t1110 is not None
    assert t1110.technique_name == "Brute Force"
    assert t1110.tactic == "Credential Access"
    assert t1110.confidence > 0.8
