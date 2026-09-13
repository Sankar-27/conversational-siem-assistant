import pytest
import asyncio
from app.modules.threat_analysis.ioc_extractor import extract_iocs
from app.modules.threat_analysis.event_correlator import correlate_events

@pytest.mark.asyncio
async def test_extract_iocs_from_logs():
    hits = [
        {
            "_id": "1",
            "_source": {
                "@timestamp": "2026-08-14T10:32:21Z",
                "source": {"ip": "185.220.101.45"},
                "user": {"name": "admin"},
                "event": {"action": "failed_login"},
                "url": {"original": "http://malicious.domain.com/login"},
            }
        }
    ]
    iocs = await extract_iocs(hits)
    ioc_list = iocs.to_list()
    values = [ioc["value"] for ioc in ioc_list]

    assert "185.220.101.45" in values
    assert "admin" in values

def test_correlate_brute_force_attack():
    # 25 failed logins from one IP
    hits = [
        {
            "_source": {
                "@timestamp": f"2026-08-14T10:{i:02d}:00Z",
                "source": {"ip": "185.220.101.45"},
                "user": {"name": "admin"},
                "event": {"action": "failed_login"},
            }
        }
        for i in range(25)
    ]
    patterns = correlate_events(hits)
    assert len(patterns) > 0
    brute = next((p for p in patterns if p.pattern_type == "brute_force"), None)
    assert brute is not None
    assert brute.source_ip == "185.220.101.45"
    assert brute.confidence >= 0.8
