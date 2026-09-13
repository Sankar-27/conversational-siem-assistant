"""
Attack Timeline Builder.

Converts retrieved log evidence into a chronological attack timeline
grouped into attack phases.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional


ATTACK_PHASES = {
    "reconnaissance": ["network_scan", "port_scan", "scanner_activity"],
    "initial_access": ["web_attack", "sql_injection", "path_traversal", "brute_force"],
    "credential_access": ["failed_login", "brute_force", "credential_stuffing"],
    "execution": ["command_execution", "script_execution"],
    "persistence": ["successful_login", "account_creation"],
    "lateral_movement": ["internal_scan", "lateral_access"],
    "exfiltration": ["data_exfiltration", "large_upload"],
    "impact": ["dos_attack", "ddos_attack", "service_disruption"],
}

EVENT_ACTION_TO_PHASE: dict[str, str] = {}
for phase, actions in ATTACK_PHASES.items():
    for action in actions:
        EVENT_ACTION_TO_PHASE[action] = phase


class TimelineEvent:
    def __init__(
        self,
        timestamp: str,
        event_action: str,
        source_ip: Optional[str],
        username: Optional[str],
        description: str,
        phase: str,
        severity: int = 5,
        log_id: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.event_action = event_action
        self.source_ip = source_ip
        self.username = username
        self.description = description
        self.phase = phase
        self.severity = severity
        self.log_id = log_id

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "event_action": self.event_action,
            "source_ip": self.source_ip,
            "username": self.username,
            "description": self.description,
            "phase": self.phase,
            "severity": self.severity,
            "log_id": self.log_id,
        }


def _get(doc: dict, *path: str):
    current = doc
    for p in path:
        if not isinstance(current, dict):
            return None
        current = current.get(p)
    return current


def _format_event_description(src: dict) -> str:
    action = _get(src, "event", "action") or "unknown"
    source_ip = _get(src, "source", "ip") or "unknown"
    user = _get(src, "user", "name") or ""
    url = _get(src, "url", "original") or ""
    status = _get(src, "http", "response", "status_code")

    parts = [f"{action.replace('_', ' ').title()}"]
    if source_ip != "unknown":
        parts.append(f"from {source_ip}")
    if user:
        parts.append(f"as user '{user}'")
    if url:
        parts.append(f"to {url}")
    if status:
        parts.append(f"[HTTP {status}]")
    return " ".join(parts)


def build_timeline(hits: list[dict], max_events: int = 200) -> list[TimelineEvent]:
    """
    Build a chronological attack timeline from ES hits.
    Returns events sorted by timestamp ascending.
    """
    timeline_events: list[TimelineEvent] = []

    for hit in hits:
        src = hit.get("_source", hit)
        ts = src.get("@timestamp", "")
        if not ts:
            continue

        action = _get(src, "event", "action") or "unknown"
        phase = EVENT_ACTION_TO_PHASE.get(action, "unknown")

        timeline_events.append(TimelineEvent(
            timestamp=ts,
            event_action=action,
            source_ip=_get(src, "source", "ip"),
            username=_get(src, "user", "name"),
            description=_format_event_description(src),
            phase=phase,
            severity=_get(src, "event", "severity") or 5,
            log_id=hit.get("_id"),
        ))

    # Sort chronologically
    timeline_events.sort(key=lambda e: e.timestamp)

    # If too many events, sample strategically: keep first, last, and interesting events
    if len(timeline_events) > max_events:
        # Keep first 20, last 20, and every N-th in between
        step = max(1, (len(timeline_events) - 40) // (max_events - 40))
        sampled = timeline_events[:20]
        sampled += timeline_events[20:-20:step]
        sampled += timeline_events[-20:]
        sampled.sort(key=lambda e: e.timestamp)
        timeline_events = sampled

    return timeline_events


def summarize_timeline(events: list[TimelineEvent]) -> dict:
    """Produce a summary of the attack timeline."""
    if not events:
        return {"phase_sequence": [], "duration_seconds": 0, "total_events": 0}

    phases_seen: list[str] = []
    for event in events:
        if not phases_seen or phases_seen[-1] != event.phase:
            if event.phase != "unknown":
                phases_seen.append(event.phase)

    try:
        first_ts = datetime.fromisoformat(events[0].timestamp.replace("Z", "+00:00"))
        last_ts = datetime.fromisoformat(events[-1].timestamp.replace("Z", "+00:00"))
        duration = (last_ts - first_ts).total_seconds()
    except (ValueError, AttributeError):
        duration = 0

    return {
        "phase_sequence": phases_seen,
        "duration_seconds": duration,
        "total_events": len(events),
        "first_event": events[0].timestamp if events else None,
        "last_event": events[-1].timestamp if events else None,
    }
