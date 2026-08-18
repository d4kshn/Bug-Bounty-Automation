from __future__ import annotations

from typing import Any


SEVERITY_SCORE = {
    "unknown": 10,
    "info": 10,
    "low": 35,
    "medium": 60,
    "high": 80,
    "critical": 95,
}
TYPE_BONUS = {
    "VULNERABILITY": 10,
    "FINDING": 8,
    "SECRET_CANDIDATE": 15,
    "CLOUD_CANDIDATE": 10,
    "DANGLING_RESOURCE": 15,
    "HTTP_RESPONSE": 0,
    "DNS_NAME": -10,
    "URL": -5,
}


def score_event(
    *,
    event_type: str,
    severity: str,
    confidence: float,
    is_new: bool,
    changed: bool,
    payload: dict[str, Any],
) -> int:
    score = SEVERITY_SCORE.get(severity.lower(), 10)
    score += TYPE_BONUS.get(event_type.upper(), 0)
    score += round(max(0.0, min(1.0, confidence)) * 10)
    if is_new:
        score += 5
    if changed:
        score += 10
    if payload.get("authenticated_surface"):
        score += 10
    if payload.get("cross_source_correlation"):
        score += 10
    return max(0, min(100, score))
