from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.orm import Session

from bbpipeline.queue import enqueue
from bbpipeline.redaction import redact_text


def queue_notification(
    session: Session,
    *,
    title: str,
    message: str,
    record_type: str,
    record_id: str,
    severity: str = "info",
    program_id: str | None = None,
    dedupe_key: str | None = None,
) -> None:
    enqueue(
        session,
        queue="scan",
        kind="notify_discord",
        program_id=program_id,
        payload={
            "title": redact_text(title)[:200],
            "message": redact_text(message)[:1500],
            "record_type": record_type,
            "record_id": record_id,
            "severity": severity,
        },
        max_attempts=5,
        dedupe_key=dedupe_key,
    )


def send_discord(webhook_url: str, payload: dict[str, Any], *, timeout: float = 15.0) -> bool:
    if not webhook_url:
        return False
    color = {
        "info": 3447003,
        "low": 5763719,
        "medium": 16776960,
        "high": 15105570,
        "critical": 10038562,
    }.get(str(payload.get("severity", "info")).lower(), 3447003)
    body = {
        "username": "BB Pipeline",
        "allowed_mentions": {"parse": []},
        "embeds": [
            {
                "title": redact_text(str(payload.get("title", "Pipeline event")))[:256],
                "description": redact_text(str(payload.get("message", "")))[:3500],
                "color": color,
                "footer": {
                    "text": f"{payload.get('record_type', 'record')}:{payload.get('record_id', '')}"
                },
            }
        ],
    }
    response = httpx.post(webhook_url, json=body, timeout=timeout)
    if response.is_error:
        raise RuntimeError(f"Discord notification failed with status {response.status_code}")
    return True
