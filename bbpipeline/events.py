from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from bbpipeline.manifest import ProgramManifest
from bbpipeline.models import Event, utcnow
from bbpipeline.packets import build_planner_packet
from bbpipeline.queue import enqueue
from bbpipeline.redaction import redact, sanitize_asset
from bbpipeline.scoring import score_event
from bbpipeline.settings import Settings


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    event_type: str
    asset: str
    severity: str = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


def _json_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def event_fingerprint(event: EventInput) -> str:
    identity = {
        "source": event.source.lower(),
        "event_type": event.event_type.upper(),
        "asset": sanitize_asset(event.asset).strip().lower(),
        "template_id": event.payload.get("template_id") or event.payload.get("rule_id"),
    }
    return _json_hash(identity)


def ingest_event(
    session: Session,
    settings: Settings,
    manifest: ProgramManifest,
    incoming: EventInput,
) -> tuple[Event, bool, bool]:
    safe_payload = redact(incoming.payload)
    safe_asset = sanitize_asset(incoming.asset)
    payload_hash = _json_hash(safe_payload)
    fingerprint = event_fingerprint(incoming)
    existing = session.scalar(
        select(Event).where(
            Event.program_id == manifest.program_id,
            Event.fingerprint == fingerprint,
        )
    )
    is_new = existing is None
    changed = existing is not None and existing.payload_hash != payload_hash
    score = score_event(
        event_type=incoming.event_type,
        severity=incoming.severity,
        confidence=incoming.confidence,
        is_new=is_new,
        changed=changed,
        payload=safe_payload,
    )

    if existing is None:
        event = Event(
            program_id=manifest.program_id,
            source=incoming.source,
            event_type=incoming.event_type.upper(),
            asset=safe_asset,
            fingerprint=fingerprint,
            payload_hash=payload_hash,
            severity=incoming.severity.lower(),
            confidence=incoming.confidence,
            score=score,
            payload=safe_payload,
            evidence_ids=sorted(set(incoming.evidence_ids)),
        )
        session.add(event)
    else:
        event = existing
        event.last_seen_at = utcnow()
        event.severity = incoming.severity.lower()
        event.confidence = incoming.confidence
        event.asset = safe_asset
        event.score = score
        event.evidence_ids = sorted(set(event.evidence_ids) | set(incoming.evidence_ids))
        if changed:
            event.payload = safe_payload
            event.payload_hash = payload_hash
            event.status = "changed"
    session.flush()

    llm_queued = False
    should_queue = (
        manifest.llm.enabled
        and score >= manifest.llm.trigger_score
        and (is_new or changed)
        and event.llm_queued_payload_hash != payload_hash
    )
    if should_queue:
        packet = build_planner_packet(settings, manifest, event)
        provider = manifest.llm.planner_provider
        enqueue(
            session,
            queue=f"llm-{provider}",
            kind="llm_planner",
            program_id=manifest.program_id,
            priority=score,
            payload={"provider": provider, "event_id": event.id, "packet": packet},
            dedupe_key=f"planner:{event.id}:{payload_hash}:{provider}",
        )
        event.llm_queued_payload_hash = payload_hash
        event.status = "llm_queued"
        llm_queued = True
        session.flush()
    return event, changed, llm_queued
