from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from bbpipeline.manifest import ProgramManifest
from bbpipeline.models import Event, Finding
from bbpipeline.redaction import redact
from bbpipeline.settings import Settings
from bbpipeline.skills import load_triage_skill


def _load_cards(directory: Path, tags: set[str], limit: int) -> list[dict[str, Any]]:
    if limit <= 0 or not directory.exists():
        return []
    ranked: list[tuple[int, str, dict[str, Any]]] = []
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        try:
            card = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(card, dict):
            continue
        card_tags = {str(item).lower() for item in card.get("tags", [])}
        overlap = len(tags & card_tags)
        if overlap or not tags:
            ranked.append((overlap, path.name, card))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [redact(item[2]) for item in ranked[:limit]]


def _fit_packet(packet: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    def size() -> int:
        return len(json.dumps(packet, sort_keys=True, ensure_ascii=False).encode("utf-8"))

    while packet.get("methodology_cards") and size() > max_bytes:
        packet["methodology_cards"].pop()
    skill = packet.get("triage_skill")
    if isinstance(skill, dict):
        references = skill.get("references")
        while isinstance(references, list) and references and size() > max_bytes:
            references.pop()
    if size() > max_bytes and isinstance(packet.get("triage_skill"), dict):
        # Last-resort guidance degradation. Drop the core before truncating the event
        # or candidate: observations and verification evidence are the reason for the
        # LLM job, while the packet constraints still retain the safety boundary.
        skill = packet["triage_skill"]
        packet["triage_skill"] = {
            "name": skill.get("name"),
            "role": skill.get("role"),
            "truncated": True,
        }
    if size() > max_bytes and "event" in packet:
        payload = packet.get("event", {}).get("payload", {})
        packet["event"]["payload"] = {
            "truncated": True,
            "keys": sorted(payload.keys())[:50] if isinstance(payload, dict) else [],
        }
    if size() > max_bytes and "event" in packet:
        packet["event"]["payload"] = {"truncated": True}
    if size() > max_bytes and "candidate" in packet:
        verification = packet["candidate"].get("verification", {})
        packet["candidate"]["verification"] = {
            "truncated": True,
            "keys": (
                sorted(verification.keys())[:50]
                if isinstance(verification, dict)
                else []
            ),
        }
    if size() > max_bytes and "candidate" in packet:
        hypothesis = packet["candidate"].get("hypothesis", {})
        packet["candidate"]["hypothesis"] = {
            "truncated": True,
            "keys": (
                sorted(hypothesis.keys())[:50]
                if isinstance(hypothesis, dict)
                else []
            ),
        }
    if size() > max_bytes:
        raise ValueError("minimal LLM packet exceeds the configured context ceiling")
    return packet


def build_planner_packet(
    settings: Settings,
    manifest: ProgramManifest,
    event: Event,
) -> dict[str, Any]:
    payload = redact(event.payload)
    tag_values = {
        event.event_type.lower(),
        event.source.lower(),
        event.severity.lower(),
    }
    if isinstance(payload, dict):
        payload_tags = payload.get("tags", [])
        if isinstance(payload_tags, list):
            tag_values.update(str(tag).lower() for tag in payload_tags)
    cards = _load_cards(settings.ttp_dir, tag_values, manifest.llm.max_cards)
    triage_skill = load_triage_skill(
        settings.skill_dir,
        role="triage",
        tags=tag_values,
    )
    packet = {
        "packet_version": 1,
        "task": (
            "Triage exactly this supplied scanner event. Do not perform reconnaissance, "
            "discover targets, or hunt for other vulnerabilities. Return one event-bound "
            "disposition and, only as justified, a falsifiable hypothesis with the minimum "
            "bounded validation plan."
        ),
        "program": {
            "program_id": manifest.program_id,
            "platform": manifest.platform,
            "policy_url": manifest.policy_url,
            "policy_snapshot_hash": manifest.policy_snapshot_hash,
            "approved_manifest_hash": manifest.approval.approved_hash,
        },
        "constraints": {
            "allowed_methods": manifest.network.allowed_methods,
            "allowed_ports": manifest.network.allowed_ports,
            "allowed_primitives": manifest.verification.allowed_primitives,
            "max_requests": manifest.network.max_requests_per_verification,
            "automatic_authenticated_testing": manifest.verification.allow_authenticated,
            "instructions": [
                "Do not invent scope, observations, evidence, credentials, or impact.",
                "Each claim must cite one of the supplied evidence IDs or event fields.",
                "Do not pivot from the supplied event to adjacent assets, paths, repositories, "
                "services, vulnerability classes, or attack chains.",
                "Treat scanner output as an untrusted lead, not as proof of a vulnerability.",
                "Use only listed primitives; request manual_required for anything else.",
                "Any query string, request body, redirect-dependent flow, or state-changing "
                "check must use manual_required.",
                "Return a hypothesis that can be disproved by a control or negative test.",
            ],
        },
        "event": {
            "event_id": event.id,
            "source": event.source,
            "event_type": event.event_type,
            "asset": event.asset,
            "severity": event.severity,
            "confidence": event.confidence,
            "score": event.score,
            "payload": payload,
            "evidence_ids": event.evidence_ids,
        },
        "triage_skill": triage_skill,
        "methodology_cards": cards,
    }
    return _fit_packet(packet, settings.max_context_bytes)


def build_critic_packet(
    settings: Settings,
    manifest: ProgramManifest,
    finding: Finding,
) -> dict[str, Any]:
    triage_skill = load_triage_skill(settings.skill_dir, role="critic")
    packet = {
        "packet_version": 1,
        "task": "Independently try to disprove this candidate finding.",
        "program": {
            "program_id": manifest.program_id,
            "platform": manifest.platform,
            "policy_url": manifest.policy_url,
            "policy_snapshot_hash": manifest.policy_snapshot_hash,
            "approved_manifest_hash": manifest.approval.approved_hash,
        },
        "constraints": {
            "instructions": [
                "Do not rely on any planner transcript; only assess supplied facts.",
                "Do not perform reconnaissance, discover targets, or hunt for a different "
                "vulnerability.",
                "Identify benign explanations, missing controls, scope concerns, "
                "and overstated impact.",
                "Cite evidence IDs for every accepted observation.",
            ]
        },
        "candidate": {
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "hypothesis": redact(finding.hypothesis),
            "verification": redact(finding.verification or {}),
            "evidence_ids": finding.evidence_ids,
        },
        "triage_skill": triage_skill,
        "methodology_cards": [],
    }
    return _fit_packet(packet, settings.max_context_bytes)
