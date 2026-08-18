from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from bbpipeline.manifest import ProgramManifest
from bbpipeline.models import Event, Finding, Job
from bbpipeline.notifications import queue_notification
from bbpipeline.packets import build_critic_packet
from bbpipeline.plans import CritiqueOutput, HypothesisOutput, TestStep, compile_plan
from bbpipeline.programs import require_active_program
from bbpipeline.queue import enqueue
from bbpipeline.redaction import redact, redact_text
from bbpipeline.settings import Settings


def process_planner_output(
    session: Session,
    settings: Settings,
    job: Job,
    output: dict[str, Any],
    *,
    llm_evidence_id: str,
) -> Finding:
    parsed = HypothesisOutput.model_validate(output)
    event_id = str(job.payload.get("event_id", ""))
    event = session.get(Event, event_id)
    if event is None or event.program_id != job.program_id:
        raise ValueError("planner job references an invalid event")
    _, manifest = require_active_program(session, event.program_id)
    plan = compile_plan(manifest, parsed)
    valid_evidence = sorted(set(parsed.evidence_ids) & set(event.evidence_ids))
    warnings: list[str] = []
    invalid = sorted(set(parsed.evidence_ids) - set(event.evidence_ids))
    if invalid:
        warnings.append("model cited evidence IDs not present in the event")
    if parsed.disposition == "not_a_finding":
        status = "rejected"
    elif parsed.disposition in {"inconclusive", "needs_manual_validation"}:
        status = "needs_human"
    else:
        status = "verification_queued" if plan.automatic else "needs_human"
    finding = Finding(
        program_id=event.program_id,
        event_id=event.id,
        status=status,
        title=redact_text(parsed.title)[:500],
        severity=parsed.severity,
        confidence=parsed.confidence,
        hypothesis=redact(
            {
                **parsed.model_dump(mode="json"),
                "compiled_plan": plan.model_dump(mode="json"),
                "validation_warnings": warnings,
            }
        ),
        evidence_ids=sorted(set(valid_evidence) | {llm_evidence_id}),
    )
    session.add(finding)
    session.flush()
    event.status = "rejected" if parsed.disposition == "not_a_finding" else "candidate"

    if parsed.disposition == "candidate" and plan.automatic:
        enqueue(
            session,
            queue="scan",
            kind="verify_http",
            program_id=manifest.program_id,
            priority=max(50, event.score),
            payload={
                "finding_id": finding.id,
                "steps": [step.model_dump(mode="json") for step in plan.steps],
            },
            dedupe_key=f"verify:{finding.id}",
        )
    elif status == "needs_human":
        queue_notification(
            session,
            title="Candidate needs manual validation",
            message=f"{manifest.program_id}: {finding.title}",
            record_type="finding",
            record_id=finding.id,
            severity=finding.severity,
            program_id=manifest.program_id,
            dedupe_key=f"notify:finding-manual:{finding.id}",
        )
    session.flush()
    return finding


def queue_critic(session: Session, settings: Settings, finding: Finding) -> Job:
    _, manifest = require_active_program(session, finding.program_id)
    provider = manifest.llm.critic_provider
    packet = build_critic_packet(settings, manifest, finding)
    return enqueue(
        session,
        queue=f"llm-{provider}",
        kind="llm_critic",
        program_id=finding.program_id,
        priority=90,
        payload={"provider": provider, "finding_id": finding.id, "packet": packet},
        dedupe_key=f"critic:{finding.id}:{provider}",
    )


def record_verification(
    session: Session,
    settings: Settings,
    *,
    finding_id: str,
    verification: dict[str, Any],
    evidence_id: str,
) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ValueError("verification references an unknown finding")
    finding.verification = redact(verification)
    finding.evidence_ids = sorted(set(finding.evidence_ids) | {evidence_id})
    _, manifest = require_active_program(session, finding.program_id)
    if manifest.llm.enabled:
        finding.status = "critic_queued"
        queue_critic(session, settings, finding)
    else:
        finding.status = "awaiting_human"
    session.flush()
    return finding


def process_critic_output(
    session: Session,
    job: Job,
    output: dict[str, Any],
    *,
    llm_evidence_id: str,
) -> Finding:
    parsed = CritiqueOutput.model_validate(output)
    finding_id = str(job.payload.get("finding_id", ""))
    finding = session.get(Finding, finding_id)
    if finding is None or finding.program_id != job.program_id:
        raise ValueError("critic job references an invalid finding")
    valid_evidence = sorted(set(parsed.evidence_ids) & set(finding.evidence_ids))
    critique = redact(parsed.model_dump(mode="json"))
    critique["valid_cited_evidence_ids"] = valid_evidence
    finding.critique = critique
    finding.evidence_ids = sorted(set(finding.evidence_ids) | {llm_evidence_id})
    finding.status = "rejected" if parsed.verdict == "unsupported" else "awaiting_human"
    if parsed.severity_assessment != "unknown":
        finding.severity = parsed.severity_assessment
    finding.confidence = min(finding.confidence, parsed.confidence)
    queue_notification(
        session,
        title=(
            "Finding ready for human review"
            if finding.status == "awaiting_human"
            else "Candidate rejected by critic"
        ),
        message=f"{finding.program_id}: {finding.title} ({parsed.verdict})",
        record_type="finding",
        record_id=finding.id,
        severity=finding.severity,
        program_id=finding.program_id,
        dedupe_key=f"notify:critic:{finding.id}:{parsed.verdict}",
    )
    session.flush()
    return finding


def process_llm_output(
    session: Session,
    settings: Settings,
    job: Job,
    output: dict[str, Any],
    *,
    llm_evidence_id: str,
) -> Finding:
    if job.kind == "llm_planner":
        return process_planner_output(
            session, settings, job, output, llm_evidence_id=llm_evidence_id
        )
    if job.kind == "llm_critic":
        return process_critic_output(session, job, output, llm_evidence_id=llm_evidence_id)
    raise ValueError(f"unsupported LLM job kind: {job.kind}")


def parse_steps(raw_steps: list[dict[str, Any]]) -> list[TestStep]:
    return [TestStep.model_validate(step) for step in raw_steps]
