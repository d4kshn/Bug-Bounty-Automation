from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from bbpipeline.adapters.bbot import run_bbot
from bbpipeline.adapters.claude import run_claude
from bbpipeline.adapters.codex import run_codex
from bbpipeline.adapters.github import run_github
from bbpipeline.adapters.gitleaks import run_gitleaks
from bbpipeline.adapters.nuclei import run_nuclei
from bbpipeline.adapters.shodan import run_shodan
from bbpipeline.db import session_scope
from bbpipeline.evidence import EvidenceStore
from bbpipeline.events import ingest_event
from bbpipeline.models import Finding, Job
from bbpipeline.notifications import queue_notification, send_discord
from bbpipeline.programs import require_active_program, sync_programs
from bbpipeline.queue import claim, complete, fail, enqueue
from bbpipeline.redaction import redact, redact_artifact, redact_text
from bbpipeline.settings import Settings
from bbpipeline.verifier import verify_http_plan
from bbpipeline.workflow import parse_steps, process_llm_output, record_verification


LOGGER = logging.getLogger(__name__)


def _store_adapter_result(
    session: Session,
    settings: Settings,
    job: Job,
    manifest,
    result,
) -> dict[str, Any]:
    store = EvidenceStore(settings)
    evidence_ids: list[str] = []
    for kind, filename, content in result.artifacts:
        safe_content = redact_artifact(content, filename)
        evidence = store.write_bytes(
            session,
            program_id=manifest.program_id,
            job_id=job.id,
            kind=kind,
            filename=filename,
            content=safe_content,
            retention_days=manifest.retention_days,
            media_type=(
                "application/json"
                if filename.endswith((".json", ".jsonl"))
                else "text/plain"
            ),
            redacted=True,
        )
        evidence_ids.append(evidence.id)

    event_records: list[dict[str, Any]] = []
    for incoming in result.events:
        incoming.evidence_ids = sorted(set(incoming.evidence_ids) | set(evidence_ids))
        event, changed, llm_queued = ingest_event(session, settings, manifest, incoming)
        event_records.append(
            {
                "event_id": event.id,
                "changed": changed,
                "llm_queued": llm_queued,
                "payload_hash": event.payload_hash,
                "event_type": event.event_type,
            }
        )
        if job.kind == "github" and event.event_type == "REPOSITORY":
            repository = str(event.payload.get("repository", ""))
            if repository and not event.payload.get("archived") and not event.payload.get("fork"):
                enqueue(
                    session,
                    queue="scan",
                    kind="gitleaks",
                    program_id=manifest.program_id,
                    payload={"repository": repository},
                    priority=25,
                    dedupe_key=(
                        f"gitleaks:{manifest.program_id}:{repository}:{event.payload_hash}"
                    ),
                )
    return {
        **result.summary,
        "evidence_ids": evidence_ids,
        "event_records": event_records,
    }


def process_scan_job(session: Session, settings: Settings, job: Job) -> dict[str, Any]:
    if job.kind == "notify_discord":
        sent = send_discord(
            settings.read_secret(settings.discord_webhook_file),
            job.payload,
        )
        return {"sent": sent}
    if job.kind == "retention":
        deleted = EvidenceStore(settings).purge_expired(session)
        return {"deleted_evidence_ids": deleted, "count": len(deleted)}

    if not job.program_id:
        raise ValueError(f"job kind {job.kind} requires program_id")
    sync_programs(session, settings, actor="scan-worker-preflight")
    _, manifest = require_active_program(session, job.program_id)

    if job.kind == "verify_http":
        finding = session.get(Finding, str(job.payload.get("finding_id", "")))
        if finding is None or finding.program_id != manifest.program_id:
            raise ValueError("verification job references an invalid finding")
        steps = parse_steps(job.payload.get("steps", []))
        verification = verify_http_plan(
            manifest,
            steps=steps,
            researcher_headers_file=settings.researcher_headers_file,
        )
        evidence = EvidenceStore(settings).write_json(
            session,
            program_id=manifest.program_id,
            job_id=job.id,
            kind="http-verification",
            filename="verification.json",
            value=verification,
            retention_days=manifest.retention_days,
        )
        record_verification(
            session,
            settings,
            finding_id=finding.id,
            verification=verification,
            evidence_id=evidence.id,
        )
        return {"finding_id": finding.id, "evidence_id": evidence.id, **verification}

    with tempfile.TemporaryDirectory(prefix=f"bbpipeline-{job.kind}-") as temporary:
        workdir = Path(temporary)
        if job.kind == "bbot":
            result = run_bbot(
                manifest,
                targets=job.payload.get("targets"),
                job_id=job.id,
                workdir=workdir,
                timeout=settings.command_timeout_seconds,
            )
        elif job.kind == "nuclei":
            result = run_nuclei(
                manifest,
                targets=job.payload.get("targets"),
                profile_dir=settings.nuclei_profile_dir,
                workdir=workdir,
                timeout=settings.command_timeout_seconds,
            )
        elif job.kind == "gitleaks":
            result = run_gitleaks(
                manifest,
                repository=str(job.payload.get("repository", "")),
                github_token=settings.read_secret(settings.github_token_file),
                workdir=workdir,
                timeout=settings.command_timeout_seconds,
            )
        elif job.kind == "github":
            result = run_github(
                manifest, token=settings.read_secret(settings.github_token_file)
            )
        elif job.kind == "shodan":
            result = run_shodan(
                manifest, api_key=settings.read_secret(settings.shodan_api_key_file)
            )
        else:
            raise ValueError(f"unsupported scan job kind: {job.kind}")
        return _store_adapter_result(session, settings, job, manifest, result)


def process_llm_job(
    session: Session, settings: Settings, job: Job, provider: str
) -> dict[str, Any]:
    if job.payload.get("provider") != provider:
        raise ValueError("LLM job provider does not match worker provider")
    if not job.program_id:
        raise ValueError("LLM job is missing program_id")
    sync_programs(session, settings, actor="llm-worker-preflight")
    _, manifest = require_active_program(session, job.program_id)
    schema_name = "hypothesis.schema.json" if job.kind == "llm_planner" else "critique.schema.json"
    packet = job.payload.get("packet")
    if not isinstance(packet, dict):
        raise ValueError("LLM job packet is invalid")
    with tempfile.TemporaryDirectory(prefix=f"bbpipeline-{provider}-") as temporary:
        workdir = Path(temporary)
        if provider == "codex":
            output = run_codex(
                settings, packet=packet, schema_name=schema_name, workdir=workdir
            )
        elif provider == "claude":
            output = run_claude(
                settings, packet=packet, schema_name=schema_name, workdir=workdir
            )
        else:
            raise ValueError(f"unsupported LLM provider: {provider}")
    evidence = EvidenceStore(settings).write_json(
        session,
        program_id=manifest.program_id,
        job_id=job.id,
        kind=f"llm-{job.kind}",
        filename=f"{job.kind}.json",
        value=output,
        retention_days=manifest.retention_days,
    )
    finding = process_llm_output(
        session,
        settings,
        job,
        output,
        llm_evidence_id=evidence.id,
    )
    return {
        "finding_id": finding.id,
        "evidence_id": evidence.id,
        "output": redact(output),
    }


def worker_loop(settings: Settings, *, queues: list[str], provider: str | None = None) -> None:
    owner = f"{settings.worker_id}:{provider or 'scan'}"
    LOGGER.info("worker started owner=%s queues=%s", owner, queues)
    while True:
        job_id: str | None = None
        with session_scope(settings) as session:
            job = claim(
                session,
                queues=queues,
                owner=owner,
                lease_seconds=settings.job_lease_seconds,
            )
            if job:
                job_id = job.id
        if job_id is None:
            time.sleep(settings.worker_poll_seconds)
            continue

        try:
            with session_scope(settings) as session:
                job = session.get(Job, job_id)
                if job is None or job.status != "running" or job.lease_owner != owner:
                    continue
                result = (
                    process_llm_job(session, settings, job, provider)
                    if provider
                    else process_scan_job(session, settings, job)
                )
                complete(session, job, result)
        except Exception as exc:
            safe_error = redact_text(f"{type(exc).__name__}: {exc}")
            LOGGER.error("job failed job_id=%s error=%s", job_id, safe_error)
            with session_scope(settings) as session:
                job = session.get(Job, job_id)
                if job is not None and job.status == "running":
                    fail(session, job, safe_error)
                    if job.status == "failed" and job.kind != "notify_discord":
                        queue_notification(
                            session,
                            title="Pipeline job failed",
                            message=f"{job.kind} exhausted retries",
                            record_type="job",
                            record_id=job.id,
                            severity="high",
                            program_id=job.program_id,
                            dedupe_key=f"notify:job-failed:{job.id}",
                        )
