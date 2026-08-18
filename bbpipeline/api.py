from __future__ import annotations

import hmac
import json
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bbpipeline.db import db_ready, init_db, session_factory, session_scope
from bbpipeline.evidence import EvidenceStore
from bbpipeline.models import (
    AuditLog,
    Event,
    Evidence,
    Finding,
    Job,
    PlatformSourceState,
    Program,
)
from bbpipeline.programs import ProgramUnavailable, require_active_program, sync_programs
from bbpipeline.queue import cancel, enqueue
from bbpipeline.redaction import redact, redact_text
from bbpipeline.settings import Settings, get_settings
from bbpipeline.workflow import record_verification


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnqueueRequest(StrictRequest):
    program_id: str
    kind: Literal["bbot", "nuclei", "github", "gitleaks", "shodan"]
    targets: list[str] = Field(default_factory=list, max_length=10000)
    repository: str | None = None

    @model_validator(mode="after")
    def valid_shape(self) -> "EnqueueRequest":
        if self.kind == "gitleaks" and not self.repository:
            raise ValueError("repository is required for a gitleaks job")
        if self.repository and self.kind != "gitleaks":
            raise ValueError("repository is accepted only for gitleaks jobs")
        if self.targets and self.kind not in {"bbot", "nuclei"}:
            raise ValueError("targets are accepted only for BBOT and Nuclei jobs")
        return self


class FindingAction(StrictRequest):
    action: Literal[
        "record_manual_verification", "validate", "reject", "mark_submitted"
    ]
    notes: str = Field(default="", max_length=4000)
    verification: dict[str, Any] | None = None
    report: dict[str, Any] | None = None

    @model_validator(mode="after")
    def bounded_payload(self) -> "FindingAction":
        if self.action == "record_manual_verification" and self.verification is None:
            raise ValueError("verification is required for record_manual_verification")
        if self.verification is not None and len(json.dumps(self.verification).encode()) > 65536:
            raise ValueError("verification exceeds 64 KiB")
        if self.report is not None and len(json.dumps(self.report).encode()) > 65536:
            raise ValueError("report exceeds 64 KiB")
        return self


class EvidenceAction(StrictRequest):
    action: Literal["hold", "release"]
    notes: str = Field(default="", max_length=4000)


def _serialize_program(program: Program) -> dict[str, Any]:
    return {
        "id": program.id,
        "name": program.name,
        "platform": program.platform,
        "policy_url": program.policy_url,
        "manifest_hash": program.manifest_hash,
        "approved_hash": program.approved_hash,
        "active": program.active,
        "paused_reason": program.paused_reason,
        "updated_at": program.updated_at,
    }


def _serialize_job(job: Job) -> dict[str, Any]:
    return {
        "id": job.id,
        "program_id": job.program_id,
        "queue": job.queue,
        "kind": job.kind,
        "status": job.status,
        "priority": job.priority,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "run_after": job.run_after,
        "error": job.error,
        "result": job.result,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


def _serialize_event(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "program_id": event.program_id,
        "source": event.source,
        "event_type": event.event_type,
        "asset": event.asset,
        "severity": event.severity,
        "confidence": event.confidence,
        "score": event.score,
        "status": event.status,
        "payload": event.payload,
        "evidence_ids": event.evidence_ids,
        "first_seen_at": event.first_seen_at,
        "last_seen_at": event.last_seen_at,
    }


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "program_id": finding.program_id,
        "event_id": finding.event_id,
        "status": finding.status,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "hypothesis": finding.hypothesis,
        "verification": finding.verification,
        "critique": finding.critique,
        "report": finding.report,
        "evidence_ids": finding.evidence_ids,
        "human_validated": finding.human_validated,
        "submitted": finding.submitted,
        "created_at": finding.created_at,
        "updated_at": finding.updated_at,
    }


def _serialize_evidence(evidence: Evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "program_id": evidence.program_id,
        "job_id": evidence.job_id,
        "kind": evidence.kind,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "media_type": evidence.media_type,
        "redacted": evidence.redacted,
        "hold": evidence.hold,
        "created_at": evidence.created_at,
        "expires_at": evidence.expires_at,
        "deleted_at": evidence.deleted_at,
    }


def _prometheus_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def get_db(settings: Settings = Depends(get_settings)):
    session = session_factory(settings)()
    try:
        yield session
    finally:
        session.close()


def require_api_token(
    authorization: str | None = Header(default=None),
    x_bb_pipeline_token: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    expected = settings.read_secret(settings.api_token_file)
    if not expected:
        raise HTTPException(status_code=503, detail="API token is not configured")
    supplied = x_bb_pipeline_token or ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    init_db(settings)
    with session_scope(settings) as session:
        sync_programs(session, settings, actor="api-startup")
    yield


app = FastAPI(
    title="Bug Bounty Automation Control Plane",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.exception_handler(ProgramUnavailable)
async def program_unavailable_handler(
    _: Request, exc: ProgramUnavailable
) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(settings: Settings = Depends(get_settings)) -> dict[str, str]:
    if not db_ready(settings):
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(
    _: None = Depends(require_api_token),
    session: Session = Depends(get_db),
) -> PlainTextResponse:
    lines = [
        "# HELP bbpipeline_jobs Jobs by status",
        "# TYPE bbpipeline_jobs gauge",
    ]
    for status_name, count in session.execute(
        select(Job.status, func.count(Job.id)).group_by(Job.status)
    ):
        lines.append(
            f'bbpipeline_jobs{{status="{_prometheus_label(status_name)}"}} {count}'
        )
    lines.extend(
        [
            "# HELP bbpipeline_findings Findings by status",
            "# TYPE bbpipeline_findings gauge",
        ]
    )
    for status_name, count in session.execute(
        select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    ):
        lines.append(
            f'bbpipeline_findings{{status="{_prometheus_label(status_name)}"}} {count}'
        )
    lines.extend(
        [
            "# HELP bbpipeline_platform_sources Platform sources by status",
            "# TYPE bbpipeline_platform_sources gauge",
        ]
    )
    for status_name, count in session.execute(
        select(PlatformSourceState.status, func.count(PlatformSourceState.source_id)).group_by(
            PlatformSourceState.status
        )
    ):
        lines.append(
            f'bbpipeline_platform_sources{{status="{_prometheus_label(status_name)}"}} {count}'
        )
    return PlainTextResponse(
        "\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.post("/api/v1/programs/sync", dependencies=[Depends(require_api_token)])
def sync_program_api(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> list[dict[str, Any]]:
    programs = sync_programs(session, settings, actor="api")
    session.commit()
    return [_serialize_program(program) for program in programs]


@app.get("/api/v1/programs", dependencies=[Depends(require_api_token)])
def list_programs(session: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        _serialize_program(program)
        for program in session.scalars(select(Program).order_by(Program.id)).all()
    ]


@app.get("/api/v1/platform-sources", dependencies=[Depends(require_api_token)])
def list_platform_sources(session: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        {
            "source_id": state.source_id,
            "program_id": state.program_id,
            "platform": state.platform,
            "remote_identifier": state.remote_identifier,
            "status": state.status,
            "revision_hash": state.revision_hash,
            "candidate_ready": state.candidate_manifest is not None,
            "last_checked_at": state.last_checked_at,
            "last_success_at": state.last_success_at,
            "changed_at": state.changed_at,
            "last_error": state.last_error,
        }
        for state in session.scalars(
            select(PlatformSourceState).order_by(PlatformSourceState.source_id)
        ).all()
    ]


@app.post("/api/v1/jobs", dependencies=[Depends(require_api_token)])
def create_job(request: EnqueueRequest, session: Session = Depends(get_db)) -> dict[str, Any]:
    _, manifest = require_active_program(session, request.program_id)
    enabled = {
        "bbot": manifest.bbot.enabled,
        "nuclei": manifest.nuclei.enabled,
        "github": manifest.repositories.enabled,
        "gitleaks": manifest.repositories.enabled,
        "shodan": manifest.shodan.enabled,
    }[request.kind]
    if not enabled:
        raise HTTPException(status_code=409, detail=f"{request.kind} is disabled for this program")
    payload: dict[str, Any] = {}
    if request.targets:
        payload["targets"] = request.targets
    if request.repository:
        payload["repository"] = request.repository
    job = enqueue(
        session,
        queue="scan",
        kind=request.kind,
        program_id=request.program_id,
        payload=payload,
        priority=20,
    )
    session.add(
        AuditLog(
            actor="api-user",
            action="job_enqueued",
            object_type="job",
            object_id=job.id,
            details={"kind": request.kind, "program_id": request.program_id},
        )
    )
    session.commit()
    return _serialize_job(job)


@app.get("/api/v1/jobs", dependencies=[Depends(require_api_token)])
def list_jobs(
    job_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = select(Job).order_by(Job.created_at.desc()).limit(limit)
    if job_status:
        statement = statement.where(Job.status == job_status)
    return [_serialize_job(job) for job in session.scalars(statement).all()]


@app.post("/api/v1/jobs/{job_id}/cancel", dependencies=[Depends(require_api_token)])
def cancel_job(job_id: str, session: Session = Depends(get_db)) -> dict[str, Any]:
    job = session.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    cancel(session, job)
    session.commit()
    return _serialize_job(job)


@app.get("/api/v1/events", dependencies=[Depends(require_api_token)])
def list_events(
    program_id: str | None = None,
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = (
        select(Event)
        .where(Event.score >= min_score)
        .order_by(Event.last_seen_at.desc())
        .limit(limit)
    )
    if program_id:
        statement = statement.where(Event.program_id == program_id)
    return [_serialize_event(event) for event in session.scalars(statement).all()]


@app.get("/api/v1/findings", dependencies=[Depends(require_api_token)])
def list_findings(
    finding_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = select(Finding).order_by(Finding.updated_at.desc()).limit(limit)
    if finding_status:
        statement = statement.where(Finding.status == finding_status)
    return [_serialize_finding(finding) for finding in session.scalars(statement).all()]


@app.get("/api/v1/findings/{finding_id}", dependencies=[Depends(require_api_token)])
def get_finding(finding_id: str, session: Session = Depends(get_db)) -> dict[str, Any]:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return _serialize_finding(finding)


@app.get("/api/v1/evidence", dependencies=[Depends(require_api_token)])
def list_evidence(
    program_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = select(Evidence).order_by(Evidence.created_at.desc()).limit(limit)
    if program_id:
        statement = statement.where(Evidence.program_id == program_id)
    return [
        _serialize_evidence(evidence)
        for evidence in session.scalars(statement).all()
    ]


@app.get("/api/v1/evidence/{evidence_id}", dependencies=[Depends(require_api_token)])
def get_evidence(
    evidence_id: str,
    include_excerpt: bool = False,
    excerpt_bytes: int = Query(default=4096, ge=1, le=16384),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    evidence = session.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    result = _serialize_evidence(evidence)
    if include_excerpt:
        try:
            result["excerpt"] = EvidenceStore(settings).read_excerpt(
                evidence, limit=excerpt_bytes
            )
        except OSError as exc:
            raise HTTPException(status_code=410, detail=f"evidence unavailable: {exc}") from exc
    return result


@app.post("/api/v1/evidence/{evidence_id}/action", dependencies=[Depends(require_api_token)])
def evidence_action(
    evidence_id: str,
    request: EvidenceAction,
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    evidence = session.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    if evidence.deleted_at is not None and request.action == "hold":
        raise HTTPException(status_code=409, detail="deleted evidence cannot be held")
    evidence.hold = request.action == "hold"
    session.add(
        AuditLog(
            actor="api-user",
            action=f"evidence_{request.action}",
            object_type="evidence",
            object_id=evidence.id,
            details={"notes": redact_text(request.notes)},
        )
    )
    session.commit()
    return _serialize_evidence(evidence)


@app.post("/api/v1/findings/{finding_id}/action", dependencies=[Depends(require_api_token)])
def finding_action(
    finding_id: str,
    request: FindingAction,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.submitted and request.action != "mark_submitted":
        raise HTTPException(status_code=409, detail="submitted finding is closed")
    if request.action == "record_manual_verification":
        if finding.submitted or finding.status in {"rejected", "rejected_by_human"}:
            raise HTTPException(status_code=409, detail="finding is closed")
        _, manifest = require_active_program(session, finding.program_id)
        evidence = EvidenceStore(settings).write_json(
            session,
            program_id=finding.program_id,
            job_id=None,
            kind="manual-verification",
            filename="manual-verification.json",
            value={"notes": request.notes, "verification": request.verification},
            retention_days=manifest.retention_days,
        )
        record_verification(
            session,
            settings,
            finding_id=finding.id,
            verification=request.verification or {},
            evidence_id=evidence.id,
        )
    elif request.action == "validate":
        _, manifest = require_active_program(session, finding.program_id)
        if finding.verification is None:
            raise HTTPException(
                status_code=409,
                detail="record a manual or deterministic verification first",
            )
        if manifest.llm.enabled and finding.critique is None:
            raise HTTPException(
                status_code=409,
                detail="record verification and wait for the independent critic first",
            )
        finding.human_validated = True
        finding.status = "validated"
        if request.report is not None:
            finding.report = redact(request.report)
    elif request.action == "reject":
        finding.human_validated = False
        finding.status = "rejected_by_human"
    elif request.action == "mark_submitted":
        if not finding.human_validated:
            raise HTTPException(status_code=409, detail="finding must be human-validated first")
        finding.submitted = True
        finding.status = "submitted"
        if request.report is not None:
            finding.report = redact(request.report)
    session.add(
        AuditLog(
            actor="api-user",
            action=f"finding_{request.action}",
            object_type="finding",
            object_id=finding.id,
            details={"notes": redact_text(request.notes)},
        )
    )
    session.commit()
    return _serialize_finding(finding)
