from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from bbpipeline.manifest import ProgramManifest
from bbpipeline.models import AuditLog, PlatformSourceState, Program, utcnow
from bbpipeline.notifications import queue_notification
from bbpipeline.platform_sources import (
    PlatformAuthError,
    PlatformDataError,
    PlatformSourceConfig,
    build_candidate_manifest,
    fetch_platform_snapshot,
    load_platform_sources,
)
from bbpipeline.redaction import redact_text
from bbpipeline.settings import Settings


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def source_is_stale(state: PlatformSourceState, settings: Settings) -> bool:
    if state.last_success_at is None:
        return True
    return _as_utc(state.last_success_at) < utcnow() - timedelta(
        seconds=settings.platform_source_max_stale_seconds
    )


def source_pause_reason(
    session: Session, settings: Settings, manifest: ProgramManifest
) -> str | None:
    reference = manifest.source
    if reference is None:
        return None
    state = session.get(PlatformSourceState, reference.source_id)
    if state is None:
        return "platform source has not synchronized"
    if state.program_id != manifest.program_id:
        return "platform source is assigned to a different program"
    if (
        state.platform != reference.platform
        or state.remote_identifier != reference.remote_identifier
    ):
        return "platform source identity does not match the approved manifest"
    if state.status == "auth_error":
        return "platform credential was rejected or expired"
    if state.status == "error":
        return "latest platform data could not produce a safe candidate"
    if source_is_stale(state, settings):
        return "platform source is stale beyond the configured safety window"
    if state.revision_hash != reference.revision_hash:
        return "platform scope or policy changed and is pending human approval"
    return None


def _existing_manifest(program: Program | None) -> ProgramManifest | None:
    if program is None:
        return None
    try:
        return ProgramManifest.model_validate(program.manifest)
    except Exception:  # noqa: BLE001 - an old invalid manifest is not a candidate base
        return None


def _pause_program(
    session: Session,
    source: PlatformSourceConfig,
    reason: str,
    *,
    action: str,
    details: dict[str, Any],
) -> Program | None:
    program = session.get(Program, source.program_id)
    if program is None:
        return None
    if program.active or program.paused_reason != reason:
        session.add(
            AuditLog(
                actor="platform-sync",
                action=action,
                object_type="program",
                object_id=program.id,
                details=details,
            )
        )
    program.active = False
    program.paused_reason = reason
    return program


def sync_platform_source(
    session: Session,
    settings: Settings,
    source: PlatformSourceConfig,
    *,
    transport: httpx.BaseTransport | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or utcnow()
    state = session.get(PlatformSourceState, source.source_id)
    if state is None:
        state = PlatformSourceState(
            source_id=source.source_id,
            program_id=source.program_id,
            platform=source.platform,
            remote_identifier=source.remote_identifier,
        )
        session.add(state)
        session.flush()
    elif (
        state.program_id != source.program_id
        or state.platform != source.platform
        or state.remote_identifier != source.remote_identifier
    ):
        raise ValueError(
            "source identity is immutable; create a new source_id for another program"
        )

    previous_status = state.status
    state.last_checked_at = current
    try:
        snapshot = fetch_platform_snapshot(settings, source, transport=transport)
    except Exception as exc:
        safe_error = redact_text(f"{type(exc).__name__}: {exc}")[:1000]
        state.last_error = safe_error
        auth_error = isinstance(exc, PlatformAuthError) or (
            source.platform == "bugcrowd" and isinstance(exc, PlatformDataError)
        )
        too_stale = source_is_stale(state, settings)
        if auth_error or too_stale:
            state.status = "auth_error" if auth_error else "error"
            reason = (
                "platform credential was rejected or expired"
                if auth_error
                else "platform source failed before any fresh snapshot was available"
            )
            program = _pause_program(
                session,
                source,
                reason,
                action="program_paused_platform_source_error",
                details={"source_id": source.source_id, "error": safe_error},
            )
            if previous_status != state.status:
                incident = (
                    _as_utc(state.last_success_at).isoformat()
                    if state.last_success_at
                    else "first-sync"
                )
                queue_notification(
                    session,
                    title="Platform source failed closed",
                    message=(
                        f"{source.platform}/{source.remote_identifier}: {reason}. "
                        "Refresh the credential or investigate the adapter before resuming."
                    ),
                    record_type="platform_source",
                    record_id=source.source_id,
                    severity="high",
                    program_id=program.id if program else None,
                    dedupe_key=(
                        f"notify:platform-error:{source.source_id}:{state.status}:{incident}"
                    ),
                )
        session.flush()
        return {
            "source_id": source.source_id,
            "program_id": source.program_id,
            "platform": source.platform,
            "changed": False,
            "status": state.status,
            "candidate_ready": state.candidate_manifest is not None,
            "error": safe_error,
        }

    previous_revision = state.revision_hash
    changed = previous_revision != snapshot.revision_hash
    state.revision_hash = snapshot.revision_hash
    state.raw_snapshot = snapshot.canonical()
    state.last_success_at = current
    state.last_error = None
    if changed:
        state.changed_at = current

    try:
        program = session.get(Program, source.program_id)
        candidate, policy_text = build_candidate_manifest(
            source,
            snapshot,
            existing=_existing_manifest(program),
            generated_at=current,
        )
    except Exception as exc:
        safe_error = redact_text(f"{type(exc).__name__}: {exc}")[:1000]
        state.status = "error"
        state.candidate_manifest = None
        state.policy_snapshot = None
        state.last_error = safe_error
        reason = "platform data changed but a safe candidate could not be generated"
        program = _pause_program(
            session,
            source,
            reason,
            action="program_paused_platform_candidate_error",
            details={
                "source_id": source.source_id,
                "previous_revision": previous_revision,
                "revision_hash": snapshot.revision_hash,
                "error": safe_error,
            },
        )
        queue_notification(
            session,
            title="Platform candidate failed closed",
            message=(
                f"{source.platform}/{source.remote_identifier} was fetched, but its "
                "scope cannot be represented safely. Manual review is required."
            ),
            record_type="platform_source",
            record_id=source.source_id,
            severity="high",
            program_id=program.id if program else None,
            dedupe_key=(
                f"notify:platform-candidate-error:{source.source_id}:"
                f"{snapshot.revision_hash}"
            ),
        )
        session.flush()
        return {
            "source_id": source.source_id,
            "program_id": source.program_id,
            "platform": source.platform,
            "revision_hash": snapshot.revision_hash,
            "changed": changed,
            "status": state.status,
            "candidate_ready": False,
            "error": safe_error,
        }

    state.candidate_manifest = candidate
    state.policy_snapshot = policy_text

    approved_revision = None
    existing = _existing_manifest(session.get(Program, source.program_id))
    if existing and existing.source:
        approved_revision = existing.source.revision_hash
    if approved_revision == snapshot.revision_hash:
        state.status = "approved"
    else:
        state.status = "pending"
        program = _pause_program(
            session,
            source,
            "platform scope or policy changed and is pending human approval",
            action="program_paused_platform_change",
            details={
                "source_id": source.source_id,
                "previous_revision": previous_revision,
                "revision_hash": snapshot.revision_hash,
            },
        )
        if changed:
            queue_notification(
                session,
                title="Program scope review required",
                message=(
                    f"{source.platform}/{source.remote_identifier} changed. "
                    "The program is paused until its generated candidate is reviewed and approved."
                ),
                record_type="platform_source",
                record_id=source.source_id,
                severity="high",
                program_id=program.id if program else None,
                dedupe_key=f"notify:platform-change:{source.source_id}:{snapshot.revision_hash}",
            )
    session.add(
        AuditLog(
            actor="platform-sync",
            action="platform_source_synchronized",
            object_type="platform_source",
            object_id=source.source_id,
            details={
                "program_id": source.program_id,
                "platform": source.platform,
                "changed": changed,
                "revision_hash": snapshot.revision_hash,
                "status": state.status,
            },
        )
    )
    session.flush()
    return {
        "source_id": source.source_id,
        "program_id": source.program_id,
        "platform": source.platform,
        "revision_hash": snapshot.revision_hash,
        "changed": changed,
        "status": state.status,
        "candidate_ready": True,
    }


def sync_platform_sources(
    session: Session,
    settings: Settings,
    *,
    source_id: str | None = None,
) -> list[dict[str, Any]]:
    sources = load_platform_sources(settings.platform_source_dir)
    matching_invalid = [item for item in sources.invalid if item.source_id == source_id]
    if source_id is not None and matching_invalid:
        errors = "; ".join(f"{item.path}: {item.error}" for item in matching_invalid)
        raise ValueError(f"invalid platform source configuration: {errors}")
    selected = [
        source
        for source in sources.loaded
        if source.enabled and (source_id is None or source.source_id == source_id)
    ]
    if source_id is not None and not selected:
        raise ValueError(f"unknown or disabled platform source: {source_id}")
    return [sync_platform_source(session, settings, source) for source in selected]


def export_platform_candidate(
    session: Session,
    source_id: str,
    output_dir: Path,
) -> dict[str, str]:
    state = session.get(PlatformSourceState, source_id)
    if state is None or state.candidate_manifest is None or state.policy_snapshot is None:
        raise ValueError(f"no candidate is available for source: {source_id}")
    root = output_dir.resolve()
    programs_dir = root / "programs"
    policies_dir = root / "policies"
    programs_dir.mkdir(parents=True, exist_ok=True)
    policies_dir.mkdir(parents=True, exist_ok=True)
    program_path = programs_dir / f"{state.program_id}.yml"
    policy_name = str(state.candidate_manifest["policy_snapshot_file"])
    if Path(policy_name).name != policy_name:
        raise ValueError("candidate policy filename is unsafe")
    policy_path = policies_dir / policy_name
    if program_path.exists() or policy_path.exists():
        raise FileExistsError("refusing to overwrite an existing exported candidate")
    program_path.write_text(
        yaml.safe_dump(state.candidate_manifest, sort_keys=False), encoding="utf-8"
    )
    policy_path.write_text(state.policy_snapshot, encoding="utf-8")
    return {
        "source_id": source_id,
        "manifest": str(program_path),
        "policy_snapshot": str(policy_path),
        "revision_hash": state.revision_hash or "",
    }


def platform_candidate_document(session: Session, source_id: str) -> dict[str, Any]:
    state = session.get(PlatformSourceState, source_id)
    if state is None or state.candidate_manifest is None or state.policy_snapshot is None:
        raise ValueError(f"no candidate is available for source: {source_id}")
    return {
        "source_id": source_id,
        "program_id": state.program_id,
        "revision_hash": state.revision_hash,
        "manifest_filename": f"{state.program_id}.yml",
        "policy_filename": str(state.candidate_manifest["policy_snapshot_file"]),
        "manifest_yaml": yaml.safe_dump(state.candidate_manifest, sort_keys=False),
        "policy_snapshot": state.policy_snapshot,
    }


def platform_source_summaries(session: Session) -> list[dict[str, Any]]:
    states = session.scalars(
        select(PlatformSourceState).order_by(PlatformSourceState.source_id)
    ).all()
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
        for state in states
    ]
