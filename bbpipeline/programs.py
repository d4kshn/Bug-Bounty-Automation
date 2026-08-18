from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from bbpipeline.manifest import (
    InvalidManifest,
    LoadedManifest,
    ProgramManifest,
    load_manifests,
)
from bbpipeline.models import AuditLog, PlatformSourceState, Program
from bbpipeline.platform_sources import load_platform_sources
from bbpipeline.platform_sync import source_pause_reason
from bbpipeline.settings import Settings


class ProgramUnavailable(RuntimeError):
    pass


def sync_programs(session: Session, settings: Settings, *, actor: str = "system") -> list[Program]:
    manifests = load_manifests(settings.program_dir)
    platform_sources = load_platform_sources(settings.platform_source_dir)
    configured_sources = {source.source_id: source for source in platform_sources.loaded}
    sources_by_program = {source.program_id: source for source in platform_sources.loaded}
    seen: set[str] = set()
    synced: list[Program] = []

    for entry in manifests.loaded:
        manifest = entry.manifest
        seen.add(manifest.program_id)
        program = session.get(Program, manifest.program_id)
        previous_hash = program.manifest_hash if program else None
        previous_active = bool(program and program.active)
        previous_paused_reason = program.paused_reason if program else None
        if program is None:
            program = Program(
                id=manifest.program_id,
                name=manifest.name,
                platform=manifest.platform,
                policy_url=manifest.policy_url,
                manifest_hash=entry.computed_hash,
                approved_hash=manifest.approval.approved_hash,
                manifest=manifest.model_dump(mode="json"),
            )
            session.add(program)

        program.name = manifest.name
        program.platform = manifest.platform
        program.policy_url = manifest.policy_url
        program.manifest_hash = entry.computed_hash
        program.approved_hash = manifest.approval.approved_hash
        program.manifest = manifest.model_dump(mode="json")
        platform_reason = None
        configured_for_program = sources_by_program.get(manifest.program_id)
        if manifest.source:
            configured_source = configured_sources.get(manifest.source.source_id)
            if configured_source is None or not configured_source.enabled:
                platform_reason = (
                    "platform source configuration is absent, invalid, or disabled"
                )
            elif (
                configured_source.program_id != manifest.program_id
                or configured_source.platform != manifest.source.platform
                or configured_source.remote_identifier != manifest.source.remote_identifier
            ):
                platform_reason = "platform source configuration does not match the manifest"
            else:
                platform_reason = source_pause_reason(session, settings, manifest)
        elif configured_for_program is not None and configured_for_program.enabled:
            platform_reason = "manifest is not bound to its enrolled platform source"
        program.active = entry.approved and platform_reason is None
        if program.active:
            program.paused_reason = None
            if manifest.source:
                source_state = session.get(
                    PlatformSourceState, manifest.source.source_id
                )
                if source_state is not None:
                    source_state.status = "approved"
        elif platform_reason:
            program.paused_reason = platform_reason
            if previous_active or previous_paused_reason != platform_reason:
                session.add(
                    AuditLog(
                        actor=actor,
                        action="program_paused_platform_gate",
                        object_type="program",
                        object_id=manifest.program_id,
                        details={"reason": platform_reason},
                    )
                )
        elif not entry.policy_snapshot_valid:
            program.paused_reason = "policy snapshot is absent or its hash does not match"
        else:
            program.paused_reason = "manifest hash is not human-approved"
        synced.append(program)

        if previous_hash != entry.computed_hash:
            session.add(
                AuditLog(
                    actor=actor,
                    action="program_manifest_synced",
                    object_type="program",
                    object_id=manifest.program_id,
                    details={
                        "previous_hash": previous_hash,
                        "manifest_hash": entry.computed_hash,
                        "approved": entry.approved,
                        "path": str(entry.path),
                    },
                )
            )

    # A manifest that no longer loads pauses only its own program. Files whose
    # program_id cannot be recovered fall through to the absent-manifest sweep below,
    # which also pauses them.
    for broken in manifests.invalid:
        if broken.program_id is None:
            continue
        seen.add(broken.program_id)
        program = session.get(Program, broken.program_id)
        if program is None:
            continue
        reason = f"manifest failed to load: {broken.error}"
        if program.active or program.paused_reason != reason:
            session.add(
                AuditLog(
                    actor=actor,
                    action="program_paused_invalid_manifest",
                    object_type="program",
                    object_id=program.id,
                    details={"path": str(broken.path), "error": broken.error},
                )
            )
        program.active = False
        program.paused_reason = reason
        if program not in synced:
            synced.append(program)

    existing = session.scalars(select(Program)).all()
    for program in existing:
        if program.id not in seen and program.active:
            program.active = False
            program.paused_reason = "manifest file is absent"
            session.add(
                AuditLog(
                    actor=actor,
                    action="program_paused_missing_manifest",
                    object_type="program",
                    object_id=program.id,
                    details={},
                )
            )

    session.flush()
    return synced


def require_active_program(session: Session, program_id: str) -> tuple[Program, ProgramManifest]:
    program = session.get(Program, program_id)
    if not program:
        raise ProgramUnavailable(f"unknown program: {program_id}")
    if not program.active:
        raise ProgramUnavailable(
            f"program {program_id} is paused: {program.paused_reason or 'not approved'}"
        )
    if program.manifest_hash != program.approved_hash:
        raise ProgramUnavailable(f"program {program_id} manifest approval hash does not match")
    return program, ProgramManifest.model_validate(program.manifest)


def invalid_manifest_summary(entry: InvalidManifest) -> dict[str, str | bool | None]:
    return {
        "program_id": entry.program_id,
        "path": str(entry.path),
        "approved": False,
        "error": entry.error,
    }


def approval_summary(entry: LoadedManifest) -> dict[str, str | bool]:
    return {
        "program_id": entry.manifest.program_id,
        "path": str(entry.path),
        "computed_hash": entry.computed_hash,
        "approved_hash": entry.manifest.approval.approved_hash,
        "policy_snapshot_actual_hash": entry.policy_snapshot_actual_hash or "missing",
        "policy_snapshot_expected_hash": entry.manifest.policy_snapshot_hash,
        "policy_snapshot_valid": entry.policy_snapshot_valid,
        "approved": entry.approved,
    }
