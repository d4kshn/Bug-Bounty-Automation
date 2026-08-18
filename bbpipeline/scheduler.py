from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.orm import Session

from bbpipeline.db import session_scope
from bbpipeline.manifest import ProgramManifest
from bbpipeline.models import Program, ScheduleState, utcnow
from bbpipeline.programs import sync_programs
from bbpipeline.queue import enqueue
from bbpipeline.settings import Settings


LOGGER = logging.getLogger(__name__)


def _job_enabled(manifest: ProgramManifest, kind: str) -> bool:
    return {
        "bbot": manifest.bbot.enabled,
        "nuclei": manifest.nuclei.enabled,
        "github": manifest.repositories.enabled,
        "gitleaks": manifest.repositories.enabled,
        "shodan": manifest.shodan.enabled,
    }.get(kind, False)


def _next_run(manifest: ProgramManifest, kind: str, expression: str, after: datetime) -> datetime:
    iterator = croniter(expression, after)
    base = iterator.get_next(datetime)
    following = iterator.get_next(datetime)
    interval_ceiling = max(0, int((following - base).total_seconds()) - 1)
    ceiling = min(manifest.schedule_jitter_seconds, interval_ceiling)
    if ceiling == 0:
        return base
    identity = f"{manifest.program_id}:{kind}:{base.isoformat()}".encode()
    seconds = int(hashlib.sha256(identity).hexdigest()[:8], 16) % (ceiling + 1)
    return base + timedelta(seconds=seconds)


def _enqueue_due(
    session: Session,
    manifest: ProgramManifest,
    *,
    kind: str,
    scheduled_for: datetime,
) -> None:
    stamp = scheduled_for.isoformat()
    if kind == "gitleaks":
        exact_repositories = [
            rule.value
            for rule in manifest.scope.include
            if rule.type == "repository" and "*" not in rule.value
        ]
        for repository in exact_repositories:
            enqueue(
                session,
                queue="scan",
                kind="gitleaks",
                program_id=manifest.program_id,
                payload={"repository": repository},
                priority=10,
                dedupe_key=f"schedule:{manifest.program_id}:gitleaks:{repository}:{stamp}",
            )
        return
    enqueue(
        session,
        queue="scan",
        kind=kind,
        program_id=manifest.program_id,
        payload={},
        priority=5,
        dedupe_key=f"schedule:{manifest.program_id}:{kind}:{stamp}",
    )


def scheduler_tick(session: Session, settings: Settings, *, now: datetime | None = None) -> int:
    current = now or utcnow()
    sync_programs(session, settings, actor="scheduler")
    enqueue(
        session,
        queue="scan",
        kind="retention",
        program_id=None,
        payload={},
        priority=1,
        dedupe_key=f"retention:{current.date().isoformat()}",
    )
    programs = session.scalars(select(Program).where(Program.active.is_(True))).all()
    queued = 0
    active_keys: set[tuple[str, str]] = set()
    for program in programs:
        # Scheduling for one program must never stop scheduling for the others, so a
        # stored manifest that no longer validates is skipped instead of raising.
        try:
            manifest = ProgramManifest.model_validate(program.manifest)
        except Exception:  # noqa: BLE001 - isolate a single program's bad manifest
            LOGGER.exception(
                "stored manifest for %s is invalid; skipping its schedules", program.id
            )
            continue
        for kind, expression in manifest.schedules.items():
            if not _job_enabled(manifest, kind):
                continue
            if not croniter.is_valid(expression):
                LOGGER.error(
                    "invalid cron expression for %s/%s: %s; skipping this schedule",
                    manifest.program_id,
                    kind,
                    expression,
                )
                continue
            active_keys.add((manifest.program_id, kind))
            state = session.scalar(
                select(ScheduleState).where(
                    ScheduleState.program_id == manifest.program_id,
                    ScheduleState.job_kind == kind,
                )
            )
            if state is None:
                state = ScheduleState(
                    program_id=manifest.program_id,
                    job_kind=kind,
                    cron=expression,
                    next_run_at=_next_run(manifest, kind, expression, current),
                )
                session.add(state)
                continue
            if state.cron != expression:
                state.cron = expression
                state.next_run_at = _next_run(manifest, kind, expression, current)
                continue
            if state.next_run_at <= current:
                scheduled_for = state.next_run_at
                _enqueue_due(session, manifest, kind=kind, scheduled_for=scheduled_for)
                state.last_run_at = current
                state.next_run_at = _next_run(manifest, kind, expression, current)
                queued += 1

    states = session.scalars(select(ScheduleState)).all()
    for state in states:
        if (state.program_id, state.job_kind) not in active_keys:
            session.delete(state)
    session.flush()
    return queued


def scheduler_loop(settings: Settings) -> None:
    LOGGER.info("scheduler started")
    while True:
        try:
            with session_scope(settings) as session:
                queued = scheduler_tick(session, settings)
                if queued:
                    LOGGER.info("scheduled %s jobs", queued)
        except Exception:
            LOGGER.exception("scheduler tick failed; no new jobs were scheduled")
        time.sleep(settings.scheduler_poll_seconds)
