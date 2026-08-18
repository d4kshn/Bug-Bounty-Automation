from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from bbpipeline.models import Job, utcnow


TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def enqueue(
    session: Session,
    *,
    queue: str,
    kind: str,
    payload: dict[str, Any],
    program_id: str | None = None,
    priority: int = 0,
    max_attempts: int = 3,
    run_after: datetime | None = None,
    dedupe_key: str | None = None,
) -> Job:
    job = Job(
        queue=queue,
        kind=kind,
        payload=payload,
        program_id=program_id,
        priority=priority,
        max_attempts=max_attempts,
        run_after=run_after or utcnow(),
        dedupe_key=dedupe_key,
    )
    if dedupe_key:
        try:
            with session.begin_nested():
                session.add(job)
                session.flush()
            return job
        except IntegrityError:
            existing = session.scalar(select(Job).where(Job.dedupe_key == dedupe_key))
            if existing is None:
                raise
            return existing
    session.add(job)
    session.flush()
    return job


def requeue_expired(session: Session, *, now: datetime | None = None) -> int:
    current = now or utcnow()
    result = session.execute(
        update(Job)
        .where(
            Job.status == "running",
            Job.lease_expires_at.is_not(None),
            Job.lease_expires_at < current,
        )
        .values(
            status="pending",
            lease_owner=None,
            lease_expires_at=None,
            error="worker lease expired; job requeued",
            run_after=current,
        )
    )
    return int(result.rowcount or 0)


def claim(
    session: Session,
    *,
    queues: list[str],
    owner: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> Job | None:
    current = now or utcnow()
    requeue_expired(session, now=current)
    statement = (
        select(Job)
        .where(
            Job.queue.in_(queues),
            Job.status == "pending",
            Job.run_after <= current,
            or_(Job.lease_expires_at.is_(None), Job.lease_expires_at < current),
        )
        .order_by(Job.priority.desc(), Job.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    job = session.scalar(statement)
    if job is None:
        return None
    job.status = "running"
    job.attempts += 1
    job.lease_owner = owner
    job.lease_expires_at = current + timedelta(seconds=lease_seconds)
    job.started_at = current
    job.error = None
    session.flush()
    return job


def complete(session: Session, job: Job, result: dict[str, Any]) -> None:
    job.status = "completed"
    job.result = result
    job.error = None
    job.lease_owner = None
    job.lease_expires_at = None
    job.completed_at = utcnow()
    session.flush()

def fail(session: Session, job: Job, error: str) -> None:
    job.error = error[:8000]
    job.lease_owner = None
    job.lease_expires_at = None
    if job.attempts < job.max_attempts:
        delay = min(3600, 30 * (2 ** max(0, job.attempts - 1)))
        job.status = "pending"
        job.run_after = datetime.now(UTC) + timedelta(seconds=delay)
    else:
        job.status = "failed"
        job.completed_at = utcnow()
    session.flush()


def cancel(session: Session, job: Job) -> None:
    if job.status in TERMINAL_STATUSES:
        return
    job.status = "cancelled"
    job.lease_owner = None
    job.lease_expires_at = None
    job.completed_at = utcnow()
    session.flush()
