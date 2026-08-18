from __future__ import annotations

from bbpipeline.db import engine_for, init_db, session_scope
from bbpipeline.queue import claim, complete, enqueue
from bbpipeline.settings import Settings


def test_queue_deduplicates_claims_and_completes(tmp_path):
    engine_for.cache_clear()
    settings = Settings(database_url=f"sqlite+pysqlite:///{tmp_path}/queue.sqlite3")
    init_db(settings)
    with session_scope(settings) as session:
        first = enqueue(
            session,
            queue="scan",
            kind="retention",
            payload={},
            dedupe_key="same",
        )
        second = enqueue(
            session,
            queue="scan",
            kind="retention",
            payload={},
            dedupe_key="same",
        )
        assert first.id == second.id

    with session_scope(settings) as session:
        job = claim(session, queues=["scan"], owner="test", lease_seconds=60)
        assert job is not None
        assert job.status == "running"
        complete(session, job, {"ok": True})

    with session_scope(settings) as session:
        assert claim(session, queues=["scan"], owner="test", lease_seconds=60) is None
