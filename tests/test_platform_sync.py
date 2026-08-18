from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime

import pytest
import yaml
from sqlalchemy import select

from bbpipeline.db import engine_for, init_db, session_scope
from bbpipeline.manifest import manifest_hash
from bbpipeline.models import Job, PlatformSourceState
from bbpipeline.platform_sources import (
    PlatformAuthError,
    PlatformSnapshot,
    PlatformSourceConfig,
    RemoteAsset,
)
from bbpipeline.platform_sync import (
    export_platform_candidate,
    sync_platform_source,
)
from bbpipeline.programs import ProgramUnavailable, require_active_program, sync_programs
from bbpipeline.scheduler import scheduler_tick
from bbpipeline.settings import Settings


@pytest.fixture
def sync_setup(tmp_path, manifest_raw):
    program_dir = tmp_path / "programs"
    policy_dir = tmp_path / "policies"
    source_dir = tmp_path / "platform-sources"
    for directory in (program_dir, policy_dir, source_dir):
        directory.mkdir()
    policy = b"initial policy\n"
    (policy_dir / "example-policy.txt").write_bytes(policy)
    raw = deepcopy(manifest_raw)
    raw["policy_snapshot_hash"] = "sha256:" + hashlib.sha256(policy).hexdigest()
    raw["approval"]["approved_hash"] = manifest_hash(raw)
    manifest_path = program_dir / "example.yml"
    manifest_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    source = PlatformSourceConfig(
        version=1,
        source_id="hackerone-example",
        program_id="example-program",
        platform="hackerone",
        remote_identifier="example",
    )
    (source_dir / "example.yml").write_text(
        yaml.safe_dump(source.model_dump(mode="json")), encoding="utf-8"
    )
    engine_for.cache_clear()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path}/sync.sqlite3",
        program_dir=program_dir,
        platform_source_dir=source_dir,
        evidence_dir=tmp_path / "evidence",
    )
    init_db(settings)
    return settings, source, manifest_path, policy_dir


def _snapshot(target: str = "example.com") -> PlatformSnapshot:
    return PlatformSnapshot(
        platform="hackerone",
        remote_identifier="example",
        name="Example",
        policy_url="https://hackerone.com/example",
        policy_text="Automated tooling is permitted at one request per second.",
        assets=[RemoteAsset(target=target, category="URL")],
    )


def test_first_sync_pauses_existing_program_and_creates_pending_candidate(
    sync_setup, monkeypatch
):
    settings, source, _, _ = sync_setup
    with session_scope(settings) as session:
        sync_programs(session, settings)
        with pytest.raises(ProgramUnavailable, match="not bound"):
            require_active_program(session, "example-program")

    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: _snapshot(),
    )
    with session_scope(settings) as session:
        result = sync_platform_source(session, settings, source)
        assert result["status"] == "pending"
        state = session.get(PlatformSourceState, source.source_id)
        assert state is not None and state.candidate_manifest is not None
        with pytest.raises(ProgramUnavailable, match="pending human approval"):
            require_active_program(session, "example-program")
    with session_scope(settings) as session:
        sync_programs(session, settings, actor="worker-preflight")
        with pytest.raises(ProgramUnavailable, match="not bound"):
            require_active_program(session, "example-program")


def test_reviewed_candidate_reactivates_only_after_both_hashes_match(
    sync_setup, monkeypatch
):
    settings, source, manifest_path, policy_dir = sync_setup
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: _snapshot(),
    )
    with session_scope(settings) as session:
        sync_programs(session, settings)
        sync_platform_source(session, settings, source)
        state = session.get(PlatformSourceState, source.source_id)
        candidate = deepcopy(state.candidate_manifest)
        policy_text = state.policy_snapshot

    policy_path = policy_dir / candidate["policy_snapshot_file"]
    policy_path.write_text(policy_text, encoding="utf-8")
    candidate["approval"]["approved_by"] = "d4kshn"
    candidate["approval"]["approved_at"] = "2026-08-18T00:00:00Z"
    candidate["approval"]["approved_hash"] = manifest_hash(candidate)
    manifest_path.write_text(yaml.safe_dump(candidate, sort_keys=False), encoding="utf-8")

    with session_scope(settings) as session:
        sync_programs(session, settings)
        program, manifest = require_active_program(session, "example-program")
        assert program.active is True
        assert manifest.source.revision_hash == _snapshot().revision_hash
        assert session.get(PlatformSourceState, source.source_id).status == "approved"


def test_later_platform_change_pauses_an_approved_program(sync_setup, monkeypatch):
    settings, source, manifest_path, policy_dir = sync_setup
    current_snapshot = _snapshot()
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: current_snapshot,
    )
    with session_scope(settings) as session:
        sync_programs(session, settings)
        sync_platform_source(session, settings, source)
        state = session.get(PlatformSourceState, source.source_id)
        candidate = deepcopy(state.candidate_manifest)
        (policy_dir / candidate["policy_snapshot_file"]).write_text(
            state.policy_snapshot, encoding="utf-8"
        )
    candidate["approval"]["approved_hash"] = manifest_hash(candidate)
    manifest_path.write_text(yaml.safe_dump(candidate), encoding="utf-8")
    with session_scope(settings) as session:
        sync_programs(session, settings)
        require_active_program(session, "example-program")

    changed_snapshot = _snapshot("api.example.com")
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: changed_snapshot,
    )
    with session_scope(settings) as session:
        result = sync_platform_source(session, settings, source)
        assert result["changed"] is True
        with pytest.raises(ProgramUnavailable, match="pending human approval"):
            require_active_program(session, "example-program")


def test_authentication_failure_pauses_immediately(sync_setup, monkeypatch):
    settings, source, _, _ = sync_setup
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: (_ for _ in ()).throw(
            PlatformAuthError("expired")
        ),
    )
    with session_scope(settings) as session:
        sync_programs(session, settings)
        result = sync_platform_source(session, settings, source)
        assert result["status"] == "auth_error"
        state = session.get(PlatformSourceState, source.source_id)
        assert state.status == "auth_error"


def test_unbuildable_changed_candidate_still_pauses_immediately(
    sync_setup, monkeypatch
):
    settings, source, manifest_path, _ = sync_setup
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    raw["schedules"] = {"bbot": "0 3 * * *"}
    raw["approval"]["approved_hash"] = manifest_hash(raw)
    manifest_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: _snapshot("*.example.com"),
    )

    with session_scope(settings) as session:
        sync_programs(session, settings)
        result = sync_platform_source(session, settings, source)
        assert result["status"] == "error"
        assert result["candidate_ready"] is False
        assert result["changed"] is True
        with pytest.raises(ProgramUnavailable, match="safe candidate"):
            require_active_program(session, "example-program")


def test_candidate_export_never_overwrites(sync_setup, monkeypatch, tmp_path):
    settings, source, _, _ = sync_setup
    monkeypatch.setattr(
        "bbpipeline.platform_sync.fetch_platform_snapshot",
        lambda settings, source, transport=None: _snapshot(),
    )
    destination = tmp_path / "candidate"
    with session_scope(settings) as session:
        sync_programs(session, settings)
        sync_platform_source(session, settings, source)
        result = export_platform_candidate(session, source.source_id, destination)
        assert result["manifest"].endswith("example-program.yml")
        with pytest.raises(FileExistsError, match="overwrite"):
            export_platform_candidate(session, source.source_id, destination)


def test_scheduler_queues_one_deduplicated_platform_sync(sync_setup):
    settings, source, _, _ = sync_setup
    now = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

    with session_scope(settings) as session:
        scheduler_tick(session, settings, now=now)
        scheduler_tick(session, settings, now=now)
        jobs = session.scalars(select(Job).where(Job.kind == "platform_sync")).all()

    assert len(jobs) == 1
    assert jobs[0].payload == {"source_id": source.source_id}
    assert jobs[0].program_id is None
