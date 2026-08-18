from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest
import yaml

from bbpipeline.db import engine_for, init_db, session_scope
from bbpipeline.manifest import manifest_hash
from bbpipeline.programs import ProgramUnavailable, require_active_program, sync_programs
from bbpipeline.settings import Settings


@pytest.fixture
def program_settings(manifest_raw, tmp_path):
    """Settings pointing at a config tree holding one approved manifest."""
    program_dir = tmp_path / "programs"
    policy_dir = tmp_path / "policies"
    program_dir.mkdir()
    policy_dir.mkdir()
    policy = b"saved program policy\n"
    (policy_dir / "example-policy.txt").write_bytes(policy)

    raw = deepcopy(manifest_raw)
    raw["policy_snapshot_hash"] = "sha256:" + hashlib.sha256(policy).hexdigest()
    raw["approval"]["approved_hash"] = manifest_hash(raw)
    (program_dir / "good.yml").write_text(yaml.safe_dump(raw), encoding="utf-8")

    engine_for.cache_clear()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path}/programs.sqlite3",
        program_dir=program_dir,
        evidence_dir=tmp_path / "evidence",
    )
    init_db(settings)
    return settings, program_dir, raw


def test_broken_sibling_manifest_leaves_the_approved_program_running(program_settings):
    settings, program_dir, raw = program_settings
    with session_scope(settings) as session:
        assert [(p.id, p.active) for p in sync_programs(session, settings)] == [
            ("example-program", True)
        ]

    broken = deepcopy(raw)
    broken["program_id"] = "broken-program"
    broken["platform"] = "not-a-real-platform"
    (program_dir / "broken.yml").write_text(yaml.safe_dump(broken), encoding="utf-8")

    with session_scope(settings) as session:
        sync_programs(session, settings)
        program, _ = require_active_program(session, "example-program")
        assert program.active is True


def test_a_program_whose_own_manifest_breaks_is_paused(program_settings):
    settings, program_dir, raw = program_settings
    with session_scope(settings) as session:
        sync_programs(session, settings)

    broken = deepcopy(raw)
    broken["platform"] = "not-a-real-platform"
    (program_dir / "good.yml").write_text(yaml.safe_dump(broken), encoding="utf-8")

    with session_scope(settings) as session:
        sync_programs(session, settings)
        with pytest.raises(ProgramUnavailable, match="manifest failed to load"):
            require_active_program(session, "example-program")


def test_a_program_is_reactivated_once_its_manifest_is_repaired(program_settings):
    settings, program_dir, raw = program_settings
    good = (program_dir / "good.yml").read_text(encoding="utf-8")
    (program_dir / "good.yml").write_text("key: [unclosed\n", encoding="utf-8")

    with session_scope(settings) as session:
        sync_programs(session, settings)
        with pytest.raises(ProgramUnavailable):
            require_active_program(session, "example-program")

    (program_dir / "good.yml").write_text(good, encoding="utf-8")
    with session_scope(settings) as session:
        sync_programs(session, settings)
        program, _ = require_active_program(session, "example-program")
        assert program.active is True
        assert program.paused_reason is None
