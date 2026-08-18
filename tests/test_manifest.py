from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest
import yaml
from pydantic import ValidationError

from bbpipeline.manifest import (
    ProgramManifest,
    load_manifest,
    load_manifests,
    manifest_hash,
)
from bbpipeline.settings import Settings


def write_program(directory, raw, filename):
    path = directory / filename
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def approved_program(tmp_path, manifest_raw):
    """A program directory holding one approved manifest and its policy snapshot."""
    program_dir = tmp_path / "programs"
    policy_dir = tmp_path / "policies"
    program_dir.mkdir()
    policy_dir.mkdir()
    policy = b"saved program policy\n"
    (policy_dir / "example-policy.txt").write_bytes(policy)
    raw = deepcopy(manifest_raw)
    raw["policy_snapshot_hash"] = "sha256:" + hashlib.sha256(policy).hexdigest()
    raw["approval"]["approved_hash"] = manifest_hash(raw)
    write_program(program_dir, raw, "good.yml")
    return program_dir, raw


def test_default_evidence_retention_is_30_days(manifest_raw):
    assert ProgramManifest.model_validate(manifest_raw).retention_days == 30
    assert Settings(database_url="sqlite+pysqlite:///:memory:").default_retention_days == 30


def test_approval_hash_excludes_approval_metadata(manifest_raw, tmp_path):
    original = manifest_hash(manifest_raw)
    changed = deepcopy(manifest_raw)
    changed["approval"]["approved_by"] = "another-reviewer"
    assert manifest_hash(changed) == original


def test_scope_change_invalidates_approval(manifest_raw, tmp_path):
    program_dir = tmp_path / "programs"
    policy_dir = tmp_path / "policies"
    program_dir.mkdir()
    policy_dir.mkdir()
    policy = b"saved program policy\n"
    (policy_dir / "example-policy.txt").write_bytes(policy)
    manifest_raw["policy_snapshot_hash"] = "sha256:" + hashlib.sha256(policy).hexdigest()
    manifest_raw["approval"]["approved_hash"] = manifest_hash(manifest_raw)
    path = program_dir / "program.yml"
    path.write_text(yaml.safe_dump(manifest_raw), encoding="utf-8")
    assert load_manifest(path).approved is True

    manifest_raw["scope"]["include"].append(
        {"type": "domain", "value": "new.example.com"}
    )
    path.write_text(yaml.safe_dump(manifest_raw), encoding="utf-8")
    loaded = load_manifest(path)
    assert loaded.approved is False
    assert loaded.computed_hash != loaded.manifest.approval.approved_hash


def test_policy_snapshot_change_pauses_approval(manifest_raw, tmp_path):
    program_dir = tmp_path / "programs"
    policy_dir = tmp_path / "policies"
    program_dir.mkdir()
    policy_dir.mkdir()
    policy_path = policy_dir / "example-policy.txt"
    policy_path.write_bytes(b"version one\n")
    manifest_raw["policy_snapshot_hash"] = (
        "sha256:" + hashlib.sha256(policy_path.read_bytes()).hexdigest()
    )
    manifest_raw["approval"]["approved_hash"] = manifest_hash(manifest_raw)
    path = program_dir / "program.yml"
    path.write_text(yaml.safe_dump(manifest_raw), encoding="utf-8")
    assert load_manifest(path).approved is True

    policy_path.write_bytes(b"version two\n")
    loaded = load_manifest(path)
    assert loaded.policy_snapshot_valid is False
    assert loaded.approved is False


def test_one_unloadable_manifest_does_not_hide_the_others(manifest_raw, tmp_path):
    program_dir, raw = approved_program(tmp_path, manifest_raw)
    broken = deepcopy(raw)
    broken["program_id"] = "broken-program"
    broken["platform"] = "not-a-real-platform"
    write_program(program_dir, broken, "broken.yml")

    manifests = load_manifests(program_dir)
    assert [entry.manifest.program_id for entry in manifests.loaded] == ["example-program"]
    assert manifests.loaded[0].approved is True
    assert [entry.program_id for entry in manifests.invalid] == ["broken-program"]
    assert "platform" in manifests.invalid[0].error


def test_unparseable_yaml_is_isolated_without_a_program_id(manifest_raw, tmp_path):
    program_dir, _ = approved_program(tmp_path, manifest_raw)
    (program_dir / "corrupt.yml").write_text("key: [unclosed\n", encoding="utf-8")

    manifests = load_manifests(program_dir)
    assert [entry.manifest.program_id for entry in manifests.loaded] == ["example-program"]
    assert len(manifests.invalid) == 1
    assert manifests.invalid[0].program_id is None


def test_duplicate_program_id_pauses_every_involved_manifest(manifest_raw, tmp_path):
    program_dir, raw = approved_program(tmp_path, manifest_raw)
    write_program(program_dir, deepcopy(raw), "duplicate.yml")

    manifests = load_manifests(program_dir)
    assert manifests.loaded == []
    assert {entry.program_id for entry in manifests.invalid} == {"example-program"}
    assert len(manifests.invalid) == 2
    assert "more than one manifest" in manifests.invalid[0].error


def test_invalid_cron_is_rejected_at_approval_time(manifest_raw):
    raw = deepcopy(manifest_raw)
    raw["schedules"] = {"bbot": "every day at 3am"}
    with pytest.raises(ValidationError, match="invalid cron expressions"):
        ProgramManifest.model_validate(raw)


def test_valid_cron_is_accepted(manifest_raw):
    raw = deepcopy(manifest_raw)
    raw["schedules"] = {"bbot": "41 2 * * *", "shodan": "7 */12 * * *"}
    assert ProgramManifest.model_validate(raw).schedules["bbot"] == "41 2 * * *"


@pytest.mark.parametrize("kind", ["bbot", "nuclei"])
def test_wildcard_only_active_scanner_schedule_is_rejected(manifest_raw, kind):
    raw = deepcopy(manifest_raw)
    raw["scope"]["include"] = [{"type": "domain", "value": "*.example.com"}]
    if kind == "nuclei":
        raw["nuclei"] = {"enabled": True}
        raw["network"]["denied_paths"] = []
    raw["schedules"] = {kind: "41 2 * * *"}

    with pytest.raises(ValidationError, match="require at least one concrete in-scope"):
        ProgramManifest.model_validate(raw)


def test_wildcard_only_scope_can_schedule_passive_discovery(manifest_raw):
    raw = deepcopy(manifest_raw)
    raw["scope"]["include"] = [{"type": "domain", "value": "*.example.com"}]
    raw["schedules"] = {"shodan": "7 */12 * * *"}

    assert ProgramManifest.model_validate(raw).schedules == {"shodan": "7 */12 * * *"}
