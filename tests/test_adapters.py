from __future__ import annotations

from copy import deepcopy

import pytest

from bbpipeline.adapters import bbot
from bbpipeline.adapters.common import CommandResult
from bbpipeline.manifest import ProgramManifest
from bbpipeline.scope import ScopeDecision


def test_bbot_separates_recursive_and_exact_scope(monkeypatch, manifest_raw, tmp_path):
    raw = deepcopy(manifest_raw)
    raw["scope"]["include"].append({"type": "domain", "value": "only.example.net"})
    manifest = ProgramManifest.model_validate(raw)
    commands: list[list[str]] = []

    monkeypatch.setattr(
        bbot,
        "authorize_target",
        lambda _manifest, target, **_kwargs: ScopeDecision(True, "test", target),
    )

    def fake_run(command, *, cwd, timeout):
        commands.append(command)
        scan_name = command[command.index("-n") + 1]
        output = cwd / scan_name / "output.json"
        output.parent.mkdir(parents=True)
        output.write_text("", encoding="utf-8")
        return CommandResult(command=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(bbot, "run_command", fake_run)
    result = bbot.run_bbot(
        manifest,
        targets=None,
        job_id="job-id",
        workdir=tmp_path,
        timeout=60,
    )
    assert len(commands) == 2
    recursive = next(command for command in commands if "example.com" in command)
    exact = next(command for command in commands if "only.example.net" in command)
    assert "-S" not in recursive
    assert "-S" in exact
    assert "web.http_rate_limit=1" in recursive
    assert result.summary["targets"] == 2


def wildcard_only_manifest(manifest_raw) -> ProgramManifest:
    raw = deepcopy(manifest_raw)
    raw["scope"]["include"] = [{"type": "domain", "value": "*.example.com"}]
    return ProgramManifest.model_validate(raw)


def test_wildcard_only_scope_never_seeds_the_unauthorized_apex(manifest_raw):
    manifest = wildcard_only_manifest(manifest_raw)
    seeds = bbot.default_targets(manifest)
    assert seeds.targets == []
    assert seeds.wildcard_only == ["*.example.com"]


def test_wildcard_only_scope_fails_with_an_actionable_message(manifest_raw, tmp_path):
    manifest = wildcard_only_manifest(manifest_raw)
    with pytest.raises(ValueError, match="authorize subdomains but not the apex"):
        bbot.run_bbot(
            manifest, targets=None, job_id="job-id", workdir=tmp_path, timeout=60
        )


def test_apex_is_seeded_when_it_is_separately_in_scope(manifest):
    seeds = bbot.default_targets(manifest)
    assert seeds.targets == ["example.com"]
    assert seeds.wildcard_only == []


def test_explicit_in_scope_subdomain_targets_still_run(monkeypatch, manifest_raw, tmp_path):
    manifest = wildcard_only_manifest(manifest_raw)
    monkeypatch.setattr(
        bbot,
        "authorize_target",
        lambda _manifest, target, **_kwargs: ScopeDecision(True, "test", target),
    )

    def fake_run(command, *, cwd, timeout):
        scan_name = command[command.index("-n") + 1]
        output = cwd / scan_name / "output.json"
        output.parent.mkdir(parents=True)
        output.write_text("", encoding="utf-8")
        return CommandResult(command=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(bbot, "run_command", fake_run)
    result = bbot.run_bbot(
        manifest,
        targets=["api.example.com"],
        job_id="job-id",
        workdir=tmp_path,
        timeout=60,
    )
    assert result.summary["targets"] == 1
