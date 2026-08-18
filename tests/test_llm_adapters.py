from __future__ import annotations

import json
from pathlib import Path

import pytest

from bbpipeline.adapters import claude as claude_adapter
from bbpipeline.adapters import codex as codex_adapter
from bbpipeline.adapters.common import CommandResult
from bbpipeline.healthcheck import auth_mode, check_llm_provider
from bbpipeline.plans import HypothesisOutput
from bbpipeline.settings import Settings

SCHEMAS = ("hypothesis.schema.json", "healthcheck.schema.json")


@pytest.fixture
def llm_settings(tmp_path):
    """Settings with a schema directory and no API keys configured."""
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    for name in SCHEMAS:
        (schema_dir / name).write_text(json.dumps({"type": "object"}), encoding="utf-8")
    return Settings(
        database_url="sqlite+pysqlite:///:memory:",
        schema_dir=schema_dir,
        anthropic_api_key_file=tmp_path / "anthropic_api_key",
        openai_api_key_file=tmp_path / "openai_api_key",
    )


def capture(
    monkeypatch,
    module,
    stdout: str,
    output: dict | None = None,
    returncode: int = 0,
    stderr: str = "",
):
    """Record the command and environment the adapter would execute."""
    calls: list[dict] = []

    def fake_run(
        command, *, cwd, timeout, input_bytes=None, env=None, accepted_codes=None
    ):
        calls.append(
            {"command": command, "env": env or {}, "accepted_codes": accepted_codes}
        )
        if output is not None:
            (cwd / "codex-output.json").write_text(json.dumps(output), encoding="utf-8")
        return CommandResult(
            command=command, returncode=returncode, stdout=stdout, stderr=stderr
        )

    monkeypatch.setattr(module, "run_command", fake_run)
    return calls


def run_claude_once(llm_settings, tmp_path, schema="hypothesis.schema.json"):
    return claude_adapter.run_claude(
        llm_settings,
        packet={"packet_version": 1},
        schema_name=schema,
        workdir=tmp_path,
    )


def test_claude_keeps_the_oauth_session_usable(monkeypatch, llm_settings, tmp_path):
    """`--bare` refuses to read the OAuth login that scripts/login-llms.sh creates."""
    calls = capture(monkeypatch, claude_adapter, json.dumps({"structured_output": {}}))
    run_claude_once(llm_settings, tmp_path)
    command = calls[0]["command"]
    assert "--bare" not in command
    assert "--safe-mode" in command
    assert command[command.index("--setting-sources") + 1] == ""
    assert "ANTHROPIC_API_KEY" not in calls[0]["env"]


def test_claude_still_runs_without_tools_mcp_or_skills(monkeypatch, llm_settings, tmp_path):
    calls = capture(monkeypatch, claude_adapter, json.dumps({"structured_output": {}}))
    run_claude_once(llm_settings, tmp_path)
    command = calls[0]["command"]
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--disallowedTools") + 1] == "mcp__*"
    assert command[command.index("--max-turns") + 1] == "1"
    assert "--strict-mcp-config" in command
    assert "--disable-slash-commands" in command


def test_configured_anthropic_key_enables_the_stricter_bare_sandbox(
    monkeypatch, llm_settings, tmp_path
):
    llm_settings.anthropic_api_key_file.write_text("sk-test-key\n", encoding="utf-8")
    calls = capture(monkeypatch, claude_adapter, json.dumps({"structured_output": {}}))
    run_claude_once(llm_settings, tmp_path)
    command = calls[0]["command"]
    assert "--bare" in command
    assert "--safe-mode" not in command
    assert "--setting-sources" not in command
    assert calls[0]["env"]["ANTHROPIC_API_KEY"] == "sk-test-key"


def test_codex_passes_a_configured_openai_key(monkeypatch, llm_settings, tmp_path):
    llm_settings.openai_api_key_file.write_text("sk-openai-key\n", encoding="utf-8")
    calls = capture(monkeypatch, codex_adapter, "", output={"ok": True})
    codex_adapter.run_codex(
        llm_settings,
        packet={"packet_version": 1},
        schema_name="healthcheck.schema.json",
        workdir=tmp_path,
    )
    assert calls[0]["env"]["CODEX_API_KEY"] == "sk-openai-key"
    assert "OPENAI_API_KEY" not in calls[0]["env"]
    assert calls[0]["env"]["CODEX_HOME"].endswith(".codex")


def test_codex_without_a_key_relies_on_the_subscription_login(
    monkeypatch, llm_settings, tmp_path
):
    calls = capture(monkeypatch, codex_adapter, "", output={"ok": True})
    codex_adapter.run_codex(
        llm_settings,
        packet={"packet_version": 1},
        schema_name="healthcheck.schema.json",
        workdir=tmp_path,
    )
    assert "CODEX_API_KEY" not in calls[0]["env"]
    assert "OPENAI_API_KEY" not in calls[0]["env"]


def test_claude_auth_failure_is_reported_as_an_error(monkeypatch, llm_settings, tmp_path):
    capture(
        monkeypatch,
        claude_adapter,
        json.dumps({"is_error": True, "result": "Not logged in · Please run /login"}),
    )
    with pytest.raises(RuntimeError, match="Not logged in"):
        run_claude_once(llm_settings, tmp_path)


def test_auth_mode_reports_the_credential_actually_in_use(llm_settings):
    assert auth_mode(llm_settings, "claude") == "subscription_oauth"
    assert auth_mode(llm_settings, "codex") == "subscription_oauth"
    llm_settings.anthropic_api_key_file.write_text("sk-test-key\n", encoding="utf-8")
    assert auth_mode(llm_settings, "claude") == "api_key"


def test_health_check_round_trips_through_the_real_adapter(
    monkeypatch, llm_settings, tmp_path
):
    calls = capture(
        monkeypatch,
        claude_adapter,
        json.dumps({"structured_output": {"ok": True, "note": "ready"}}),
    )
    result = check_llm_provider(llm_settings, "claude")
    assert result["authenticated"] is True
    assert result["auth_mode"] == "subscription_oauth"
    assert result["output"] == {"ok": True, "note": "ready"}
    # The check must exercise the production flag set, not a hand-written command.
    assert "--json-schema" in calls[0]["command"]


def test_health_check_rejects_output_that_misses_the_schema(
    monkeypatch, llm_settings, tmp_path
):
    capture(
        monkeypatch,
        claude_adapter,
        json.dumps({"structured_output": {"unexpected": "shape"}}),
    )
    with pytest.raises(RuntimeError, match="healthcheck.schema.json"):
        check_llm_provider(llm_settings, "claude")


def test_dialect_annotation_is_stripped_before_transport(monkeypatch, llm_settings, tmp_path):
    """The CLI rejects a `$schema` URI it cannot resolve offline."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["ok"],
    }
    (llm_settings.schema_dir / "healthcheck.schema.json").write_text(
        json.dumps(schema), encoding="utf-8"
    )
    calls = capture(monkeypatch, claude_adapter, json.dumps({"structured_output": {}}))
    run_claude_once(llm_settings, tmp_path, schema="healthcheck.schema.json")

    command = calls[0]["command"]
    sent = json.loads(command[command.index("--json-schema") + 1])
    assert "$schema" not in sent
    assert sent["required"] == ["ok"]
    assert sent["additionalProperties"] is False


def test_repository_schemas_survive_the_stripping(monkeypatch, tmp_path):
    """The real schema files still describe the same contract after transport."""
    repository_schemas = Path(__file__).parents[1] / "schemas"
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        schema_dir=repository_schemas,
        anthropic_api_key_file=tmp_path / "absent",
    )
    calls = capture(monkeypatch, claude_adapter, json.dumps({"structured_output": {}}))
    claude_adapter.run_claude(
        settings,
        packet={"packet_version": 1},
        schema_name="hypothesis.schema.json",
        workdir=tmp_path,
    )
    command = calls[0]["command"]
    sent = json.loads(command[command.index("--json-schema") + 1])
    assert "$schema" not in sent
    assert set(sent["required"]) == set(HypothesisOutput.model_fields)
    assert sent["additionalProperties"] is False


def test_refusal_on_exit_one_is_parsed_not_discarded(monkeypatch, llm_settings, tmp_path):
    """The CLI exits 1 with an empty stderr and the reason inside its JSON result."""
    calls = capture(
        monkeypatch,
        claude_adapter,
        json.dumps({"is_error": True, "result": "Not logged in · Please run /login"}),
        returncode=1,
        stderr="",
    )
    with pytest.raises(RuntimeError, match="Not logged in"):
        run_claude_once(llm_settings, tmp_path)
    assert calls[0]["accepted_codes"] == {0, 1}


def test_non_json_failure_surfaces_the_command_output(monkeypatch, llm_settings, tmp_path):
    capture(
        monkeypatch,
        claude_adapter,
        "",
        returncode=1,
        stderr="error: unknown option '--nope'",
    )
    with pytest.raises(RuntimeError, match="unknown option"):
        run_claude_once(llm_settings, tmp_path)
