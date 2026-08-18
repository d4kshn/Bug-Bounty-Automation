from __future__ import annotations

import json
import subprocess

import httpx
import pytest
import yaml

from bbpipeline.platform_sources import (
    PlatformAuthError,
    PlatformSnapshot,
    PlatformSourceConfig,
    RemoteAsset,
    build_candidate_manifest,
    discover_platform_programs,
    fetch_platform_snapshot,
    load_platform_sources,
    normalize_snapshot,
)
from bbpipeline.settings import Settings


def _source(platform: str, remote: str = "acme") -> PlatformSourceConfig:
    return PlatformSourceConfig(
        version=1,
        source_id=f"{platform}-acme",
        program_id=f"{platform}-acme",
        platform=platform,
        remote_identifier=remote,
    )


def _secret(tmp_path, name: str, value: str = "secret"):
    path = tmp_path / name
    path.write_text(value, encoding="utf-8")
    return path


def test_source_loader_isolates_a_malformed_file(tmp_path):
    directory = tmp_path / "sources"
    directory.mkdir()
    (directory / "good.yml").write_text(
        yaml.safe_dump(_source("hackerone").model_dump(mode="json")),
        encoding="utf-8",
    )
    (directory / "bad.yml").write_text("platform: [broken\n", encoding="utf-8")

    loaded = load_platform_sources(directory)

    assert [item.source_id for item in loaded.loaded] == ["hackerone-acme"]
    assert len(loaded.invalid) == 1


def test_normalization_is_conservative_and_reports_unsupported_assets():
    snapshot = PlatformSnapshot(
        platform="hackerone",
        remote_identifier="acme",
        name="Acme",
        policy_url="https://hackerone.com/acme",
        assets=[
            RemoteAsset(target="*.example.com", category="WILDCARD"),
            RemoteAsset(target="https://api.example.com/v1", category="URL"),
            RemoteAsset(target="192.0.2.3", category="IP_ADDRESS"),
            RemoteAsset(target="https://github.com/acme/widget.git", category="SOURCE_CODE"),
            RemoteAsset(target="https://*.example.com/private/*", category="URL"),
            RemoteAsset(target="admin.example.com", category="URL", in_scope=False),
        ],
    )

    normalized = normalize_snapshot(snapshot)

    assert [(rule.type, rule.value) for rule in normalized.include] == [
        ("cidr", "192.0.2.3/32"),
        ("domain", "*.example.com"),
        ("repository", "acme/widget"),
        ("url", "https://api.example.com/v1"),
    ]
    assert [(rule.type, rule.value) for rule in normalized.exclude] == [
        ("domain", "admin.example.com")
    ]
    assert normalized.unsupported == [
        {
            "target": "https://*.example.com/private/*",
            "category": "URL",
            "scope": "in",
            "disposition": "manual_review_required",
        }
    ]


def test_new_candidate_disables_scanners_and_carries_revision():
    snapshot = PlatformSnapshot(
        platform="intigriti",
        remote_identifier="program-uuid",
        name="Acme",
        policy_url="https://app.intigriti.com/programs/acme/detail",
        assets=[RemoteAsset(target="example.com", category="Web application")],
    )

    candidate, policy = build_candidate_manifest(
        _source("intigriti", "program-uuid"), snapshot
    )

    assert candidate["approval"]["approved_hash"] == "pending"
    assert candidate["source"]["revision_hash"] == snapshot.revision_hash
    assert candidate["bbot"]["enabled"] is False
    assert candidate["nuclei"]["enabled"] is False
    assert candidate["repositories"]["enabled"] is False
    assert candidate["shodan"]["enabled"] is False
    assert "not approval" in policy


def test_unrepresentable_out_of_scope_rule_disables_preserved_automation(manifest):
    snapshot = PlatformSnapshot(
        platform="hackerone",
        remote_identifier="acme",
        name="Acme",
        policy_url="https://hackerone.com/acme",
        assets=[
            RemoteAsset(target="*.example.com", category="WILDCARD"),
            RemoteAsset(
                target="https://*.example.com/private/*",
                category="URL",
                in_scope=False,
            ),
        ],
    )

    candidate, _ = build_candidate_manifest(
        _source("hackerone"), snapshot, existing=manifest
    )

    assert candidate["bbot"]["enabled"] is False
    assert candidate["nuclei"]["enabled"] is False
    assert candidate["repositories"]["enabled"] is False
    assert candidate["shodan"]["enabled"] is False
    assert candidate["schedules"] == {}
    assert candidate["notes"].startswith("FAIL-CLOSED")


def test_hackerone_fetch_uses_researcher_basic_auth_and_structured_scope(tmp_path):
    token_path = _secret(tmp_path, "h1")
    seen_authorization: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers.get("Authorization", ""))
        if request.url.path.endswith("/structured_scopes"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "1",
                            "attributes": {
                                "asset_identifier": "*.example.com",
                                "asset_type": "WILDCARD",
                                "eligible_for_submission": True,
                                "eligible_for_bounty": True,
                                "instruction": "No apex",
                            },
                        },
                        {
                            "id": "2",
                            "attributes": {
                                "asset_identifier": "old.example.com",
                                "asset_type": "URL",
                                "eligible_for_submission": False,
                            },
                        },
                    ],
                    "links": {"next": None},
                },
            )
        if request.url.path.endswith("/scope_exclusions"):
            return httpx.Response(200, json={"data": [], "links": {"next": None}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "name": "Acme",
                        "handle": "acme",
                        "policy": "Automation is permitted at 1 rps.",
                        "open_scope": True,
                        "state": "public_mode",
                        "submission_state": "open",
                    }
                }
            },
        )

    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        researcher_handle="d4kshn",
        hackerone_api_token_file=token_path,
    )
    snapshot = fetch_platform_snapshot(
        settings, _source("hackerone"), transport=httpx.MockTransport(handler)
    )

    assert snapshot.name == "Acme"
    assert [(asset.target, asset.in_scope) for asset in snapshot.assets] == [
        ("*.example.com", True),
        ("old.example.com", False),
    ]
    assert snapshot.rules["open_scope"] is True
    assert all(value.startswith("Basic ") for value in seen_authorization)


def test_hackerone_rejected_token_is_an_auth_error(tmp_path):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        hackerone_api_token_file=_secret(tmp_path, "h1"),
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(401, json={}))

    with pytest.raises(PlatformAuthError, match="rejected"):
        fetch_platform_snapshot(settings, _source("hackerone"), transport=transport)


def test_intigriti_fetch_preserves_automation_rules(tmp_path):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        intigriti_api_token_file=_secret(tmp_path, "intigriti"),
    )
    payload = {
        "id": "uuid",
        "handle": "acme",
        "name": "Acme",
        "status": "open",
        "domains": {
            "content": [
                {
                    "id": "d1",
                    "type": {"value": "Web application"},
                    "endpoint": "https://example.com",
                    "tier": 1,
                    "description": "Production",
                }
            ]
        },
        "rulesOfEngagement": {
            "content": {
                "description": "Program brief",
                "testingRequirements": {
                    "automatedTooling": 2,
                    "userAgent": "d4kshn",
                },
            }
        },
        "webLinks": {"detail": "https://app.intigriti.com/programs/acme/detail"},
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))

    snapshot = fetch_platform_snapshot(
        settings, _source("intigriti", "uuid"), transport=transport
    )

    assert snapshot.assets[0].target == "https://example.com"
    requirements = snapshot.rules["rules_of_engagement"]["testingRequirements"]
    assert requirements["automatedTooling"] == 2


def test_yeswehack_requires_program_access_and_reads_scopes(tmp_path):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        yeswehack_access_token_file=_secret(tmp_path, "ywh"),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "/hunter/access/programs/" in request.url.path:
            return httpx.Response(
                200,
                json={"items": [{"slug": "acme", "title": "Acme", "archived": False}]},
            )
        if request.url.path == "/programs/acme":
            return httpx.Response(
                200,
                json={
                    "title": "Acme",
                    "rules": "Automation is allowed at one request per second.",
                    "status": "published",
                    "scopes": [
                        {
                            "asset_value": "*.example.com",
                            "scope_type_name": "wildcard",
                            "report_count": 0,
                        }
                    ],
                    "out_of_scope": ["Social engineering"],
                    "archived": False,
                },
            )
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "asset_value": "*.example.com",
                        "scope_type_name": "wildcard",
                        "report_count": 0,
                    }
                ]
            },
        )

    snapshot = fetch_platform_snapshot(
        settings, _source("yeswehack"), transport=httpx.MockTransport(handler)
    )

    assert snapshot.name == "Acme"
    assert snapshot.assets[0].target == "*.example.com"
    assert snapshot.policy_text.startswith("Automation is allowed")
    assert snapshot.rules["out_of_scope_text"] == ["Social engineering"]


def test_bugcrowd_cookie_is_passed_by_file_not_process_argument(tmp_path, monkeypatch):
    cookie_path = _secret(tmp_path, "bugcrowd", "_bugcrowd_session=COOKIE-VALUE")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        bugcrowd_session_cookie_file=cookie_path,
    )
    captured: list[str] = []

    def fake_run(command, **kwargs):
        captured.extend(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "url": "https://bugcrowd.com/engagements/acme",
                    "in_scope": [
                        {
                            "target": "*.example.com",
                            "description": "",
                            "category": "wildcard",
                        }
                    ],
                    "out_of_scope": [],
                }
            ),
            stderr="",
        )

    monkeypatch.setattr("bbpipeline.platform_sources.subprocess.run", fake_run)
    snapshot = fetch_platform_snapshot(
        settings, _source("bugcrowd", "/engagements/acme")
    )

    assert snapshot.assets[0].target == "*.example.com"
    assert "COOKIE-VALUE" not in captured
    assert captured == [
        "bbscope-cookie",
        "--token-file",
        str(cookie_path),
        "--handle",
        "/engagements/acme",
    ]


def test_discovery_returns_only_identifiers_and_names(tmp_path):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        intigriti_api_token_file=_secret(tmp_path, "intigriti"),
    )
    payload = {"records": [{"id": "uuid", "name": "Acme", "extra": "not exposed"}]}

    programs = discover_platform_programs(
        settings,
        "intigriti",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload)),
    )

    assert programs == [
        {"remote_identifier": "uuid", "name": "Acme", "platform": "intigriti"}
    ]
    assert "extra" not in json.dumps(programs)
