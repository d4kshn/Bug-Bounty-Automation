from __future__ import annotations

from bbpipeline.scope import authorize_target, rule_matches


def test_exclusion_wins(manifest):
    decision = authorize_target(
        manifest,
        "https://status.example.com/",
        resolver=lambda _: ["203.0.113.10"],
    )
    assert decision.allowed is False
    assert "excluded" in decision.reason


def test_wildcard_does_not_include_apex(manifest):
    wildcard = manifest.scope.include[1]
    assert rule_matches(wildcard, "api.example.com") is True
    assert rule_matches(wildcard, "example.com") is False


def test_dns_resolution_blocks_private_address(manifest):
    decision = authorize_target(
        manifest,
        "https://api.example.com/",
        resolver=lambda _: ["127.0.0.1"],
    )
    assert decision.allowed is False
    assert "not globally routable" in decision.reason


def test_method_and_path_are_enforced(manifest):
    method = authorize_target(manifest, "https://example.com/", method="POST")
    path = authorize_target(
        manifest,
        "https://example.com/logout-now",
        resolver=lambda _: ["8.8.8.8"],
    )
    assert method.allowed is False
    assert path.allowed is False
