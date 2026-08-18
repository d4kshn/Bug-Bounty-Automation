from __future__ import annotations

from copy import deepcopy

import pytest

from bbpipeline.manifest import ProgramManifest, manifest_hash


@pytest.fixture
def manifest_raw() -> dict:
    raw = {
        "version": 1,
        "program_id": "example-program",
        "name": "Example",
        "platform": "hackerone",
        "policy_url": "https://example.com/policy",
        "policy_snapshot_file": "example-policy.txt",
        "policy_snapshot_hash": "sha256:policy",
        "approval": {
            "approved_hash": "pending",
            "approved_by": "tester",
            "approved_at": "2026-08-17T00:00:00Z",
        },
        "scope": {
            "include": [
                {"type": "domain", "value": "example.com"},
                {"type": "domain", "value": "*.example.com"},
                {"type": "repository", "value": "example-org/*"},
            ],
            "exclude": [{"type": "domain", "value": "status.example.com"}],
        },
        "network": {
            "allowed_ports": [80, 443],
            "allowed_methods": ["GET", "HEAD"],
            "allowed_paths": ["*"],
            "denied_paths": ["/logout*"],
            "requests_per_second": 1,
            "concurrency": 2,
            "timeout_seconds": 10,
            "max_requests_per_verification": 5,
            "require_https": False,
            "allow_private_targets": False,
            "resolve_before_scan": True,
        },
        "llm": {"enabled": False},
    }
    raw["approval"]["approved_hash"] = manifest_hash(raw)
    return raw


@pytest.fixture
def manifest(manifest_raw: dict) -> ProgramManifest:
    return ProgramManifest.model_validate(deepcopy(manifest_raw))
