from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from bbpipeline.models import Event, Finding
from bbpipeline.packets import build_critic_packet, build_planner_packet
from bbpipeline.settings import Settings

SKILL_DIR = Path(__file__).parents[1] / "skills" / "bug-bounty-review"


def test_planner_packet_loads_only_scanner_triage_guidance(manifest, tmp_path):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        ttp_dir=tmp_path,
        skill_dir=SKILL_DIR,
    )
    event = Event(
        id="event-1",
        program_id=manifest.program_id,
        source="gitleaks",
        event_type="SECRET_CANDIDATE",
        asset="https://github.com/example-org/repo/blob/commit/app.py#L10",
        fingerprint="f" * 64,
        payload_hash="p" * 64,
        severity="high",
        confidence=0.7,
        score=90,
        payload={"rule_id": "generic-api-key", "tags": ["secret"]},
        evidence_ids=["evidence-1"],
    )

    packet = build_planner_packet(settings, manifest, event)

    assert "Do not perform reconnaissance" in packet["task"]
    assert packet["triage_skill"]["role"] == "triage"
    names = [item["name"] for item in packet["triage_skill"]["references"]]
    assert "repository-secret-findings.md" in names
    assert "web-api-findings.md" not in names
    assert "Never validate a secret automatically" in json.dumps(packet)


def test_critic_packet_loads_independent_validation_not_attack_guidance(
    manifest, tmp_path
):
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        ttp_dir=tmp_path,
        skill_dir=SKILL_DIR,
    )
    finding = Finding(
        id="finding-1",
        program_id=manifest.program_id,
        event_id=None,
        status="critic_queued",
        title="Candidate",
        severity="medium",
        confidence=0.7,
        hypothesis={"observed_facts": ["supplied observation"]},
        verification={"control": "same response"},
        evidence_ids=["evidence-1"],
    )

    packet = build_critic_packet(settings, manifest, finding)

    assert packet["triage_skill"]["role"] == "critic"
    names = [item["name"] for item in packet["triage_skill"]["references"]]
    assert names[0] == "independent-validation.md"
    assert "web-api-findings.md" not in names
    assert packet["methodology_cards"] == []


def test_large_critic_packet_is_bounded(manifest, tmp_path):
    # skill_dir is pinned so the result does not depend on whether the default
    # /app/skills path happens to exist, which differs between host and container.
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        max_context_bytes=16384,
        ttp_dir=tmp_path,
        skill_dir=SKILL_DIR,
    )
    finding = Finding(
        id="finding-1",
        program_id=manifest.program_id,
        event_id=None,
        status="critic_queued",
        title="Candidate",
        severity="medium",
        confidence=0.7,
        hypothesis={"detail": "h" * 12000},
        verification={"body": "v" * 50000},
        evidence_ids=["evidence-1"],
    )
    packet = build_critic_packet(settings, manifest, finding)
    encoded = json.dumps(packet, sort_keys=True).encode()
    assert len(encoded) <= settings.max_context_bytes
    assert packet["candidate"]["verification"]["truncated"] is True


def test_context_ceiling_cannot_be_set_below_the_skill_core(manifest):
    """A ceiling too small for the skill would fail every planner and critic job."""
    with pytest.raises(ValidationError):
        Settings(database_url="sqlite+pysqlite:///:memory:", max_context_bytes=4096)


def test_oversized_skill_degrades_instead_of_failing_the_job(manifest, tmp_path):
    """Guidance is droppable; a job must not hard-fail because the skill grew."""
    skill_dir = tmp_path / "skill"
    (skill_dir / "references").mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("S" * 60_000, encoding="utf-8")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        max_context_bytes=16384,
        ttp_dir=tmp_path,
        skill_dir=skill_dir,
    )
    finding = Finding(
        id="finding-1",
        program_id=manifest.program_id,
        event_id=None,
        status="critic_queued",
        title="Candidate",
        severity="medium",
        confidence=0.7,
        hypothesis={"observed_facts": ["supplied observation"]},
        verification={"control": "same response"},
        evidence_ids=["evidence-1"],
    )

    packet = build_critic_packet(settings, manifest, finding)

    encoded = json.dumps(packet, sort_keys=True).encode()
    assert len(encoded) <= settings.max_context_bytes
    assert packet["triage_skill"]["truncated"] is True
    assert "core" not in packet["triage_skill"]
    # The evidence the critic reasons about must survive the guidance being dropped.
    assert packet["candidate"]["finding_id"] == "finding-1"
    assert packet["candidate"]["evidence_ids"] == ["evidence-1"]
    assert packet["candidate"]["verification"] == {"control": "same response"}
    assert packet["candidate"]["hypothesis"] == {
        "observed_facts": ["supplied observation"]
    }
