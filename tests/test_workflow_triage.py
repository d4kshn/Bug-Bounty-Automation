from __future__ import annotations

from sqlalchemy import select

from bbpipeline.db import engine_for, init_db, session_scope
from bbpipeline.models import Event, Job, Program
from bbpipeline.settings import Settings
from bbpipeline.workflow import process_planner_output


def test_not_a_finding_is_rejected_without_validation_or_notification(
    manifest, tmp_path
):
    engine_for.cache_clear()
    settings = Settings(database_url=f"sqlite+pysqlite:///{tmp_path}/triage.sqlite3")
    init_db(settings)
    with session_scope(settings) as session:
        session.add(
            Program(
                id=manifest.program_id,
                name=manifest.name,
                platform=manifest.platform,
                policy_url=manifest.policy_url,
                manifest_hash=manifest.approval.approved_hash,
                approved_hash=manifest.approval.approved_hash,
                active=True,
                manifest=manifest.model_dump(mode="json"),
            )
        )
        event = Event(
            program_id=manifest.program_id,
            source="shodan",
            event_type="SHODAN_SERVICE",
            asset="192.0.2.10:443",
            fingerprint="f" * 64,
            payload_hash="p" * 64,
            severity="info",
            confidence=0.75,
            score=75,
            payload={"product": "HTTPS"},
            evidence_ids=["evidence-1"],
        )
        session.add(event)
        session.flush()
        job = Job(
            program_id=manifest.program_id,
            queue="llm-codex",
            kind="llm_planner",
            payload={"event_id": event.id},
        )

        finding = process_planner_output(
            session,
            settings,
            job,
            {
                "disposition": "not_a_finding",
                "disposition_reason": "The packet establishes service inventory only.",
                "title": "Observed HTTPS service is inventory",
                "vulnerability_class": "none",
                "trust_boundary": "none demonstrated",
                "hypothesis": "No security boundary failure is established.",
                "observed_facts": ["Shodan reported an HTTPS service."],
                "prerequisites": [],
                "possible_impact": "No impact demonstrated.",
                "severity": "info",
                "confidence": 0.95,
                "evidence_ids": ["evidence-1"],
                "test_steps": [],
                "stop_conditions": [],
                "benign_explanations": ["Expected public HTTPS service."],
            },
            llm_evidence_id="llm-evidence-1",
        )

        assert finding.status == "rejected"
        assert event.status == "rejected"
        assert session.scalars(select(Job)).all() == []
