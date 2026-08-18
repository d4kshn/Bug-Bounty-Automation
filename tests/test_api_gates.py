from __future__ import annotations

import pytest
from fastapi import HTTPException

from bbpipeline.api import FindingAction, finding_action
from bbpipeline.db import engine_for, init_db, session_scope
from bbpipeline.models import Finding, Program
from bbpipeline.settings import Settings


def test_verification_validation_and_submission_are_separate_gates(
    manifest, tmp_path
):
    engine_for.cache_clear()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path}/api.sqlite3",
        evidence_dir=tmp_path / "evidence",
    )
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
        finding = Finding(
            program_id=manifest.program_id,
            title="Candidate",
            status="needs_human",
            severity="medium",
            confidence=0.6,
            hypothesis={},
            evidence_ids=[],
        )
        session.add(finding)
        session.flush()

        with pytest.raises(HTTPException, match="verification"):
            finding_action(
                finding.id,
                FindingAction(action="validate"),
                session=session,
                settings=settings,
            )

        finding_action(
            finding.id,
            FindingAction(
                action="record_manual_verification",
                notes="clean manual reproduction",
                verification={"reproduced": True, "negative_control": "not affected"},
            ),
            session=session,
            settings=settings,
        )
        validated = finding_action(
            finding.id,
            FindingAction(action="validate", notes="scope and impact checked"),
            session=session,
            settings=settings,
        )
        assert validated["human_validated"] is True
        assert validated["submitted"] is False

        submitted = finding_action(
            finding.id,
            FindingAction(action="mark_submitted", notes="submitted manually"),
            session=session,
            settings=settings,
        )
        assert submitted["submitted"] is True
        assert submitted["status"] == "submitted"
