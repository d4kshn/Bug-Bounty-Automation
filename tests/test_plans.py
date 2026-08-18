from __future__ import annotations

from copy import deepcopy

import pytest

from bbpipeline.manifest import ProgramManifest
from bbpipeline.plans import HypothesisOutput, compile_plan


def hypothesis(**overrides) -> HypothesisOutput:
    value = {
        "disposition": "candidate",
        "disposition_reason": "The supplied event warrants bounded validation.",
        "title": "Candidate",
        "vulnerability_class": "misconfiguration",
        "trust_boundary": "public to application",
        "hypothesis": "A public endpoint may expose metadata.",
        "observed_facts": ["endpoint discovered"],
        "prerequisites": [],
        "possible_impact": "unknown",
        "severity": "low",
        "confidence": 0.5,
        "evidence_ids": ["evidence-1"],
        "test_steps": [
            {
                "primitive": "http_head",
                "target": "https://example.com",
                "path": "/health",
                "account_role": None,
                "purpose": "observe headers",
                "expected_observation": "metadata header",
                "falsifier": "header is absent",
                "max_requests": 1,
            }
        ],
        "stop_conditions": ["unexpected state change"],
        "benign_explanations": ["generic response"],
    }
    value.update(overrides)
    return HypothesisOutput.model_validate(value)


def test_verification_is_human_only_by_default(manifest):
    plan = compile_plan(manifest, hypothesis())
    assert plan.automatic is False
    assert "automatic HTTP verification is disabled for this program" in plan.manual_reasons


def test_bounded_safe_plan_can_be_automatic(manifest_raw):
    raw = deepcopy(manifest_raw)
    raw["verification"] = {
        "auto_http": True,
        "allowed_primitives": ["http_head"],
        "allow_authenticated": False,
    }
    raw["network"]["resolve_before_scan"] = False
    active = ProgramManifest.model_validate(raw)
    plan = compile_plan(active, hypothesis())
    assert plan.automatic is True


def test_manual_primitive_never_compiles_automatically(manifest_raw):
    raw = deepcopy(manifest_raw)
    raw["verification"] = {"auto_http": True}
    active = ProgramManifest.model_validate(raw)
    output = hypothesis(
        test_steps=[
            {
                "primitive": "manual_required",
                "target": "https://example.com",
                "path": "/",
                "account_role": None,
                "purpose": "browser flow",
                "expected_observation": "manual observation",
                "falsifier": "control behaves the same",
                "max_requests": 1,
            }
        ]
    )
    assert compile_plan(active, output).automatic is False


def test_automatic_step_rejects_query_parameters():
    with pytest.raises(ValueError, match="without a query"):
        hypothesis(
            test_steps=[
                {
                    "primitive": "http_get",
                    "target": "https://example.com",
                    "path": "/read?change=true",
                    "account_role": None,
                    "purpose": "unsafe query",
                    "expected_observation": "none",
                    "falsifier": "none",
                    "max_requests": 1,
                }
            ]
        )
