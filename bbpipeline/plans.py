from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from bbpipeline.manifest import ProgramManifest
from bbpipeline.scope import authorize_target


class StrictOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TestStep(StrictOutput):
    primitive: Literal["http_get", "http_head", "http_options", "manual_required"]
    target: str
    path: str = "/"
    account_role: str | None = None
    purpose: str
    expected_observation: str
    falsifier: str
    max_requests: int = Field(default=1, ge=1, le=20)

    @model_validator(mode="after")
    def automatic_step_has_plain_http_target(self) -> "TestStep":
        if self.primitive == "manual_required":
            return self
        parsed = urlsplit(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("automatic steps require an absolute HTTP(S) target")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "automatic targets cannot contain credentials, a query, or a fragment"
            )
        if not self.path.startswith("/") or any(
            character in self.path for character in {"?", "#", "\r", "\n"}
        ):
            raise ValueError("automatic paths must be plain absolute paths without a query")
        return self


class HypothesisOutput(StrictOutput):
    disposition: Literal[
        "candidate", "not_a_finding", "inconclusive", "needs_manual_validation"
    ]
    disposition_reason: str
    title: str
    vulnerability_class: str
    trust_boundary: str
    hypothesis: str
    observed_facts: list[str]
    prerequisites: list[str]
    possible_impact: str
    severity: Literal["unknown", "info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str]
    test_steps: list[TestStep]
    stop_conditions: list[str]
    benign_explanations: list[str]


class CritiqueOutput(StrictOutput):
    verdict: Literal["supported", "unsupported", "inconclusive", "needs_manual_validation"]
    confidence: float = Field(ge=0.0, le=1.0)
    accepted_observations: list[str]
    benign_explanations: list[str]
    missing_evidence: list[str]
    scope_concerns: list[str]
    impact_assessment: str
    severity_assessment: Literal["unknown", "info", "low", "medium", "high", "critical"]
    required_manual_checks: list[str]
    evidence_ids: list[str]


class CompiledPlan(StrictOutput):
    automatic: bool
    manual_reasons: list[str]
    steps: list[TestStep]


def _step_url(step: TestStep) -> str:
    parsed = urlsplit(step.target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return step.target
    path = step.path if step.path.startswith("/") else "/" + step.path
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def compile_plan(manifest: ProgramManifest, output: HypothesisOutput) -> CompiledPlan:
    reasons: list[str] = []
    total_requests = 0
    for step in output.test_steps:
        total_requests += step.max_requests
        if step.primitive == "manual_required":
            reasons.append(f"step requires manual execution: {step.purpose}")
            continue
        if step.primitive not in manifest.verification.allowed_primitives:
            reasons.append(f"primitive is not approved: {step.primitive}")
        method = {
            "http_get": "GET",
            "http_head": "HEAD",
            "http_options": "OPTIONS",
        }[step.primitive]
        decision = authorize_target(manifest, _step_url(step), method=method)
        if not decision.allowed:
            reasons.append(f"scope denial for {step.target}: {decision.reason}")
        if step.account_role:
            if step.account_role not in manifest.identity.approved_account_roles:
                reasons.append(f"account role is not approved: {step.account_role}")
            elif not manifest.verification.allow_authenticated:
                reasons.append("automatic authenticated verification is disabled")
    if total_requests > manifest.network.max_requests_per_verification:
        reasons.append(
            f"plan requests {total_requests} requests, exceeding the approved maximum of "
            f"{manifest.network.max_requests_per_verification}"
        )
    if not manifest.verification.auto_http:
        reasons.append("automatic HTTP verification is disabled for this program")
    return CompiledPlan(
        automatic=not reasons,
        manual_reasons=sorted(set(reasons)),
        steps=output.test_steps,
    )
