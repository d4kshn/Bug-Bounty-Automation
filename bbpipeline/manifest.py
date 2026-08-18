from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from croniter import croniter
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


SAFE_BBOT_PRESETS = {"subdomain-enum", "web", "spider", "web-screenshots"}
JOB_KINDS = {"bbot", "nuclei", "gitleaks", "github", "shodan"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Approval(StrictModel):
    approved_hash: str
    approved_by: str
    approved_at: datetime


class ScopeRule(StrictModel):
    type: Literal["domain", "url", "cidr", "repository", "cloud"]
    value: str
    note: str | None = None

    @field_validator("value")
    @classmethod
    def nonempty_value(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("scope value cannot be empty")
        return cleaned

    @model_validator(mode="after")
    def value_matches_rule_type(self) -> "ScopeRule":
        if self.type == "domain":
            hostname = self.value.removeprefix("*.")
            labels = hostname.split(".")
            if (
                len(hostname) > 253
                or len(labels) < 2
                or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                        label,
                    )
                    for label in labels
                )
                or ("*" in self.value and not self.value.startswith("*."))
            ):
                raise ValueError("domain scope rule is invalid")
        elif self.type == "url":
            parsed = urlsplit(self.value)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("URL scope rule has an invalid port") from exc
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or (port is not None and not 1 <= port <= 65535)
            ):
                raise ValueError("URL scope rules require a plain HTTP(S) URL")
        elif self.type == "cidr":
            try:
                ipaddress.ip_network(self.value, strict=False)
            except ValueError as exc:
                raise ValueError("CIDR scope rule is invalid") from exc
        elif self.type == "repository":
            parts = self.value.split("/")
            if len(parts) != 2:
                raise ValueError("repository scope must be owner/name or owner/*")
            owner, name = parts
            owner_valid = bool(
                re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
                    owner,
                )
            )
            name_valid = name == "*" or (
                bool(re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name))
                and name not in {".", ".."}
            )
            if not owner_valid or not name_valid:
                raise ValueError("repository scope must be a valid GitHub owner/name pattern")
        return self


class ScopePolicy(StrictModel):
    include: list[ScopeRule]
    exclude: list[ScopeRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_includes(self) -> "ScopePolicy":
        if not self.include:
            raise ValueError("at least one in-scope rule is required")
        return self


class NetworkPolicy(StrictModel):
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS"]] = Field(
        default_factory=lambda: ["GET", "HEAD"]
    )
    denied_paths: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=lambda: ["*"])
    requests_per_second: float = Field(default=1.0, gt=0, le=50)
    concurrency: int = Field(default=2, ge=1, le=50)
    timeout_seconds: int = Field(default=15, ge=1, le=120)
    max_requests_per_verification: int = Field(default=5, ge=1, le=20)
    require_https: bool = False
    allow_private_targets: bool = False
    resolve_before_scan: bool = True
    max_cidr_addresses: int = Field(default=256, ge=1, le=65536)

    @field_validator("allowed_ports")
    @classmethod
    def ports_are_valid(cls, value: list[int]) -> list[int]:
        if not value or any(port < 1 or port > 65535 for port in value):
            raise ValueError("allowed_ports must contain valid TCP ports")
        return sorted(set(value))


class IdentityPolicy(StrictModel):
    required_header: str | None = None
    default_account_role: str | None = None
    approved_account_roles: list[str] = Field(default_factory=list)

    @field_validator("required_header")
    @classmethod
    def required_header_is_valid(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", value):
            raise ValueError("required_header is not a valid HTTP header name")
        return value

    @field_validator("default_account_role")
    @classmethod
    def default_role_is_plain(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", value):
            raise ValueError("default_account_role must be a plain role name")
        return value

    @field_validator("approved_account_roles")
    @classmethod
    def approved_roles_are_plain(cls, value: list[str]) -> list[str]:
        if any(
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", role)
            for role in value
        ):
            raise ValueError("approved_account_roles contain an invalid role name")
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def default_role_is_approved(self) -> "IdentityPolicy":
        if (
            self.default_account_role
            and self.default_account_role not in self.approved_account_roles
        ):
            raise ValueError("default_account_role must appear in approved_account_roles")
        return self


class BbotPolicy(StrictModel):
    enabled: bool = True
    presets: list[str] = Field(default_factory=lambda: ["subdomain-enum"])
    extra_modules: list[str] = Field(default_factory=list)
    max_targets: int = Field(default=100, ge=1, le=10000)

    @field_validator("presets")
    @classmethod
    def presets_are_safe(cls, value: list[str]) -> list[str]:
        disallowed = sorted(set(value) - SAFE_BBOT_PRESETS)
        if disallowed:
            raise ValueError(f"BBOT presets are not in the v1 safe allow-list: {disallowed}")
        return value

    @field_validator("extra_modules")
    @classmethod
    def module_names_are_plain(cls, value: list[str]) -> list[str]:
        if value:
            raise ValueError(
                "standalone BBOT modules are disabled in v1; use an approved safe preset"
            )
        for module in value:
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", module):
                raise ValueError(f"invalid BBOT module name: {module}")
        return value


class NucleiPolicy(StrictModel):
    enabled: bool = False
    profile: str = "safe-observation"
    profile_hash: str = "sha256:REPLACE_WITH_PROFILE_HASH"
    max_targets: int = Field(default=100, ge=1, le=10000)

    @field_validator("profile")
    @classmethod
    def profile_name_is_plain(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
            raise ValueError("nuclei profile must be a simple name")
        return value


class RepositoryPolicy(StrictModel):
    enabled: bool = True
    max_repository_mb: int = Field(default=500, ge=1, le=10000)
    scan_history: bool = True


class ShodanPolicy(StrictModel):
    enabled: bool = True
    max_results_per_query: int = Field(default=100, ge=1, le=1000)


class VerificationPolicy(StrictModel):
    auto_http: bool = False
    allowed_primitives: list[Literal["http_get", "http_head", "http_options"]] = Field(
        default_factory=lambda: ["http_get", "http_head"]
    )
    allow_authenticated: bool = False


class LlmPolicy(StrictModel):
    enabled: bool = True
    trigger_score: int = Field(default=70, ge=0, le=100)
    planner_provider: Literal["codex", "claude"] = "codex"
    critic_provider: Literal["codex", "claude"] = "claude"
    max_cards: int = Field(default=5, ge=0, le=8)


class PlatformSourceRef(StrictModel):
    source_id: str
    platform: Literal["hackerone", "bugcrowd", "intigriti", "yeswehack"]
    remote_identifier: str
    revision_hash: str

    @field_validator("source_id")
    @classmethod
    def source_id_is_safe(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", value):
            raise ValueError("source_id must contain 2-64 lowercase letters, digits, _ or -")
        return value

    @field_validator("revision_hash")
    @classmethod
    def revision_hash_is_sha256(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("revision_hash must be a sha256 digest")
        return value


class ProgramManifest(StrictModel):
    version: Literal[1]
    program_id: str
    name: str
    platform: Literal["hackerone", "bugcrowd", "intigriti", "yeswehack", "other"]
    policy_url: str
    policy_snapshot_file: str
    policy_snapshot_hash: str
    source: PlatformSourceRef | None = None
    approval: Approval
    scope: ScopePolicy
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    identity: IdentityPolicy = Field(default_factory=IdentityPolicy)
    bbot: BbotPolicy = Field(default_factory=BbotPolicy)
    nuclei: NucleiPolicy = Field(default_factory=NucleiPolicy)
    repositories: RepositoryPolicy = Field(default_factory=RepositoryPolicy)
    shodan: ShodanPolicy = Field(default_factory=ShodanPolicy)
    verification: VerificationPolicy = Field(default_factory=VerificationPolicy)
    llm: LlmPolicy = Field(default_factory=LlmPolicy)
    schedules: dict[str, str] = Field(default_factory=dict)
    schedule_jitter_seconds: int = Field(default=300, ge=0, le=3600)
    retention_days: int = Field(default=30, ge=1, le=3650)
    notes: str | None = None

    @model_validator(mode="after")
    def source_platform_matches_manifest(self) -> "ProgramManifest":
        if self.source and self.source.platform != self.platform:
            raise ValueError("source platform must match the program platform")
        return self

    @model_validator(mode="after")
    def third_party_scanners_need_host_wide_path_permission(self) -> "ProgramManifest":
        paths_are_restricted = self.network.allowed_paths != ["*"] or bool(
            self.network.denied_paths
        )
        bbot_uses_http = bool(
            set(self.bbot.presets) & {"web", "spider", "web-screenshots"}
        )
        if paths_are_restricted and (
            (self.bbot.enabled and bbot_uses_http) or self.nuclei.enabled
        ):
            raise ValueError(
                "BBOT web presets and Nuclei cannot enforce path-level policy; "
                "disable them or approve host-wide paths"
            )
        if (
            self.network.requests_per_second < 1
            and ((self.bbot.enabled and bbot_uses_http) or self.nuclei.enabled)
        ):
            raise ValueError(
                "BBOT web presets and Nuclei require at least one request per second; "
                "use the deterministic verifier for slower rates"
            )
        return self

    @model_validator(mode="after")
    def scheduled_scanners_need_concrete_targets(self) -> "ProgramManifest":
        scheduled_scanners = []
        if self.bbot.enabled and "bbot" in self.schedules:
            scheduled_scanners.append("BBOT")
        if self.nuclei.enabled and "nuclei" in self.schedules:
            scheduled_scanners.append("Nuclei")
        if not scheduled_scanners:
            return self

        has_concrete_target = any(
            (rule.type == "domain" and not rule.value.startswith("*."))
            or (rule.type in {"url", "cidr"} and "*" not in rule.value)
            for rule in self.scope.include
        )
        if has_concrete_target:
            return self

        wildcard_rules = [
            rule.value
            for rule in self.scope.include
            if rule.type == "domain" and rule.value.startswith("*.")
        ]
        wildcard_detail = (
            f" Wildcard rules ({', '.join(wildcard_rules)}) authorize subdomains but "
            "do not authorize their apex as a seed."
            if wildcard_rules
            else ""
        )
        kinds = " and ".join(scheduled_scanners)
        raise ValueError(
            f"scheduled {kinds} jobs require at least one concrete in-scope domain, "
            "URL, or CIDR because scheduled jobs have no explicit target payload."
            f"{wildcard_detail} Add a policy-permitted concrete seed, remove the "
            "schedule, or enqueue explicit in-scope targets after discovery."
        )

    @field_validator("program_id")
    @classmethod
    def program_id_is_safe(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", value):
            raise ValueError("program_id must contain 2-64 lowercase letters, digits, _ or -")
        return value

    @field_validator("policy_snapshot_file")
    @classmethod
    def policy_snapshot_file_is_safe(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", value):
            raise ValueError("policy_snapshot_file must be a plain filename")
        return value

    @field_validator("schedules")
    @classmethod
    def schedules_are_valid(cls, value: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(value) - JOB_KINDS)
        if unknown:
            raise ValueError(f"unknown scheduled job kinds: {unknown}")
        # Validated here rather than only in the scheduler so a typo is caught at
        # approval time instead of stalling every program's scheduling at runtime.
        malformed = sorted(
            kind for kind, expression in value.items() if not croniter.is_valid(expression)
        )
        if malformed:
            raise ValueError(f"invalid cron expressions for scheduled kinds: {malformed}")
        return value


class LoadedManifest(StrictModel):
    path: Path
    manifest: ProgramManifest
    computed_hash: str
    policy_snapshot_actual_hash: str | None
    policy_snapshot_valid: bool
    approved: bool


class InvalidManifest(StrictModel):
    """A manifest file that could not be read, parsed, or validated."""

    path: Path
    program_id: str | None
    error: str


class ManifestSet(StrictModel):
    loaded: list[LoadedManifest] = Field(default_factory=list)
    invalid: list[InvalidManifest] = Field(default_factory=list)


def canonical_manifest_data(raw: dict) -> dict:
    data = copy.deepcopy(raw)
    data.pop("approval", None)
    return data


def manifest_hash(raw: dict) -> str:
    canonical = json.dumps(
        canonical_manifest_data(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def load_manifest(path: Path) -> LoadedManifest:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"manifest must be a YAML mapping: {path}")
    computed = manifest_hash(raw)
    manifest = ProgramManifest.model_validate(raw)
    policy_root = (path.parent.parent / "policies").resolve()
    policy_path = (policy_root / manifest.policy_snapshot_file).resolve()
    if policy_root not in policy_path.parents:
        raise ValueError("policy snapshot escapes the policy directory")
    try:
        policy_content = policy_path.read_bytes()
    except FileNotFoundError:
        actual_policy_hash = None
    else:
        actual_policy_hash = "sha256:" + hashlib.sha256(policy_content).hexdigest()
    policy_snapshot_valid = actual_policy_hash == manifest.policy_snapshot_hash
    return LoadedManifest(
        path=path,
        manifest=manifest,
        computed_hash=computed,
        policy_snapshot_actual_hash=actual_policy_hash,
        policy_snapshot_valid=policy_snapshot_valid,
        approved=(
            manifest.approval.approved_hash == computed and policy_snapshot_valid
        ),
    )


def describe_manifest_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        message = "; ".join(
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()[:5]
        )
    else:
        message = f"{type(exc).__name__}: {exc}"
    return message[:500]


def declared_program_id(path: Path) -> str | None:
    """Best-effort program_id from a manifest that failed validation."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(raw, dict):
        return None
    value = raw.get("program_id")
    if isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", value):
        return value
    return None


def load_manifests(directory: Path) -> ManifestSet:
    """Load every manifest, isolating failures to the file that caused them.

    A single unreadable manifest must not pause approved programs or stop the API,
    scheduler, and workers from starting, so failures are reported per file and the
    caller pauses only the affected program.
    """
    if not directory.exists():
        return ManifestSet()
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    loaded: list[LoadedManifest] = []
    invalid: list[InvalidManifest] = []
    for path in paths:
        try:
            loaded.append(load_manifest(path))
        except Exception as exc:  # noqa: BLE001 - one bad file must not fail the sync
            invalid.append(
                InvalidManifest(
                    path=path,
                    program_id=declared_program_id(path),
                    error=describe_manifest_error(exc),
                )
            )

    ids = [entry.manifest.program_id for entry in loaded]
    duplicates = {program_id for program_id in ids if ids.count(program_id) > 1}
    if duplicates:
        # Ambiguous ownership: pause every manifest involved rather than guessing.
        kept: list[LoadedManifest] = []
        for entry in loaded:
            program_id = entry.manifest.program_id
            if program_id in duplicates:
                invalid.append(
                    InvalidManifest(
                        path=entry.path,
                        program_id=program_id,
                        error=f"program_id {program_id} is declared by more than one manifest",
                    )
                )
            else:
                kept.append(entry)
        loaded = kept
    return ManifestSet(loaded=loaded, invalid=invalid)
