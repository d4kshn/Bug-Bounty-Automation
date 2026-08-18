from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bbpipeline.adapters.bbot import default_targets, wildcard_only_error
from bbpipeline.adapters.common import AdapterResult, run_command
from bbpipeline.events import EventInput
from bbpipeline.manifest import ProgramManifest
from bbpipeline.redaction import redact, sanitize_asset
from bbpipeline.scope import authorize_target, rule_matches


class NucleiProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    name: str
    template_root: Literal["/opt/nuclei-templates"] = "/opt/nuclei-templates"
    template_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=lambda: ["low", "medium", "high", "critical"])
    protocols: list[str] = Field(default_factory=lambda: ["http", "ssl"])
    rate_limit: int = Field(default=1, ge=1, le=50)
    concurrency: int = Field(default=2, ge=1, le=25)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    retries: int = Field(default=1, ge=0, le=3)

    @model_validator(mode="after")
    def has_filter(self) -> "NucleiProfile":
        if not self.template_ids and not self.tags:
            raise ValueError("nuclei profile must specify template_ids or tags")
        return self

    @field_validator("protocols")
    @classmethod
    def safe_protocols(cls, value: list[str]) -> list[str]:
        allowed = {"http", "ssl", "dns"}
        if not value or set(value) - allowed:
            raise ValueError("v1 nuclei profiles may use only http, ssl, and dns protocols")
        return value

    @field_validator("severities")
    @classmethod
    def safe_severities(cls, value: list[str]) -> list[str]:
        allowed = {"info", "low", "medium", "high", "critical"}
        if not value or set(value) - allowed:
            raise ValueError("invalid Nuclei severity selection")
        return list(dict.fromkeys(value))

    @field_validator("template_ids", "tags", "exclude_tags")
    @classmethod
    def safe_selectors(cls, value: list[str]) -> list[str]:
        for selector in value:
            if not selector or any(character in selector for character in {",", "\n", "\r"}):
                raise ValueError("Nuclei selectors must be nonempty single values")
        return list(dict.fromkeys(value))


def profile_hash(raw: dict[str, Any]) -> str:
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def load_profile(profile_dir: Path, manifest: ProgramManifest) -> NucleiProfile:
    path = (profile_dir / f"{manifest.nuclei.profile}.yml").resolve()
    root = profile_dir.resolve()
    if root not in path.parents:
        raise ValueError("nuclei profile escapes the profile directory")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("nuclei profile must be a YAML mapping")
    computed = profile_hash(raw)
    if computed != manifest.nuclei.profile_hash:
        raise ValueError(
            f"nuclei profile hash is not approved; computed {computed}, "
            f"manifest has {manifest.nuclei.profile_hash}"
        )
    profile = NucleiProfile.model_validate(raw)
    if profile.name != manifest.nuclei.profile:
        raise ValueError("Nuclei profile name does not match the manifest")
    return profile


def _parse(path: Path) -> list[EventInput]:
    events: list[EventInput] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= 50_000:
                break
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
            severity = str(info.get("severity") or raw.get("severity") or "info").lower()
            asset = str(
                raw.get("matched-at") or raw.get("host") or raw.get("url") or "unknown"
            )
            events.append(
                EventInput(
                    source="nuclei",
                    event_type="VULNERABILITY",
                    asset=sanitize_asset(asset),
                    severity=(
                        severity
                        if severity in {"info", "low", "medium", "high", "critical"}
                        else "info"
                    ),
                    confidence=0.8,
                    payload={
                        "template_id": raw.get("template-id"),
                        "name": info.get("name"),
                        "tags": info.get("tags", []),
                        "matcher_name": raw.get("matcher-name"),
                        "type": raw.get("type"),
                        "ip": raw.get("ip"),
                    },
                )
            )
    return events


def run_nuclei(
    manifest: ProgramManifest,
    *,
    targets: list[str] | None,
    profile_dir: Path,
    workdir: Path,
    timeout: int,
) -> AdapterResult:
    if not manifest.nuclei.enabled:
        raise ValueError("Nuclei is disabled for this program")
    profile = load_profile(profile_dir, manifest)
    seeds = default_targets(manifest)
    requested = targets or seeds.targets
    if not requested and seeds.wildcard_only:
        raise ValueError(wildcard_only_error("Nuclei", seeds.wildcard_only))
    if not requested:
        raise ValueError("Nuclei target count is empty")
    selected: list[str] = []
    for target in requested:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            selected.append(target)
            continue
        if network.num_addresses > manifest.network.max_cidr_addresses:
            raise ValueError("Nuclei CIDR exceeds the approved address expansion limit")
        selected.extend(
            str(address)
            for address in network.hosts()
            if not any(
                rule_matches(rule, str(address)) for rule in manifest.scope.exclude
            )
        )
    selected = list(dict.fromkeys(selected))
    if not selected or len(selected) > manifest.nuclei.max_targets:
        raise ValueError("Nuclei target count is empty or exceeds the program limit")
    for target in selected:
        decision = authorize_target(manifest, target, resolve_dns=True)
        if not decision.allowed:
            raise ValueError(f"Nuclei target denied: {target}: {decision.reason}")

    target_file = workdir / "targets.txt"
    target_file.write_text("\n".join(selected) + "\n", encoding="utf-8")
    result_file = workdir / "nuclei.jsonl"
    command = [
        "nuclei",
        "-l",
        str(target_file),
        "-t",
        profile.template_root,
        "-jle",
        str(result_file),
        "-silent",
        "-nc",
        "-duc",
        "-dut",
        "-ni",
        "-or",
        "-ot",
        "-no-stdin",
        "-dr",
        "-pt",
        ",".join(profile.protocols),
        "-s",
        ",".join(profile.severities),
        "-rl",
        str(min(profile.rate_limit, max(1, int(manifest.network.requests_per_second)))),
        "-c",
        str(min(profile.concurrency, manifest.network.concurrency)),
        "-timeout",
        str(min(profile.timeout_seconds, manifest.network.timeout_seconds)),
        "-retries",
        str(profile.retries),
    ]
    if profile.template_ids:
        command.extend(["-id", ",".join(profile.template_ids)])
    if profile.tags:
        command.extend(["-tags", ",".join(profile.tags)])
    excluded = sorted(
        set(profile.exclude_tags)
        | {"fuzz", "dast", "headless", "code", "intrusive", "dos", "default-login"}
    )
    command.extend(["-etags", ",".join(excluded)])
    completed = run_command(command, cwd=workdir, timeout=timeout)
    events = _parse(result_file)
    artifacts = [
        ("nuclei-log", "nuclei.log", (completed.stdout + "\n" + completed.stderr).encode())
    ]
    if result_file.exists():
        normalized = [redact(event.model_dump(mode="json")) for event in events]
        artifacts.append(
            (
                "nuclei-events",
                "nuclei.json",
                json.dumps(normalized, indent=2, sort_keys=True).encode(),
            )
        )
    return AdapterResult(
        events=events,
        artifacts=artifacts,
        summary={"targets": len(selected), "events": len(events), "profile": profile.name},
    )
