from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bbpipeline.adapters.common import AdapterResult, run_command
from bbpipeline.events import EventInput
from bbpipeline.manifest import ProgramManifest
from bbpipeline.redaction import redact, sanitize_asset
from bbpipeline.scope import authorize_target


CONFIDENCE = {"LOW": 0.35, "MEDIUM": 0.6, "HIGH": 0.85, "CONFIRMED": 1.0}


def _should_resolve(target: str) -> bool:
    if target.startswith("*."):
        return False
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return True
    return False


@dataclass(frozen=True)
class SeedTargets:
    targets: list[str]
    wildcard_only: list[str]


def _apex_is_in_scope(manifest: ProgramManifest, apex: str) -> bool:
    wanted = apex.lower().rstrip(".")
    return any(
        rule.type == "domain"
        and not rule.value.startswith("*.")
        and rule.value.lower().rstrip(".") == wanted
        for rule in manifest.scope.include
    )


def default_targets(manifest: ProgramManifest) -> SeedTargets:
    """Derive scan seeds from scope.

    A ``*.example.com`` rule authorizes subdomains but not the apex, so the apex is
    used as a seed only when it is separately in scope. Seeding a scanner with an
    unauthorized apex would put every one of its requests out of scope, so wildcard
    rules without an in-scope apex are reported instead and the caller explains them.
    """
    targets: list[str] = []
    wildcard_only: list[str] = []
    for rule in manifest.scope.include:
        if rule.type not in {"domain", "url", "cidr"}:
            continue
        if rule.type != "domain" or not rule.value.startswith("*."):
            targets.append(rule.value)
            continue
        apex = rule.value.removeprefix("*.")
        if _apex_is_in_scope(manifest, apex):
            targets.append(apex)
        else:
            wildcard_only.append(rule.value)
    return SeedTargets(
        targets=list(dict.fromkeys(targets)),
        wildcard_only=list(dict.fromkeys(wildcard_only)),
    )


def wildcard_only_error(tool: str, wildcard_only: list[str]) -> str:
    return (
        f"no {tool} seed target is in scope: {', '.join(wildcard_only)} "
        "authorize subdomains but not the apex. Add the apex domain to scope.include "
        "if the program permits it, or enqueue explicit in-scope subdomains as targets."
    )


def _can_expand_subdomains(manifest: ProgramManifest, target: str) -> bool:
    parsed = urlsplit(target if "://" in target else f"//{target}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    return any(
        rule.type == "domain"
        and rule.value.startswith("*.")
        and (
            hostname == rule.value[2:].lower().rstrip(".")
            or hostname.endswith("." + rule.value[2:].lower().rstrip("."))
        )
        for rule in manifest.scope.include
    )


def _asset(raw: dict[str, Any]) -> str:
    data = raw.get("data")
    if isinstance(data, str):
        return data
    structured = raw.get("data_json") or data
    if isinstance(structured, dict):
        for key in ("url", "host", "hostname", "name", "description"):
            if structured.get(key):
                return str(structured[key])
        return json.dumps(structured, sort_keys=True)[:1000]
    return str(data or raw.get("id") or "unknown")


def _parse_events(path: Path) -> list[EventInput]:
    events: list[EventInput] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index >= 100_000:
                break
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = str(raw.get("type", "UNKNOWN")).upper()
            structured = raw.get("data_json") if isinstance(raw.get("data_json"), dict) else {}
            severity = str(structured.get("severity") or raw.get("severity") or "info").lower()
            confidence_raw = str(
                structured.get("confidence") or raw.get("confidence") or "LOW"
            ).upper()
            events.append(
                EventInput(
                    source="bbot",
                    event_type=event_type,
                    asset=sanitize_asset(_asset(raw)),
                    severity=(
                        severity
                        if severity in {"info", "low", "medium", "high", "critical"}
                        else "info"
                    ),
                    confidence=CONFIDENCE.get(confidence_raw, 0.4),
                    payload={
                        "module": raw.get("module"),
                        "tags": raw.get("tags", []),
                        "scope_distance": raw.get("scope_distance"),
                        "resolved_hosts": raw.get("resolved_hosts", []),
                        "details": structured,
                    },
                )
            )
    return events


def run_bbot(
    manifest: ProgramManifest,
    *,
    targets: list[str] | None,
    job_id: str,
    workdir: Path,
    timeout: int,
) -> AdapterResult:
    seeds = default_targets(manifest)
    selected = list(dict.fromkeys(targets or seeds.targets))
    if not manifest.bbot.enabled:
        raise ValueError("BBOT is disabled for this program")
    if not selected and seeds.wildcard_only:
        raise ValueError(wildcard_only_error("BBOT", seeds.wildcard_only))
    if not selected or len(selected) > manifest.bbot.max_targets:
        raise ValueError("BBOT target count is empty or exceeds the program limit")
    for target in selected:
        if target.startswith("*."):
            target = target[2:]
        decision = authorize_target(
            manifest,
            target,
            resolve_dns=_should_resolve(target),
        )
        if not decision.allowed:
            raise ValueError(f"BBOT target denied: {target}: {decision.reason}")

    selected = list(dict.fromkeys(target.removeprefix("*.") for target in selected))
    strict_targets = [target for target in selected if not _can_expand_subdomains(manifest, target)]
    recursive_targets = [target for target in selected if _can_expand_subdomains(manifest, target)]
    events: list[EventInput] = []
    artifacts: list[tuple[str, str, bytes]] = []
    logs: list[str] = []
    blacklist = [rule.value for rule in manifest.scope.exclude]
    for label, group, strict in (
        ("recursive", recursive_targets, False),
        ("strict", strict_targets, True),
    ):
        if not group:
            continue
        scan_name = "job_" + job_id.replace("-", "_") + "_" + label
        command = ["bbot", "-t", *group]
        if blacklist:
            command.extend(["-b", *blacklist])
        if manifest.bbot.presets:
            command.extend(["-p", *manifest.bbot.presets])
        command.extend(
            [
                "-c",
                f"web.http_rate_limit={max(1, int(manifest.network.requests_per_second))}",
                f"web.http_timeout={manifest.network.timeout_seconds}",
                "web.http_max_redirects=0",
                f"max_threads={manifest.network.concurrency}",
                f"modules.http.threads={manifest.network.concurrency}",
                f"modules.gowitness.threads={manifest.network.concurrency}",
                f"modules.speculate.ports={','.join(map(str, manifest.network.allowed_ports))}",
                "scope.search_distance=0",
                "scope.report_distance=0",
                "file_blobs=false",
                "folder_blobs=false",
                "-n",
                scan_name,
                "-o",
                str(workdir),
                "-y",
                "--no-color",
                "--no-deps",
            ]
        )
        if strict:
            command.append("-S")
        completed = run_command(command, cwd=workdir, timeout=timeout)
        logs.append(completed.stdout + "\n" + completed.stderr)
        output_file = workdir / scan_name / "output.json"
        group_events = _parse_events(output_file)
        events.extend(group_events)
        if output_file.exists():
            normalized = [
                redact(event.model_dump(mode="json")) for event in group_events
            ]
            artifacts.append(
                (
                    "bbot-events",
                    f"output-{label}.json",
                    json.dumps(normalized, indent=2, sort_keys=True).encode(),
                )
            )
    artifacts.insert(0, ("bbot-log", "bbot.log", "\n".join(logs).encode()))
    return AdapterResult(
        events=events,
        artifacts=artifacts,
        summary={
            "targets": len(selected),
            "events": len(events),
            "skipped_wildcard_only_rules": seeds.wildcard_only,
        },
    )
