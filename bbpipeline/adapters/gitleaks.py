from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from bbpipeline.adapters.common import AdapterResult, run_command
from bbpipeline.events import EventInput
from bbpipeline.manifest import ProgramManifest
from bbpipeline.redaction import redact
from bbpipeline.scope import authorize_target


def _validate_repo(repository: str) -> tuple[str, str]:
    parts = repository.split("/")
    if len(parts) != 2:
        raise ValueError("repository must be an exact GitHub owner/name pair")
    owner, name = parts
    owner_valid = bool(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
    )
    name_valid = bool(re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name)) and name not in {
        ".",
        "..",
    }
    if not owner_valid or not name_valid or "*" in repository:
        raise ValueError("repository is not a valid exact GitHub owner/name pair")
    return owner, name


def _repository_size_mb(repository: str, github_token: str) -> float | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "bbpipeline/0.1"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    response = httpx.get(
        f"https://api.github.com/repos/{repository}",
        headers=headers,
        timeout=20,
        follow_redirects=False,
    )
    response.raise_for_status()
    size_kb = response.json().get("size")
    return float(size_kb) / 1024 if isinstance(size_kb, (int, float)) else None


def run_gitleaks(
    manifest: ProgramManifest,
    *,
    repository: str,
    github_token: str,
    workdir: Path,
    timeout: int,
) -> AdapterResult:
    if not manifest.repositories.enabled:
        raise ValueError("repository scanning is disabled for this program")
    owner, name = _validate_repo(repository)
    decision = authorize_target(manifest, repository, resolve_dns=False)
    if not decision.allowed:
        raise ValueError(f"repository denied: {decision.reason}")
    size_mb = _repository_size_mb(repository, github_token)
    if size_mb is not None and size_mb > manifest.repositories.max_repository_mb:
        raise ValueError(
            f"repository size {size_mb:.1f} MiB exceeds approved maximum "
            f"{manifest.repositories.max_repository_mb} MiB"
        )

    clone_dir = workdir / "repository"
    clone_command = [
        "git",
        "clone",
        "--no-tags",
    ]
    if manifest.repositories.scan_history:
        clone_command.append("--no-checkout")
    else:
        clone_command.extend(["--depth", "1"])
    clone_command.extend(
        [f"https://github.com/{owner}/{name}.git", str(clone_dir)]
    )
    clone = run_command(
        clone_command,
        cwd=workdir,
        timeout=timeout,
        env={"GIT_TERMINAL_PROMPT": "0"},
    )
    report_path = workdir / "gitleaks.json"
    command = [
        "gitleaks",
        "git" if manifest.repositories.scan_history else "dir",
        "--no-banner",
        "--no-color",
        "--redact=100",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--timeout",
        str(timeout),
        str(clone_dir),
    ]
    scan = run_command(command, cwd=workdir, timeout=timeout, accepted_codes={0, 1})
    try:
        raw_findings = (
            json.loads(report_path.read_text(encoding="utf-8"))
            if report_path.exists()
            else []
        )
    except json.JSONDecodeError:
        raw_findings = []
    if not isinstance(raw_findings, list):
        raw_findings = []
    events: list[EventInput] = []
    for finding in raw_findings[:10_000]:
        if not isinstance(finding, dict):
            continue
        safe = redact(finding)
        commit = str(finding.get("Commit", ""))
        file_path = str(finding.get("File", "unknown"))
        line = finding.get("StartLine")
        asset = f"https://github.com/{repository}/blob/{commit}/{file_path}"
        if line:
            asset += f"#L{line}"
        events.append(
            EventInput(
                source="gitleaks",
                event_type="SECRET_CANDIDATE",
                asset=asset,
                severity="high",
                confidence=0.7,
                payload={
                    "rule_id": finding.get("RuleID"),
                    "description": finding.get("Description"),
                    "repository": repository,
                    "commit": commit,
                    "file": file_path,
                    "line": line,
                    "fingerprint": finding.get("Fingerprint"),
                    "redacted_finding": safe,
                    "never_automatically_verify_secret": True,
                },
            )
        )
    redacted_report = json.dumps(redact(raw_findings), indent=2, sort_keys=True).encode("utf-8")
    return AdapterResult(
        events=events,
        artifacts=[
            ("gitleaks-report", "gitleaks.json", redacted_report),
            (
                "gitleaks-log",
                "gitleaks.log",
                (clone.stdout + clone.stderr + scan.stdout + scan.stderr).encode(),
            ),
        ],
        summary={"repository": repository, "findings": len(events), "size_mb": size_mb},
    )
