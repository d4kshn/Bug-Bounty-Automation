from __future__ import annotations

from pathlib import Path


SKILL_NAME = "bug-bounty-review"
MAX_SKILL_FILE_BYTES = 64 * 1024


def _read_skill_file(root: Path, relative_path: str) -> str | None:
    path = (root / relative_path).resolve()
    resolved_root = root.resolve()
    if resolved_root not in path.parents or not path.is_file():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_SKILL_FILE_BYTES:
        raise ValueError(f"triage skill file is too large: {relative_path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"triage skill file is not UTF-8: {relative_path}") from exc


def _finding_family_reference(tags: set[str]) -> str:
    if tags & {
        "gitleaks",
        "github",
        "repository",
        "secret",
        "secret_candidate",
    }:
        return "repository-secret-findings.md"
    if tags & {
        "shodan",
        "shodan_service",
        "cloud",
        "cloud_asset",
        "storage_bucket",
        "dns_name",
        "dangling_resource",
        "takeover",
    }:
        return "cloud-service-findings.md"
    return "web-api-findings.md"


def load_triage_skill(
    directory: Path,
    *,
    role: str,
    tags: set[str] | None = None,
) -> dict[str, object] | None:
    """Load the provider-neutral reasoning package embedded in an LLM packet.

    Reference order is intentional: the packet fitter discards from the end, leaving
    the role- or finding-specific guidance in context for as long as possible.
    """

    core = _read_skill_file(directory, "SKILL.md")
    if core is None:
        return None
    normalized_tags = {str(tag).lower() for tag in tags or set()}
    if role == "triage":
        references = [
            _finding_family_reference(normalized_tags),
            "scanner-signal-triage.md",
            "scope-and-evidence.md",
        ]
    elif role == "critic":
        references = [
            "independent-validation.md",
            "severity-report-readiness.md",
            "scope-and-evidence.md",
        ]
    else:
        raise ValueError(f"unsupported triage skill role: {role}")

    loaded: list[dict[str, str]] = []
    for name in references:
        content = _read_skill_file(directory, f"references/{name}")
        if content is not None:
            loaded.append({"name": name, "content": content})
    return {
        "name": SKILL_NAME,
        "role": role,
        "core": core,
        "references": loaded,
    }
