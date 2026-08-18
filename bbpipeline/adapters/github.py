from __future__ import annotations

from typing import Any

import httpx

from bbpipeline.adapters.common import AdapterResult
from bbpipeline.events import EventInput
from bbpipeline.manifest import ProgramManifest
from bbpipeline.scope import rule_matches


def _headers(token: str) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "bbpipeline/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    return headers


def _get_json(client: httpx.Client, url: str) -> Any:
    response = client.get(url)
    response.raise_for_status()
    return response.json()


def run_github(manifest: ProgramManifest, *, token: str) -> AdapterResult:
    if not manifest.repositories.enabled:
        raise ValueError("repository discovery is disabled for this program")
    rules = [rule for rule in manifest.scope.include if rule.type == "repository"]
    repositories: dict[str, dict[str, Any]] = {}
    with httpx.Client(
        headers=_headers(token), timeout=20, follow_redirects=False
    ) as client:
        for rule in rules:
            if rule.value.endswith("/*"):
                owner = rule.value[:-2]
                for page in range(1, 11):
                    data = _get_json(
                        client,
                        f"https://api.github.com/users/{owner}/repos"
                        f"?type=public&per_page=100&page={page}",
                    )
                    if not isinstance(data, list):
                        break
                    for item in data:
                        if isinstance(item, dict) and item.get("full_name"):
                            repositories[str(item["full_name"])] = item
                    if len(data) < 100:
                        break
            elif "*" not in rule.value:
                data = _get_json(client, f"https://api.github.com/repos/{rule.value}")
                if isinstance(data, dict) and data.get("full_name"):
                    repositories[str(data["full_name"])] = data

    events: list[EventInput] = []
    expanded: list[str] = []
    for repository, data in sorted(repositories.items()):
        if not any(rule_matches(rule, repository) for rule in rules):
            continue
        expanded.append(repository)
        events.append(
            EventInput(
                source="github",
                event_type="REPOSITORY",
                asset=f"https://github.com/{repository}",
                severity="info",
                confidence=1.0,
                payload={
                    "repository": repository,
                    "default_branch": data.get("default_branch"),
                    "archived": data.get("archived"),
                    "fork": data.get("fork"),
                    "size_kb": data.get("size"),
                    "pushed_at": data.get("pushed_at"),
                    "topics": data.get("topics", []),
                    "visibility": data.get("visibility"),
                },
            )
        )
    return AdapterResult(
        events=events,
        summary={"repositories": len(events), "expanded_repositories": expanded},
    )
