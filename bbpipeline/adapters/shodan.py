from __future__ import annotations

from typing import Any

import httpx

from bbpipeline.adapters.common import AdapterResult
from bbpipeline.events import EventInput
from bbpipeline.manifest import ProgramManifest


def run_shodan(manifest: ProgramManifest, *, api_key: str) -> AdapterResult:
    if not manifest.shodan.enabled:
        raise ValueError("Shodan is disabled for this program")
    if not api_key:
        raise ValueError("Shodan API key is not configured")
    roots = sorted(
        {
            rule.value.removeprefix("*.")
            for rule in manifest.scope.include
            if rule.type == "domain"
        }
    )
    events: list[EventInput] = []
    queries: list[str] = []
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        for root in roots:
            query = f"hostname:{root}"
            queries.append(query)
            response = client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query},
            )
            if response.is_error:
                raise RuntimeError(
                    f"Shodan search failed with status {response.status_code}"
                )
            data = response.json()
            matches = data.get("matches", []) if isinstance(data, dict) else []
            if not isinstance(matches, list):
                continue
            for match in matches[: manifest.shodan.max_results_per_query]:
                if not isinstance(match, dict):
                    continue
                ip = str(match.get("ip_str") or "unknown")
                port = match.get("port")
                hostnames = [str(value).lower() for value in match.get("hostnames", [])]
                if not any(name == root or name.endswith("." + root) for name in hostnames):
                    continue
                events.append(
                    EventInput(
                        source="shodan",
                        event_type="SHODAN_SERVICE",
                        asset=f"{ip}:{port}",
                        severity="info",
                        confidence=0.75,
                        payload={
                            "hostnames": hostnames,
                            "domains": match.get("domains", []),
                            "port": port,
                            "transport": match.get("transport"),
                            "product": match.get("product"),
                            "version": match.get("version"),
                            "org": match.get("org"),
                            "timestamp": match.get("timestamp"),
                        },
                    )
                )
    return AdapterResult(events=events, summary={"queries": queries, "services": len(events)})
