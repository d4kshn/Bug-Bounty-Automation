from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlsplit

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from bbpipeline.manifest import ProgramManifest, ScopeRule
from bbpipeline.settings import Settings

PlatformName = Literal["hackerone", "bugcrowd", "intigriti", "yeswehack"]


class PlatformSourceError(RuntimeError):
    pass


class PlatformAuthError(PlatformSourceError):
    pass


class PlatformDataError(PlatformSourceError):
    pass


class PlatformSourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    source_id: str
    program_id: str
    platform: PlatformName
    remote_identifier: str
    enabled: bool = True
    policy_url: str | None = None
    program_type: Literal["bug-bounty", "vdp"] = "bug-bounty"

    @field_validator("source_id", "program_id")
    @classmethod
    def identifier_is_safe(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", value):
            raise ValueError("identifier must contain 2-64 lowercase letters, digits, _ or -")
        return value

    @field_validator("remote_identifier")
    @classmethod
    def remote_identifier_is_bounded(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 500 or "\x00" in cleaned:
            raise ValueError("remote_identifier is empty or too long")
        return cleaned


class InvalidPlatformSource(BaseModel):
    path: Path
    source_id: str | None = None
    error: str


class PlatformSourceSet(BaseModel):
    loaded: list[PlatformSourceConfig] = Field(default_factory=list)
    invalid: list[InvalidPlatformSource] = Field(default_factory=list)


class RemoteAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=10000)
    category: str = Field(default="", max_length=500)
    description: str = Field(default="", max_length=100000)
    in_scope: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class PlatformSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: PlatformName
    remote_identifier: str
    name: str = Field(max_length=200)
    policy_url: str = Field(max_length=4000)
    policy_text: str = Field(default="", max_length=2000000)
    assets: list[RemoteAsset] = Field(max_length=10000)
    rules: dict[str, Any] = Field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @property
    def revision_hash(self) -> str:
        encoded = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class NormalizedScope:
    include: list[ScopeRule]
    exclude: list[ScopeRule]
    unsupported: list[dict[str, str]]


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in exc.errors()[:5]
        )[:1000]
    return f"{type(exc).__name__}: {exc}"[:1000]


def load_platform_sources(directory: Path) -> PlatformSourceSet:
    if not directory.exists():
        return PlatformSourceSet()
    loaded: list[PlatformSourceConfig] = []
    invalid: list[InvalidPlatformSource] = []
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    for path in paths:
        source_id: str | None = None
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("platform source must be a YAML mapping")
            if isinstance(raw.get("source_id"), str):
                source_id = raw["source_id"]
            loaded.append(PlatformSourceConfig.model_validate(raw))
        except Exception as exc:  # noqa: BLE001 - isolate one malformed source
            invalid.append(
                InvalidPlatformSource(path=path, source_id=source_id, error=_error_text(exc))
            )

    counts: dict[str, int] = {}
    program_counts: dict[str, int] = {}
    for item in loaded:
        counts[item.source_id] = counts.get(item.source_id, 0) + 1
        program_counts[item.program_id] = program_counts.get(item.program_id, 0) + 1
    duplicates = {source_id for source_id, count in counts.items() if count > 1}
    duplicate_programs = {
        program_id for program_id, count in program_counts.items() if count > 1
    }
    if duplicates or duplicate_programs:
        kept: list[PlatformSourceConfig] = []
        for item in loaded:
            if item.source_id in duplicates or item.program_id in duplicate_programs:
                reason = (
                    "source_id is declared more than once"
                    if item.source_id in duplicates
                    else "program_id is assigned to more than one platform source"
                )
                invalid.append(
                    InvalidPlatformSource(
                        path=directory,
                        source_id=item.source_id,
                        error=reason,
                    )
                )
            else:
                kept.append(item)
        loaded = kept
    return PlatformSourceSet(loaded=loaded, invalid=invalid)


def _raise_for_platform_response(response: httpx.Response, platform: str) -> None:
    if response.status_code in {401, 403}:
        raise PlatformAuthError(
            f"{platform} rejected the configured credential with status "
            f"{response.status_code}"
        )
    if response.is_error:
        raise PlatformSourceError(
            f"{platform} request failed with status {response.status_code}"
        )


def _response_json(response: httpx.Response, platform: str) -> Any:
    _raise_for_platform_response(response, platform)
    if len(response.content) > 8 * 1024 * 1024:
        raise PlatformDataError(f"{platform} response exceeded 8 MiB")
    try:
        return response.json()
    except ValueError as exc:
        raise PlatformDataError(f"{platform} returned invalid JSON") from exc


def _same_origin_next(current_url: str, next_url: str) -> str:
    joined = urljoin(current_url, next_url)
    current = urlsplit(current_url)
    following = urlsplit(joined)
    if following.scheme != "https" or following.netloc != current.netloc:
        raise PlatformDataError("platform pagination attempted to change origin")
    return joined


def _jsonapi_pages(client: httpx.Client, url: str, platform: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > 100:
            raise PlatformDataError(f"{platform} pagination exceeded 100 pages")
        data = _response_json(client.get(next_url), platform)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise PlatformDataError(f"{platform} returned an unexpected collection")
        items.extend(item for item in data["data"] if isinstance(item, dict))
        raw_next = data.get("links", {}).get("next")
        next_url = _same_origin_next(next_url, raw_next) if isinstance(raw_next, str) else None
    return items


def _http_client(
    settings: Settings,
    *,
    headers: dict[str, str] | None = None,
    auth: httpx.Auth | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    return httpx.Client(
        headers={"Accept": "application/json", "User-Agent": "bbpipeline/0.2", **(headers or {})},
        auth=auth,
        timeout=settings.platform_http_timeout_seconds,
        follow_redirects=False,
        transport=transport,
    )


def _hackerone_snapshot(
    settings: Settings,
    source: PlatformSourceConfig,
    transport: httpx.BaseTransport | None,
) -> PlatformSnapshot:
    token = settings.read_secret(settings.hackerone_api_token_file, required=True)
    handle = quote(source.remote_identifier, safe="")
    base = "https://api.hackerone.com/v1/hackers/programs/"
    with _http_client(
        settings,
        auth=httpx.BasicAuth(settings.researcher_handle, token),
        transport=transport,
    ) as client:
        detail = _response_json(client.get(base + handle), "HackerOne")
        scopes = _jsonapi_pages(
            client, base + handle + "/structured_scopes", "HackerOne"
        )
        exclusions = _jsonapi_pages(
            client, base + handle + "/scope_exclusions", "HackerOne"
        )
    detail_data = detail.get("data", {}) if isinstance(detail, dict) else {}
    attributes = detail_data.get("attributes", {}) if isinstance(detail_data, dict) else {}
    if not isinstance(attributes, dict):
        raise PlatformDataError("HackerOne program attributes are missing")
    assets: list[RemoteAsset] = []
    for item in scopes:
        attrs = item.get("attributes", {})
        if not isinstance(attrs, dict) or not attrs.get("asset_identifier"):
            continue
        assets.append(
            RemoteAsset(
                target=str(attrs["asset_identifier"]),
                category=str(attrs.get("asset_type") or ""),
                description=str(attrs.get("instruction") or ""),
                in_scope=bool(attrs.get("eligible_for_submission")),
                metadata={
                    "eligible_for_bounty": bool(attrs.get("eligible_for_bounty")),
                    "reference_id": str(attrs.get("reference") or item.get("id") or ""),
                },
            )
        )
    policy_url = source.policy_url or f"https://hackerone.com/{source.remote_identifier}"
    return PlatformSnapshot(
        platform="hackerone",
        remote_identifier=source.remote_identifier,
        name=str(attributes.get("name") or attributes.get("handle") or source.program_id),
        policy_url=policy_url,
        policy_text=str(attributes.get("policy") or ""),
        assets=assets,
        rules={
            "open_scope": bool(attributes.get("open_scope")),
            "state": attributes.get("state"),
            "submission_state": attributes.get("submission_state"),
            "scope_exclusions": exclusions,
            "note": "open_scope never widens the generated scanner allow-list",
        },
    )


def _intigriti_snapshot(
    settings: Settings,
    source: PlatformSourceConfig,
    transport: httpx.BaseTransport | None,
) -> PlatformSnapshot:
    token = settings.read_secret(settings.intigriti_api_token_file, required=True)
    identifier = quote(source.remote_identifier, safe="")
    url = f"https://api.intigriti.com/external/researcher/v1/programs/{identifier}"
    with _http_client(
        settings, headers={"Authorization": f"Bearer {token}"}, transport=transport
    ) as client:
        detail = _response_json(client.get(url), "Intigriti")
    if not isinstance(detail, dict):
        raise PlatformDataError("Intigriti returned an unexpected program document")
    domains = detail.get("domains", {})
    domain_content = domains.get("content", []) if isinstance(domains, dict) else []
    assets: list[RemoteAsset] = []
    for item in domain_content if isinstance(domain_content, list) else []:
        if not isinstance(item, dict) or not item.get("endpoint"):
            continue
        raw_type = item.get("type", {})
        category = raw_type.get("value", "") if isinstance(raw_type, dict) else raw_type
        assets.append(
            RemoteAsset(
                target=str(item["endpoint"]),
                category=str(category or ""),
                description=str(item.get("description") or ""),
                metadata={"tier": item.get("tier"), "domain_id": item.get("id")},
            )
        )
    rules = detail.get("rulesOfEngagement", {})
    rules_content = rules.get("content", {}) if isinstance(rules, dict) else {}
    links = detail.get("webLinks", {})
    policy_url = source.policy_url or (
        str(links.get("detail")) if isinstance(links, dict) and links.get("detail") else ""
    )
    if not policy_url:
        policy_url = f"https://app.intigriti.com/programs/{source.remote_identifier}/detail"
    return PlatformSnapshot(
        platform="intigriti",
        remote_identifier=source.remote_identifier,
        name=str(detail.get("name") or detail.get("handle") or source.program_id),
        policy_url=policy_url,
        policy_text=(
            str(rules_content.get("description") or "")
            if isinstance(rules_content, dict)
            else ""
        ),
        assets=assets,
        rules={
            "status": detail.get("status"),
            "type": detail.get("type"),
            "confidentiality_level": detail.get("confidentialityLevel"),
            "rules_of_engagement": rules_content,
        },
    )


def _yeswehack_snapshot(
    settings: Settings,
    source: PlatformSourceConfig,
    transport: httpx.BaseTransport | None,
) -> PlatformSnapshot:
    token = settings.read_secret(settings.yeswehack_access_token_file, required=True)
    slug = quote(source.remote_identifier, safe="")
    access_url = f"https://apps.yeswehack.com/v2/hunter/access/programs/{source.program_type}"
    detail_url = f"https://apps.yeswehack.com/programs/{slug}"
    scope_url = f"https://apps.yeswehack.com/programs/{slug}/scopes"
    with _http_client(
        settings, headers={"Authorization": f"Bearer {token}"}, transport=transport
    ) as client:
        access = _response_json(client.get(access_url), "YesWeHack")
        detail = _response_json(client.get(detail_url), "YesWeHack")
        if not isinstance(detail, dict):
            raise PlatformDataError("YesWeHack returned an unexpected program document")
        scope_items = detail.get("scopes")
        if not isinstance(scope_items, list):
            scopes = _response_json(client.get(scope_url), "YesWeHack")
            scope_items = scopes.get("items", []) if isinstance(scopes, dict) else scopes
    access_items = access.get("items", []) if isinstance(access, dict) else []
    selected = next(
        (
            item
            for item in access_items
            if isinstance(item, dict) and str(item.get("slug")) == source.remote_identifier
        ),
        {},
    )
    if not selected:
        raise PlatformAuthError(
            "YesWeHack credential does not list the configured program as accessible"
        )
    if not isinstance(scope_items, list):
        raise PlatformDataError("YesWeHack returned an unexpected scope document")
    assets: list[RemoteAsset] = []
    for item in scope_items:
        if not isinstance(item, dict):
            continue
        target = item.get("asset_value") or item.get("scope")
        if not isinstance(target, str) or not target.strip():
            continue
        assets.append(
            RemoteAsset(
                target=target,
                category=str(item.get("scope_type_name") or item.get("scope_type") or ""),
                description=str(item.get("description") or ""),
                metadata={"report_count": item.get("report_count")},
            )
        )
    policy_url = source.policy_url or f"https://yeswehack.com/programs/{source.remote_identifier}"
    return PlatformSnapshot(
        platform="yeswehack",
        remote_identifier=source.remote_identifier,
        name=str(detail.get("title") or selected.get("title") or source.program_id),
        policy_url=policy_url,
        policy_text=str(detail.get("rules") or ""),
        assets=assets,
        rules={
            "status": detail.get("status"),
            "archived": detail.get("archived", selected.get("archived")),
            "disabled": detail.get("disabled"),
            "secured": detail.get("secured"),
            "rights": detail.get("rights", selected.get("rights")),
            "out_of_scope_text": detail.get("out_of_scope", []),
            "required_user_agent": detail.get("ywh_triager_user_agent"),
        },
    )


def _run_bbscope_cookie(
    settings: Settings, source: PlatformSourceConfig, *, list_programs: bool = False
) -> Any:
    settings.read_secret(settings.bugcrowd_session_cookie_file, required=True)
    command = [
        settings.bbscope_cookie_command,
        "--token-file",
        str(settings.bugcrowd_session_cookie_file),
    ]
    if list_programs:
        command.append("--list")
    else:
        command.extend(["--handle", source.remote_identifier])
    try:
        completed = subprocess.run(  # noqa: S603 - argv only; shell execution is disabled
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=settings.platform_http_timeout_seconds * 4,
        )
    except FileNotFoundError as exc:
        raise PlatformSourceError("pinned BBscope cookie helper is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise PlatformSourceError("BBscope cookie fetch timed out") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.strip().lower()
        if any(word in stderr for word in ("login", "session", "unauthorized", "forbidden")):
            raise PlatformAuthError("Bugcrowd rejected or expired the session cookie")
        raise PlatformSourceError(
            f"BBscope cookie helper failed with exit status {completed.returncode}"
        )
    try:
        return json.loads(completed.stdout)
    except ValueError as exc:
        raise PlatformDataError("BBscope cookie helper returned invalid JSON") from exc


def _bugcrowd_snapshot(settings: Settings, source: PlatformSourceConfig) -> PlatformSnapshot:
    data = _run_bbscope_cookie(settings, source)
    if not isinstance(data, dict):
        raise PlatformDataError("BBscope returned an unexpected scope document")
    assets: list[RemoteAsset] = []
    for in_scope, key in ((True, "in_scope"), (False, "out_of_scope")):
        items = data.get(key, [])
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or not item.get("target"):
                continue
            assets.append(
                RemoteAsset(
                    target=str(item["target"]),
                    category=str(item.get("category") or ""),
                    description=str(item.get("description") or ""),
                    in_scope=in_scope,
                )
            )
    policy_url = source.policy_url or str(data.get("url") or "")
    if not policy_url:
        handle = source.remote_identifier.lstrip("/")
        policy_url = f"https://bugcrowd.com/{handle}"
    return PlatformSnapshot(
        platform="bugcrowd",
        remote_identifier=source.remote_identifier,
        name=str(data.get("name") or source.program_id),
        policy_url=policy_url,
        policy_text=str(data.get("policy_text") or ""),
        assets=assets,
        rules={
            "collector": "BBscope pinned cookie adapter",
            "warning": "Review the complete Bugcrowd brief before approving the candidate.",
        },
    )


def fetch_platform_snapshot(
    settings: Settings,
    source: PlatformSourceConfig,
    *,
    transport: httpx.BaseTransport | None = None,
) -> PlatformSnapshot:
    if source.platform == "hackerone":
        return _hackerone_snapshot(settings, source, transport)
    if source.platform == "intigriti":
        return _intigriti_snapshot(settings, source, transport)
    if source.platform == "yeswehack":
        return _yeswehack_snapshot(settings, source, transport)
    return _bugcrowd_snapshot(settings, source)


def _scope_rule(kind: str, value: str, note: str) -> ScopeRule | None:
    try:
        return ScopeRule(type=kind, value=value, note=note or None)
    except ValidationError:
        return None


def _normalize_one(asset: RemoteAsset) -> ScopeRule | None:
    target = asset.target.strip()
    category = asset.category.strip().lower().replace("_", "-")
    note = asset.description.strip()[:500]
    if not target or target in {"*", "NO_IN_SCOPE_TABLE", "2FA_REQUIRED"}:
        return None

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        network = None
    if network is not None:
        return _scope_rule("cidr", str(network), note)

    parsed = urlsplit(target)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        if parsed.hostname.startswith("*."):
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                return None
            return _scope_rule("domain", parsed.hostname.lower(), note)
        if "github.com" == parsed.hostname.lower():
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) == 2 and parts[1].removesuffix(".git"):
                return _scope_rule(
                    "repository", f"{parts[0]}/{parts[1].removesuffix('.git')}", note
                )
        if "*" not in target:
            return _scope_rule("url", target, note)
        return None

    repo_categories = {"source-code", "code", "github", "source code"}
    if category in repo_categories:
        cleaned = target.removeprefix("github.com/").removesuffix(".git")
        return _scope_rule("repository", cleaned, note)

    cleaned_domain = target.lower().rstrip(".")
    domain_rule = _scope_rule("domain", cleaned_domain, note)
    if domain_rule is not None:
        return domain_rule

    cloud_markers = {"aws-cloud-config", "cloud", "azure", "gcp"}
    if category in cloud_markers and not any(character.isspace() for character in target):
        return _scope_rule("cloud", target, note)
    return None


def normalize_snapshot(snapshot: PlatformSnapshot) -> NormalizedScope:
    includes: dict[tuple[str, str], ScopeRule] = {}
    excludes: dict[tuple[str, str], ScopeRule] = {}
    unsupported: list[dict[str, str]] = []
    for asset in snapshot.assets:
        rule = _normalize_one(asset)
        if rule is None:
            unsupported.append(
                {
                    "target": asset.target[:500],
                    "category": asset.category[:200],
                    "scope": "in" if asset.in_scope else "out",
                    "disposition": "manual_review_required",
                }
            )
            continue
        bucket = includes if asset.in_scope else excludes
        bucket[(rule.type, rule.value.lower())] = rule
    return NormalizedScope(
        include=[includes[key] for key in sorted(includes)],
        exclude=[excludes[key] for key in sorted(excludes)],
        unsupported=sorted(unsupported, key=lambda item: (item["target"], item["category"])),
    )


def policy_snapshot_text(
    snapshot: PlatformSnapshot, normalized: NormalizedScope
) -> str:
    document = {
        "schema": "bbpipeline-platform-policy-snapshot-v1",
        "source": snapshot.canonical(),
        "normalization": {
            "include": [rule.model_dump(mode="json") for rule in normalized.include],
            "exclude": [rule.model_dump(mode="json") for rule in normalized.exclude],
            "unsupported": normalized.unsupported,
            "warning": (
                "This machine-generated snapshot is not approval. Review the live program "
                "brief, automation limits, exclusions, and every normalized rule."
            ),
        },
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_candidate_manifest(
    source: PlatformSourceConfig,
    snapshot: PlatformSnapshot,
    *,
    existing: ProgramManifest | None = None,
    generated_at: datetime | None = None,
) -> tuple[dict[str, Any], str]:
    normalized = normalize_snapshot(snapshot)
    if not normalized.include:
        raise PlatformDataError(
            "platform scope contains no supported in-scope target; manual review is required"
        )
    policy_text = policy_snapshot_text(snapshot, normalized)
    policy_hash = "sha256:" + hashlib.sha256(policy_text.encode()).hexdigest()
    filename = f"{source.program_id}-{source.platform}-policy.json"
    if existing is not None:
        candidate = existing.model_dump(mode="json")
        local_excludes = {
            (rule.type, rule.value.lower()): rule for rule in existing.scope.exclude
        }
    else:
        candidate = {
            "version": 1,
            "program_id": source.program_id,
            "name": snapshot.name,
            "platform": source.platform,
            "policy_url": snapshot.policy_url,
            "policy_snapshot_file": filename,
            "policy_snapshot_hash": policy_hash,
            "approval": {
                "approved_hash": "pending",
                "approved_by": "UNREVIEWED",
                "approved_at": "1970-01-01T00:00:00Z",
            },
            "scope": {"include": [], "exclude": []},
            "bbot": {"enabled": False},
            "nuclei": {"enabled": False},
            "repositories": {"enabled": False},
            "shodan": {"enabled": False},
            "verification": {"auto_http": False},
            "llm": {"enabled": True},
            "schedules": {},
            "retention_days": 30,
        }
        local_excludes = {}
    for rule in normalized.exclude:
        local_excludes[(rule.type, rule.value.lower())] = rule
    unsafe_exclusions = [
        item for item in normalized.unsupported if item.get("scope") == "out"
    ]
    candidate.update(
        {
            "name": snapshot.name,
            "platform": source.platform,
            "policy_url": snapshot.policy_url,
            "policy_snapshot_file": filename,
            "policy_snapshot_hash": policy_hash,
            "source": {
                "source_id": source.source_id,
                "platform": source.platform,
                "remote_identifier": source.remote_identifier,
                "revision_hash": snapshot.revision_hash,
            },
            "approval": {
                "approved_hash": "pending",
                "approved_by": "UNREVIEWED",
                "approved_at": (generated_at or datetime.now(UTC)).isoformat(),
            },
            "scope": {
                "include": [rule.model_dump(mode="json") for rule in normalized.include],
                "exclude": [
                    local_excludes[key].model_dump(mode="json")
                    for key in sorted(local_excludes)
                ],
            },
            "notes": (
                "Platform-generated candidate. Review unsupported assets in the policy "
                "snapshot and the live brief before computing the human approval hash."
            ),
        }
    )
    if unsafe_exclusions:
        candidate["bbot"]["enabled"] = False
        candidate["nuclei"]["enabled"] = False
        candidate["repositories"]["enabled"] = False
        candidate["shodan"]["enabled"] = False
        candidate["verification"]["auto_http"] = False
        candidate["schedules"] = {}
        candidate["notes"] = (
            "FAIL-CLOSED CANDIDATE: at least one out-of-scope entry cannot be "
            "represented by the policy engine. All automation was disabled. Resolve "
            "every unsupported exclusion against the live brief before enabling a tool."
        )
    validated = ProgramManifest.model_validate(candidate)
    return validated.model_dump(mode="json"), policy_text


def _collection_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("items", "records", "programs", "data"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def discover_platform_programs(
    settings: Settings,
    platform: PlatformName,
    *,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, Any]]:
    if platform == "bugcrowd":
        items = _run_bbscope_cookie(
            settings,
            PlatformSourceConfig(
                version=1,
                source_id="bugcrowd-discovery",
                program_id="bugcrowd-discovery",
                platform="bugcrowd",
                remote_identifier="/engagements/discovery",
            ),
            list_programs=True,
        )
        if not isinstance(items, list):
            raise PlatformDataError("BBscope returned an unexpected program list")
        return [
            {"remote_identifier": str(item), "name": str(item), "platform": platform}
            for item in items
            if isinstance(item, str)
        ]

    if platform == "hackerone":
        token = settings.read_secret(settings.hackerone_api_token_file, required=True)
        with _http_client(
            settings,
            auth=httpx.BasicAuth(settings.researcher_handle, token),
            transport=transport,
        ) as client:
            items = _jsonapi_pages(
                client, "https://api.hackerone.com/v1/hackers/programs", "HackerOne"
            )
        return [
            {
                "remote_identifier": str(
                    item.get("attributes", {}).get("handle") or item.get("id")
                ),
                "name": str(item.get("attributes", {}).get("name") or ""),
                "platform": platform,
            }
            for item in items
            if isinstance(item.get("attributes"), dict)
        ]

    token_file = (
        settings.intigriti_api_token_file
        if platform == "intigriti"
        else settings.yeswehack_access_token_file
    )
    token = settings.read_secret(token_file, required=True)
    if platform == "intigriti":
        url = "https://api.intigriti.com/external/researcher/v1/programs?limit=1000&offset=0"
    else:
        url = "https://apps.yeswehack.com/v2/hunter/access/programs/bug-bounty"
    with _http_client(
        settings, headers={"Authorization": f"Bearer {token}"}, transport=transport
    ) as client:
        data = _response_json(client.get(url), platform)
    items = _collection_items(data)
    return [
        {
            "remote_identifier": str(
                item.get("id") if platform == "intigriti" else item.get("slug")
            ),
            "name": str(item.get("name") or item.get("title") or item.get("handle") or ""),
            "platform": platform,
        }
        for item in items
        if (platform == "intigriti" and item.get("id"))
        or (platform == "yeswehack" and item.get("slug"))
    ]


def write_platform_source(path: Path, source: PlatformSourceConfig) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing source: {path}")
    path.write_text(
        yaml.safe_dump(source.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
