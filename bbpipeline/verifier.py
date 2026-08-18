from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from bbpipeline.manifest import ProgramManifest
from bbpipeline.plans import TestStep
from bbpipeline.redaction import redact, redact_text
from bbpipeline.scope import authorize_target


SAFE_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "location",
    "server",
    "allow",
    "www-authenticate",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "cache-control",
    "etag",
    "last-modified",
}
FORBIDDEN_REQUEST_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-http-method-override",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
}


def load_researcher_headers(path: Path, program_id: str, role: str | None) -> dict[str, str]:
    if not role:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError("researcher header secret file is missing") from None
    except json.JSONDecodeError as exc:
        raise ValueError("researcher header secret file is invalid JSON") from exc
    headers = raw.get(program_id, {}).get(role, {}) if isinstance(raw, dict) else {}
    if not isinstance(headers, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
    ):
        raise ValueError(f"invalid headers for account role {role}")
    for key, value in headers.items():
        if key.lower() in FORBIDDEN_REQUEST_HEADERS:
            raise ValueError(f"forbidden researcher header: {key}")
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise ValueError("researcher headers cannot contain newline characters")
    return headers


def _url(step: TestStep) -> str:
    parsed = urlsplit(step.target)
    path = step.path if step.path.startswith("/") else "/" + step.path
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def verify_http_plan(
    manifest: ProgramManifest,
    *,
    steps: list[TestStep],
    researcher_headers_file: Path,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    request_count = 0
    last_request_at: float | None = None
    with httpx.Client(
        timeout=manifest.network.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for step in steps:
            if step.primitive == "manual_required":
                raise ValueError("manual_required step reached automatic verifier")
            method = {
                "http_get": "GET",
                "http_head": "HEAD",
                "http_options": "OPTIONS",
            }[step.primitive]
            target = _url(step)
            decision = authorize_target(manifest, target, method=method, resolve_dns=True)
            if not decision.allowed:
                raise ValueError(f"last-mile authorization denied {target}: {decision.reason}")
            effective_role = step.account_role or manifest.identity.default_account_role
            if (
                effective_role
                and effective_role not in manifest.identity.approved_account_roles
            ):
                raise ValueError(f"account role is not approved: {effective_role}")
            if step.account_role and not manifest.verification.allow_authenticated:
                raise ValueError("automatic authenticated verification is disabled")
            headers = load_researcher_headers(
                researcher_headers_file, manifest.program_id, effective_role
            )
            header_names = {key.lower() for key in headers}
            if (
                header_names & {"authorization", "cookie"}
                and not manifest.verification.allow_authenticated
            ):
                raise ValueError("authenticated researcher headers are disabled")
            if "accept-encoding" not in header_names:
                headers["Accept-Encoding"] = "identity"
            if "user-agent" not in header_names:
                headers["User-Agent"] = "bbpipeline/0.1"
            if (
                manifest.identity.required_header
                and manifest.identity.required_header.lower() not in header_names
            ):
                raise ValueError(
                    f"required researcher header {manifest.identity.required_header} is missing"
                )
            request_count += 1
            if request_count > manifest.network.max_requests_per_verification:
                raise ValueError("verification request budget exceeded")
            if last_request_at is not None:
                minimum_interval = 1.0 / manifest.network.requests_per_second
                remaining = minimum_interval - (time.monotonic() - last_request_at)
                if remaining > 0:
                    time.sleep(remaining)
            started_at = time.monotonic()
            with client.stream(method, target, headers=headers) as response:
                content_type = response.headers.get("content-type", "")
                body_bytes = b""
                if method != "HEAD" and (
                    content_type.startswith("text/")
                    or "json" in content_type
                    or "xml" in content_type
                    or not content_type
                ):
                    chunks: list[bytes] = []
                    collected = 0
                    for chunk in response.iter_bytes(chunk_size=1024):
                        remaining = 8192 - collected
                        if remaining <= 0:
                            break
                        chunks.append(chunk[:remaining])
                        collected += min(len(chunk), remaining)
                        if collected >= 8192:
                            break
                    body_bytes = b"".join(chunks)
                body = redact_text(
                    body_bytes.decode(response.encoding or "utf-8", errors="replace")
                )
                status_code = response.status_code
                response_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() in SAFE_RESPONSE_HEADERS
                }
            elapsed_ms = round((time.monotonic() - started_at) * 1000)
            last_request_at = time.monotonic()
            results.append(
                redact(
                    {
                        "primitive": step.primitive,
                        "target": target,
                        "account_role": effective_role,
                        "purpose": step.purpose,
                        "expected_observation": step.expected_observation,
                        "falsifier": step.falsifier,
                        "status_code": status_code,
                        "elapsed_ms": elapsed_ms,
                        "resolved_ips": decision.resolved_ips,
                        "headers": response_headers,
                        "body_excerpt": body,
                    }
                )
            )
    return {"request_count": request_count, "steps": results}
