from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
VALUE_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)([?&](?:key|api[_-]?key|token|access[_-]?token)=)[^&\s]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in VALUE_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)(bearer"):
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        elif pattern.pattern.lower().startswith("(?i)([?&]"):
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def sanitize_asset(value: str) -> str:
    """Remove URL credentials/query/fragment and redact recognizable token patterns."""
    cleaned = redact_text(value)
    if "://" not in cleaned:
        return cleaned
    try:
        parsed = urlsplit(cleaned)
        if not parsed.hostname:
            return cleaned
        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, hostname + port, parsed.path, "", ""))
    except ValueError:
        return cleaned


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            output[str(key)] = "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_artifact(content: bytes, filename: str) -> bytes:
    """Redact structured scanner output before it enters durable evidence storage."""
    text = content.decode("utf-8", errors="replace")
    if filename.endswith((".json", ".jsonl", ".ndjson")):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            lines: list[str] = []
            for line in text.splitlines():
                try:
                    lines.append(json.dumps(redact(json.loads(line)), sort_keys=True))
                except json.JSONDecodeError:
                    lines.append(redact_text(line))
            return ("\n".join(lines) + ("\n" if text.endswith("\n") else "")).encode()
        return json.dumps(redact(value), indent=2, sort_keys=True).encode()
    return redact_text(text).encode()
