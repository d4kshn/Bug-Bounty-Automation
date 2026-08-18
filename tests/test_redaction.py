from __future__ import annotations

import json

from bbpipeline.redaction import redact, redact_artifact, sanitize_asset


def test_nested_sensitive_values_are_removed():
    value = {
        "Authorization": "Bearer abcdefghijklmnop",
        "nested": {"api_key": "never-store-me"},
    }
    safe = redact(value)
    assert safe["Authorization"] == "[REDACTED]"
    assert safe["nested"]["api_key"] == "[REDACTED]"


def test_ndjson_artifact_is_redacted_line_by_line():
    content = b'{"url":"https://x","cookie":"session=secret"}\nBearer abcdefghijklmnop\n'
    safe = redact_artifact(content, "output.json")
    first, second = safe.decode().splitlines()
    assert json.loads(first)["cookie"] == "[REDACTED]"
    assert second == "Bearer [REDACTED]"
    assert b"session=secret" not in safe


def test_asset_url_drops_credentials_query_and_fragment():
    value = "https://user:pass@example.com:8443/path?access_token=secret#fragment"
    assert sanitize_asset(value) == "https://example.com:8443/path"


def test_query_string_api_key_is_redacted_from_errors():
    safe = redact_artifact(
        b"request failed: https://api.example.test/search?key=super-secret&q=x",
        "scanner.log",
    ).decode()
    assert "super-secret" not in safe
    assert "key=[REDACTED]" in safe
