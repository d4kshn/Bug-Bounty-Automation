from __future__ import annotations

import json

import pytest

from bbpipeline.verifier import load_researcher_headers


def test_researcher_headers_block_routing_and_method_overrides(tmp_path):
    headers = tmp_path / "headers.json"
    headers.write_text(
        json.dumps(
            {
                "example-program": {
                    "researcher": {"Host": "internal", "X-Bug-Bounty": "alias"}
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden researcher header"):
        load_researcher_headers(headers, "example-program", "researcher")
