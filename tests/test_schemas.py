from __future__ import annotations

import json
from pathlib import Path

from bbpipeline.plans import CritiqueOutput, HypothesisOutput


def test_structured_output_schemas_cover_all_model_fields():
    root = Path(__file__).parents[1] / "schemas"
    hypothesis = json.loads((root / "hypothesis.schema.json").read_text())
    critique = json.loads((root / "critique.schema.json").read_text())
    assert set(hypothesis["required"]) == set(HypothesisOutput.model_fields)
    assert set(critique["required"]) == set(CritiqueOutput.model_fields)
    assert hypothesis["additionalProperties"] is False
    assert critique["additionalProperties"] is False
