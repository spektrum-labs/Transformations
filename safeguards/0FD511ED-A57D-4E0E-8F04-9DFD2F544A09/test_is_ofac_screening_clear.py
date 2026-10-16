"""Unit tests for the isOfacScreeningClear transform (fail-closed behaviour)."""

import importlib.util
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "is_ofac_screening_clear_transform",
    os.path.join(_HERE, "is_ofac_screening_clear_transform.py"),
)
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)
transform = _MOD.transform


def _key(result):
    return result["transformedResponse"]["isOfacScreeningClear"]


def test_clean_clear_passes():
    out = transform({"status": "clear", "is_clear": True, "potential_matches": []})
    assert _key(out) is True


def test_potential_match_fails_closed():
    out = transform(
        {"status": "potential_match", "potential_matches": [{"fixed_ref": "10001"}]}
    )
    assert _key(out) is False


def test_unknown_status_fails_closed():
    assert _key(transform({"status": "unknown"})) is False


def test_matches_present_without_clear_status_fails_closed():
    # Even if status somehow says clear, surfaced matches must fail closed.
    out = transform({"status": "clear", "potential_matches": [{"fixed_ref": "x"}]})
    assert _key(out) is False


def test_accepts_json_string_input():
    out = transform(json.dumps({"status": "clear", "potential_matches": []}))
    assert _key(out) is True


def test_unwraps_data_wrapper():
    out = transform({"data": {"status": "clear", "potential_matches": []}})
    assert _key(out) is True


def test_malformed_input_fails_closed():
    assert _key(transform("not json")) is False


def test_non_object_response_fails_closed():
    assert _key(transform("[1, 2, 3]")) is False
