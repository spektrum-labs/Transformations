"""A partial Sophos endpoint read, or a body with no endpoint list, is Not evaluated.

mdr_transform.py and epp_transform.py score the endpoints they are handed. When the list is
only the first part of the fleet (pages.nextKey still set, a truncation marker, or a page
count that says more pages exist), a coverage figure, a "none found" False or a count taken
from it is not a total: the answer rests on endpoints nobody has seen. Every key comes back None
with a data-collection error instead.

A body that carries only the explicit configured flag has no endpoint list either, so the
coverage keys beside the flag are None, not 0 / False. The flag itself keeps its value.

A complete read (no cursor, no marker) keeps its verdict, including a proven negative.
All payloads here are synthetic.
"""
import importlib.util
import json
import pathlib
from datetime import datetime

import pytest

HERE = pathlib.Path(__file__).parent
FILES = ["mdr_transform.py", "epp_transform.py"]
FLAG_KEY = {"mdr_transform.py": "isMDRConfigured", "epp_transform.py": "isEPPConfigured"}
OTHER_FLAG = {"mdr_transform.py": "isEPPConfigured", "epp_transform.py": "isMDRConfigured"}
NOW = datetime.utcnow().isoformat()[:19] + "Z"
SENTINEL = "DO-NOT-ECHO-VENDOR-TEXT"
OK_VALIDATION = {"status": "unknown", "errors": [], "warnings": []}


def load(name):
    spec = importlib.util.spec_from_file_location("sophos_pages_" + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(name, body):
    return load(name).transform(body)


def endpoint(eid, products, **extra):
    item = {"id": eid, "type": "computer", "lastSeenAt": NOW,
            "assignedProducts": [{"code": c, "status": "installed"} for c in products],
            "health": {"services": {"serviceDetails": []}}}
    item.update(extra)
    return item


def enveloped(body):
    return {"data": body, "validation": OK_VALIDATION}


MANAGED = [endpoint("e1", ["endpointProtection", "mtr"])]
UNMANAGED = [endpoint("e1", ["endpointProtection"]), endpoint("e2", ["endpointProtection"], mdrManaged=False)]

PARTIAL_BODIES = [
    ("next key with a managed endpoint seen",
     {"items": MANAGED, "pages": {"size": "1", "maxSize": "500", "nextKey": "cursor-abc"}}),
    ("next key with no managed endpoint seen",
     {"items": UNMANAGED, "pages": {"size": "2", "maxSize": "500", "nextKey": "cursor-abc"}}),
    ("next key as a number", {"items": UNMANAGED, "pages": {"nextKey": 12345}}),
    ("next key with other stringified fields",
     {"items": UNMANAGED, "pages": {"size": "2", "maxSize": "500", "total": "3", "nextKey": "cursor-abc"}}),
    ("pages marked truncated", {"items": UNMANAGED, "pages": {"size": "2", "truncated": True}}),
    ("pages marked truncated as text", {"items": UNMANAGED, "pages": {"truncated": "true"}}),
    ("body marked truncated", {"items": UNMANAGED, "truncated": True}),
    ("more items reported than present", {"items": UNMANAGED, "pages": {"size": "2", "items": "250"}}),
    ("more pages reported than present", {"items": UNMANAGED, "pages": {"size": "500", "total": "3"}}),
    ("wrapped partial read", {"response": {"items": UNMANAGED, "pages": {"nextKey": "cursor-abc"}}}),
    ("enveloped partial read", enveloped({"items": UNMANAGED, "pages": {"nextKey": "cursor-abc"}})),
    ("partial read beside an unset flag", {"items": UNMANAGED, "pages": {"nextKey": "cursor-abc"}, "isMDRConfigured": None,
                                           "isEPPConfigured": None}),
]

# No cursor and no marker: a complete read, scored as before.
COMPLETE_BODIES = [
    ("no pages object", {"items": UNMANAGED}),
    ("pages with no next key", {"items": UNMANAGED, "pages": {"size": "2", "maxSize": "500"}}),
    ("next key null", {"items": UNMANAGED, "pages": {"size": "2", "nextKey": None}}),
    ("next key stringified none", {"items": UNMANAGED, "pages": {"size": "2", "nextKey": "None"}}),
    ("next key stringified null", {"items": UNMANAGED, "pages": {"size": "2", "nextKey": "null"}}),
    ("next key empty", {"items": UNMANAGED, "pages": {"size": "2", "nextKey": ""}}),
    ("truncated false", {"items": UNMANAGED, "pages": {"truncated": False}}),
    ("truncated stringified false", {"items": UNMANAGED, "pages": {"truncated": "false"}}),
    ("one page of one", {"items": UNMANAGED, "pages": {"size": "2", "total": "1"}}),
    ("item total matches", {"items": UNMANAGED, "pages": {"size": "2", "items": "2"}}),
    ("merged pages", {"items": UNMANAGED, "pages": {"size": "1", "maxSize": "1", "total": "2"}}),
    ("bare list", UNMANAGED),
    ("enveloped", enveloped({"items": UNMANAGED, "pages": {"size": "2"}})),
]

# Bodies with no endpoint list, only an explicit configured flag.
FLAG_ONLY_BODIES = [
    ("flag only true", True),
    ("flag only false", False),
]


def success_keys(name):
    out = run(name, {"items": [endpoint("e1", ["endpointProtection"])]})
    return set(out["transformedResponse"])


def assert_not_evaluated(name, out, kept=None):
    """Every key is None (except the explicit flag named in `kept`), with a data-collection error."""
    result = out["transformedResponse"]
    assert set(result) == success_keys(name)
    for key, value in result.items():
        if kept is not None and key == kept[0]:
            assert value is kept[1], key
        else:
            assert value is None, (key, value)
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert isinstance(collection["errors"], list) and collection["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert SENTINEL not in json.dumps(out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("label,body", PARTIAL_BODIES, ids=[label for label, _ in PARTIAL_BODIES])
def test_partial_read_is_not_evaluated(name, label, body):
    assert_not_evaluated(name, run(name, body))


@pytest.mark.parametrize("name", FILES)
def test_partial_read_reason_names_the_unread_pages_and_echoes_nothing(name):
    body = {"items": UNMANAGED, "pages": {"nextKey": "cursor-" + SENTINEL}}
    out = run(name, body)
    assert_not_evaluated(name, out)
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert "further pages" in reason
    assert "cursor-" not in json.dumps(out)


@pytest.mark.parametrize("name", FILES)
def test_partial_read_never_reports_a_figure_a_total_or_a_boolean(name):
    for label, body in PARTIAL_BODIES:
        for key, value in run(name, body)["transformedResponse"].items():
            assert value is None, (label, key, value)


@pytest.mark.parametrize("name", FILES)
def test_a_managed_endpoint_on_a_partial_page_does_not_report_a_coverage_figure(name):
    """100% of the one page seen is not the coverage of the whole fleet."""
    out = run(name, {"items": MANAGED, "pages": {"size": "1", "nextKey": "cursor-abc"}})
    assert out["transformedResponse"]["MDR"] is None
    assert out["transformedResponse"]["requiredCoveragePercentage"] is None
    assert out["transformedResponse"]["isMDREnabled"] is None


@pytest.mark.parametrize("name", FILES)
def test_a_partial_page_does_not_report_a_none_found_false(name):
    """No managed endpoint on the first page does not prove there is none on the rest."""
    out = run(name, {"items": UNMANAGED, "pages": {"size": "2", "nextKey": "cursor-abc"}})
    assert out["transformedResponse"]["isMDREnabled"] is None
    assert out["transformedResponse"]["MDR"] is None
    assert out["transformedResponse"]["isMDRLoggingEnabled"] is None


def test_epp_stale_endpoint_count_is_not_a_total_on_a_partial_page():
    old = "2020-01-01T00:00:00Z"
    body = {"items": [endpoint("e1", ["endpointProtection"]), endpoint("e2", ["endpointProtection"], lastSeenAt=old)],
            "pages": {"nextKey": "cursor-abc"}}
    out = run("epp_transform.py", body)
    assert out["transformedResponse"]["staleEndpointCount"] is None
    assert out["transformedResponse"]["isEPPEnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, False])
def test_explicit_flag_on_a_partial_page_keeps_its_value_and_nothing_else_is_scored(name, flag):
    """A negative the body states outright stays False; the coverage keys beside it are not totals."""
    key = FLAG_KEY[name]
    body = {"items": UNMANAGED, "pages": {"nextKey": "cursor-abc"}, key: flag}
    assert_not_evaluated(name, run(name, body), kept=(key, flag))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("label,body", COMPLETE_BODIES, ids=[label for label, _ in COMPLETE_BODIES])
def test_complete_read_keeps_its_proven_negative(name, label, body):
    out = run(name, body)
    result = out["transformedResponse"]
    assert result["MDR"] == 0
    assert result["isMDREnabled"] is False
    assert result["isMDRLoggingEnabled"] is False
    assert result["isEPPEnabled"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("name", FILES)
def test_complete_read_with_a_managed_endpoint_still_reads_true(name):
    out = run(name, {"items": MANAGED, "pages": {"size": "1", "nextKey": "None"}})
    assert out["transformedResponse"]["isMDREnabled"] is True
    assert out["transformedResponse"]["MDR"] == 100
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


# A body with only the explicit configured flag has no endpoint list.

@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("label,flag", FLAG_ONLY_BODIES, ids=[label for label, _ in FLAG_ONLY_BODIES])
def test_flag_only_body_scores_nothing_else(name, label, flag):
    key = FLAG_KEY[name]
    out = run(name, {key: flag})
    assert_not_evaluated(name, out, kept=(key, flag))
    assert out["transformedResponse"]["isMDREnabled"] is None
    assert out["transformedResponse"]["MDR"] is None
    assert out["transformedResponse"]["Endpoint Protection"] is None


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, False])
def test_each_flag_alone_scores_nothing_else_in_either_transform(name, flag):
    """A flag aimed at the other transform's key is not this transform's flag: every key is None."""
    out = run(name, {OTHER_FLAG[name]: flag})
    assert_not_evaluated(name, out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("wrap", [lambda body: body, enveloped, lambda body: {"response": body}],
                         ids=["plain", "enveloped", "wrapped"])
def test_flag_only_body_in_every_wrapper(name, wrap):
    key = FLAG_KEY[name]
    assert_not_evaluated(name, run(name, wrap({key: True})), kept=(key, True))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("body", [{"items": []}, {"items": None}, {"items": "none"}, {"items": ["x", 1]}],
                         ids=["empty items", "null items", "items not a list", "items with no record"])
def test_flag_beside_no_endpoint_records_scores_nothing_else(name, body):
    key = FLAG_KEY[name]
    full = dict(body)
    full[key] = False
    assert_not_evaluated(name, run(name, full), kept=(key, False))


@pytest.mark.parametrize("name", FILES)
def test_flag_beside_an_error_body_is_not_kept(name):
    """An error body proves nothing, so even an explicit flag next to it is None."""
    key = FLAG_KEY[name]
    assert_not_evaluated(name, run(name, {"error": "forbidden " + SENTINEL, key: True}))
    assert_not_evaluated(name, run(name, {"statusCode": 403, key: False}))
    assert_not_evaluated(name, run(name, {"items": [{"error": "forbidden"}], key: True}))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, False])
def test_flag_beside_a_complete_list_still_overrides_the_derived_value(name, flag):
    key = FLAG_KEY[name]
    out = run(name, {"items": UNMANAGED, key: flag})
    assert out["transformedResponse"][key] is flag
    assert out["transformedResponse"]["MDR"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", FILES)
def test_unset_flag_beside_no_list_is_not_a_flag(name):
    key = FLAG_KEY[name]
    assert_not_evaluated(name, run(name, {key: None}))
