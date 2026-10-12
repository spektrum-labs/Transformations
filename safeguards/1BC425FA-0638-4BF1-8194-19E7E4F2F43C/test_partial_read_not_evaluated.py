"""A partial Sophos endpoint read, or a body with no endpoint list, is Not evaluated.

mdr_transform.py and epp_transform.py score the endpoints they are handed. When the list is
only the first part of the fleet (pages.nextKey still set, a truncation marker, or a page
count that says more pages exist), a coverage figure, a "none found" False or a count taken
from it is not a total: the answer rests on endpoints nobody has seen. Every key comes back None
with a data-collection error instead.

A page that does not start at the beginning (pages.fromKey set) is also only part of the fleet.
A page count above the number of items returned, with no page size to compare, cannot be a whole
read either.

A body that carries only a configured flag has no endpoint list, so every key is None. The configured
keys (isMDRConfigured, isEPPConfigured) are derived from the endpoint list alone; Sophos documents no such
field, so a flag in the body is never read, never kept and never overrides what the list shows.

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
    ("total pages above the items returned, no page size", {"items": UNMANAGED, "pages": {"total": "3"}}),
    ("total as a number above the items returned, no page size", {"items": UNMANAGED, "pages": {"total": 250}}),
    ("a page that does not start at the beginning", {"items": UNMANAGED, "pages": {"fromKey": "cursor-abc", "size": "2"}}),
    ("a later page with no further cursor", {"items": UNMANAGED, "pages": {"fromKey": "cursor-abc", "nextKey": None}}),
    ("a later page with a numeric key", {"items": UNMANAGED, "pages": {"fromKey": 777}}),
    ("a later page, wrapped", {"response": {"items": MANAGED, "pages": {"fromKey": "cursor-abc"}}}),
    ("a later page, enveloped", enveloped({"items": MANAGED, "pages": {"fromKey": "cursor-abc"}})),
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
    ("page total equal to the items returned, no size", {"items": UNMANAGED, "pages": {"total": "2"}}),
    ("page total of one, no size", {"items": UNMANAGED, "pages": {"total": "1"}}),
    ("start key null", {"items": UNMANAGED, "pages": {"size": "2", "fromKey": None}}),
    ("start key stringified none", {"items": UNMANAGED, "pages": {"size": "2", "fromKey": "None"}}),
    ("start key stringified null", {"items": UNMANAGED, "pages": {"size": "2", "fromKey": "null"}}),
    ("start key empty", {"items": UNMANAGED, "pages": {"size": "2", "fromKey": ""}}),
    ("bare list", UNMANAGED),
    ("enveloped", enveloped({"items": UNMANAGED, "pages": {"size": "2"}})),
]

# Every shape a configured flag can arrive in. None of them is read.
FLAG_VALUES = [True, False, "true", "false", "True", "False", "None", "null", "", 0, 1]
FLAG_IDS = ["true", "false", "text-true", "text-false", "text-True", "text-False", "text-None", "text-null",
            "empty-text", "zero", "one"]


def success_keys(name):
    out = run(name, {"items": [endpoint("e1", ["endpointProtection"])]})
    return set(out["transformedResponse"])


def assert_not_evaluated(name, out):
    """Every key is None, with a data-collection error."""
    result = out["transformedResponse"]
    assert set(result) == success_keys(name)
    for key, value in result.items():
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
@pytest.mark.parametrize("flag", FLAG_VALUES, ids=FLAG_IDS)
def test_a_flag_on_a_partial_page_is_not_kept_and_nothing_is_scored(name, flag):
    """A negative or a positive the body states outright proves nothing about a partial list: every key is None."""
    body = {"items": UNMANAGED, "pages": {"nextKey": "cursor-abc"}, FLAG_KEY[name]: flag}
    assert_not_evaluated(name, run(name, body))


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


# A body with only a configured flag has no endpoint list. The flag is never read.

@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", FLAG_VALUES, ids=FLAG_IDS)
def test_flag_only_body_is_not_evaluated_including_the_flag(name, flag):
    out = run(name, {FLAG_KEY[name]: flag})
    assert_not_evaluated(name, out)
    assert out["transformedResponse"][FLAG_KEY[name]] is None
    assert out["transformedResponse"]["isMDREnabled"] is None
    assert out["transformedResponse"]["MDR"] is None
    assert out["transformedResponse"]["Endpoint Protection"] is None


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, False])
def test_the_other_transforms_flag_alone_is_not_evaluated_either(name, flag):
    assert_not_evaluated(name, run(name, {OTHER_FLAG[name]: flag}))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("wrap", [lambda body: body, enveloped, lambda body: {"response": body}],
                         ids=["plain", "enveloped", "wrapped"])
def test_flag_only_body_in_every_wrapper(name, wrap):
    assert_not_evaluated(name, run(name, wrap({FLAG_KEY[name]: True})))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("body", [{"items": []}, {"items": None}, {"items": "none"}, {"items": ["x", 1]}],
                         ids=["empty items", "null items", "items not a list", "items with no record"])
def test_flag_beside_no_endpoint_records_is_not_evaluated(name, body):
    for flag in (True, False):
        full = dict(body)
        full[FLAG_KEY[name]] = flag
        assert_not_evaluated(name, run(name, full))


@pytest.mark.parametrize("name", FILES)
def test_flag_beside_an_error_body_is_not_evaluated(name):
    key = FLAG_KEY[name]
    assert_not_evaluated(name, run(name, {"error": "forbidden " + SENTINEL, key: True}))
    assert_not_evaluated(name, run(name, {"statusCode": 403, key: False}))
    assert_not_evaluated(name, run(name, {"items": [{"error": "forbidden"}], key: True}))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", FLAG_VALUES, ids=FLAG_IDS)
@pytest.mark.parametrize("items_label,items", [("unmanaged", UNMANAGED), ("managed", MANAGED)])
def test_a_flag_beside_a_complete_list_never_moves_the_answer(name, flag, items_label, items):
    """The configured keys come from the endpoint list alone, so the same list gives the same answer with or without a flag."""
    plain = run(name, {"items": items})["transformedResponse"]
    flagged = run(name, {"items": items, FLAG_KEY[name]: flag, OTHER_FLAG[name]: flag})["transformedResponse"]
    assert flagged == plain


@pytest.mark.parametrize("flag", [True, "true", 1])
def test_epp_a_true_flag_cannot_turn_zero_protection_into_a_pass(flag):
    """A complete list with no endpoint protection reads 0%: configured False, misconfigured True, whatever the body says."""
    items = [endpoint("e1", [], lastSeenAt=NOW), endpoint("e2", ["mtr"])]
    out = run("epp_transform.py", {"items": items, "isEPPConfigured": flag})
    result = out["transformedResponse"]
    assert result["Endpoint Protection"] == 0
    assert result["isEPPConfigured"] is False
    assert result["isEPPMisconfigured"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("flag", [True, "true", 1])
def test_mdr_a_true_flag_cannot_turn_zero_mdr_into_configured(flag):
    out = run("mdr_transform.py", {"items": UNMANAGED, "isMDRConfigured": flag})
    result = out["transformedResponse"]
    assert result["MDR"] == 0
    assert result["isMDRConfigured"] is False


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [False, "false", 0])
def test_a_false_flag_cannot_turn_a_covered_fleet_into_a_fail(name, flag):
    items = MANAGED
    out = run(name, {"items": items, FLAG_KEY[name]: flag})
    assert out["transformedResponse"][FLAG_KEY[name]] is True


@pytest.mark.parametrize("name", FILES)
def test_the_transform_does_not_read_a_configured_flag_from_the_body(name):
    """Sophos documents no such field: neither transform may read the key it answers out of the vendor body."""
    source = (HERE / name).read_text()
    for key in ("isMDRConfigured", "isEPPConfigured"):
        assert 'get("%s")' % key not in source
        assert "get('%s')" % key not in source
