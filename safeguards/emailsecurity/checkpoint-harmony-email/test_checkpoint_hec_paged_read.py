"""Check Point HEC queryOffice365Events read across pages by Integration-Service.

Integration-Service follows responseEnvelope.scrollId and hands the transform ONE merged body: every
page's responseData, page 1's envelope with scrollId cleared to null. When it cuts the read off (page
cap, or the scroll ending short of recordsNumber) it sets responseEnvelope.truncated (and
paginationTruncated). A cut-off read cannot prove an absence, so that reads None; a match already
seen still counts (for messageMoveAuditTrailEnabled, an audited move action, or a move action that lacks
its audit fields). A truncated marker that is false, missing or null changes nothing.

Built from the synthetic event page fixture; nothing here is a real tenant.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
EVENTS = json.loads((HERE / "fixtures" / "office365_events_real_2026-09-25.json").read_text())


def verdict(name, body):
    spec = importlib.util.spec_from_file_location("cphec_paged_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = module.transform(body)
    return list(out["transformedResponse"].values())[0], out


def merged(mutate=None, records=None, **envelope):
    """The body Integration-Service returns after paging: scrollId null, recordsNumber the total read."""
    body = copy.deepcopy(EVENTS)
    if records is not None:
        body["responseData"] = records
    if mutate:
        for r in body["responseData"]:
            mutate(r)
    body["responseEnvelope"]["scrollId"] = None
    body["responseEnvelope"]["recordsNumber"] = len(body["responseData"])
    body["responseEnvelope"].update(envelope)
    return body


def drop_actions(r):
    r["actions"] = []


def ms_only(r):
    r["data"] = r["data"].replace("avanan_ap_scan", "ms_defender_scan")


def no_quarantine(r):
    r["actions"] = [a for a in r["actions"] if "quarantine" not in a["actionType"]]


def strip_create_time(r):
    for a in r["actions"]:
        if "quarantine" in a["actionType"]:
            a["createTime"] = "None"


# (file, flip that removes the match, verdict of the flipped body when the read is complete)
CASES = [
    ("isemailsecurityloggingenabled", drop_actions, False),
    ("ispostdeliveryquarantineenabled", no_quarantine, False),
    ("isimposteremaildetectionenabled", ms_only, False),
    ("islinkedo365accountactive", None, False),
]


@pytest.mark.parametrize("name,flip,flipped", CASES)
def test_presence_checks_on_a_complete_paged_read(name, flip, flipped):
    assert verdict(name, merged())[0] is True
    body = merged(flip) if flip else merged(records=[])
    assert verdict(name, body)[0] is flipped


@pytest.mark.parametrize("name,flip,flipped", CASES)
@pytest.mark.parametrize("marker", [{"truncated": True}, {"truncated": "true"}, {"paginationTruncated": True}, {"truncated": 1}, {"truncated": "yes"}])
def test_a_cut_off_read_keeps_a_match_but_proves_no_absence(name, flip, flipped, marker):
    assert verdict(name, merged(**marker))[0] is True
    body = merged(flip, **marker) if flip else merged(records=[], **marker)
    value, out = verdict(name, body)
    assert value is None
    reasons = out["additionalInfo"]["evaluation"]["failReasons"]
    assert reasons and "partial page" in reasons[0]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name,flip,flipped", CASES)
@pytest.mark.parametrize("marker", [{"truncated": False}, {"truncated": None}, {"truncated": "None"}, {}])
def test_a_false_or_missing_marker_changes_nothing(name, flip, flipped, marker):
    body = merged(flip, **marker) if flip else merged(records=[], **marker)
    assert verdict(name, body)[0] is flipped


def strip_all_move_fields(r):
    for a in r["actions"]:
        if any(w in a["actionType"] for w in ("quarantine", "restore", "delete", "move")):
            a["createTime"] = "None"


def no_move(r):
    r["actions"] = [a for a in r["actions"]
                    if not any(w in a["actionType"] for w in ("quarantine", "restore", "delete", "move"))]


def reasons_and_code(out):
    dc = out["additionalInfo"]["dataCollection"]
    return out["additionalInfo"]["evaluation"]["failReasons"], dc.get("errorCode"), dc["status"]


def test_move_audit_trail_on_paged_reads():
    name = "messagemoveaudittrailenabled"
    assert verdict(name, merged())[0] is True
    assert verdict(name, merged(truncated=True))[0] is True  # an audited move already read proves the trail
    assert verdict(name, merged(strip_create_time))[0] is False  # complete read, every move lacks its fields
    assert verdict(name, merged(strip_all_move_fields))[0] is False  # complete read, only gaps
    assert verdict(name, merged(strip_all_move_fields, truncated=True))[0] is None  # an unread page may hold an audited move
    assert verdict(name, merged(records=[]))[0] is False
    assert verdict(name, merged(no_move))[0] is False  # complete read, no move action: proven absence
    assert verdict(name, merged(no_move, truncated=True))[0] is None  # absence on a cut-off read is unproven


def test_move_audit_trail_cut_off_reason_is_specific_coded_and_carries_no_record_text():
    value, out = verdict("messagemoveaudittrailenabled", merged(no_move, truncated=True))
    reasons, code, status = reasons_and_code(out)
    assert value is None and reasons and status == "error"
    assert "partial page" in reasons[0]
    assert code == "partial_read"
    assert "@" not in json.dumps(reasons)


def capped_rows(n, mutate=None):
    rows = [copy.deepcopy(EVENTS["responseData"][i % len(EVENTS["responseData"])]) for i in range(n)]
    for r in rows:
        if mutate:
            mutate(r)
    return rows


def test_move_audit_trail_capped_total_keeps_a_seen_trail_and_codes_an_unproven_absence():
    name = "messagemoveaudittrailenabled"
    body = merged(records=capped_rows(10000))
    body["responseEnvelope"]["recordsNumber"] = 10000
    assert verdict(name, body)[0] is True
    body = merged(records=capped_rows(10000, no_move))
    body["responseEnvelope"]["recordsNumber"] = 10000
    value, out = verdict(name, body)
    reasons, code, status = reasons_and_code(out)
    assert value is None and status == "error"
    assert code == "vendor_count_capped"
    assert "10000" in reasons[0]
    assert out["additionalInfo"]["transformation"]["inputSummary"]["vendorCountCapped"] is True
    body["responseEnvelope"]["recordsNumber"] = 9999
    body["responseData"] = body["responseData"][:9999]
    assert verdict(name, body)[0] is False  # under the cap a complete read proves the absence


def test_move_audit_trail_over_cap_rows_without_a_move_read_none():
    body = merged(records=capped_rows(10100, no_move))
    body["responseEnvelope"]["recordsNumber"] = 10000
    value, out = verdict("messagemoveaudittrailenabled", body)
    assert value is None
    assert reasons_and_code(out)[1] == "vendor_count_capped"


@pytest.mark.parametrize("name,flip,flipped", CASES)
def test_a_capped_total_is_a_lower_bound_never_a_complete_read(name, flip, flipped):
    """recordsNumber stops at 10000: 10000 rows against 10000 may be the first 10000 of more."""
    rows = [copy.deepcopy(EVENTS["responseData"][i % len(EVENTS["responseData"])]) for i in range(10000)]
    body = merged(records=rows)
    body["responseEnvelope"]["recordsNumber"] = 10000
    assert verdict(name, body)[0] is True  # a match already seen still counts
    if flip:
        for r in rows:
            flip(r)
    else:
        body["responseData"] = []
        body["responseEnvelope"]["recordsNumber"] = 10000
    value, out = verdict(name, body)
    assert value is None
    assert "partial page" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("name,flip,flipped", CASES)
def test_a_capped_total_with_more_rows_than_the_cap_is_still_partial(name, flip, flipped):
    """IS stops the scroll at the cap, so 10100 rows against recordsNumber 10000 is a cut read."""
    rows = [copy.deepcopy(EVENTS["responseData"][i % len(EVENTS["responseData"])]) for i in range(10100)]
    if flip:
        for r in rows:
            flip(r)
    body = merged(records=rows) if flip else merged(records=[])
    body["responseEnvelope"]["recordsNumber"] = 10000
    if not flip:
        body["responseData"] = []
    value, out = verdict(name, body)
    assert value is None
    assert "partial page" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("name,flip,flipped", CASES)
@pytest.mark.parametrize("wrap", [
    lambda b: {"response": b, "truncated": True},
    lambda b: {"apiResponse": b, "response_metadata": {"paginationTruncated": "true"}},
])
def test_a_marker_on_an_outer_wrapper_still_proves_no_absence(name, flip, flipped, wrap):
    body = merged(flip) if flip else merged(records=[])
    value, out = verdict(name, wrap(body))
    assert value is None
    assert "partial page" in out["additionalInfo"]["evaluation"]["failReasons"][0]
