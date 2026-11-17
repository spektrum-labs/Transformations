"""Check Point HEC queryOffice365Events read across pages by Integration-Service.

Integration-Service follows responseEnvelope.scrollId and hands the transform ONE merged body: every
page's responseData, page 1's envelope with scrollId cleared to null. When it cuts the read off (page
cap, or the scroll ending short of recordsNumber) it sets responseEnvelope.truncated (and
paginationTruncated). A cut-off read cannot prove an absence or an "every" claim, so those read None;
a match already seen still counts. A truncated marker that is false, missing or null changes nothing.

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


def test_move_audit_trail_on_paged_reads():
    name = "messagemoveaudittrailenabled"
    assert verdict(name, merged())[0] is True  # every move action on every page carries its fields
    assert verdict(name, merged(truncated=True))[0] is None  # "every" is unproven on a cut-off read
    assert verdict(name, merged(strip_create_time))[0] is False
    assert verdict(name, merged(strip_create_time, truncated=True))[0] is False  # a seen gap stays False
    assert verdict(name, merged(records=[]))[0] is False


def test_move_audit_trail_cut_off_reason_is_specific_and_carries_no_record_text():
    value, out = verdict("messagemoveaudittrailenabled", merged(truncated=True))
    reasons = out["additionalInfo"]["evaluation"]["failReasons"]
    assert value is None and reasons
    assert "partial page" in reasons[0]
    assert "@" not in json.dumps(reasons)


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


def test_move_audit_trail_capped_total_reads_none_and_a_smaller_total_is_exact():
    name = "messagemoveaudittrailenabled"
    body = merged(records=[copy.deepcopy(EVENTS["responseData"][i % len(EVENTS["responseData"])]) for i in range(10000)])
    body["responseEnvelope"]["recordsNumber"] = 10000
    assert verdict(name, body)[0] is None
    body["responseEnvelope"]["recordsNumber"] = 9999
    body["responseData"] = body["responseData"][:9999]
    assert verdict(name, body)[0] is True


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


def test_move_audit_trail_over_cap_rows_read_none():
    body = merged(records=[copy.deepcopy(EVENTS["responseData"][i % len(EVENTS["responseData"])]) for i in range(10100)])
    body["responseEnvelope"]["recordsNumber"] = 10000
    assert verdict("messagemoveaudittrailenabled", body)[0] is None
