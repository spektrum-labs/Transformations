"""Keepit isDeletionRetentionPeriodEnforced: the delete-retention-period resource, on bodies shaped
as Integration-Service hands them over (Keepit XML parsed by xmltodict: one element is a dict,
several a list, empty is None, every value is a string).

The shape copies a real Keepit response from a tenant whose four Google Workspace connectors state
no backup-retention and whose generic-snapshot-retention resource has no limit, but whose
resources list carries `{"name": "delete-retention-period", "type": "period", "limit": "P1M"}`.
Names and GUIDs are synthetic. Keepit documents delete-retention-period as the "period during which
deleted device/user can be recovered".

The rule under test (minimum one month, 30 days, as before):
  * a period below the minimum, anywhere it is stated (the delete-retention-period resource or any
    connector's effective snapshot retention), answers False: the shortest window is the one that
    counts, and a long period elsewhere does not offset it;
  * a stated value that is not an ISO 8601 duration answers None, never False;
  * otherwise, when delete-retention-period is stated and meets the minimum, the answer is True,
    even for a connector that states no snapshot retention of its own;
  * without delete-retention-period the check answers as it always has: True only when every
    connector states a snapshot retention that meets the minimum, None when one is not stated;
  * an account with no cloud connectors is a measured False, as before;
  * an error, empty, refused or partial body answers None and says so, never False.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "isDeletionRetentionPeriodEnforced"


def load():
    spec = importlib.util.spec_from_file_location("keepit_deletion_retention_period",
                                                  HERE / "isdeletionretentionperiodenforced.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


transform = load()


def answer(body):
    out = transform(body)
    return out.get("transformedResponse", out)[KEY]


def connector(i, kind="gsuite", own=None):
    c = {"guid": "aaaaa%d-bbbbbb-cccccc" % i, "created": "2026-01-0%dT10:00:00Z" % (i + 1),
         "name": "Workspace Backup %d" % i, "type": kind, "uri": "None", "login": "None",
         "password": "<redacted>", "backup-retention-updated": "2026-01-19T13:32:50Z"}
    if own is not None:
        c["backup-retention"] = own
    return c


def devices(n=4, own=None):
    return {"cloud": [connector(i, own=own) for i in range(n)],
            "system": {"guid": "sys000-000000-000000", "created": "2026-09-21T10:44:55Z", "name": "SupportData"}}


def resource(name, limit=None, kind="period"):
    r = {"evaluated": "2026-10-04T07:51:22Z", "name": name, "type": kind}
    if limit is not None:
        r["limit"] = limit
    return r


def account(delete=None, generic=None, gsuite=None, own=None, n=4, extra=()):
    """A merged getRetentionConfig body: the /devices call and the /resources call."""
    items = [dict(resource("gsuite-users", kind="integer"), usage="3240", violated="false"),
             resource("deleteditems", "true", "boolean"),
             resource("generic-snapshot-retention", generic)]
    if gsuite is not None:
        items.append(resource("gsuite-snapshot-retention", gsuite))
    if delete is not None:
        items.append(resource("delete-retention-period", delete))
    items.extend(extra)
    return {"devices": devices(n, own=own), "resources": {"resource": items}}


# the shape seen on a real tenant: no snapshot retention anywhere, delete-retention-period P1M
REAL_SHAPE = account(delete="P1M")


def collection(body):
    return transform(body)["additionalInfo"]["dataCollection"]


# ---- the real shape ----------------------------------------------------------------------

def test_real_shape_answers_true_from_the_delete_retention_period():
    out = transform(REAL_SHAPE)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["dataCollection"] == {"status": "success", "errors": []}
    evidence = out["transformedResponse"]["deleteRetentionPeriod"]
    assert evidence["retention"] == "P1M"
    assert evidence["days"] == 30.0
    assert out["transformedResponse"]["minimumDays"] == 30


def test_real_shape_without_the_period_is_not_measured():
    body = account(delete=None)
    assert answer(body) is None
    assert collection(body)["status"] == "error"


def test_real_shape_with_a_short_period_is_false():
    body = account(delete="P7D")
    assert answer(body) is False
    assert collection(body) == {"status": "success", "errors": []}


# ---- the period is read as an ISO 8601 duration -----------------------------------------

@pytest.mark.parametrize("period", ["P1M", "P30D", "P1Y", "P6M", "P2M", "P5W", "PT720H", "P1Y6M", "p1m",
                                    " P1M ", "P0.5Y", "P99Y"])
def test_a_period_at_or_above_one_month_answers_true(period):
    assert answer(account(delete=period)) is True, period


@pytest.mark.parametrize("period", ["P2W", "P4W", "P7D", "P29D", "PT24H", "PT719H", "PT1M", "P1D"])
def test_a_period_below_one_month_answers_false(period):
    body = account(delete=period)
    assert answer(body) is False, period
    assert collection(body)["status"] == "success", period


def test_the_boundary_is_exactly_thirty_days():
    assert answer(account(delete="P30D")) is True
    assert answer(account(delete="P29D")) is False
    assert answer(account(delete="PT720H")) is True
    assert answer(account(delete="PT719H")) is False
    assert answer(account(delete="P1M")) is True


@pytest.mark.parametrize("odd", ["unlimited", "forever", "365", "30", "2592000", "30 days", "1 month", "P0D",
                                 "PT0S", "P", "PT", "P1X", "P1MT", "-P1M", "P1M ago", "true"])
def test_a_period_that_is_not_an_iso_duration_is_not_measured(odd):
    # A bare number has no documented unit (seconds? days?), and a zero duration has no documented
    # meaning: neither may pass or fail a customer.
    body = account(delete=odd)
    assert answer(body) is None, odd
    info = collection(body)
    assert info["status"] == "error", odd
    assert info["errors"] and all(isinstance(e, str) and e for e in info["errors"]), odd
    assert "retention" in info["errors"][0].lower(), odd


def test_a_resource_with_no_limit_states_nothing():
    # generic-snapshot-retention in the real body has a type and no limit
    body = account(delete=None, extra=[resource("delete-retention-period")])
    assert answer(body) is None
    assert transform(body)["transformedResponse"]["deleteRetentionPeriod"] is None


def test_a_single_resource_element_is_a_dict_not_a_list():
    body = {"devices": devices(), "resources": {"resource": resource("delete-retention-period", "P1M")}}
    assert answer(body) is True
    body = {"devices": devices(), "resources": {"resource": resource("delete-retention-period", "P2W")}}
    assert answer(body) is False


def test_only_the_named_resource_is_read():
    body = account(delete=None, extra=[resource("deleteditems", "P1Y", "period"),
                                       resource("delete-retention", "P1Y"),
                                       resource("undelete-retention-period", "P1Y")])
    assert answer(body) is None


def test_a_wrapped_body_is_unwrapped():
    assert answer({"apiResponse": REAL_SHAPE}) is True
    assert answer({"_response_data": {"response": account(delete="P1W")}}) is False


# ---- snapshot retention without the period: exactly as before ----------------------------

def test_snapshot_retention_alone_behaves_as_before():
    assert answer(account(generic="P1Y")) is True
    assert answer(account(generic="P30D")) is True
    assert answer(account(generic="P14D")) is False
    # the connector-type resource beats the generic one, the connector's own value beats both
    assert answer(account(generic="P1Y", gsuite="P7D")) is False
    assert answer(account(generic="P7D", gsuite="P3M")) is True
    assert answer(account(generic="P1Y", own="P1W")) is False
    assert answer(account(generic="P7D", own="P1Y")) is True


def test_snapshot_retention_not_stated_on_every_connector_is_not_measured():
    body = account()
    assert answer(body) is None
    assert collection(body)["status"] == "error"
    mixed = account(own=None)
    mixed["devices"]["cloud"][0]["backup-retention"] = "P1Y"
    assert answer(mixed) is None


def test_a_short_snapshot_retention_beats_an_unstated_one():
    mixed = account(own=None)
    mixed["devices"]["cloud"][0]["backup-retention"] = "P7D"
    assert answer(mixed) is False


@pytest.mark.parametrize("odd", ["unlimited", "P0D", "365", "", "P", "PT"])
def test_unreadable_snapshot_retention_is_not_measured(odd):
    assert answer(account(generic=odd)) is None, odd


# ---- both stated: the shortest window decides --------------------------------------------

def test_both_meet_the_minimum_is_true():
    assert answer(account(delete="P1M", generic="P1Y")) is True
    assert answer(account(delete="P1Y", own="P30D")) is True


def test_a_short_snapshot_retention_fails_even_when_the_period_is_long():
    body = account(delete="P1Y", generic="P14D")
    assert answer(body) is False
    assert "snapshot" in transform(body)["transformedResponse"]["reason"].lower()
    assert answer(account(delete="P1Y", own="P1W")) is False
    assert answer(account(delete="P1Y", generic="P1Y", gsuite="P7D")) is False


def test_a_short_period_fails_even_when_the_snapshot_retention_is_long():
    body = account(delete="P7D", generic="P1Y")
    assert answer(body) is False
    assert "delete-retention-period" in transform(body)["transformedResponse"]["reason"]


def test_both_short_is_false():
    assert answer(account(delete="P7D", generic="P14D")) is False


def test_the_period_meeting_the_minimum_covers_a_connector_that_states_no_snapshot_retention():
    body = account(delete="P1M", own=None)
    body["devices"]["cloud"][0]["backup-retention"] = "P1Y"
    assert answer(body) is True


def test_an_unreadable_snapshot_retention_blocks_a_true_even_when_the_period_meets_it():
    # a stated value we cannot read may be shorter than the period
    assert answer(account(delete="P1M", generic="unlimited")) is None
    body = account(delete="P1M", own=None)
    body["devices"]["cloud"][1]["backup-retention"] = "365"
    assert answer(body) is None


def test_an_unreadable_period_blocks_a_true_that_snapshot_retention_alone_would_give():
    body = account(delete="unlimited", generic="P1Y")
    assert answer(body) is None
    assert collection(body)["status"] == "error"


def test_a_measured_short_value_still_wins_over_an_unreadable_one():
    assert answer(account(delete="unlimited", generic="P7D")) is False
    assert answer(account(delete="P7D", generic="unlimited")) is False


def test_the_period_is_account_wide_so_every_connector_kind_is_covered():
    body = account(delete="P1M")
    body["devices"]["cloud"].append(connector(9, kind="o365-admin"))
    body["devices"]["cloud"].append(connector(8, kind="sforce"))
    assert answer(body) is True


# ---- no cloud connectors: a measured "nothing is protected" ------------------------------

def test_no_cloud_connectors_is_false_whatever_the_period():
    for delete in [None, "P1M", "P1Y", "P7D"]:
        resources = {"resource": [resource("delete-retention-period", delete)]} if delete else None
        body = {"devices": None, "resources": resources}
        assert answer(body) is False, delete
        assert collection(body)["status"] == "success", delete


# ---- error, empty, refused and partial bodies: None, never False -------------------------

REFUSED_403 = {"error": True, "statusCode": 403, "message": "Forbidden"}
NO_EVIDENCE = [
    ("empty dict", {}),
    ("null", None),
    ("empty json", "{}"),
    ("empty string", ""),
    ("empty list", []),
    ("401 envelope", {"error": True, "statusCode": 401, "message": "Unauthorized"}),
    ("403 envelope", REFUSED_403),
    ("403 envelope wrapped", {"apiResponse": REFUSED_403}),
    ("not available", {"status": "Not Available"}),
    ("raw xml", "<resources><resource/></resources>"),
    ("devices only: the resources call did not run", {"devices": devices()}),
    ("resources only: the devices call did not run", {"resources": {"resource": [
        resource("delete-retention-period", "P1M")]}}),
    ("resources only, short period", {"resources": {"resource": [resource("delete-retention-period", "P1D")]}}),
    ("devices refused inside the merge", {"devices": REFUSED_403, "resources": REAL_SHAPE["resources"]}),
    ("resources refused inside the merge", {"devices": devices(own="P1Y"), "resources": REFUSED_403}),
    ("a connector entry that is not an object", {"devices": {"cloud": [connector(0), "None"]},
                                                 "resources": REAL_SHAPE["resources"]}),
    ("a connector list with a hole", {"devices": {"cloud": [connector(0), None, connector(2)]},
                                      "resources": REAL_SHAPE["resources"]}),
    ("error flag on the merged object", dict(copy.deepcopy(REAL_SHAPE), error=True)),
]


@pytest.mark.parametrize("label,body", NO_EVIDENCE, ids=[n for n, _ in NO_EVIDENCE])
def test_a_body_that_proves_nothing_is_not_evaluated_never_false(label, body):
    out = transform(body)
    assert out["transformedResponse"][KEY] is None, label
    info = out["additionalInfo"]["dataCollection"]
    assert info["status"] == "error", label
    assert info["errors"] and all(isinstance(e, str) and e for e in info["errors"]), label


def test_a_poisoned_body_is_not_evaluated():
    class Poisoned(dict):
        def __init__(self):
            super().__init__(poisoned=True)

        def boom(self, *args, **kwargs):
            raise RuntimeError("poisoned read")

        get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

        def __len__(self):
            return 1

    out = transform(Poisoned())
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_false_stays_reachable_on_complete_data():
    # the check discriminates: complete data with too short a period answers False
    assert answer(account(delete="P1D")) is False
    assert answer(account(delete="P1M")) is True
    assert answer(account(delete="P1D", generic="P1Y")) is False
    assert answer(account(delete="P1M", generic="P1D")) is False


# ---- the answer in the platform envelope -------------------------------------------------

def test_true_and_false_report_success_and_none_reports_an_error():
    true_out = transform(account(delete="P1M"))
    assert true_out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert true_out["additionalInfo"]["evaluation"]["passReasons"]
    assert true_out["additionalInfo"]["evaluation"]["failReasons"] == []
    false_out = transform(account(delete="P1W"))
    assert false_out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert false_out["additionalInfo"]["evaluation"]["failReasons"]
    none_out = transform(account(delete="forever"))
    assert none_out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert none_out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert none_out["additionalInfo"]["metadata"]["transformationId"] == KEY


def test_the_evidence_shows_what_was_compared():
    out = transform(account(delete="P1M", generic="P1Y"))["transformedResponse"]
    assert out["deleteRetentionPeriod"] == {"retention": "P1M", "days": 30.0}
    assert len(out["connectors"]) == 4
    assert all(row["retention"] == "P1Y" and row["days"] == 365.0 for row in out["connectors"])
    assert out["minimumDays"] == 30
