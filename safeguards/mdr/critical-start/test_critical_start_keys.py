"""Critical Start MDR (ZTAP): hasActiveIncidentTicketing, hasMultiSourceTelemetryIntegration and
meanTimeToVerificationAckMinutesCount from getIncidents; hasMobileIncidentEscalationCapability from getGroups.
SYNTHETIC fixtures only, in the ZTAP /api/1.5/ shapes read live on 2026-11-05 ({"objects": [...], "total": N, "page": 1,
"size": 100}). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "cskeys"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(name, body, mode):
    out = load(name, mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(name), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


NO_EVIDENCE = [None, {}, [], "", "not json", {"objects": None}, {"errNo": 401, "errMsg": "Unauthorized", "errors": []},
               {"error": True, "statusCode": 403, "message": "Forbidden"},
               {"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"}]


def incident(source="Proofpoint", group="Low Priority", monitored="not_monitored", created="2026-11-05T21:11:20Z",
             assigned="2026-11-05T21:15:47Z", autorouted=False, default=False, subs=3):
    return {"id": 1, "status": "assigned", "status_display": "Open", "alert_source": source.lower().replace(" ", "_"),
            "alert_source_display": source, "is_autorouted": autorouted,
            "assigned_group": ({"id": 1, "name": group, "is_default": default, "subscriptions": [{"id": i} for i in range(subs)]} if group else None),
            "monitored_by": monitored, "datetime_created": created, "datetime_org_assigned": assigned,
            "organization": {"id": 1, "name": "Org"}, "priority": {"name": "0 - INFO"}}


def incidents(rows, total=None, truncated=False):
    body = {"objects": rows, "total": len(rows) if total is None else total, "page": 1, "size": 100, "view": None, "scroll": None}
    if truncated:
        body["paginationTruncated"] = True
    return body


def group(methods=("email",), name="Default"):
    return {"id": 1, "name": name, "delivery_methods": list(methods), "is_default": True, "subscriptions": []}


def groups(rows, total=None, truncated=False):
    body = {"objects": rows, "total": len(rows) if total is None else total, "page": 1, "limit": 100}
    if truncated:
        body["paginationTruncated"] = True
    return body


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", ["hasActiveIncidentTicketing", "hasMultiSourceTelemetryIntegration",
                                  "meanTimeToVerificationAckMinutesCount", "hasMobileIncidentEscalationCapability"])
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_measured(name, body, mode):
    for wrapped in (body, ts(body)):
        value, status, _ = run(name, wrapped, mode)
        assert value is None and status == "error"


@pytest.mark.parametrize("mode", MODES)
def test_ticketing_true_false_none(mode):
    name = "hasActiveIncidentTicketing"
    assert run(name, ts(incidents([incident(), incident(group=None)])), mode)[0] is True
    assert run(name, ts(incidents([incident(group="Default", default=True, subs=2)])), mode)[0] is True     # default group, subscribed
    assert run(name, ts(incidents([incident(group=None), incident(group="")])), mode)[0] is False
    assert run(name, ts(incidents([incident(group="Default", default=True, subs=0)] * 3)), mode)[0] is False  # auto-routed to an empty default group
    assert run(name, ts({"objects": [incident()], "page": 1}), mode)[0] is None                          # no total: no complete read
    assert run(name, ts(incidents([incident(group=None)], total=50)), mode)[0] is None          # partial read, no proof
    assert run(name, ts(incidents([incident(group=None)], truncated=True)), mode)[0] is None
    assert run(name, ts(incidents([])), mode)[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_ticketing_needs_a_subscriber_in_any_group(mode):
    name = "hasActiveIncidentTicketing"
    empty_named = incident(group="Tier 1", default=False, subs=0)
    assert run(name, ts(incidents([empty_named] * 2)), mode)[0] is False                      # non-default group, nobody subscribed
    no_flag = incident(group="Tier 1", subs=0)
    del no_flag["assigned_group"]["is_default"]
    assert run(name, ts(incidents([no_flag])), mode)[0] is False                              # is_default missing, nobody subscribed
    flag_str = incident(group="Default", subs=0)
    flag_str["assigned_group"]["is_default"] = "true"
    assert run(name, ts(incidents([flag_str])), mode)[0] is False                             # non-boolean is_default, nobody subscribed
    slim = incident(group="Tier 1")
    del slim["assigned_group"]["subscriptions"]
    value, status, _ = run(name, ts(incidents([slim, empty_named])), mode)
    assert value is None and status == "error"                                                # subscriptions not shown: not measured
    assert run(name, ts(incidents([slim, incident()])), mode)[0] is True                      # one subscribed group still proves it


@pytest.mark.parametrize("mode", MODES)
def test_multi_source_true_false_none(mode):
    name = "hasMultiSourceTelemetryIntegration"
    assert run(name, ts(incidents([incident("Proofpoint"), incident("Microsoft Sentinel")])), mode)[0] is True
    assert run(name, ts(incidents([incident("Proofpoint"), incident("Proofpoint")])), mode)[0] is False
    assert run(name, ts(incidents([incident("Proofpoint")], total=9)), mode)[0] is None
    assert run(name, ts(incidents([incident(""), incident("")])), mode)[0] is None
    assert run(name, ts(incidents([])), mode)[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_ack_minutes_measures_only_soc_monitored(mode):
    name = "meanTimeToVerificationAckMinutesCount"
    rows = [incident(monitored="criticalstart", created="2026-11-05T10:00:00Z", assigned="2026-11-05T10:06:00Z"),
            incident(monitored="criticalstart", created="2026-11-05T11:00:00Z", assigned="2026-11-05T11:10:00Z"),
            incident(monitored="not_monitored", created="2026-11-05T12:00:00Z", assigned="2026-11-05T12:00:05Z")]
    value, status, out = run(name, ts(incidents(rows)), mode)
    assert value == 8.0 and status == "success"
    assert out["transformedResponse"]["measuredIncidents"] == 2
    tuning = [incident(monitored="not_monitored"), incident(monitored="customer"),
              incident(monitored="criticalstart", autorouted=True, created="2026-11-05T12:00:00Z", assigned="2026-11-05T12:00:05Z")]
    value, status, _ = run(name, ts(incidents(tuning)), mode)
    assert value is None and status == "error"
    bad_time = [incident(monitored="criticalstart", created="yesterday", assigned="2026-11-05T10:06:00Z")]
    assert run(name, ts(incidents(bad_time)), mode)[0] is None
    assert run(name, ts(incidents([])), mode)[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_mobile_escalation_true_false_none(mode):
    name = "hasMobileIncidentEscalationCapability"
    assert run(name, ts(groups([group(("email",)), group(("email", "sms"), "High")])), mode)[0] is True
    assert run(name, ts(groups([group(("email",)), group(("email",), "High")])), mode)[0] is False
    assert run(name, ts(groups([group(("email", "slack_app", "callback", "pagerduty"))])), mode)[0] is False  # not mobile
    assert run(name, ts(groups([group(("email", "mobile_push"))])), mode)[0] is True
    assert run(name, ts(groups([group(())])), mode)[0] is False
    assert run(name, ts(groups([group(("email",))], total=5)), mode)[0] is None
    assert run(name, ts(groups([group(("email",))], truncated=True)), mode)[0] is None
    assert run(name, ts(groups([])), mode)[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_self_answer_is_ignored(mode):
    for name in ("hasActiveIncidentTicketing", "hasMultiSourceTelemetryIntegration", "hasMobileIncidentEscalationCapability"):
        value, status, _ = run(name, ts({name: True, "objects": []}), mode)
        assert value is None and status == "error"
