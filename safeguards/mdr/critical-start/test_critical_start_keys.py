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


def group(methods=("email",), name="Default", subs=3):
    return {"id": 1, "name": name, "delivery_methods": list(methods), "is_default": True, "subscriptions": [{"id": i} for i in range(subs)]}


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
    ids = incident(group="Tier 1")
    ids["assigned_group"]["subscriptions"] = [101, "102"]
    assert run(name, ts(incidents([ids])), mode)[0] is True                                   # bare subscriber ids still count
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
def test_multi_source_normalises_slug_and_label(mode):
    name = "hasMultiSourceTelemetryIntegration"
    slug_only = incident("Microsoft Sentinel")
    del slug_only["alert_source_display"]                                                     # alert_source microsoft_sentinel
    label_only = incident("Microsoft Sentinel")
    del label_only["alert_source"]
    assert run(name, ts(incidents([slug_only, label_only])), mode)[0] is False                # one product, slug and label
    camel = incident("Microsoft Sentinel")
    camel["alert_source"] = "MicrosoftSentinel"
    assert run(name, ts(incidents([slug_only, camel])), mode)[0] is False
    nested = incident("Microsoft Sentinel")
    nested["alert_source"] = {"name": "Microsoft Sentinel"}
    assert run(name, ts(incidents([slug_only, nested])), mode)[0] is False
    both = incident("Microsoft Sentinel")
    both["alert_source"] = "ms_sent"                                                           # live spelling: slug unlike the label
    label_only["alert_source_display"] = "Microsoft Sentinel"
    value, _, out = run(name, ts(incidents([both, label_only])), mode)
    assert value is False and out["additionalInfo"]["transformation"]["inputSummary"]["telemetrySourceKeys"] == ["mssent"]
    value, _, out = run(name, ts(incidents([slug_only, incident("Proofpoint")])), mode)
    assert value is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["telemetrySourceKeys"] == ["microsoftsentinel", "proofpoint"]
    assert out["additionalInfo"]["transformation"]["inputSummary"]["telemetrySources"] == ["microsoft_sentinel", "Proofpoint"]


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
def test_ack_minutes_counts_pending_and_skipped(mode):
    name = "meanTimeToVerificationAckMinutesCount"
    fast = incident(monitored="criticalstart", created="2026-11-05T10:00:00Z", assigned="2026-11-05T10:05:00Z")
    pending = incident(monitored="criticalstart", created="2026-11-05T11:00:00Z", assigned=None)
    backwards = incident(monitored="criticalstart", created="2026-11-05T12:00:00Z", assigned="2026-11-05T11:00:00Z")
    value, status, _ = run(name, ts(incidents([fast, fast, pending, pending, pending])), mode)
    assert value is None and status == "error"                                    # 2 measured of 5 monitored: not measured
    value, status, _ = run(name, ts(incidents([fast, pending, backwards])), mode)
    assert value is None and status == "error"                                    # skipped intervals count against the sample too
    value, status, out = run(name, ts(incidents([fast, fast, pending])), mode)
    assert value == 5.0 and status == "success"
    assert out["transformedResponse"]["pendingIncidents"] == 1 and out["transformedResponse"]["skippedIncidents"] == 0


@pytest.mark.parametrize("mode", MODES)
def test_ack_minutes_reads_utc_offsets(mode):
    name = "meanTimeToVerificationAckMinutesCount"
    five = [incident(monitored="criticalstart", created="2026-11-05T10:00:00Z", assigned="2026-11-05T15:05:00+05:00"),      # 5 min on the UTC line
            incident(monitored="criticalstart", created="2026-11-05T02:00:00-08:00", assigned="2026-11-05T10:05:00.250Z"),  # fraction, negative offset
            incident(monitored="criticalstart", created="2026-11-05T10:00:00+0000", assigned="2026-11-05T10:05:00-00:00"),  # compact and signed zero
            incident(monitored="criticalstart", created="2026-11-05T10:00:00+00", assigned="2026-11-05T10:05:00z")]
    value, status, _ = run(name, ts(incidents(five)), mode)
    assert value == 5.0 and status == "success"
    naive = incident(monitored="criticalstart", created="2026-11-05T10:00:00", assigned="2026-11-05T10:05:00Z")             # no offset: skipped
    value, status, _ = run(name, ts(incidents([naive])), mode)
    assert value is None and status == "error"
    fast = incident(monitored="criticalstart", created="2026-11-05T10:00:00Z", assigned="2026-11-05T10:05:00Z")
    bad_zone = incident(monitored="criticalstart", created="2026-11-05T10:00:00+25:00", assigned="2026-11-05T10:05:00Z")
    value, _, out = run(name, ts(incidents([fast, fast, naive, bad_zone, naive])), mode)
    assert value is None and out["additionalInfo"]["dataCollection"]["status"] == "error"     # 2 measured, 3 skipped: not measured
    value, _, out = run(name, ts(incidents([fast, fast, fast, bad_zone])), mode)
    assert value == 5.0 and out["transformedResponse"]["skippedIncidents"] == 1
    value, _, out = run(name, ts(incidents([fast, fast], total=50)), mode)
    assert value == 5.0 and out["transformedResponse"]["completeRead"] is False
    assert "partial read" in out["additionalInfo"]["evaluation"]["passReasons"][0]


@pytest.mark.parametrize("mode", MODES)
def test_ack_minutes_partial_read_gate_is_stricter(mode):
    name = "meanTimeToVerificationAckMinutesCount"
    fast = incident(monitored="criticalstart", created="2026-11-05T10:00:00Z", assigned="2026-11-05T10:05:00Z")
    pending = incident(monitored="criticalstart", created="2026-11-05T11:00:00Z", assigned=None)
    assert run(name, ts(incidents([fast, pending])), mode)[0] == 5.0                              # complete: 1 measured vs 1 pending measures
    value, status, out = run(name, ts(incidents([fast, pending], total=400)), mode)
    assert value is None and status == "error" and "partial read" in out["additionalInfo"]["dataCollection"]["errors"][0]
    value, _, out = run(name, ts(incidents([fast, fast, pending], total=400)), mode)
    assert value == 5.0 and out["transformedResponse"]["completeRead"] is False
    flagged = incident(monitored="criticalstart", autorouted="true", created="2026-11-05T10:00:00Z", assigned="2026-11-05T10:00:05Z")
    assert run(name, ts(incidents([flagged])), mode)[0] is None                                   # "true" string is auto-routed too


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
def test_mobile_tokens_are_specific(mode):
    name = "hasMobileIncidentEscalationCapability"
    for method in ("email_text", "plain_text", "rich_text_email", "mobile_email", "mobile_app_email", "api_call", "webhook_call",
                   "text", "call", "mobile", "voicemail", "push_email", "sms_and_email"):
        assert run(name, ts(groups([group(("email", method))])), mode)[0] is False, method
    for method in ("sms", "mms", "phone", "voice", "push", "mobile_push", "phone call", "text_message", "phone_call", "SMS", "Text Message"):
        assert run(name, ts(groups([group(("email", method))])), mode)[0] is True, method


@pytest.mark.parametrize("mode", MODES)
def test_mobile_needs_a_subscriber(mode):
    name = "hasMobileIncidentEscalationCapability"
    assert run(name, ts(groups([group(("email", "sms"), subs=0)])), mode)[0] is False                        # mobile method, nobody paged
    value, _, out = run(name, ts(groups([group(("email", "sms"), subs=0), group(("email",), "B")])), mode)
    assert value is False and out["additionalInfo"]["transformation"]["inputSummary"]["unsubscribedMobileGroups"] == 1
    assert "no subscribers" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    slim = group(("sms",))
    del slim["subscriptions"]
    value, status, _ = run(name, ts(groups([slim])), mode)
    assert value is None and status == "error"                                                                  # subscriptions not shown
    assert run(name, ts(groups([slim, group(("sms",), "B")])), mode)[0] is True                                 # another group proves it
    assert run(name, ts(groups([slim, group(("email",), "B")], total=5)), mode)[0] is None
    assert run(name, ts(groups([group(("email",), subs=0)])), mode)[0] is False                                 # email-only stays False
    ids = group(("sms",))
    ids["subscriptions"] = [7, "8"]
    assert run(name, ts(groups([ids])), mode)[0] is True                                                        # bare subscriber ids still count


@pytest.mark.parametrize("mode", MODES)
def test_self_answer_is_ignored(mode):
    for name in ("hasActiveIncidentTicketing", "hasMultiSourceTelemetryIntegration", "hasMobileIncidentEscalationCapability"):
        value, status, _ = run(name, ts({name: True, "objects": []}), mode)
        assert value is None and status == "error"
