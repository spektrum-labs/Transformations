"""Check Point Harmony Email & Collaboration: isAttachmentSandboxDetonationEnabled.

The check read queryEvents (security events) and passed on any event that mentioned "sandbox",
"emulat", "threatcloud" or "detonat" in a free-text field. A keyword in a description is not a
measurement of a setting, so the check could pass for a tenant whose attachment sandboxing (Threat
Emulation) is off, and it read False for a tenant that simply had no events yet.

The public Check Point Email Security API (API Reference Guide, "Get the Details of a Specific
Entity" and "Search for Secured Entities") exposes the scan results of five engines only:
entitySecurityResults and combinedVerdict carry ap, dlp, clicktimeProtection, shadowIt and av. There
is no threat-emulation or sandbox result, no policy or security-engine endpoint and no licence
endpoint. The Anti-Malware engine bundles Anti-Virus with Threat Emulation, and which of the two a
tenant is licensed for is visible only in the admin console. So neither the event list nor the
entity results can show whether attachments are sandboxed.

The rule these tests pin: this check never says True and never says False from this data. It
says None (Not evaluated): the criterion is None and dataCollection.status is "error", which the
evaluator shows as Not evaluated. Each tool measures for that tool, so no Check Point row appears
until the API exposes a real field.

All payloads are synthetic. The event shape follows the Check Point security-event record
(eventId, customerId, saas, entityId, state, type, confidenceIndicator, eventCreated, severity,
description, data, additionalData).
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "isAttachmentSandboxDetonationEnabled"


def load():
    spec = importlib.util.spec_from_file_location("cp_sandbox_detonation", HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(body):
    return load().transform(body)


def event(index=0, **overrides):
    record = {
        "eventId": "evt%03d" % index,
        "customerId": "example",
        "saas": "office365_emails",
        "entityId": "ent%03d" % index,
        "state": "remediated",
        "type": "malware",
        "confidenceIndicator": "malicious",
        "eventCreated": "2026-10-01T10:00:00.000000+00:00",
        "severity": "3",
        "description": "Malware found in an attachment",
        "data": "",
        "additionalData": None,
        "availableEventActions": None,
        "actions": [{"actionType": "quarantine_email", "createTime": "2026-10-01T10:00:05Z",
                     "relatedEntityId": "evt%03d" % index}],
    }
    record.update(overrides)
    return record


def body(events):
    return {"responseEnvelope": {"requestId": "r", "responseCode": "200", "responseText": ""},
            "responseData": events}


def value(out):
    return out["transformedResponse"][KEY]


def assert_not_evaluated(out):
    """None, a data-collection error (so the evaluator shows Not evaluated), no pass reason."""
    assert KEY in out["transformedResponse"]
    assert out["transformedResponse"][KEY] is None
    info = out["additionalInfo"]
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"]
    assert info["evaluation"]["passReasons"] == []


# --- a keyword is not a measurement -----------------------------------------------------------

KEYWORD_EVENTS = [
    ("sandbox in the description of a malware event",
     event(description="Attachment detonated in the Check Point sandbox")),
    ("threat emulation in the description of a malware event",
     event(description="Threat Emulation found a malicious file")),
    ("ThreatCloud in additionalData",
     event(additionalData={"engine": "ThreatCloud", "verdict": "malicious"})),
    ("emulat in data of a suspicious malware event",
     event(type="suspicious_malware", data="File emulation result: suspicious")),
    ("zero-day in the description of a phishing event",
     event(type="phishing", description="Zero-day link seen in the message")),
    ("detonat in the description of a dlp event",
     event(type="dlp", description="Detonation of a macro was logged")),
    ("an event type named threat_emulation",
     event(type="threat_emulation", description="scan finished")),
]


@pytest.mark.parametrize("label,ev", KEYWORD_EVENTS, ids=[k[0] for k in KEYWORD_EVENTS])
def test_a_keyword_hit_alone_is_never_true(label, ev):
    out = run(body([ev]))
    assert value(out) is not True
    assert_not_evaluated(out)


def test_many_keyword_events_are_still_not_a_pass():
    events = [event(i, description="sandbox detonation verdict") for i in range(25)]
    out = run(body(events))
    assert value(out) is not True
    assert_not_evaluated(out)


def test_the_keyword_count_is_no_longer_reported_as_a_detonation_count():
    out = run(body([event(description="sandbox")]))
    assert "detonationEventCount" not in out["transformedResponse"]


# --- no events, or events without a keyword, prove nothing either way --------------------------

def test_a_successful_read_with_no_events_is_none_never_true_never_false():
    out = run(body([]))
    assert value(out) is not True
    assert value(out) is not False
    assert_not_evaluated(out)


@pytest.mark.parametrize("events", [
    [event(0), event(1, type="graymail", description="Bulk mail"), event(2, type="spam")],
    [event(0, type="anomaly", description="Unusual sign-in")],
], ids=["malware and spam without a keyword", "anomaly only"])
def test_events_without_a_keyword_are_none_never_false(events):
    out = run(body(events))
    assert value(out) is not False
    assert_not_evaluated(out)


def test_the_facts_really_read_are_still_reported():
    events = [event(i) for i in range(4)]
    out = run(body(events))
    assert out["transformedResponse"]["totalEventsQueried"] == 4
    assert out["additionalInfo"]["transformation"]["inputSummary"]["totalEvents"] == 4


# --- unreadable bodies and the except path are Not evaluated -----------------------------------

UNREADABLE = [
    ("empty dict", {}),
    ("null", None),
    ("empty json string", "{}"),
    ("not json", "not json at all"),
    ("auth error", {"error": {"type": "authentication_error", "message": "invalid credentials"}}),
    ("401", {"statusCode": 401, "error": "Unauthorized"}),
    ("403", {"statusCode": 403, "error": "Forbidden"}),
    ("authentication errorType", {"errorType": "authentication", "errorMessage": "token rejected"}),
    ("error envelope", {"responseEnvelope": {"responseCode": "401", "responseText": "Unauthorized"},
                        "responseData": []}),
    ("unrelated json", {"hello": "world"}),
    ("responseData is not a list", {"responseData": {"unexpected": "shape"}}),
    ("list of non-dicts", {"responseData": ["sandbox", 3, None]}),
]


@pytest.mark.parametrize("label,payload", UNREADABLE, ids=[u[0] for u in UNREADABLE])
def test_unreadable_bodies_are_not_evaluated(label, payload):
    out = run(payload)
    assert value(out) is not True
    assert value(out) is not False
    assert_not_evaluated(out)


class Poisoned(dict):
    """A body whose every read raises, which drives transform() down its except path."""

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


def test_the_except_path_is_not_evaluated_with_a_data_collection_error():
    out = run(Poisoned())
    assert value(out) is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]


# --- the enriched and wrapped input forms behave the same --------------------------------------

def test_the_enriched_and_wrapped_forms_are_not_evaluated_too():
    keyword = body([event(description="sandbox detonation")])
    forms = [
        {"data": keyword, "validation": {"status": "passed", "errors": [], "warnings": []}},
        {"data": keyword, "validation": {"status": "skipped", "errors": [], "warnings": []}},
        {"apiResponse": copy.deepcopy(keyword)},
        {"response": {"result": copy.deepcopy(keyword)}},
    ]
    for form in forms:
        out = run(form)
        assert value(out) is not True
        assert_not_evaluated(out)


# --- the reason is fixed text and never copies vendor text -------------------------------------

def test_the_reason_is_fixed_text_that_never_copies_the_vendor_error():
    marker = "VENDOR-SECRET-TEXT-12345"
    out = run({"statusCode": 401, "error": "Unauthorized", "errorMessage": marker, "message": marker})
    text = json.dumps(out)
    assert marker not in text
    assert out["additionalInfo"]["dataCollection"]["errors"]


def test_the_reason_says_what_the_api_does_not_expose_and_asks_for_no_fix():
    out = run(body([event(description="sandbox")]))
    reasons = " ".join(out["additionalInfo"]["dataCollection"]["errors"]
                       + out["additionalInfo"]["evaluation"]["failReasons"]).lower()
    assert "threat emulation" in reasons
    assert "not" in reasons and "expose" in reasons
    assert out["additionalInfo"]["evaluation"]["recommendations"] == []


def test_the_result_never_carries_a_true_or_false_criterion_for_any_event_mix():
    mixes = [
        [],
        [event(0)],
        [event(0, description="sandbox")],
        [event(0, type="threat_emulation")],
        [event(i, description="sandbox threatcloud emulation detonation") for i in range(10)],
    ]
    for events in mixes:
        out = run(body(events))
        assert out["transformedResponse"][KEY] is None
