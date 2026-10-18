"""An error or empty read from Check Point Harmony Email & Collaboration is Not evaluated, never False.

Every transform in this folder used to answer False (or a measured 0) when the vendor call was
refused, errored, timed out or returned a body it could not read, so a transient failure showed
up as a failed control. The rule now: a body that proves nothing returns None for the criterion
AND dataCollection.status "error" with a non-empty errors list, which the evaluator shows as Not
evaluated. The reason text is fixed; the vendor's own error text is never copied into the result.

A real, readable answer that proves a negative (a well-formed response that lists no matching
event, an empty block list, a DNS probe that reports no SPF record) keeps its verdict.

All payloads here are synthetic.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}

#: planted in every error body; it must never come back out in the result
SENTINEL = "planted-vendor-text-9c41"

# file -> the one criterion it answers
HEC_FALSE_CHECKS = {
    "confirmedlicensepurchased": "confirmedLicensePurchased",
    "isaccounttakeoverdetectionenabled": "isAccountTakeoverDetectionEnabled",
    "isantiphishingenabled": "isAntiPhishingEnabled",
    "isantivirusverdictengineenabled": "isAntivirusVerdictEngineEnabled",
    "isclicktimeurlrewriteenabled": "isClickTimeURLRewriteEnabled",
    "isclouddataleakpreventionenabled": "isCloudDataLeakPreventionEnabled",
    "isemailsecurityloggingenabled": "isEmailSecurityLoggingEnabled",
    "isimposteremaildetectionenabled": "isImposterEmailDetectionEnabled",
    "islinkedo365accountactive": "isLinkedO365AccountActive",
    "ispostdeliveryquarantineenabled": "isPostDeliveryQuarantineEnabled",
    "isshadowitdiscoveryenabled": "isShadowITDiscoveryEnabled",
    "isurlreputationblocklistenforced": "isURLReputationBlockListEnforced",
    "messagemoveaudittrailenabled": "messageMoveAuditTrailEnabled",
}
HEC_COUNT_CHECKS = {
    "openquarantinedmessagescount": "openQuarantinedMessagesCount",
    "unverifiedallowpolicycount": "unverifiedAllowPolicyCount",
}
HEC_CHECKS = dict(HEC_FALSE_CHECKS, **HEC_COUNT_CHECKS)
DNS_CHECKS = {"isspfenforced": "isSPFEnforced"}
ALL_CHECKS = dict(HEC_CHECKS, **DNS_CHECKS)


def load(name):
    spec = importlib.util.spec_from_file_location("cphec_err_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def refused(code, text=SENTINEL):
    return {"responseEnvelope": {"requestId": "r", "responseCode": code, "responseText": text}, "responseData": []}


def enveloped(body):
    return {"data": body, "validation": VALIDATION}


# Bodies every transform in the folder must read as "nothing measured". Each is a factory so
# no case can leak state into the next.
COMMON_BAD = [
    ("error flag", lambda: {"error": True, "message": SENTINEL}),
    ("error text", lambda: {"error": SENTINEL}),
    ("errors list", lambda: {"errors": [{"code": "forbidden", "message": SENTINEL}]}),
    ("http 403 body", lambda: {"statusCode": 403, "message": "Forbidden " + SENTINEL}),
    ("http 401 body", lambda: {"status_code": 401, "error": "Unauthorized " + SENTINEL}),
    ("http 500 body", lambda: {"status_code": 500, "detail": SENTINEL}),
    ("empty object", lambda: {}),
    ("empty list", lambda: []),
    ("none", lambda: None),
    ("empty string", lambda: ""),
    ("blank string", lambda: "   "),
    ("non-json text", lambda: "Forbidden " + SENTINEL),
    ("unrelated json", lambda: {"hello": "world"}),
    ("error as json text", lambda: json.dumps({"error": SENTINEL})),
    ("error as bytes", lambda: json.dumps({"error": SENTINEL}).encode("utf-8")),
    ("wrapped error", lambda: {"apiResponse": {"error": SENTINEL}}),
    ("enveloped error", lambda: enveloped({"error": SENTINEL})),
    ("enveloped http 403", lambda: enveloped({"statusCode": 403, "message": SENTINEL})),
    ("enveloped empty object", lambda: enveloped({})),
    ("enveloped empty list", lambda: enveloped([])),
    ("poisoned read", Poisoned),
]

# Bodies in the Harmony Email & Collaboration response shape that say the call failed.
HEC_BAD = [
    ("envelope 401 text code", lambda: refused("401")),
    ("envelope 500 numeric code", lambda: refused(500)),
    ("envelope refused as json text", lambda: json.dumps(refused("403"))),
    ("envelope refused, wrapped", lambda: {"apiResponse": refused("429")}),
    ("envelope refused, enveloped", lambda: enveloped(refused("403"))),
    ("error beside responseData", lambda: {"error": SENTINEL, "responseData": []}),
    ("errors beside responseData", lambda: {"errors": [{"message": SENTINEL}], "responseData": []}),
    ("http 503 beside responseData", lambda: {"statusCode": 503, "message": SENTINEL, "responseData": []}),
]


def spf(value):
    return {"SPF": value, "DKIM": "v=DKIM1; k=rsa; p=MIGf", "DMARC": "v=DMARC1; p=reject", "SMTPBanner": "None"}


# The DNS probe answers a flat {"SPF": ..., "DKIM": ..., "DMARC": ...}. An SPF value that is not a
# record, a "no record" marker or null cannot be read.
DNS_BAD = [
    ("spf true without a record", lambda: spf(True)),
    ("spf object", lambda: spf({"record": "v=spf1 -all"})),
    ("spf list", lambda: spf(["v=spf1 -all"])),
    ("spf number", lambda: spf(5)),
    ("spf free text", lambda: spf("Forbidden " + SENTINEL)),
    ("spf holds another record type", lambda: spf("v=DMARC1; p=none")),
    ("probe error beside the result", lambda: {"error": SENTINEL, "result": "Forbidden " + SENTINEL}),
    ("probe result is an error", lambda: {"result": {"error": SENTINEL}}),
    ("probe result is text", lambda: {"result": "Forbidden " + SENTINEL}),
]


def cases():
    for name in ALL_CHECKS:
        for label, make in COMMON_BAD:
            yield pytest.param(name, make, id=name + "-" + label)
        if name in HEC_CHECKS:
            for label, make in HEC_BAD:
                yield pytest.param(name, make, id=name + "-" + label)
        else:
            for label, make in DNS_BAD:
                yield pytest.param(name, make, id=name + "-" + label)


@pytest.mark.parametrize("name,make", list(cases()))
def test_unreadable_body_is_not_evaluated(name, make):
    out = load(name).transform(make())
    assert out["transformedResponse"] == {ALL_CHECKS[name]: None}
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert all(isinstance(e, str) and e for e in collection["errors"])
    evaluation = out["additionalInfo"]["evaluation"]
    assert evaluation["passReasons"] == []
    assert evaluation["failReasons"]
    # the vendor's own error text is never copied into the result
    assert SENTINEL not in json.dumps(out)


@pytest.mark.parametrize("name", sorted(ALL_CHECKS))
def test_exception_text_stays_under_transformation_errors(name):
    out = load(name).transform(Poisoned())
    info = out["additionalInfo"]
    assert out["transformedResponse"] == {ALL_CHECKS[name]: None}
    assert info["dataCollection"]["status"] == "error"
    assert "poisoned read" not in json.dumps(info["dataCollection"])
    assert "poisoned read" not in json.dumps(info["evaluation"])


# --- A real, readable answer that proves a negative keeps its verdict --------------------------

def quiet(code=200):
    """What the vendor returns for a tenant with nothing to list."""
    return {"responseEnvelope": {"requestId": "r", "responseCode": code, "responseText": "", "recordsNumber": "0",
                                 "scrollId": ""}, "responseData": []}


QUIET_FORMS = [
    ("numeric code", lambda: quiet(200)),
    ("zero code", lambda: quiet(0)),
    ("text code", lambda: quiet("200")),
    ("no envelope", lambda: {"responseData": []}),
    ("wrapped", lambda: {"apiResponse": quiet()}),
    ("enveloped", lambda: enveloped(quiet())),
    ("json text", lambda: json.dumps(quiet())),
]


@pytest.mark.parametrize("label,make", QUIET_FORMS, ids=[f[0] for f in QUIET_FORMS])
@pytest.mark.parametrize("name", sorted(HEC_FALSE_CHECKS))
def test_quiet_tenant_still_reads_false(name, label, make):
    out = load(name).transform(make())
    assert out["transformedResponse"] == {HEC_FALSE_CHECKS[name]: False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []
    assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("label,make", QUIET_FORMS, ids=[f[0] for f in QUIET_FORMS])
def test_unverified_allow_list_empty_still_reads_zero(label, make):
    out = load("unverifiedallowpolicycount").transform(make())
    assert out["transformedResponse"] == {"unverifiedAllowPolicyCount": 0}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_open_quarantined_messages_zero_still_reads_zero():
    out = load("openquarantinedmessagescount").transform(quiet())
    assert out["transformedResponse"] == {"openQuarantinedMessagesCount": 0}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def event(**fields):
    base = {"eventId": "1001", "type": "other", "saas": "other_saas", "eventCreated": "2026-10-01T10:00:00",
            "actions": [], "data": ""}
    base.update(fields)
    return base


def page(records):
    body = quiet()
    body["responseEnvelope"]["recordsNumber"] = str(len(records))
    body["responseData"] = records
    return body


# (file, an event that satisfies it, an event of another kind that must not)
EVENT_MATCH = [
    ("isaccounttakeoverdetectionenabled", event(type="anomaly"), event(type="phishing")),
    ("isantiphishingenabled", event(type="phishing"), event(type="dlp")),
    ("isclouddataleakpreventionenabled", event(type="dlp"), event(type="shadow_it")),
    ("isshadowitdiscoveryenabled", event(type="shadow_it"), event(type="anomaly")),
    ("islinkedo365accountactive", event(saas="office365_emails"), event(saas="other_saas")),
]


@pytest.mark.parametrize("name,matching,other", EVENT_MATCH, ids=[m[0] for m in EVENT_MATCH])
def test_event_type_checks_still_pass_and_fail_on_real_pages(name, matching, other):
    key = HEC_FALSE_CHECKS[name]
    hit = load(name).transform(page([other, matching]))
    assert hit["transformedResponse"] == {key: True}
    assert hit["additionalInfo"]["dataCollection"]["status"] == "success"
    assert hit["additionalInfo"]["evaluation"]["passReasons"]
    miss = load(name).transform(page([other]))
    assert miss["transformedResponse"] == {key: False}
    assert miss["additionalInfo"]["dataCollection"]["status"] == "success"


def test_license_check_still_reads_scopes():
    mod = load("confirmedlicensepurchased")
    ok = mod.transform({"responseEnvelope": {"responseCode": 200}, "responseData": ["farm1:tenant1"]})
    assert ok["transformedResponse"] == {"confirmedLicensePurchased": True}
    no_scope = mod.transform({"responseEnvelope": {"responseCode": 200}, "responseData": ["not-a-scope"]})
    assert no_scope["transformedResponse"] == {"confirmedLicensePurchased": False}
    assert no_scope["additionalInfo"]["dataCollection"]["status"] == "success"


def test_url_block_list_still_reads_entries():
    mod = load("isurlreputationblocklistenforced")
    entry = {"entityId": "100", "linkDomains": "bad.example", "senderEmail": "None"}
    assert mod.transform(page([entry]))["transformedResponse"] == {"isURLReputationBlockListEnforced": True}
    assert mod.transform(page([dict(entry, linkDomains="None")]))["transformedResponse"] == {
        "isURLReputationBlockListEnforced": False}


def test_allow_list_with_entries_still_counts_them():
    out = load("unverifiedallowpolicycount").transform(page([{"entityId": "1"}, {"entityId": "2"}]))
    assert out["transformedResponse"] == {"unverifiedAllowPolicyCount": 2}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


# --- isSPFEnforced: a probe that answers "no record" is a readable negative ---------------------

@pytest.mark.parametrize("value", [False, None, "", "  ", "None", "False", "false", "not found", "N/A"], ids=repr)
def test_spf_no_record_still_reads_false(value):
    out = load("isspfenforced").transform(spf(value))
    assert out["transformedResponse"] == {"isSPFEnforced": False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("body", [
    spf("v=spf1 include:abc123xyz.spf.checkpoint-spf.com include:spf.protection.outlook.com ~all"),
    {"result": spf("v=spf1 include:spfr.cpmails.com -all")},
    enveloped(spf("v=spf1 include:abc123xyz.spf.checkpoint-spf.com -all")),
    json.dumps({"apiResponse": spf("v=spf1 include:abc123xyz.spf.checkpoint-spf.com ~all")}),
], ids=["plain", "result wrapper", "enveloped", "json text"])
def test_spf_with_check_point_include_still_passes(body):
    out = load("isspfenforced").transform(body)
    assert out["transformedResponse"] == {"isSPFEnforced": True}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_spf_record_without_check_point_include_still_fails():
    out = load("isspfenforced").transform(spf("v=spf1 include:spf.protection.outlook.com ~all"))
    assert out["transformedResponse"] == {"isSPFEnforced": False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
