"""Check Point Harmony Email & Collaboration: partial pages, unreadable entries, wrapper errors, string status codes.

THE PAGINATION RULE. A transform is handed ONE page of a paged vendor answer. When the response
says records remain (a non-empty responseEnvelope.scrollId, or a recordsNumber larger than the
page) the page is partial, and every result that rests on ABSENCE reads None (Not evaluated):

  * True for "every" or "none" style claims, and a False that says "none found";
  * a total count taken from the page.

A match already seen on the page still proves a presence check (True stays True). A negative that
an item already seen proves (a message-move action that lacks its audit fields) stays False. A
count is the vendor's own recordsNumber total when that total is at least the page length (the search
endpoint sends a scrollId on its last page too), else None.

THE UNREADABLE-ENTRY RULE. An entry that cannot be read is never skipped: an entry that is not an
object, or a field that should hold JSON (entitySecurityResult or entitySecurityResults, entityPayload, emailLinks,
actions) and does not parse, or an action that is not an object. The unread entry may be the match
or the counter-example, so a result that rests on an absence reads None, a match or a negative
already seen keeps its verdict, and a count reads None. A missing, blank or "None" field is a
readable empty one.

THE TOTAL RULE. A recordsNumber that is stated but cannot be read as a whole number (text that is not
digits, a negative number, a boolean, a list, an object) means nobody knows whether the page is
complete. It is treated like a partial page: an absence verdict and a total are None, a match or a
negative already seen keeps its verdict (the count stays None). A missing, null, blank or "None"
total states nothing and the page is judged by its scrollId alone.

THE FIELD-TYPE RULE. A type or saas field that a check matches on and that holds something other than
text (a number, a boolean, a list, an object) is an unreadable entry, not "no match". A missing,
null or blank field is a readable empty one.

WRAPPER ERRORS. An error marker (error, errors, or an HTTP status of 400 or more in status,
statusCode or status_code) on any wrapper around the response body makes the result None, exactly
as it does on the body itself. A status code written as text ("401", " 403 ") counts like the
number. Booleans, blank or non-numeric text and values below 400 are not errors.

All payloads here are synthetic.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL = "planted-vendor-text-5e17"
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}


def load(name):
    spec = importlib.util.spec_from_file_location("cphec_part_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(name, body):
    return load(name).transform(body)


def value(out):
    inner = out["transformedResponse"]
    assert len(inner) == 1
    return list(inner.values())[0]


def assert_not_evaluated(out):
    assert value(out) is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert all(isinstance(e, str) and e for e in collection["errors"])
    evaluation = out["additionalInfo"]["evaluation"]
    assert evaluation["passReasons"] == []
    assert evaluation["failReasons"]
    assert SENTINEL not in json.dumps(out)


def assert_measured(out, expected):
    assert value(out) == expected and type(value(out)) is type(expected)
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


# --- synthetic records -------------------------------------------------------------------------

def ev(**fields):
    base = {"eventId": "1001", "type": "other", "saas": "other_saas", "eventCreated": "2026-10-01T10:00:00",
            "actions": [], "data": ""}
    base.update(fields)
    return base


def act(kind="quarantine_email", create="2026-10-01T10:01:00Z", related="1001"):
    return {"actionType": kind, "createTime": create, "relatedEntityId": related}


AP_DATA = 'Check Point scanned #{"label": "x", "entity_id": "e", "entity_type": "avanan_ap_scan"}'
MS_DATA = 'Microsoft scanned #{"label": "x", "entity_id": "e", "entity_type": "ms_defender_scan"}'


def entity(av=None, ctp=None, links=()):
    return {"entityInfo": {"entityId": "e1", "saas": "office365_emails",
                           "saasEntityType": "office365_emails_email"},
            "entityPayload": {"attachmentCount": "1", "emailLinks": list(links)},
            "entitySecurityResults": {"combinedVerdict": {"av": av, "clicktimeProtection": ctp},
                                      "av": [], "clicktimeProtection": None}}


LINK = ("https://example.com/a",)

# file -> (criterion key, records that satisfy the check, records that are readable but do not)
PRESENCE_CHECKS = {
    "isaccounttakeoverdetectionenabled": ("isAccountTakeoverDetectionEnabled",
                                          [ev(type="anomaly")], [ev(type="phishing")]),
    "isantiphishingenabled": ("isAntiPhishingEnabled", [ev(type="phishing")], [ev(type="dlp")]),
    "isclouddataleakpreventionenabled": ("isCloudDataLeakPreventionEnabled",
                                         [ev(type="dlp")], [ev(type="shadow_it")]),
    "isshadowitdiscoveryenabled": ("isShadowITDiscoveryEnabled", [ev(type="shadow_it")], [ev(type="anomaly")]),
    "islinkedo365accountactive": ("isLinkedO365AccountActive",
                                  [ev(saas="office365_emails")], [ev(saas="other_saas")]),
    "isemailsecurityloggingenabled": ("isEmailSecurityLoggingEnabled", [ev(actions=[act()])], [ev()]),
    "isimposteremaildetectionenabled": ("isImposterEmailDetectionEnabled",
                                        [ev(data=AP_DATA)], [ev(data=MS_DATA)]),
    "ispostdeliveryquarantineenabled": ("isPostDeliveryQuarantineEnabled", [ev(actions=[act()])], [ev()]),
    "isantivirusverdictengineenabled": ("isAntivirusVerdictEngineEnabled",
                                        [entity(av="clean")], [entity()]),
    "isclicktimeurlrewriteenabled": ("isClickTimeURLRewriteEnabled",
                                     [entity(ctp="clean", links=LINK)], [entity(links=LINK)]),
    "isurlreputationblocklistenforced": ("isURLReputationBlockListEnforced",
                                        [{"entityId": "1", "linkDomains": "bad.example"}],
                                        [{"entityId": "2", "linkDomains": "None"}]),
    "confirmedlicensepurchased": ("confirmedLicensePurchased", ["farm1:tenant1"], ["not-a-scope"]),
}
# messageMoveAuditTrailEnabled says "every move action carries its audit fields"; it is tested apart.
MOVE = "messagemoveaudittrailenabled"
MOVE_KEY = "messageMoveAuditTrailEnabled"
ALLOW = "unverifiedallowpolicycount"
ALLOW_KEY = "unverifiedAllowPolicyCount"
QUARANTINE = "openquarantinedmessagescount"
QUARANTINE_KEY = "openQuarantinedMessagesCount"
SPF = "isspfenforced"


def envelope(records, scroll="", total=None, code=200):
    return {"responseEnvelope": {"requestId": "r", "responseCode": code, "responseText": "",
                                 "recordsNumber": str(len(records) if total is None else total),
                                 "scrollId": scroll},
            "responseData": records}


def enveloped(body):
    return {"data": body, "validation": VALIDATION}


# Ways a response says "there is more": every one must read as a partial page.
PARTIAL_FORMS = [
    ("scrollId set", lambda recs: envelope(recs, scroll="next-page-token")),
    ("scrollId set, total equals the page", lambda recs: envelope(recs, scroll="tok", total=len(recs))),
    ("total above the page", lambda recs: envelope(recs, total=len(recs) + 50)),
    ("total above the page, scrollId None text", lambda recs: envelope(recs, scroll="None", total=len(recs) + 50)),
    ("total above the page as a number",
     lambda recs: dict(envelope(recs), responseEnvelope={"responseCode": 200, "recordsNumber": len(recs) + 7,
                                                         "scrollId": ""})),
    ("scrollId and a large total", lambda recs: envelope(recs, scroll="tok", total=10000)),
    ("scrollId only, no envelope code", lambda recs: {"responseEnvelope": {"scrollId": "tok"}, "responseData": recs}),
    ("scrollId beside responseData", lambda recs: {"scrollId": "tok", "responseData": recs}),
    ("wrapped", lambda recs: {"apiResponse": envelope(recs, scroll="tok")}),
    ("enveloped", lambda recs: enveloped(envelope(recs, scroll="tok"))),
    ("json text", lambda recs: json.dumps(envelope(recs, scroll="tok"))),
]

# Ways a response says "that is all": each must read as a complete page.
COMPLETE_FORMS = [
    ("scrollId empty", lambda recs: envelope(recs)),
    ("scrollId None text", lambda recs: envelope(recs, scroll="None")),
    ("scrollId null text", lambda recs: envelope(recs, scroll="null")),
    ("scrollId blank", lambda recs: envelope(recs, scroll="   ")),
    ("scrollId JSON null", lambda recs: envelope(recs, scroll=None)),
    ("no scrollId", lambda recs: {"responseEnvelope": {"responseCode": 200, "recordsNumber": str(len(recs))},
                                   "responseData": recs}),
    ("no envelope", lambda recs: {"responseData": recs}),
    ("total below the page", lambda recs: envelope(recs, total=max(len(recs) - 1, 0))),
    ("total not a number", lambda recs: envelope(recs, total="None")),
    ("wrapped", lambda recs: {"apiResponse": envelope(recs)}),
    ("json text", lambda recs: json.dumps(envelope(recs))),
]


def partial_cases():
    for name in PRESENCE_CHECKS:
        for label, make in PARTIAL_FORMS:
            yield pytest.param(name, make, id=name + "-" + label)


# --- (a) a partial page with no match is Not evaluated, never False ---------------------------------

@pytest.mark.parametrize("name,make", list(partial_cases()))
def test_partial_page_without_a_match_is_not_evaluated(name, make):
    other = PRESENCE_CHECKS[name][2]
    assert_not_evaluated(run(name, make(other)))


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_partial_empty_page_is_not_evaluated(name):
    assert_not_evaluated(run(name, envelope([], scroll="tok", total=500)))
    assert_not_evaluated(run(name, envelope([], scroll="tok")))


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_the_partial_page_reason_says_the_page_is_partial(name):
    out = run(name, envelope(PRESENCE_CHECKS[name][2], scroll="tok"))
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["dataCollection"]["errors"])
    assert "partial" in text.lower()


# --- a match already seen still proves a presence check ----------------------------------------------

@pytest.mark.parametrize("name,make", list(partial_cases()))
def test_partial_page_with_a_match_stays_true(name, make):
    match = PRESENCE_CHECKS[name][1]
    other = PRESENCE_CHECKS[name][2]
    out = run(name, make(other + match))
    assert_measured(out, True)
    assert out["additionalInfo"]["evaluation"]["passReasons"]


# --- a complete page keeps its False -----------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
@pytest.mark.parametrize("label,make", COMPLETE_FORMS, ids=[f[0] for f in COMPLETE_FORMS])
def test_complete_page_without_a_match_still_reads_false(name, label, make):
    out = run(name, make(PRESENCE_CHECKS[name][2]))
    assert_measured(out, False)
    assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
@pytest.mark.parametrize("label,make", COMPLETE_FORMS, ids=[f[0] for f in COMPLETE_FORMS])
def test_complete_page_with_a_match_still_reads_true(name, label, make):
    assert_measured(run(name, make(PRESENCE_CHECKS[name][1])), True)


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_complete_empty_page_still_reads_false(name):
    assert_measured(run(name, envelope([])), False)


# --- (b) messageMoveAuditTrailEnabled: a proven negative stays False, an unproven True does not --

GOOD_MOVES = [ev(actions=[act("quarantine_email"), act("restore_email")])]
BAD_MOVES = [ev(actions=[act("quarantine_email"), act("delete_email", create="None")])]
NO_MOVES = [ev(actions=[act("add_banner_to_email")])]


@pytest.mark.parametrize("label,make", PARTIAL_FORMS, ids=[f[0] for f in PARTIAL_FORMS])
def test_move_audit_partial_page_with_a_gap_stays_false(label, make):
    # the gap is on the page already read: no unread page can fix it
    assert_measured(run(MOVE, make(BAD_MOVES)), False)


@pytest.mark.parametrize("label,make", PARTIAL_FORMS, ids=[f[0] for f in PARTIAL_FORMS])
def test_move_audit_partial_page_cannot_prove_every_action_is_complete(label, make):
    assert_not_evaluated(run(MOVE, make(GOOD_MOVES)))


@pytest.mark.parametrize("label,make", PARTIAL_FORMS, ids=[f[0] for f in PARTIAL_FORMS])
def test_move_audit_partial_page_with_no_move_is_not_evaluated(label, make):
    assert_not_evaluated(run(MOVE, make(NO_MOVES)))
    assert_not_evaluated(run(MOVE, make([])))


@pytest.mark.parametrize("label,make", COMPLETE_FORMS, ids=[f[0] for f in COMPLETE_FORMS])
def test_move_audit_complete_page_keeps_every_verdict(label, make):
    assert_measured(run(MOVE, make(GOOD_MOVES)), True)
    assert_measured(run(MOVE, make(BAD_MOVES)), False)
    assert_measured(run(MOVE, make(NO_MOVES)), False)
    assert_measured(run(MOVE, make([])), False)


# --- (b) counts: never a total taken from a partial page -----------------------------------------------

ENTRIES = [{"entityId": "1"}, {"entityId": "2"}]


def test_allow_list_count_on_a_partial_page_is_the_vendor_total_or_not_evaluated():
    # the vendor states a total above the page: that is its own figure, not a count of the page
    assert_measured(run(ALLOW, envelope(ENTRIES, scroll="tok", total=250)), 250)
    assert_measured(run(ALLOW, envelope(ENTRIES, total=250)), 250)
    assert_measured(run(ALLOW, envelope(ENTRIES, scroll="tok", total="250")), 250)
    # no usable total: the page length is a lower bound, never the count
    assert_not_evaluated(run(ALLOW, envelope(ENTRIES, scroll="tok", total=len(ENTRIES))))
    assert_not_evaluated(run(ALLOW, envelope(ENTRIES, scroll="tok", total="None")))
    assert_not_evaluated(run(ALLOW, envelope(ENTRIES, scroll="tok", total=1)))
    assert_not_evaluated(run(ALLOW, {"responseEnvelope": {"scrollId": "tok"}, "responseData": ENTRIES}))
    assert_not_evaluated(run(ALLOW, {"scrollId": "tok", "responseData": ENTRIES}))
    assert_not_evaluated(run(ALLOW, json.dumps(envelope(ENTRIES, scroll="tok", total=2))))
    # an empty partial page does not prove zero
    assert_not_evaluated(run(ALLOW, envelope([], scroll="tok")))
    assert_not_evaluated(run(ALLOW, envelope([], scroll="tok", total=0)))


@pytest.mark.parametrize("label,make", COMPLETE_FORMS, ids=[f[0] for f in COMPLETE_FORMS])
def test_allow_list_count_on_a_complete_page_is_the_page(label, make):
    assert_measured(run(ALLOW, make(ENTRIES)), len(ENTRIES))
    assert_measured(run(ALLOW, make([])), 0)


def pending(**over):
    payload = {"isQuarantined": "true", "isRestoreRequested": "true", "isRestored": "false",
               "isRestoreDeclined": "false"}
    payload.update(over)
    return {"entityInfo": {"entityId": "q1", "saas": "office365_emails"}, "entityPayload": payload,
            "entitySecurityResults": {}}


def test_open_quarantined_count_with_a_token_trusts_a_total_at_or_above_the_page():
    three = [pending(), pending(), pending()]
    assert_measured(run(QUARANTINE, envelope(three, scroll="tok", total=250)), 250)
    # HEC sends a scrollId on the last page too (live, 27 Oct 2026): a total equal to the page is complete
    assert_measured(run(QUARANTINE, envelope(three, scroll="tok", total=3)), 3)
    assert_measured(run(QUARANTINE, envelope([], scroll="tok", total=0)), 0)
    # a total below the page contradicts the page, so the page is only a lower bound
    assert_not_evaluated(run(QUARANTINE, envelope(three, scroll="tok", total=2)))
    assert_not_evaluated(run(QUARANTINE, envelope(three, scroll="tok", total="None")))
    # a token with no total at all stays unreadable (QUARANTINE_NONE_PATHS, "paged, no total")
    # a stray entity proves the filter was not applied, so the count is unreadable even with a total
    assert_not_evaluated(run(QUARANTINE, envelope(three + [pending(isRestored="true")], scroll="tok", total=250)))


def test_open_quarantined_count_on_a_complete_page_is_unchanged():
    assert_measured(run(QUARANTINE, envelope([pending(), pending()])), 2)
    assert_measured(run(QUARANTINE, envelope([])), 0)
    assert_measured(run(QUARANTINE, envelope([pending()] * 3, total=1)), 3)


# --- (c) an error marker on a wrapper around the body --------------------------------------------------

def good_body(name):
    if name == SPF:
        return {"SPF": "v=spf1 include:abc123xyz.spf.checkpoint-spf.com -all", "DKIM": "v=DKIM1; k=rsa; p=MIGf",
                "DMARC": "v=DMARC1; p=reject", "SMTPBanner": "None"}
    if name in PRESENCE_CHECKS:
        return envelope(PRESENCE_CHECKS[name][1])
    if name == MOVE:
        return envelope(GOOD_MOVES)
    if name == ALLOW:
        return envelope(ENTRIES)
    return envelope([])


ALL_NAMES = sorted(list(PRESENCE_CHECKS) + [MOVE, ALLOW, QUARANTINE, SPF])
KEYS = {n: PRESENCE_CHECKS[n][0] for n in PRESENCE_CHECKS}
KEYS.update({MOVE: MOVE_KEY, ALLOW: ALLOW_KEY, QUARANTINE: QUARANTINE_KEY, SPF: "isSPFEnforced"})

# Each wraps a perfectly good answer in a wrapper that says the call failed.
OUTER_ERRORS = [
    ("error flag", lambda good: {"error": True, "apiResponse": good}),
    ("error text", lambda good: {"error": SENTINEL, "result": good}),
    ("errors list", lambda good: {"errors": [{"message": SENTINEL}], "response": good}),
    ("statusCode 500", lambda good: {"statusCode": 500, "data": good}),
    ("status_code 401", lambda good: {"status_code": 401, "data": good}),
    ("status 503", lambda good: {"status": 503, "apiResponse": good}),
    ("status 400, the lowest error", lambda good: {"statusCode": 400, "apiResponse": good}),
    ("statusCode as text", lambda good: {"statusCode": "403", "apiResponse": good}),
    ("statusCode as padded text", lambda good: {"statusCode": " 401 ", "apiResponse": good}),
    ("status as text", lambda good: {"status": "502", "result": good}),
    ("two levels deep", lambda good: {"data": {"statusCode": 502, "apiResponse": good}}),
    ("middle wrapper", lambda good: {"apiResponse": {"errors": ["x"], "result": good}}),
    ("error above json text", lambda good: {"error": True, "apiResponse": json.dumps(good)}),
    ("error in json text", lambda good: json.dumps({"statusCode": 500, "data": good})),
    ("error in json text, deep", lambda good: json.dumps({"data": json.dumps({"error": SENTINEL, "result": good})})),
    ("rawResponse wrapper", lambda good: {"statusCode": 504, "rawResponse": good}),
    ("error as bytes", lambda good: json.dumps({"error": True, "apiResponse": good}).encode("utf-8")),
]


@pytest.mark.parametrize("name", ALL_NAMES)
@pytest.mark.parametrize("label,make", OUTER_ERRORS, ids=[f[0] for f in OUTER_ERRORS])
def test_error_marker_on_an_outer_wrapper_is_not_evaluated(name, label, make):
    out = run(name, make(good_body(name)))
    assert out["transformedResponse"] == {KEYS[name]: None}
    assert_not_evaluated(out)


@pytest.mark.parametrize("name", ALL_NAMES)
def test_the_good_body_alone_is_measured(name):
    assert value(run(name, good_body(name))) is not None


# Markers that are NOT errors: the answer must be read as if the marker were absent.
NOT_ERRORS = [
    {"statusCode": 200}, {"status": 200}, {"status_code": "200"}, {"statusCode": 399}, {"statusCode": "399"},
    {"statusCode": " 399 "}, {"statusCode": 0}, {"statusCode": -500}, {"statusCode": True}, {"statusCode": False},
    {"status": True}, {"statusCode": ""}, {"statusCode": "   "}, {"statusCode": "ok"}, {"status": "success"},
    {"status": "error-free"}, {"statusCode": "4xx"}, {"statusCode": "40 1"}, {"statusCode": None},
    {"statusCode": []}, {"statusCode": {}}, {"error": None}, {"error": False}, {"error": ""}, {"error": 0},
    {"errors": []}, {"errors": None}, {"errors": {}},
]


def label_of(marker):
    return json.dumps(marker)


@pytest.mark.parametrize("name", ALL_NAMES)
@pytest.mark.parametrize("marker", NOT_ERRORS, ids=[label_of(m) for m in NOT_ERRORS])
def test_markers_that_are_not_errors_on_a_wrapper_change_nothing(name, marker):
    good = good_body(name)
    expected = run(name, good)["transformedResponse"]
    wrapped = run(name, dict(marker, apiResponse=good))
    assert wrapped["transformedResponse"] == expected
    assert wrapped["additionalInfo"]["dataCollection"]["status"] == "success"


# --- (d) a status code written as text is an HTTP error like the number --------------------------------

HEC_NAMES = [n for n in ALL_NAMES if n != SPF]


@pytest.mark.parametrize("name", HEC_NAMES)
@pytest.mark.parametrize("field", ["statusCode", "status_code", "status"])
@pytest.mark.parametrize("code", ["401", " 403 ", "500", "400", 401, 503, "0500"], ids=repr)
def test_http_error_code_on_the_body_is_not_evaluated_as_text_or_number(name, field, code):
    body = dict(good_body(name), **{field: code})
    out = run(name, body)
    assert out["transformedResponse"] == {KEYS[name]: None}
    assert_not_evaluated(out)


@pytest.mark.parametrize("name", HEC_NAMES)
@pytest.mark.parametrize("field", ["statusCode", "status_code", "status"])
@pytest.mark.parametrize("code", [True, False, "", "  ", "abc", "OK", "399", " 200 ", 200, 399, None, "4O1"], ids=repr)
def test_codes_below_400_booleans_and_text_on_the_body_change_nothing(name, field, code):
    good = good_body(name)
    expected = run(name, good)["transformedResponse"]
    out = run(name, dict(good, **{field: code}))
    assert out["transformedResponse"] == expected
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("field", ["statusCode", "status_code", "status"])
@pytest.mark.parametrize("code", ["401", " 403 ", 500, "502"], ids=repr)
def test_spf_probe_with_an_http_error_code_is_not_evaluated(field, code):
    body = dict(good_body(SPF), **{field: code})
    assert_not_evaluated(run(SPF, body))
    assert_not_evaluated(run(SPF, {"result": body}))


@pytest.mark.parametrize("marker", [{"error": True}, {"error": SENTINEL}, {"errors": [{"message": SENTINEL}]}])
def test_spf_probe_with_an_error_marker_beside_the_record_is_not_evaluated(marker):
    assert_not_evaluated(run(SPF, dict(good_body(SPF), **marker)))
    assert_not_evaluated(run(SPF, {"result": dict(good_body(SPF), **marker)}))


def test_spf_probe_without_markers_still_reads_the_record():
    assert_measured(run(SPF, good_body(SPF)), True)
    assert_measured(run(SPF, {"result": good_body(SPF)}), True)
    assert_measured(run(SPF, dict(good_body(SPF), SPF="v=spf1 include:spf.protection.outlook.com ~all")), False)


# --- unreadable entries are never skipped --------------------------------------------------------------

# Entries that are not objects. confirmedLicensePurchased reads a list of text scopes, so for it only
# a non-text entry is unreadable (a text entry that is not a scope is a readable non-scope).
NON_OBJECT_ENTRIES = ["garbled", None, 7, ["x"], True]
NON_TEXT_ENTRIES = [None, 7, ["x"], {"scope": "farm1:tenant1"}, True]


def garbled_for(name):
    return NON_TEXT_ENTRIES if name == "confirmedlicensepurchased" else NON_OBJECT_ENTRIES


def readable_forms():
    return [
        ("plain", lambda recs: envelope(recs)),
        ("wrapped", lambda recs: {"apiResponse": envelope(recs)}),
        ("json text", lambda recs: json.dumps(envelope(recs))),
    ]


def unreadable_cases():
    for name in PRESENCE_CHECKS:
        for bad in garbled_for(name):
            for label, make in readable_forms():
                yield pytest.param(name, bad, make, id=name + "-" + repr(bad) + "-" + label)


@pytest.mark.parametrize("name,bad,make", list(unreadable_cases()))
def test_unreadable_entry_without_a_match_is_not_evaluated(name, bad, make):
    # alone, and beside a readable record that does not match: either may hide the match
    assert_not_evaluated(run(name, make([bad])))
    assert_not_evaluated(run(name, make(PRESENCE_CHECKS[name][2] + [bad])))


@pytest.mark.parametrize("name,bad,make", list(unreadable_cases()))
def test_unreadable_entry_beside_a_match_keeps_the_match(name, bad, make):
    out = run(name, make(PRESENCE_CHECKS[name][1] + [bad]))
    assert_measured(out, True)
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_the_unreadable_reason_says_so(name):
    out = run(name, envelope(PRESENCE_CHECKS[name][2] + [garbled_for(name)[0]]))
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["dataCollection"]["errors"])
    assert "could not be read" in text


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_an_unreadable_entry_on_a_partial_page_is_still_not_evaluated(name):
    assert_not_evaluated(run(name, envelope(PRESENCE_CHECKS[name][2] + [garbled_for(name)[0]], scroll="tok")))


# A field that should hold JSON text and does not parse is an unreadable entry too.
BAD_JSON = "{not json"


def entity_with(**fields):
    base = entity()
    base.update(fields)
    return base


BAD_ENTITY_FIELDS = {
    "isantivirusverdictengineenabled": [
        ("entitySecurityResults", lambda: entity_with(entitySecurityResults=BAD_JSON)),
        ("entitySecurityResults list", lambda: entity_with(entitySecurityResults=["x"])),
        ("entitySecurityResult", lambda: singular(entity_with(entitySecurityResults=BAD_JSON))),
        ("entitySecurityResult list", lambda: singular(entity_with(entitySecurityResults=["x"]))),
        ("entityInfo", lambda: entity_with(entityInfo=BAD_JSON)),
    ],
    "isclicktimeurlrewriteenabled": [
        ("entitySecurityResults", lambda: dict(entity(links=LINK), entitySecurityResults=BAD_JSON)),
        ("entitySecurityResult", lambda: singular(dict(entity(links=LINK), entitySecurityResults=BAD_JSON))),
        ("entityPayload", lambda: dict(entity(links=LINK), entityPayload=BAD_JSON)),
        ("entityPayload list", lambda: dict(entity(links=LINK), entityPayload=["x"])),
        ("emailLinks", lambda: dict(entity(links=LINK),
                                    entityPayload={"attachmentCount": "1", "emailLinks": "[not json"})),
        ("emailLinks object", lambda: dict(entity(links=LINK),
                                           entityPayload={"attachmentCount": "1", "emailLinks": {"a": 1}})),
    ],
    "ispostdeliveryquarantineenabled": [
        ("actions text", lambda: ev(actions=BAD_JSON)),
        ("actions object", lambda: ev(actions={"actionType": "quarantine_email"})),
        ("action entry", lambda: ev(actions=["garbled"])),
        ("action entry none", lambda: ev(actions=[None])),
    ],
    "isemailsecurityloggingenabled": [
        ("actions text", lambda: ev(actions=BAD_JSON)),
        ("actions object", lambda: ev(actions={"actionType": "quarantine_email"})),
        ("action entry", lambda: ev(actions=["garbled"])),
    ],
}


def bad_field_cases():
    for name, items in BAD_ENTITY_FIELDS.items():
        for label, make in items:
            yield pytest.param(name, make, id=name + "-" + label)


@pytest.mark.parametrize("name,make", list(bad_field_cases()))
def test_unparseable_field_without_a_match_is_not_evaluated(name, make):
    assert_not_evaluated(run(name, envelope([make()])))
    assert_not_evaluated(run(name, envelope(PRESENCE_CHECKS[name][2] + [make()])))


@pytest.mark.parametrize("name,make", list(bad_field_cases()))
def test_unparseable_field_beside_a_match_keeps_the_match(name, make):
    assert_measured(run(name, envelope(PRESENCE_CHECKS[name][1] + [make()])), True)


# Missing, blank and "None" fields are readable and empty: a complete page still reads False.
EMPTY_FIELDS = [None, "", "  ", "None", "null", "[]"]


@pytest.mark.parametrize("name", ["ispostdeliveryquarantineenabled", "isemailsecurityloggingenabled", MOVE])
@pytest.mark.parametrize("empty", EMPTY_FIELDS, ids=repr)
def test_blank_actions_are_readable_and_empty(name, empty):
    assert_measured(run(name, envelope([ev(actions=empty)])), False)
    assert_measured(run(name, envelope([{k: v for k, v in ev().items() if k != "actions"}])), False)


@pytest.mark.parametrize("empty", EMPTY_FIELDS, ids=repr)
def test_blank_entity_fields_are_readable_and_empty(empty):
    assert_measured(run("isantivirusverdictengineenabled", envelope([entity_with(entitySecurityResults=empty)])), False)
    assert_measured(run("isantivirusverdictengineenabled", envelope([singular(entity_with(entitySecurityResults=empty))])), False)
    assert_measured(run("isclicktimeurlrewriteenabled",
                        envelope([dict(entity(links=LINK), entitySecurityResults=empty)])), False)
    assert_measured(run("isclicktimeurlrewriteenabled",
                        envelope([singular(dict(entity(links=LINK), entitySecurityResults=empty))])), False)
    assert_measured(run("isclicktimeurlrewriteenabled",
                        envelope([dict(entity(), entityPayload=empty)])), False)


def test_text_forms_of_objects_and_lists_are_read():
    as_text = json.dumps
    out = run("isantivirusverdictengineenabled",
              envelope([entity_with(entityInfo=as_text(entity()["entityInfo"]),
                                    entitySecurityResults=as_text(entity(av="clean")["entitySecurityResults"]))]))
    assert_measured(out, True)
    linked = entity(ctp="clean", links=LINK)
    assert_measured(run("isclicktimeurlrewriteenabled",
                        envelope([dict(linked, entityPayload=as_text(linked["entityPayload"]),
                                       entitySecurityResults=as_text(linked["entitySecurityResults"]))])), True)
    assert_measured(run("ispostdeliveryquarantineenabled", envelope([ev(actions=as_text([act()]))])), True)
    # the live spelling, as JSON text
    assert_measured(run("isantivirusverdictengineenabled",
                        envelope([singular(entity_with(entitySecurityResults=as_text(entity(av="clean")["entitySecurityResults"])))])), True)


# --- messageMoveAuditTrailEnabled with unreadable entries ----------------------------------------------

UNREADABLE_MOVE_RECORDS = [("not an object", "garbled"), ("none", None), ("actions text", ev(actions=BAD_JSON)),
                           ("action entry", ev(actions=["garbled"]))]


@pytest.mark.parametrize("label,bad", UNREADABLE_MOVE_RECORDS, ids=[u[0] for u in UNREADABLE_MOVE_RECORDS])
@pytest.mark.parametrize("flabel,make", readable_forms(), ids=[f[0] for f in readable_forms()])
def test_move_audit_unreadable_entry_cannot_prove_every_action_is_complete(label, bad, flabel, make):
    assert_not_evaluated(run(MOVE, make(GOOD_MOVES + [bad])))
    assert_not_evaluated(run(MOVE, make(NO_MOVES + [bad])))
    assert_not_evaluated(run(MOVE, make([bad])))


@pytest.mark.parametrize("label,bad", UNREADABLE_MOVE_RECORDS, ids=[u[0] for u in UNREADABLE_MOVE_RECORDS])
def test_move_audit_gap_already_seen_stays_false_beside_an_unreadable_entry(label, bad):
    assert_measured(run(MOVE, envelope(BAD_MOVES + [bad])), False)


# --- counts: an unreadable entry makes the count None --------------------------------------------------

@pytest.mark.parametrize("bad", NON_OBJECT_ENTRIES, ids=repr)
@pytest.mark.parametrize("flabel,make", readable_forms(), ids=[f[0] for f in readable_forms()])
def test_allow_list_count_is_not_evaluated_with_an_unreadable_entry(bad, flabel, make):
    assert_not_evaluated(run(ALLOW, make([bad])))
    assert_not_evaluated(run(ALLOW, make(ENTRIES + [bad])))
    assert_not_evaluated(run(ALLOW, envelope(ENTRIES + [bad], scroll="tok", total=250)))
    assert_not_evaluated(run(ALLOW, envelope(ENTRIES + [bad], total=250)))


@pytest.mark.parametrize("bad", NON_OBJECT_ENTRIES, ids=repr)
@pytest.mark.parametrize("flabel,make", readable_forms(), ids=[f[0] for f in readable_forms()])
def test_open_quarantined_count_is_not_evaluated_with_an_unreadable_entry(bad, flabel, make):
    assert_not_evaluated(run(QUARANTINE, make([bad])))
    assert_not_evaluated(run(QUARANTINE, make([pending(), bad])))
    assert_not_evaluated(run(QUARANTINE, envelope([pending(), bad], scroll="tok", total=250)))
    assert_not_evaluated(run(QUARANTINE, envelope([bad], total=250)))


def test_open_quarantined_entity_payload_that_does_not_parse_is_not_evaluated():
    assert_not_evaluated(run(QUARANTINE, envelope([dict(pending(), entityPayload=BAD_JSON)])))
    assert_measured(run(QUARANTINE, envelope([dict(pending(), entityPayload=json.dumps(pending()["entityPayload"]))])), 1)


# --- a record total that is stated but cannot be read: completeness is unknown -------------------------

BAD_TOTALS = ["many", "abc", "12abc", "1.5", "-3", "0x10", "1e3", "3 000", True, False, [], {}, ["5"], {"n": 5},
              -1, 2.5, SENTINEL]
ABSENT_TOTALS = [None, "", "   ", "None", "null"]


def raw_total_body(records, raw, scroll=""):
    return {"responseEnvelope": {"requestId": "r", "responseCode": 200, "responseText": "",
                                 "recordsNumber": raw, "scrollId": scroll},
            "responseData": records}


def total_forms():
    return [
        ("plain", lambda recs, raw: raw_total_body(recs, raw)),
        ("wrapped", lambda recs, raw: {"apiResponse": raw_total_body(recs, raw)}),
        ("json text", lambda recs, raw: json.dumps(raw_total_body(recs, raw))),
    ]


def bad_total_cases():
    for name in PRESENCE_CHECKS:
        for raw in BAD_TOTALS:
            for label, make in total_forms():
                yield pytest.param(name, raw, make, id=name + "-" + repr(raw) + "-" + label)


@pytest.mark.parametrize("name,raw,make", list(bad_total_cases()))
def test_unreadable_total_without_a_match_is_not_evaluated(name, raw, make):
    assert_not_evaluated(run(name, make(PRESENCE_CHECKS[name][2], raw)))
    assert_not_evaluated(run(name, make([], raw)))


@pytest.mark.parametrize("name,raw,make", list(bad_total_cases()))
def test_unreadable_total_beside_a_match_keeps_the_match(name, raw, make):
    out = run(name, make(PRESENCE_CHECKS[name][1], raw))
    assert_measured(out, True)
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
def test_the_unreadable_total_reason_says_so(name):
    out = run(name, raw_total_body(PRESENCE_CHECKS[name][2], "many"))
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["dataCollection"]["errors"])
    assert "total could not be read" in text


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
@pytest.mark.parametrize("raw", ABSENT_TOTALS, ids=repr)
def test_a_missing_or_blank_total_states_nothing_and_the_page_is_complete(name, raw):
    assert_measured(run(name, raw_total_body(PRESENCE_CHECKS[name][2], raw)), False)
    assert_measured(run(name, raw_total_body(PRESENCE_CHECKS[name][1], raw)), True)


@pytest.mark.parametrize("name", sorted(PRESENCE_CHECKS))
@pytest.mark.parametrize("raw", ["1", " 1 ", 1, "001"], ids=repr)
def test_a_readable_total_equal_to_the_page_is_complete(name, raw):
    page = PRESENCE_CHECKS[name][2][:1]
    assert len(page) == 1
    assert_measured(run(name, raw_total_body(page, raw)), False)


@pytest.mark.parametrize("raw", BAD_TOTALS, ids=repr)
@pytest.mark.parametrize("flabel,make", total_forms(), ids=[f[0] for f in total_forms()])
def test_move_audit_unreadable_total_cannot_prove_every_action_is_complete(raw, flabel, make):
    assert_not_evaluated(run(MOVE, make(GOOD_MOVES, raw)))
    assert_not_evaluated(run(MOVE, make(NO_MOVES, raw)))
    assert_not_evaluated(run(MOVE, make([], raw)))
    # a gap already seen is a proven negative; no unread page can close it
    assert_measured(run(MOVE, make(BAD_MOVES, raw)), False)


@pytest.mark.parametrize("raw", BAD_TOTALS, ids=repr)
@pytest.mark.parametrize("flabel,make", total_forms(), ids=[f[0] for f in total_forms()])
def test_allow_list_count_is_not_evaluated_with_an_unreadable_total(raw, flabel, make):
    assert_not_evaluated(run(ALLOW, make(ENTRIES, raw)))
    assert_not_evaluated(run(ALLOW, make([], raw)))
    assert_not_evaluated(run(ALLOW, raw_total_body(ENTRIES, raw, scroll="tok")))


@pytest.mark.parametrize("raw", BAD_TOTALS, ids=repr)
@pytest.mark.parametrize("flabel,make", total_forms(), ids=[f[0] for f in total_forms()])
def test_open_quarantined_count_is_not_evaluated_with_an_unreadable_total(raw, flabel, make):
    assert_not_evaluated(run(QUARANTINE, make([pending(), pending()], raw)))
    assert_not_evaluated(run(QUARANTINE, make([], raw)))
    assert_not_evaluated(run(QUARANTINE, raw_total_body([pending()], raw, scroll="tok")))


@pytest.mark.parametrize("raw", ABSENT_TOTALS, ids=repr)
def test_counts_with_a_missing_or_blank_total_keep_the_page_count(raw):
    assert_measured(run(ALLOW, raw_total_body(ENTRIES, raw)), len(ENTRIES))
    assert_measured(run(ALLOW, raw_total_body([], raw)), 0)
    assert_measured(run(QUARANTINE, raw_total_body([pending(), pending()], raw)), 2)
    assert_measured(run(QUARANTINE, raw_total_body([], raw)), 0)


# --- a type or saas field that is not text is an unreadable entry ---------------------------------------

# file -> the field it matches on
MATCH_FIELD = {
    "isaccounttakeoverdetectionenabled": "type",
    "isantiphishingenabled": "type",
    "isclouddataleakpreventionenabled": "type",
    "isshadowitdiscoveryenabled": "type",
    "islinkedo365accountactive": "saas",
    "isemailsecurityloggingenabled": "type",
}
NON_TEXT_FIELD_VALUES = [7, 0, True, False, 1.5, ["x"], {"v": "x"}]


def field_cases():
    for name, field in MATCH_FIELD.items():
        for bad in NON_TEXT_FIELD_VALUES:
            for label, make in readable_forms():
                yield pytest.param(name, field, bad, make, id=name + "-" + repr(bad) + "-" + label)


@pytest.mark.parametrize("name,field,bad,make", list(field_cases()))
def test_a_non_text_match_field_is_not_evaluated_without_a_match(name, field, bad, make):
    record = ev(**{field: bad})
    assert_not_evaluated(run(name, make([record])))
    assert_not_evaluated(run(name, make(PRESENCE_CHECKS[name][2] + [record])))


@pytest.mark.parametrize("name,field,bad,make", list(field_cases()))
def test_a_non_text_match_field_beside_a_match_keeps_the_match(name, field, bad, make):
    assert_measured(run(name, make(PRESENCE_CHECKS[name][1] + [ev(**{field: bad})])), True)


@pytest.mark.parametrize("name", sorted(MATCH_FIELD))
def test_a_non_text_match_field_on_a_partial_page_is_still_not_evaluated(name):
    field = MATCH_FIELD[name]
    assert_not_evaluated(run(name, envelope(PRESENCE_CHECKS[name][2] + [ev(**{field: 7})], scroll="tok")))


@pytest.mark.parametrize("name", sorted(MATCH_FIELD))
def test_the_non_text_match_field_reason_says_so(name):
    out = run(name, envelope(PRESENCE_CHECKS[name][2] + [ev(**{MATCH_FIELD[name]: 7})]))
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["dataCollection"]["errors"])
    assert "could not be read" in text


@pytest.mark.parametrize("name", sorted(MATCH_FIELD))
@pytest.mark.parametrize("empty", [None, "", "   "], ids=repr)
def test_a_missing_or_blank_match_field_is_a_readable_non_match(name, empty):
    field = MATCH_FIELD[name]
    expected = False
    out = run(name, envelope([ev(**{field: empty})]))
    if name == "isemailsecurityloggingenabled":
        # a record with no type is not a logged event, but it is a readable one
        assert_measured(out, expected)
    else:
        assert_measured(out, expected)
    gone = {k: v for k, v in ev().items() if k != field}
    assert_measured(run(name, envelope([gone])), expected)


# --- openQuarantinedMessagesCount: every None return reports the error itself --------------------------

# The four paths that answer None. Each one must set dataCollection.status "error" with the reason in
# dataCollection.errors from the inner function too, not only through the public wrapper.
QUARANTINE_NONE_PATHS = [
    ("unreadable entry", lambda: envelope([pending(), "garbled"])),
    ("stray entity", lambda: envelope([pending(isRestored="true")])),
    ("unreadable total", lambda: raw_total_body([pending()], "many")),
    ("paged, total below the page", lambda: envelope([pending(), pending()], scroll="tok", total=1)),
    ("paged, no total", lambda: {"responseEnvelope": {"scrollId": "tok"}, "responseData": [pending()]}),
]


@pytest.mark.parametrize("entry", ["transform_unmarked", "transform"])
@pytest.mark.parametrize("label,make", QUARANTINE_NONE_PATHS, ids=[p[0] for p in QUARANTINE_NONE_PATHS])
def test_open_quarantined_none_return_sets_the_data_collection_error(entry, label, make):
    out = getattr(load(QUARANTINE), entry)(make())
    assert value(out) is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert all(isinstance(e, str) and e for e in collection["errors"])
    assert collection["errors"] == out["additionalInfo"]["evaluation"]["failReasons"]
    assert SENTINEL not in json.dumps(out)


# --- (e) the live field name: entitySecurityResult, singular ----------------------------------------

def singular(e):
    """The live HEC search API names the block entitySecurityResult (measured on a real tenant,
    27 Oct 2026); the API reference and the builders above spell it entitySecurityResults."""
    e = dict(e)
    e["entitySecurityResult"] = e.pop("entitySecurityResults")
    return e


def test_click_time_and_av_read_the_singular_live_field_name():
    assert_measured(run("isclicktimeurlrewriteenabled", envelope([singular(entity(ctp="links_replaced", links=LINK))])), True)
    assert_measured(run("isantivirusverdictengineenabled", envelope([singular(entity(av="clean"))])), True)
    # the plural spelling still reads, so the API-reference shape is not broken
    assert_measured(run("isclicktimeurlrewriteenabled", envelope([entity(ctp="links_replaced", links=LINK)])), True)
    assert_measured(run("isantivirusverdictengineenabled", envelope([entity(av="clean")])), True)


@pytest.mark.parametrize("blank", [{}, None, "None"], ids=repr)
def test_a_present_singular_block_wins_over_a_stale_plural_one(blank):
    e = singular(entity(ctp="links_replaced", links=LINK))
    e["entitySecurityResults"] = e["entitySecurityResult"]
    e["entitySecurityResult"] = blank
    assert_measured(run("isclicktimeurlrewriteenabled", envelope([e])), False)
    a = singular(entity(av="clean"))
    a["entitySecurityResults"] = a["entitySecurityResult"]
    a["entitySecurityResult"] = blank
    assert_measured(run("isantivirusverdictengineenabled", envelope([a])), False)
