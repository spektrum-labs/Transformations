"""Check Point Harmony Email & Collaboration: the Atlas checks added 2026-09-25.

Four checks read queryOffice365Events, and fixtures/office365_events_real_2026-09-25.json is
that method's REAL first page from a customer tenant (scrubbed). isSPFEnforced reads the Spektrum DNS probe;
SPF_REAL is the real record shape from the same evaluation. isAntivirusVerdictEngineEnabled and
openQuarantinedMessagesCount read entity-search methods not yet in the live definition: their
bodies follow the HEC API reference response sample (Email Security API Reference Guide, 31 March
2026, 4.1 and 4.2) and are marked as such.

Every check gets: the real/doc body (expected verdict), a flip that must change the verdict, and
the fail-closed bodies (empty dict, None, an error envelope, a string that is not JSON)."""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
EVENTS = json.loads((HERE / "fixtures" / "office365_events_real_2026-09-25.json").read_text())


def load(name):
    spec = importlib.util.spec_from_file_location("cphec_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verdict(name, body):
    out = load(name).transform(body)
    key = [k for k in out["transformedResponse"]][0]
    return out["transformedResponse"][key]


def events(mutate=None, records=None):
    body = copy.deepcopy(EVENTS)
    if records is not None:
        body["responseData"] = records
    if mutate:
        for r in body["responseData"]:
            mutate(r)
    return body


ERROR_ENVELOPE = {"responseEnvelope": {"responseCode": "401", "responseText": "Unauthorized"}, "responseData": []}
UNREADABLE = [{}, None, ERROR_ENVELOPE, "not json", {"hello": "world"}]


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


EVENT_CASES = [
    # (file, real verdict, flip, flipped verdict)
    ("isemailsecurityloggingenabled", True, drop_actions, False),
    ("messagemoveaudittrailenabled", True, strip_create_time, False),
    ("ispostdeliveryquarantineenabled", True, no_quarantine, False),
    ("isimposteremaildetectionenabled", True, ms_only, False),
]


@pytest.mark.parametrize("name,real,flip,flipped", EVENT_CASES)
def test_event_checks_real_and_flipped(name, real, flip, flipped):
    assert verdict(name, events()) is real
    assert verdict(name, events(flip)) is flipped


@pytest.mark.parametrize("name", [c[0] for c in EVENT_CASES])
def test_event_checks_fail_closed(name):
    for body in UNREADABLE:
        assert verdict(name, body) is False, body
    assert verdict(name, events(records=[])) is False


@pytest.mark.parametrize("name", [c[0] for c in EVENT_CASES])
def test_event_checks_accept_wrapped_and_string_forms(name):
    assert verdict(name, {"apiResponse": events()}) is True
    assert verdict(name, json.dumps(events())) is True


def test_real_page_facts_the_checks_rely_on():
    recs = EVENTS["responseData"]
    assert len(recs) == 100
    assert sum(1 for r in recs if "avanan_ap_scan" in r["data"]) == 84
    assert sum(1 for r in recs for a in r["actions"] if a["actionType"] == "quarantine_email") == 14


def test_move_audit_ignores_non_move_actions():
    def headers_only(r):
        r["actions"] = [a for a in r["actions"] if a["actionType"].startswith("add_")]
    assert verdict("messagemoveaudittrailenabled", events(headers_only)) is False


def test_logging_needs_events_with_core_fields():
    def blank(r):
        r["eventCreated"] = "None"
    assert verdict("isemailsecurityloggingenabled", events(blank)) is False


# isSPFEnforced: Spektrum DNS probe (isDNSConfigured); real record shape, tenant id replaced.
SPF_REAL = {"SPF": "v=spf1 include:abc123xyz.spf.checkpoint-spf.com include:spf.protection.outlook.com ~all",
            "DKIM": "v=DKIM1; k=rsa; p=MIGf", "DMARC": "v=DMARC1; p=reject", "SMTPBanner": "None"}


def spf(record):
    return dict(SPF_REAL, SPF=record)


@pytest.mark.parametrize("body,expected", [
    (SPF_REAL, True),
    ({"result": SPF_REAL}, True),
    (json.dumps({"apiResponse": SPF_REAL}), True),
    (spf("v=spf1 include:spfr.cpmails.com -all"), True),
    (spf("v=spf1 include:spf.protection.outlook.com ~all"), False),
    (spf("v=spf1 include:abc.spf.checkpoint-spf.com +all"), False),
    (spf("v=spf1 include:abc.spf.checkpoint-spf.com ?all"), False),
    (spf("v=spf1 include:abc.spf.checkpoint-spf.com"), False),
    (spf("v=spf1 include:checkpoint-spf.com.evil.example ~all"), False),
    (spf(False), False),
    (spf("None"), False),
    ({}, False), (None, False), ("not json", False), ({"error": "timeout"}, False),
])
def test_spf_enforced(body, expected):
    assert verdict("isspfenforced", body) is expected


# Entity search (HEC API reference 4.1/4.2 response sample). No live payload yet.
def entity(av=None, combined_av=None, payload=None):
    return {
        "entityInfo": {"entityId": "b05f596bc33cf53b74ea75e37cf66b98", "saas": "office365_emails",
                       "saasEntityType": "office365_emails_email", "entityActionState": "Clean"},
        "entityPayload": payload if payload is not None else {"attachmentCount": "1", "isQuarantined": "false"},
        "entitySecurityResults": {
            "combinedVerdict": {"ap": "clean", "dlp": None, "clicktimeProtection": None, "shadowIt": "clean",
                                "av": combined_av},
            "ap": [], "dlp": None, "clicktimeProtection": None, "shadowIt": [],
            "av": av,
        },
        "entityActions": [{}],
        "entityAvailableActions": [{"entityActionName": "quarantine", "entityActionParam": ""}],
    }


def search(entities, records=None, scroll=""):
    return {"responseEnvelope": {"requestId": "r", "responseCode": 0, "responseText": "Success",
                                 "recordsNumber": len(entities) if records is None else records,
                                 "totalRecordsNumber": len(entities), "scrollId": scroll},
            "responseData": entities}


AV_RESULT = [{"entityId": "a", "entityType": "office365_emails_email", "payload": {}, "score": "0",
              "securityResultEntityType": "checkpoint_av_scan", "statusCode": "0", "verdict": "clean"}]


@pytest.mark.parametrize("body,expected", [
    (search([entity(av=AV_RESULT), entity()]), True),
    (search([entity(combined_av="clean")]), True),
    (search([entity(av=AV_RESULT)], records="1"), True),
    (search([entity(), entity(av=[])]), False),
    (search([entity(combined_av="None")]), False),
    (search([]), False),
    ({}, False), (None, False), (ERROR_ENVELOPE, False), ("not json", False),
])
def test_antivirus_verdict_engine(body, expected):
    assert verdict("isantivirusverdictengineenabled", body) is expected


def pending(**over):
    p = {"isQuarantined": "true", "isRestoreRequested": "true", "isRestored": "false", "isRestoreDeclined": "false"}
    p.update(over)
    return entity(payload=p)


@pytest.mark.parametrize("body,expected", [
    (search([]), 0),
    (search([], records="0"), 0),
    (search([pending(), pending()]), 2),
    (search([pending()] * 3, records="250", scroll="next"), 250),
    (search([pending()] * 3, records="1"), 3),
    (search([pending(isRestoreRequested=True, isRestored=False, isRestoreDeclined=False)]), 1),
    (search([pending(), pending(isRestored="true")]), None),
    (search([pending(isRestoreRequested="false")]), None),
    (search([entity()]), None),
    (search([pending()], records="None", scroll="next"), None),
    ({}, None), (None, None), (ERROR_ENVELOPE, None), ("not json", None),
])
def test_open_quarantined_messages_count(body, expected):
    assert verdict("openquarantinedmessagescount", body) == expected


# isDKIMConfigured / isDMARCConfigured / isSPFConfigured reuse mimecast/isdnsconfigured.py on the same
# Spektrum DNS probe (the isDNSConfigured method this change copies into the Check Point definition).
DNS_FILE = HERE.parent / "mimecast" / "isdnsconfigured.py"


def dns(body):
    spec = importlib.util.spec_from_file_location("cphec_dns", DNS_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)["transformedResponse"]


@pytest.mark.parametrize("key,proto", [("isSPFConfigured", "SPF"), ("isDKIMConfigured", "DKIM"),
                                       ("isDMARCConfigured", "DMARC")])
def test_dns_configured_keys(key, proto):
    assert dns(SPF_REAL)[key] is True
    assert dns({"result": SPF_REAL})[key] is True
    assert dns(dict(SPF_REAL, **{proto: False}))[key] is False
    assert dns(dict(SPF_REAL, **{proto: "None"}))[key] is False
    for body in ({}, None, "not json", {"error": "timeout"}):
        assert dns(body)[key] is False, body


# isClickTimeURLRewriteEnabled: entity search for emails with links (HEC API reference 4.2). No live payload yet.
def linked(ctp=None, combined=None, links=("https://example.com/a",)):
    e = entity(payload={"attachmentCount": "0", "emailLinks": list(links)})
    e["entitySecurityResults"]["combinedVerdict"]["clicktimeProtection"] = combined
    e["entitySecurityResults"]["clicktimeProtection"] = ctp
    return e


CTP_RESULT = [{"entityId": "a", "entityType": "office365_emails_email", "payload": {}, "score": "0",
               "securityResultEntityType": "click_time_protection", "statusCode": "0", "verdict": "clean"}]


@pytest.mark.parametrize("body,expected", [
    (search([linked(combined="clean"), linked()]), True),
    (search([linked(ctp=CTP_RESULT)]), True),
    (json.dumps({"apiResponse": search([linked(combined="malicious")])}), True),
    (search([linked(), linked(ctp=[])]), False),
    (search([linked(combined="None")]), False),
    # an entity without links does not count, even with a verdict: the vendor filter is not trusted
    (search([linked(combined="clean", links=())]), False),
    (search([]), False),
    ({}, False), (None, False), (ERROR_ENVELOPE, False), ("not json", False),
])
def test_click_time_url_rewrite(body, expected):
    assert verdict("isclicktimeurlrewriteenabled", body) is expected


# isURLReputationBlockListEnforced: GET /exceptions/blacklist. Entry shape = the live getAntiPhishingAllowList
# read (same schema per API reference 6.1), stored-raw strings; values synthetic.
def exc(link_domains="None", sender="None"):
    return {"entityId": "100", "attachmentMd5": "None", "senderEmail": sender, "senderName": "None",
            "recipient": "None", "senderClientIp": "None", "domain": "None", "senderDomain": "None",
            "senderIp": "None", "linkDomains": link_domains, "subject": "None", "comment": "",
            "actionNeeded": "", "ignoringSpfCheck": "False", "subjectMatching": "contains",
            "linkDomainMatching": "contains", "senderNameMatching": "", "senderDomainMatching": "",
            "senderEmailMatching": "", "recipientMatching": "", "addedBy": "1", "editedBy": "", "updateTime": ""}


def exceptions(entries):
    return {"responseEnvelope": {"requestId": "r", "responseCode": "200", "responseText": "", "additionalText": "",
                                 "recordsNumber": str(len(entries)), "scrollId": "None"},
            "responseData": entries}


@pytest.mark.parametrize("body,expected", [
    (exceptions([exc(link_domains="bad.example, worse.example"), exc(sender="a@b.example")]), True),
    ({"apiResponse": exceptions([exc(link_domains="bad.example")])}, True),
    (exceptions([exc(sender="a@b.example"), exc()]), False),
    (exceptions([exc(link_domains="  ")]), False),
    (exceptions([]), False),
    ({}, False), (None, False), (ERROR_ENVELOPE, False), ("not json", False),
])
def test_url_block_list(body, expected):
    assert verdict("isurlreputationblocklistenforced", body) is expected
