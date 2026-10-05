"""Proofpoint Essentials email-security checks.

Bodies follow the Proofpoint Essentials API specification
(https://us1.proofpointessentials.com/api/v1/docs/specification.php: GET /me, /orgs/{domain},
/orgs/{domain}/features, /licensing, /email-tagging, /reporting/{domain}/{period},
/orgs/{domain}/domains/{targetDomain}/dkim) as projected and merged by the Integration-Service
workflows. Every domain, name and number is synthetic."""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("ppe_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


KEYS = ["confirmedLicensePurchased", "isAntiPhishingEnabled", "isSafeLinksEnabled", "isURLRewriteEnabled",
        "isClickTimeURLRewriteEnabled", "isSafeAttachmentsEnabled", "isAttachmentSandboxDetonationEnabled",
        "isPostDeliveryQuarantineEnabled", "isEmailWarningTagsEnabled", "isDKIMConfigured"]
T = {key: load(key.lower()) for key in KEYS}
FEATURE_KEYS = {"isSafeLinksEnabled": "url_defense", "isURLRewriteEnabled": "url_defense",
                "isClickTimeURLRewriteEnabled": "url_defense", "isSafeAttachmentsEnabled": "attachment_defense",
                "isAttachmentSandboxDetonationEnabled": "attachment_defense_sandboxing",
                "isPostDeliveryQuarantineEnabled": "automatic_remediation"}

ME = {"type": "organization_admin", "is_admin": True, "is_partner_admin": False, "read_only_user": True,
      "entity_type": "organization", "entity_primary_domain": "example.com"}
ORG = {"primary_domain": "example.com", "is_active": True, "type": "organization",
       "licensing_package": "professional_plus", "is_on_trial": False, "user_licenses": 120, "active_users": 97,
       "when_renewal": "2027-03-01", "deployment_method": "mx_record", "configuration_type": "manual",
       "domains": [{"name": "example.com", "is_active": True, "is_relay": True},
                   {"name": "example.net", "is_active": False, "is_relay": False}]}
FEATURES = {"attachment_defense": True, "attachment_defense_sandboxing": "true", "url_defense": True,
            "anti_spoofing": True, "email_warning_tags": True, "automatic_remediation": True,
            "instant_replay": "30", "dlp": True}
LICENSING = {"license_count": 120, "package": "professional_plus", "is_on_trial": False, "is_beginner_plus": False}
REPORT = {"period": "30d", "frequency": "24h",
          "inbound": {"clean_total": 9100, "spam_total": 820, "virus_total": 4, "fraud_total": 11,
                      "blocklist_total": 3, "safelist_total": 40, "attachment_defended_total": 610}}
TAGGING = {"email_warning_tags": {"is_enabled": True, "info_tags": {"external_sender": True},
                                  "warning_tags": {"dmarc_failure": True, "domain_age_failure": False,
                                                   "geo_ip_failure": True}},
           "email_subject_tags": {"is_enabled": False}}
DKIM = [[{"did": 1, "domain": "example.com", "is_valid": True, "selector": "s1", "public_key": "UFVCTElD"}],
        [{"did": 2, "domain": "example.net", "is_valid": True, "selector": "s1", "public_key": "UFVCTElD"}]]


def estate(**changes):
    body = {"me": copy.deepcopy(ME), "organization": copy.deepcopy(ORG), "features": copy.deepcopy(FEATURES),
            "licensing": copy.deepcopy(LICENSING), "inboundReport": copy.deepcopy(REPORT),
            "emailTagging": copy.deepcopy(TAGGING), "dkim": copy.deepcopy(DKIM)}
    body.update(changes)
    return body


def verdict(key, body):
    out = T[key](body)
    assert set(out) == {"transformedResponse", "additionalInfo"}
    return out["transformedResponse"][key], out["additionalInfo"]


def text(info):
    return json.dumps(info["evaluation"]) + json.dumps(info["dataCollection"])


# ── every check passes on a well-configured organization ────────────────────

@pytest.mark.parametrize("key", KEYS)
def test_good_estate_passes(key):
    value, info = verdict(key, estate())
    assert value is True, info
    assert info["dataCollection"]["status"] == "success"
    assert info["evaluation"]["passReasons"]


@pytest.mark.parametrize("key", KEYS)
def test_good_estate_passes_under_the_usual_wrappers_and_as_a_string(key):
    assert verdict(key, {"apiResponse": {"data": estate()}})[0] is True
    assert verdict(key, json.dumps(estate()))[0] is True


# ── fail closed: nothing that proves nothing may pass ───────────────────────

NO_EVIDENCE = [None, {}, "{}", "", [], {"apiResponse": {}},
               {"error": True, "errorType": "vendor_error", "statusCode": 401, "message": "Unauthorized"},
               {"error": True, "errorType": "vendor_error", "statusCode": 403, "message": "Forbidden"},
               {"statusCode": 500, "message": "internal server error"}]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(key, body):
    value, info = verdict(key, body)
    assert value is None
    assert info["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("leg", ["me", "organization"])
@pytest.mark.parametrize("bad", [{"error": True, "statusCode": 401, "message": "Unauthorized"},
                                 {"statusCode": 403}, {}, None])
def test_an_unreadable_identity_leg_is_not_evaluated(key, leg, bad):
    body = estate(**{leg: bad})
    assert verdict(key, body)[0] is None


@pytest.mark.parametrize("key", KEYS)
def test_a_partner_login_is_refused(key):
    for me in (dict(ME, is_partner_admin=True), dict(ME, type="channel_admin"),
               dict(ME, entity_type="channel", entity_primary_domain="msp.example")):
        value, info = verdict(key, estate(me=me))
        assert value is None
        assert "partner" in text(info)


@pytest.mark.parametrize("key", KEYS)
def test_a_login_for_another_organization_is_refused(key):
    value, info = verdict(key, estate(me=dict(ME, entity_primary_domain="other.example")))
    assert value is None
    assert info["dataCollection"]["errors"] == [
        "the connected login belongs to other.example, not to example.com; "
        "connect with an Organization Admin of example.com"]


@pytest.mark.parametrize("key", [k for k in KEYS if k not in ("confirmedLicensePurchased",)])
def test_the_own_leg_failing_is_not_evaluated(key):
    leg = {"isAntiPhishingEnabled": "inboundReport", "isEmailWarningTagsEnabled": "emailTagging",
           "isDKIMConfigured": "dkim"}.get(key, "features")
    for bad in ({"error": True, "statusCode": 401}, {"statusCode": 403, "message": "not authorized"}, {}):
        assert verdict(key, estate(**{leg: bad}))[0] is None, (leg, bad)


# ── feature flags ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("key", list(FEATURE_KEYS))
def test_feature_off_fails(key):
    flag = FEATURE_KEYS[key]
    for off in (False, "false", "False", 0, "0"):
        value, info = verdict(key, estate(features=dict(FEATURES, **{flag: off})))
        assert value is False, off
        assert flag in text(info)


@pytest.mark.parametrize("key", list(FEATURE_KEYS))
def test_feature_unrecognised_or_missing_is_not_evaluated(key):
    flag = FEATURE_KEYS[key]
    assert verdict(key, estate(features=dict(FEATURES, **{flag: "30"})))[0] is None
    missing = dict(FEATURES)
    missing.pop(flag)
    assert verdict(key, estate(features=missing))[0] is None, "the package includes it, so absence is a read gap"


def test_a_feature_outside_the_package_fails():
    features = {"anti_spoofing": True, "disclaimers": True, "smtp_discovery": True}
    beginner = estate(features=features, organization=dict(ORG, licensing_package="beginner"))
    for key in FEATURE_KEYS:
        value, info = verdict(key, beginner)
        assert value is False, key
        assert "beginner" in text(info)
    advanced = estate(features={"url_defense": True, "attachment_defense": True, "anti_spoofing": True},
                      organization=dict(ORG, licensing_package="advanced"))
    assert verdict("isPostDeliveryQuarantineEnabled", advanced)[0] is False
    assert verdict("isAttachmentSandboxDetonationEnabled", advanced)[0] is None


@pytest.mark.parametrize("key", list(FEATURE_KEYS) + ["isAntiPhishingEnabled", "confirmedLicensePurchased"])
def test_an_inactive_organization_fails(key):
    assert verdict(key, estate(organization=dict(ORG, is_active=False)))[0] is False


def test_stored_string_leaves_read_the_same():
    """Token-Service stores raw responses with every leaf as a string."""
    org = dict(ORG, is_active="True", is_on_trial="False", user_licenses="120", active_users="97")
    features = {k: str(v) for k, v in FEATURES.items()}
    report = {"period": "30d", "inbound": {k: str(v) for k, v in REPORT["inbound"].items()}}
    body = estate(organization=org, features=features, inboundReport=report,
                  me=dict(ME, is_partner_admin="False"),
                  licensing={k: str(v) for k, v in LICENSING.items()})
    for key in ("confirmedLicensePurchased", "isAntiPhishingEnabled", "isSafeLinksEnabled"):
        assert verdict(key, body)[0] is True, key


# ── licence ─────────────────────────────────────────────────────────────────

def test_licence_reports_coverage_counts():
    out = T["confirmedLicensePurchased"](estate())
    result = out["transformedResponse"]
    assert result["licensedUsers"] == 120 and result["activeUsers"] == 97
    assert result["domainCount"] == 2 and result["activeRelayDomainCount"] == 1


def test_a_trial_or_no_licences_fails():
    assert verdict("confirmedLicensePurchased", estate(licensing=dict(LICENSING, is_on_trial=True)))[0] is False
    assert verdict("confirmedLicensePurchased", estate(licensing=dict(LICENSING, license_count=0)))[0] is False


def test_licence_fields_missing_is_not_evaluated():
    org = dict(ORG)
    org.pop("is_on_trial")
    value, info = verdict("confirmedLicensePurchased", estate(licensing={"package": "business"}, organization=org))
    assert value is None and "trial state" in text(info)


# ── anti-phishing: anti-spoofing plus mail actually filtered ────────────────

def test_anti_spoofing_off_fails():
    assert verdict("isAntiPhishingEnabled", estate(features=dict(FEATURES, anti_spoofing="false")))[0] is False


def test_no_inbound_mail_filtered_fails():
    zero = {"period": "30d", "inbound": {k: 0 for k in REPORT["inbound"]}}
    value, info = verdict("isAntiPhishingEnabled", estate(inboundReport=zero))
    assert value is False and "no inbound mail" in text(info)


def test_inbound_totals_missing_is_not_evaluated():
    partial = {"period": "30d", "inbound": {"clean_total": 10}}
    assert verdict("isAntiPhishingEnabled", estate(inboundReport=partial))[0] is None
    assert verdict("isAntiPhishingEnabled", estate(inboundReport={"period": "30d"}))[0] is None


def test_anti_phishing_reports_what_was_blocked():
    out = T["isAntiPhishingEnabled"](estate())
    assert out["transformedResponse"]["inboundFiltered30d"] == 9100 + 820 + 4 + 11 + 3 + 40
    assert out["transformedResponse"]["inboundBlocked30d"] == 820 + 4 + 11 + 3


# ── warning tags ────────────────────────────────────────────────────────────

def test_warning_tags_off_or_without_external_sender_fails():
    off = copy.deepcopy(TAGGING)
    off["email_warning_tags"]["is_enabled"] = False
    assert verdict("isEmailWarningTagsEnabled", estate(emailTagging=off))[0] is False
    no_external = copy.deepcopy(TAGGING)
    no_external["email_warning_tags"]["info_tags"]["external_sender"] = False
    assert verdict("isEmailWarningTagsEnabled", estate(emailTagging=no_external))[0] is False


def test_warning_tag_fields_missing_is_not_evaluated():
    assert verdict("isEmailWarningTagsEnabled", estate(emailTagging={"email_subject_tags": {}}))[0] is None
    partial = {"email_warning_tags": {"is_enabled": True}}
    assert verdict("isEmailWarningTagsEnabled", estate(emailTagging=partial))[0] is None


# ── DKIM ────────────────────────────────────────────────────────────────────

def test_dkim_primary_unsigned_fails_when_essentials_signs_for_another_domain():
    dkim = [[], DKIM[1]]
    value, info = verdict("isDKIMConfigured", estate(dkim=dkim))
    summary = info["transformation"]["inputSummary"]
    assert value is False
    assert summary["primaryDomain"] == "example.com" and summary["unsignedDomains"] == ["example.com"]
    assert summary["validDomains"] == ["example.net"]


def test_dkim_invalid_keys_fail():
    dkim = [DKIM[0], [{"domain": "example.net", "is_valid": False, "selector": "s1"}]]
    value, info = verdict("isDKIMConfigured", estate(dkim=dkim))
    assert value is False
    assert info["transformation"]["inputSummary"]["invalidDomains"] == ["example.net"]


def test_dkim_unsigned_secondary_domain_still_passes_and_is_named():
    out = T["isDKIMConfigured"](estate(dkim=[DKIM[0], []]))
    assert out["transformedResponse"]["isDKIMConfigured"] is True
    findings = out["additionalInfo"]["evaluation"]["additionalFindings"]
    assert findings[-1] == "Domains with no Proofpoint Essentials DKIM key: example.net"


def test_dkim_wrapped_responses_read_the_same():
    assert verdict("isDKIMConfigured", estate(dkim=[{"apiResponse": DKIM[0]}, {"apiResponse": DKIM[1]}]))[0] is True


@pytest.mark.parametrize("dkim, extra", [
    ([[], []], {}),                                                    # Essentials signs nothing: not ours to judge
    ([DKIM[0]], {}),                                                   # one response for two domains
    ([DKIM[0], {"error": True, "statusCode": 403}], {}),               # one domain unreadable
    ([DKIM[1], DKIM[0]], {}),                                          # responses not aligned with domains
    ([DKIM[0], [{"domain": "example.net", "selector": "s1"}]], {}),    # validation state missing
    (DKIM, {"iterateTruncated": True}),                                # more domains than were read
    ({"error": True, "statusCode": 401}, {}),
    (None, {}),
])
def test_dkim_incomplete_reads_are_not_evaluated(dkim, extra):
    body = estate(dkim=dkim)
    body.update(extra)
    assert verdict("isDKIMConfigured", body)[0] is None
