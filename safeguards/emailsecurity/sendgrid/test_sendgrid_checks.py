"""SendGrid email-security checks.

Bodies follow the SendGrid v3 API reference as merged by the Integration-Service workflows
(GET /v3/user/settings/enforced_tls, /v3/sso/integrations, /v3/access_settings/whitelist,
/v3/whitelabel/domains, /v3/whitelabel/links). The fixtures mirror a read of a real account taken
2026-10-16 with every address, id and name replaced by synthetic values."""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("sg_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


KEYS = {
    "isOutboundTLSEnforced": "enforcedTls",
    "isOutboundCertificateValidationEnforced": "enforcedTls",
    "isOutboundMinimumTLSVersionSecure": "enforcedTls",
    "isSSOEnabled": "ssoIntegrations",
    "isSSOEnforcedForAllUsers": "teammates",
    "isIPAllowlistEnabled": "ipAllowlist",
    "areSendingDomainsAuthenticated": "authenticatedDomains",
    "isLinkBrandingValid": "brandedLinks",
}
T = {key: load(key.lower()) for key in KEYS}

TLS_OFF = {"require_tls": False, "require_valid_cert": False, "version": 1.1}
TLS_ON = {"require_tls": True, "require_valid_cert": True, "version": 1.2}
SSO = [{"id": "11111111-aaaa-4aaa-8aaa-000000000001", "name": "Okta IdP configuration", "enabled": True,
        "completed_integration": True, "jit_provisioning_enabled": True}]
WHITELIST = {"result": [{"id": 1, "ip": "203.0.113.0/24", "created_at": 1700000000, "updated_at": 1700000000}]}
TEAMMATES_OK = {"result": [{"username": "alex@example.com", "is_sso": True, "user_type": "admin"},
                           {"username": "sam", "is_sso": True, "user_type": "teammate"}]}
# Shape only (synthetic names and counts): 5 teammates, 3 with SSO, 2 without.
TEAMMATES_MIXED = {"result": [{"username": n + "@example.com", "email": n + "@example.com", "is_sso": v}
                              for n, v in (("a", True), ("b", True), ("c", True), ("d", False), ("e", False))]}
ACTIVITY_UNUSED = {"result": []}


def domain(name, valid=True):
    return {"id": 1, "domain": name, "subdomain": "em1", "valid": valid, "default": False, "legacy": False,
            "dns": {"mail_cname": {"valid": valid}, "dkim1": {"valid": valid}, "dkim2": {"valid": valid}}}


def link(name, valid=True):
    return {"id": 2, "domain": name, "subdomain": "url1", "valid": valid, "default": False, "legacy": False,
            "dns": {"domain_cname": {"valid": valid}, "owner_cname": {"valid": valid}}}


PAGED = ("isSSOEnforcedForAllUsers", "areSendingDomainsAuthenticated", "isLinkBrandingValid")


def payload(key, body):
    """What the workflow hands the transform: the leg, plus (for the paged reads) the completeness marker
    reportPagination attaches: paginationStats[leg].paginationTruncated false."""
    data = {KEYS[key]: copy.deepcopy(body)}
    if key in PAGED:
        data["paginationStats"] = {KEYS[key]: {"paginationTruncated": False}}
    return data


def run(key, body, wrap=None):
    data = payload(key, body)
    if wrap:
        for name in wrap:
            data = {name: data}
    return T[key](data)


def value(result, key):
    return result["transformedResponse"][key]


def status(result):
    return result["additionalInfo"]["dataCollection"]["status"]


# ---- Enforced TLS -------------------------------------------------------------------------------

def test_tls_off_is_false_for_all_three():
    for key in ("isOutboundTLSEnforced", "isOutboundCertificateValidationEnforced", "isOutboundMinimumTLSVersionSecure"):
        result = run(key, TLS_OFF)
        assert value(result, key) is False, key
        assert status(result) == "success"
        assert result["additionalInfo"]["evaluation"]["failReasons"], key


def test_tls_on_is_true_for_all_three():
    for key in ("isOutboundTLSEnforced", "isOutboundCertificateValidationEnforced", "isOutboundMinimumTLSVersionSecure"):
        result = run(key, TLS_ON)
        assert value(result, key) is True, key
        assert result["additionalInfo"]["evaluation"]["passReasons"], key


def test_tls_and_certificate_are_independent():
    body = {"require_tls": True, "require_valid_cert": False, "version": 1.2}
    assert value(run("isOutboundTLSEnforced", body), "isOutboundTLSEnforced") is True
    assert value(run("isOutboundCertificateValidationEnforced", body), "isOutboundCertificateValidationEnforced") is False


def test_certificate_check_is_false_when_tls_is_not_required_like_the_version_check():
    body = {"require_tls": False, "require_valid_cert": True, "version": 1.2}
    result = run("isOutboundCertificateValidationEnforced", body)
    assert value(result, "isOutboundCertificateValidationEnforced") is False
    assert status(result) == "success"
    assert "TLS is not required" in result["additionalInfo"]["evaluation"]["failReasons"][0]
    for text in ("false", "False"):
        assert value(run("isOutboundCertificateValidationEnforced", dict(body, require_tls=text)),
                     "isOutboundCertificateValidationEnforced") is False


def test_certificate_check_needs_both_flags_to_be_readable():
    for body in ({"require_valid_cert": True}, {"require_tls": True}, {"require_tls": None, "require_valid_cert": True}):
        result = run("isOutboundCertificateValidationEnforced", body)
        assert value(result, "isOutboundCertificateValidationEnforced") is None
        assert status(result) == "error"


def test_minimum_version_below_1_2_is_false_even_when_tls_required():
    body = {"require_tls": True, "require_valid_cert": True, "version": 1.1}
    assert value(run("isOutboundMinimumTLSVersionSecure", body), "isOutboundMinimumTLSVersionSecure") is False


def test_minimum_version_1_2_without_required_tls_is_false():
    body = {"require_tls": False, "require_valid_cert": False, "version": 1.2}
    result = run("isOutboundMinimumTLSVersionSecure", body)
    assert value(result, "isOutboundMinimumTLSVersionSecure") is False
    assert "not required" in result["additionalInfo"]["evaluation"]["failReasons"][0]


def test_minimum_version_1_3_and_string_forms_are_secure():
    for version in (1.3, "1.3", "1.2", 1.2):
        body = {"require_tls": "true", "require_valid_cert": True, "version": version}
        assert value(run("isOutboundMinimumTLSVersionSecure", body), "isOutboundMinimumTLSVersionSecure") is True, version


def test_tls_string_false_is_false_not_truthy():
    body = {"require_tls": "false", "require_valid_cert": "false", "version": "1.2"}
    assert value(run("isOutboundTLSEnforced", body), "isOutboundTLSEnforced") is False
    assert value(run("isOutboundCertificateValidationEnforced", body), "isOutboundCertificateValidationEnforced") is False


@pytest.mark.parametrize("key", ["isOutboundTLSEnforced", "isOutboundCertificateValidationEnforced", "isOutboundMinimumTLSVersionSecure"])
@pytest.mark.parametrize("body", [
    {"errors": [{"field": None, "message": "access forbidden"}]},
    {"statusCode": 403, "message": "Forbidden"},
    {"error": True, "statusCode": 401, "message": "authorization required"},
    {}, [], "", None, "oops", {"require_tls": "maybe", "require_valid_cert": "maybe", "version": "x"},
])
def test_tls_unreadable_is_not_evaluated(key, body):
    result = T[key]({"enforcedTls": copy.deepcopy(body)})
    assert value(result, key) is None
    assert status(result) == "error"
    assert result["additionalInfo"]["dataCollection"]["errors"]


def test_missing_version_is_not_evaluated_only_for_the_version_check():
    body = {"require_tls": True, "require_valid_cert": True}
    result = run("isOutboundMinimumTLSVersionSecure", body)
    assert value(result, "isOutboundMinimumTLSVersionSecure") is None
    assert status(result) == "error"
    assert value(run("isOutboundTLSEnforced", body), "isOutboundTLSEnforced") is True


@pytest.mark.parametrize("key", list(KEYS))
@pytest.mark.parametrize("input", [{}, [], "", None, "not json", {"data": {}}, {"unrelated": {}}, 42])
def test_missing_leg_is_not_evaluated(key, input):
    result = T[key](input)
    assert value(result, key) is None
    assert status(result) == "error"


@pytest.mark.parametrize("key", list(KEYS))
def test_input_as_json_string_and_wrappers(key):
    good = {"isOutboundTLSEnforced": TLS_ON, "isOutboundCertificateValidationEnforced": TLS_ON,
            "isOutboundMinimumTLSVersionSecure": TLS_ON, "isSSOEnabled": SSO, "isSSOEnforcedForAllUsers": TEAMMATES_OK, "isIPAllowlistEnabled": WHITELIST,
            "areSendingDomainsAuthenticated": [domain("example.com")], "isLinkBrandingValid": [link("example.com")]}[key]
    plain = value(run(key, good), key)
    assert plain is True
    assert value(run(key, good, wrap=["data"]), key) is True
    assert value(run(key, good, wrap=["apiResponse", "response"]), key) is True
    assert value(T[key](json.dumps(payload(key, good))), key) is True
    assert value(T[key](json.dumps(payload(key, good)).encode("utf-8")), key) is True


# ---- SSO ----------------------------------------------------------------------------------------

def test_sso_enabled_and_completed_is_true():
    result = run("isSSOEnabled", SSO)
    assert value(result, "isSSOEnabled") is True
    assert "Okta IdP configuration" in result["additionalInfo"]["evaluation"]["passReasons"][0]


def test_sso_none_configured_is_false():
    result = run("isSSOEnabled", [])
    assert value(result, "isSSOEnabled") is False
    assert status(result) == "success"


def test_sso_disabled_or_unfinished_is_false_with_finding():
    items = [dict(SSO[0], enabled=False), dict(SSO[0], name="Half done", completed_integration=False)]
    result = run("isSSOEnabled", items)
    assert value(result, "isSSOEnabled") is False
    assert result["additionalInfo"]["evaluation"]["additionalFindings"]


def test_sso_one_active_among_inactive_is_true_with_finding():
    items = [dict(SSO[0], enabled=False, name="Old"), SSO[0]]
    result = run("isSSOEnabled", items)
    assert value(result, "isSSOEnabled") is True
    assert "Old" in result["additionalInfo"]["evaluation"]["additionalFindings"][0]


def test_sso_list_under_a_wrapper_key_is_read():
    assert value(T["isSSOEnabled"]({"ssoIntegrations": {"result": SSO}}), "isSSOEnabled") is True


@pytest.mark.parametrize("body", [
    {"errors": [{"field": None, "message": "access forbidden"}]},
    {"statusCode": 403}, {"error": True, "message": "x"}, "text", 5, None, {"unrecognised": []},
    [{"enabled": True}], [{"completed_integration": True}], ["not an object"], [dict(SSO[0], enabled="maybe")],
])
def test_sso_unreadable_is_not_evaluated(body):
    result = T["isSSOEnabled"]({"ssoIntegrations": body})
    assert value(result, "isSSOEnabled") is None
    assert status(result) == "error"


def test_sso_list_is_not_paged_so_a_long_list_is_read_whole():
    items = [dict(SSO[0], enabled=False) for index in range(120)] + [SSO[0]]
    assert value(run("isSSOEnabled", items), "isSSOEnabled") is True


# ---- IP allow list ------------------------------------------------------------------------------

def test_ip_allowlist_with_entries_is_true_and_addresses_are_not_kept():
    result = run("isIPAllowlistEnabled", WHITELIST)
    assert value(result, "isIPAllowlistEnabled") is True
    assert result["transformedResponse"]["allowlistEntries"] == 1
    assert "203.0.113" not in json.dumps(result)


@pytest.mark.parametrize("entries", [[{}], [{"id": 1}], [{"id": 1, "ip": ""}], [{"id": 1, "ip": "   "}],
                                     [{"id": 1, "ip": None}], [{"ip": "203.0.113.5"}, {"id": 2}]])
def test_ip_allowlist_entry_without_an_address_is_not_evaluated(entries):
    result = T["isIPAllowlistEnabled"]({"ipAllowlist": {"result": entries}})
    assert value(result, "isIPAllowlistEnabled") is None
    assert status(result) == "error"
    assert "no ip address" in result["additionalInfo"]["dataCollection"]["errors"][0]


def test_ip_allowlist_empty_is_false():
    result = run("isIPAllowlistEnabled", {"result": []})
    assert value(result, "isIPAllowlistEnabled") is False
    assert status(result) == "success"


@pytest.mark.parametrize("body", [
    {"errors": [{"field": None, "message": "access forbidden"}]}, {"statusCode": 403}, {"error": True},
    "text", None, {"unrecognised": 1}, {"result": "none"}, {"result": ["not an object"]},
])
def test_ip_allowlist_unreadable_is_not_evaluated(body):
    result = T["isIPAllowlistEnabled"]({"ipAllowlist": body})
    assert value(result, "isIPAllowlistEnabled") is None
    assert status(result) == "error"


# ---- Sender authentication ----------------------------------------------------------------------

def test_domains_all_valid_is_true():
    result = run("areSendingDomainsAuthenticated", [domain("example.com"), domain("example.net")])
    assert value(result, "areSendingDomainsAuthenticated") is True
    assert result["transformedResponse"]["authenticatedDomains"] == 2


def test_domain_with_only_invalid_record_is_false():
    result = run("areSendingDomainsAuthenticated", [domain("example.com"), domain("example.net", valid=False)])
    assert value(result, "areSendingDomainsAuthenticated") is False
    assert result["additionalInfo"]["evaluation"]["failReasons"] == ["No valid SendGrid domain authentication record for: example.net"]


def test_stale_invalid_duplicate_beside_a_valid_record_is_a_finding_not_a_fail():
    items = [domain("example.com", valid=False), domain("example.com"), domain("example.net")]
    result = run("areSendingDomainsAuthenticated", items)
    assert value(result, "areSendingDomainsAuthenticated") is True
    assert result["additionalInfo"]["evaluation"]["additionalFindings"] == [
        "Domains that also hold an invalid, stale authentication record (delete it in SendGrid): example.com"]


def test_domains_none_authenticated_is_false():
    result = run("areSendingDomainsAuthenticated", [])
    assert value(result, "areSendingDomainsAuthenticated") is False
    assert status(result) == "success"


def test_domains_are_case_insensitive():
    items = [domain("Example.COM", valid=False), domain("example.com")]
    assert value(run("areSendingDomainsAuthenticated", items), "areSendingDomainsAuthenticated") is True


@pytest.mark.parametrize("key,maker", [("areSendingDomainsAuthenticated", domain), ("isLinkBrandingValid", link)])
@pytest.mark.parametrize("body", [
    {"errors": [{"field": None, "message": "access forbidden"}]}, {"statusCode": 403}, "text", None,
    {"unrecognised": 1}, ["not an object"], [{"domain": "example.com"}], [{"valid": True}],
    [{"domain": "example.com", "valid": "maybe"}],
])
def test_sender_reads_unreadable_are_not_evaluated(key, maker, body):
    result = T[key]({KEYS[key]: body})
    assert value(result, key) is None
    assert status(result) == "error"


@pytest.mark.parametrize("key,maker", [("areSendingDomainsAuthenticated", domain), ("isLinkBrandingValid", link)])
def test_a_full_hundred_page_that_the_workflow_reports_complete_is_read(key, maker):
    items = [maker("d" + str(index) + ".example.com") for index in range(100)]
    assert value(run(key, items), key) is True


MARKERS_NOT_COMPLETE = [
    {},                                                                              # no marker at all
    {"paginationStats": {}},
    {"paginationStats": {"other": {"paginationTruncated": False}}},
    {"paginationStats": {"LEG": {}}},
    {"paginationStats": {"LEG": {"paginationTruncated": None}}},
    {"paginationStats": {"LEG": {"paginationTruncated": "false"}}},
    {"paginationStats": {"LEG": {"paginationTruncated": True}}},
    {"paginationStats": {"LEG": {"paginationTruncated": False}}, "paginationTruncated": True},
]


@pytest.mark.parametrize("key,maker", [("areSendingDomainsAuthenticated", domain), ("isLinkBrandingValid", link),
                                       ("isSSOEnforcedForAllUsers", None)])
@pytest.mark.parametrize("marker", MARKERS_NOT_COMPLETE)
def test_a_paged_read_not_reported_complete_is_not_evaluated(key, maker, marker):
    leg = KEYS[key]
    body = copy.deepcopy(TEAMMATES_OK) if maker is None else [maker("example.com")]
    data = {leg: body}
    data.update(json.loads(json.dumps(marker).replace("LEG", leg)))
    for wrapped in (data, {"data": data}):
        result = T[key](wrapped)
        assert value(result, key) is None
        assert status(result) == "error"
        assert result["additionalInfo"]["dataCollection"]["errors"]


# ---- Link branding ------------------------------------------------------------------------------

def test_link_branding_valid_is_true():
    assert value(run("isLinkBrandingValid", [link("example.com")]), "isLinkBrandingValid") is True


def test_link_branding_invalid_is_false():
    result = run("isLinkBrandingValid", [link("example.com"), link("example.net", valid=False)])
    assert value(result, "isLinkBrandingValid") is False
    assert result["additionalInfo"]["evaluation"]["failReasons"] == ["No valid SendGrid link branding record for: example.net"]


def test_link_branding_none_is_false():
    assert value(run("isLinkBrandingValid", []), "isLinkBrandingValid") is False


def test_link_branding_stale_duplicate_is_a_finding():
    result = run("isLinkBrandingValid", [link("example.com", valid=False), link("example.com")])
    assert value(result, "isLinkBrandingValid") is True
    assert result["additionalInfo"]["evaluation"]["additionalFindings"]


# ---- Envelope -----------------------------------------------------------------------------------

@pytest.mark.parametrize("key", list(KEYS))
def test_metadata_and_never_leaks_a_key(key):
    good = {"isOutboundTLSEnforced": TLS_ON, "isOutboundCertificateValidationEnforced": TLS_ON,
            "isOutboundMinimumTLSVersionSecure": TLS_ON, "isSSOEnabled": SSO, "isSSOEnforcedForAllUsers": TEAMMATES_OK, "isIPAllowlistEnabled": WHITELIST,
            "areSendingDomainsAuthenticated": [domain("example.com")], "isLinkBrandingValid": [link("example.com")]}[key]
    result = run(key, good)
    meta = result["additionalInfo"]["metadata"]
    assert meta["vendor"] == "SendGrid" and meta["category"] == "Email Security"
    assert meta["transformationId"] == key.lower()
    assert "SG." not in json.dumps(result)


# ---- SSO enforced for every user ----------------------------------------------------------------

def test_every_teammate_with_sso_is_true():
    result = run("isSSOEnforcedForAllUsers", TEAMMATES_OK)
    assert value(result, "isSSOEnforcedForAllUsers") is True
    assert result["additionalInfo"]["evaluation"]["passReasons"] == ["All 2 teammates sign in with SSO (is_sso true)"]
    assert "owner" in result["additionalInfo"]["evaluation"]["additionalFindings"][0]


def test_any_teammate_without_sso_is_false_with_count_and_names_only():
    result = run("isSSOEnforcedForAllUsers", TEAMMATES_MIXED)
    assert value(result, "isSSOEnforcedForAllUsers") is False
    assert result["transformedResponse"]["teammatesTotal"] == 5
    assert result["transformedResponse"]["teammatesWithSso"] == 3
    assert result["transformedResponse"]["teammatesWithoutSso"] == 2
    assert result["additionalInfo"]["evaluation"]["failReasons"] == [
        "2 of 5 teammates do not sign in with SSO (is_sso false): d, e"]
    assert "@" not in json.dumps(result)


def test_a_plain_username_is_shown_and_an_email_username_loses_its_domain():
    body = {"result": [{"username": "plain-user", "is_sso": False}, {"username": "pat@example.org", "is_sso": False}]}
    reason = run("isSSOEnforcedForAllUsers", body)["additionalInfo"]["evaluation"]["failReasons"][0]
    assert reason.endswith(": plain-user, pat") and "@" not in reason


def test_teammates_as_bare_list_and_string_flags():
    body = [{"username": "a", "is_sso": "true"}, {"username": "b", "is_sso": "false"}]
    assert value(T["isSSOEnforcedForAllUsers"](payload("isSSOEnforcedForAllUsers", body)), "isSSOEnforcedForAllUsers") is False


def test_teammates_cut_off_by_the_page_cap_is_not_evaluated():
    for marker in ({"paginationTruncated": True}, {"paginationStats": {"teammates": {"paginationTruncated": True}}}):
        data = dict({"teammates": copy.deepcopy(TEAMMATES_OK)}, **marker)
        result = T["isSSOEnforcedForAllUsers"](data)
        assert value(result, "isSSOEnforcedForAllUsers") is None
        assert status(result) == "error"
        wrapped = T["isSSOEnforcedForAllUsers"]({"data": data})
        assert value(wrapped, "isSSOEnforcedForAllUsers") is None
    clean = {"teammates": copy.deepcopy(TEAMMATES_OK), "paginationStats": {"teammates": {"paginationTruncated": False}}}
    assert value(T["isSSOEnforcedForAllUsers"](clean), "isSSOEnforcedForAllUsers") is True


@pytest.mark.parametrize("body", [
    {"errors": [{"field": None, "message": "access forbidden"}]}, {"statusCode": 403}, {"statusCode": 500},
    {"error": True, "statusCode": 401}, "text", None, {"unrecognised": []}, {"result": []}, [],
    {"result": [{"username": "a"}]}, {"result": [{"username": "a", "is_sso": "maybe"}]}, {"result": ["x"]},
])
def test_teammates_unreadable_is_not_evaluated(body):
    result = T["isSSOEnforcedForAllUsers"]({"teammates": body})
    assert value(result, "isSSOEnforcedForAllUsers") is None
    assert status(result) == "error"


# ---- Not evaluated versus not configured, for every check -----------------------------------------
# A successful 200 read that shows the control is not configured is the real state: False, with a
# reason that says how many there are. Not evaluated (None) is only for a 401/403, a 5xx, a timeout,
# a body that does not parse or lacks the expected field.

NOT_CONFIGURED = [
    ("isSSOEnabled", [], "0 SAML single sign-on integrations"),
    ("isIPAllowlistEnabled", {"result": []}, "0 IP allow-list entries"),
    ("areSendingDomainsAuthenticated", [], "0 authenticated sending domains"),
    ("isLinkBrandingValid", [], "0 branded link domains"),
    ("isOutboundTLSEnforced", TLS_OFF, "require_tls is false"),
    ("isOutboundCertificateValidationEnforced", TLS_OFF, "require_tls is false"),
    ("isOutboundMinimumTLSVersionSecure", TLS_OFF, "minimum TLS version is 1.1"),
]


@pytest.mark.parametrize("key,body,words", NOT_CONFIGURED)
def test_a_good_read_of_an_unconfigured_control_is_false_with_the_count_in_the_reason(key, body, words):
    result = run(key, body)
    assert value(result, key) is False
    assert status(result) == "success" and not result["additionalInfo"]["dataCollection"]["errors"]
    assert words in result["additionalInfo"]["evaluation"]["failReasons"][0]


FAILED_READS = [
    {"errors": [{"field": None, "message": "authorization required"}]},   # 401 body
    {"errors": [{"field": None, "message": "access forbidden"}]},         # 403 body
    {"statusCode": 401}, {"statusCode": 403}, {"statusCode": 500}, {"statusCode": 502}, {"statusCode": 504},
    {"error": True, "errorType": "Timeout", "message": "timed out"},
    {"error": "upstream connect error"},
]


@pytest.mark.parametrize("key", list(KEYS))
@pytest.mark.parametrize("body", FAILED_READS)
def test_a_failed_read_is_not_evaluated_for_every_check(key, body):
    result = T[key]({KEYS[key]: copy.deepcopy(body)})
    assert value(result, key) is None
    assert status(result) == "error"
    assert result["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("key", list(KEYS))
@pytest.mark.parametrize("body", ["this is not json", "", None, {}, {"unexpected": "shape"}, 7])
def test_an_unparsable_or_field_less_body_is_not_evaluated_for_every_check(key, body):
    result = T[key]({KEYS[key]: body})
    assert value(result, key) is None
    assert status(result) == "error"


@pytest.mark.parametrize("key", list(KEYS))
def test_a_workflow_input_that_is_invalid_json_text_is_not_evaluated(key):
    result = T[key]("{not json")
    assert value(result, key) is None
    assert status(result) == "error"


def test_the_ip_allow_list_needs_its_result_field():
    assert value(T["isIPAllowlistEnabled"]({"ipAllowlist": []}), "isIPAllowlistEnabled") is None
    assert value(T["isIPAllowlistEnabled"]({"ipAllowlist": {"other": []}}), "isIPAllowlistEnabled") is None


# ---- A real error wins over the completeness reason -----------------------------------------------

@pytest.mark.parametrize("key", PAGED)
@pytest.mark.parametrize("body,words", [
    ({"statusCode": 403}, "HTTP 403"),
    ({"statusCode": 401}, "HTTP 401"),
    ({"errors": [{"field": None, "message": "access forbidden"}]}, "access forbidden"),
    ({"error": True, "statusCode": 502, "message": "bad gateway"}, "502"),
])
def test_an_error_leg_without_a_marker_reports_the_real_error_not_the_pager(key, body, words):
    result = T[key]({KEYS[key]: copy.deepcopy(body)})
    assert value(result, key) is None
    errors = result["additionalInfo"]["dataCollection"]["errors"]
    assert words in errors[0] and "paged read" not in errors[0]
