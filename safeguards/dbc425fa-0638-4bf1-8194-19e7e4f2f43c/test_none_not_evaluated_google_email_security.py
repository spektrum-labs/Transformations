"""An unreadable Google email-security read must reach the evaluator as Not evaluated, never as Failed.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is "error"
(create_response sets that only from a non-empty api_errors). Every body below is one that proves
nothing about the tenant: an error or refusal, an empty or missing list, a body that is not JSON, a
paged list cut short before the answer could be known, or an exception inside the transform. Each
transform must answer None for every criterion key it owns AND say why through dataCollection.

Each file also keeps a measured case: a read that really shows the control is off still answers False
with its reasons, so the change moves only what an unreadable read looks like, not what is graded.
Synthetic data only; every identifier below is made up.
"""
import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = "synthetic-next-page"


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


_LOADED = {}


def load(name):
    if name not in _LOADED:
        spec = importlib.util.spec_from_file_location("ges_nne_" + name, os.path.join(HERE, name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _LOADED[name] = module
    return _LOADED[name]


# Bodies that prove nothing for any of these transforms. Each entry builds a fresh body.
COMMON = [
    ("error_body", lambda: {"error": {"code": 500, "message": "Backend error", "status": "INTERNAL"}}),
    ("refused_403", lambda: {"error": {"code": 403, "message": "Request had insufficient authentication scopes.",
                                       "status": "PERMISSION_DENIED"}}),
    ("refused_integration_envelope", lambda: {"statusCode": 403, "message": "Forbidden"}),
    ("error_body_as_json_string", lambda: json.dumps({"error": {"code": 500, "message": "Backend error"}})),
    ("empty_object", lambda: {}),
    ("empty_list", lambda: []),
    ("empty_string", lambda: ""),
    ("empty_bytes", lambda: b""),
    ("none", lambda: None),
    ("not_json", lambda: "{not json"),
    ("json_scalar", lambda: "42"),
    ("exception", lambda: Poisoned()),
]


# ---------------------------------------------------------------------------------------------
# Body builders
# ---------------------------------------------------------------------------------------------

def gmail_policy(setting_type, value, org_unit="orgUnits/synthetic-root", sort_order="201.1", policy_type="ADMIN"):
    return {"name": "policies/synthetic-1", "type": policy_type,
            "policyQuery": {"orgUnit": org_unit, "sortOrder": sort_order},
            "setting": {"type": "settings/" + setting_type, "value": value}}


def system_default(setting_type, value, org_unit="orgUnits/synthetic-root"):
    """A SYSTEM default for the same org unit, with a lower sortOrder than gmail_policy's ADMIN override."""
    return gmail_policy(setting_type, value, org_unit, sort_order="1.0", policy_type="SYSTEM")


OTHER_GMAIL = gmail_policy("gmail.mail_delegation", {"enableMailDelegation": False})


def policy_family(name, key, setting_type, fields, counts=("policiesJudged", "policiesCompliant")):
    """The four Gmail-policy transforms and the link check share one rule: every policy for the
    setting in force must have every required field on. Only the policy with the greatest
    policyQuery.sortOrder on each org unit is in force; the rest are superseded and not judged. A
    policy in force that reports a required field off proves False; one that does not report a field
    proves nothing (None); a complete list with no policy for the setting is a proven negative (False).
    A truncated list is Not evaluated even when a policy read so far is off, because a later page can
    hold an override with a greater sortOrder."""
    judged, compliant = counts
    all_on = dict((f, True) for f in fields)
    all_off = dict((f, False) for f in fields)
    one_off = dict(all_on)
    one_off[fields[0]] = False
    string_off = dict((f, "False") for f in fields)
    string_on = dict((f, "True") for f in fields)
    one_missing = dict(all_on)
    del one_missing[fields[-1]]
    one_null = dict(all_on)
    one_null[fields[-1]] = None
    return {
        "name": name,
        "keys": (key,),
        "unmeasured": [
            ("empty_policy_list", lambda: {"policies": []}),
            ("list_without_policy_records", lambda: {"policies": ["junk", 7]}),
            ("no_policies_key", lambda: {"items": []}),
            ("policies_not_a_list", lambda: {"policies": "none"}),
            ("truncated_list_without_the_setting",
             lambda: {"policies": [OTHER_GMAIL], "nextPageToken": TOKEN}),
            ("truncated_list_all_on_so_far",
             lambda: {"policies": [gmail_policy(setting_type, all_on)], "nextPageToken": TOKEN}),
            ("truncation_marker_all_on_so_far",
             lambda: {"policies": [gmail_policy(setting_type, all_on)], "paginationTruncated": True}),
            ("truncation_marker_string_all_on_so_far",
             lambda: {"policies": [gmail_policy(setting_type, all_on)], "paginationTruncated": "true"}),
            ("matching_policy_without_a_value", lambda: {"policies": [gmail_policy(setting_type, {})]}),
            ("matching_policy_value_not_an_object", lambda: {"policies": [gmail_policy(setting_type, "none")]}),
            ("a_required_field_missing", lambda: {"policies": [gmail_policy(setting_type, one_missing)]}),
            ("a_required_field_null", lambda: {"policies": [gmail_policy(setting_type, one_null)]}),
            ("one_policy_on_and_another_missing_a_field",
             lambda: {"policies": [gmail_policy(setting_type, all_on, "orgUnits/synthetic-a"),
                                   gmail_policy(setting_type, one_missing, "orgUnits/synthetic-b")]}),
            ("truncated_and_a_required_field_missing",
             lambda: {"policies": [gmail_policy(setting_type, one_missing)], "nextPageToken": TOKEN}),
            ("truncated_but_a_policy_is_off",
             lambda: {"policies": [gmail_policy(setting_type, one_off)], "nextPageToken": TOKEN}),
            ("truncation_marker_but_a_policy_is_off",
             lambda: {"policies": [gmail_policy(setting_type, one_off)], "paginationTruncated": True}),
            ("truncated_with_one_policy_on_and_one_off",
             lambda: {"policies": [gmail_policy(setting_type, all_on, "orgUnits/synthetic-a"),
                                   gmail_policy(setting_type, one_off, "orgUnits/synthetic-b")],
                      "nextPageToken": TOKEN}),
            ("override_in_force_missing_a_field_over_a_complete_default",
             lambda: {"policies": [system_default(setting_type, all_on), gmail_policy(setting_type, one_missing)]}),
        ],
        "measured": [
            ("setting_off", lambda: {"policies": [gmail_policy(setting_type, all_off)]},
             {key: False, judged: 1, compliant: 0}),
            ("one_of_two_policies_off",
             lambda: {"policies": [gmail_policy(setting_type, all_on, "orgUnits/synthetic-a"),
                                   gmail_policy(setting_type, one_off, "orgUnits/synthetic-b")]},
             {key: False, judged: 2, compliant: 1}),
            ("complete_list_without_the_setting", lambda: {"policies": [OTHER_GMAIL]},
             {key: False, judged: 0, compliant: 0}),
            ("override_on_supersedes_a_default_that_is_off",
             lambda: {"policies": [system_default(setting_type, all_off), gmail_policy(setting_type, all_on)]},
             {key: True, judged: 1, compliant: 1}),
            ("override_off_supersedes_a_default_that_is_on",
             lambda: {"policies": [system_default(setting_type, all_on), gmail_policy(setting_type, one_off)]},
             {key: False, judged: 1, compliant: 0}),
            ("a_superseded_default_missing_a_field_is_not_judged",
             lambda: {"policies": [system_default(setting_type, one_missing), gmail_policy(setting_type, all_on)]},
             {key: True, judged: 1, compliant: 1}),
            ("a_default_on_another_org_unit_is_judged_on_its_own",
             lambda: {"policies": [system_default(setting_type, all_off, "orgUnits/synthetic-b"),
                                   gmail_policy(setting_type, all_on, "orgUnits/synthetic-a")]},
             {key: False, judged: 2, compliant: 1}),
            ("a_field_the_string_false_reads_as_off", lambda: {"policies": [gmail_policy(setting_type, string_off)]},
             {key: False, judged: 1, compliant: 0}),
            ("one_policy_off_and_another_missing_a_field",
             lambda: {"policies": [gmail_policy(setting_type, one_off, "orgUnits/synthetic-a"),
                                   gmail_policy(setting_type, one_missing, "orgUnits/synthetic-b")]},
             {key: False, judged: 2, compliant: 0}),
            ("all_on", lambda: {"policies": [gmail_policy(setting_type, all_on)]},
             {key: True, judged: 1, compliant: 1}),
            ("all_on_as_the_string_true", lambda: {"policies": [gmail_policy(setting_type, string_on)]},
             {key: True, judged: 1, compliant: 1}),
            ("bare_list_all_on", lambda: [gmail_policy(setting_type, all_on)],
             {key: True, judged: 1, compliant: 1}),
        ],
    }


def phishing(value, **extra):
    body = {"policies": [{"setting": {"value": value}}]}
    body.update(extra)
    return body


def spoofing_policy(value, sort_order, policy_type, org_unit="orgUnits/synthetic-root"):
    return {"type": policy_type, "policyQuery": {"orgUnit": org_unit, "sortOrder": sort_order},
            "setting": {"type": "settings/gmail.spoofing_and_authentication", "value": value}}


SPOOF_ON = {"detectDomainNameSpoofing": True, "detectEmployeeNameSpoofing": True}
SPOOF_OFF = {"detectDomainNameSpoofing": False, "detectEmployeeNameSpoofing": True}
SPOOF_STRING_OFF = {"detectDomainNameSpoofing": "False", "detectEmployeeNameSpoofing": "True"}
SPOOF_STRING_ON = {"detectDomainNameSpoofing": "True", "detectEmployeeNameSpoofing": "true"}
SPOOF_ONE_MISSING = {"detectDomainNameSpoofing": True}
SPOOF_ONE_NULL = {"detectDomainNameSpoofing": None, "detectEmployeeNameSpoofing": True}


def when(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def gmail_feed(*items, **extra):
    body = {"kind": "admin#reports#activities"}
    if items:
        body["items"] = list(items)
    body.update(extra)
    return body


def activity(app, days_ago):
    return {"kind": "admin#reports#activity", "id": {"applicationName": app, "time": when(days_ago)}, "events": []}


def logging_spec(name, key):
    return {
        "name": name,
        "keys": (key,),
        "unmeasured": [
            ("empty_gmail_feed", lambda: gmail_feed()),
            ("admin_events_only", lambda: gmail_feed(activity("admin", 1))),
            ("gmail_events_without_a_time",
             lambda: gmail_feed({"id": {"applicationName": "gmail"}, "events": []})),
            ("not_a_reports_feed", lambda: {"policies": []}),
            # A feed cut short could hold a recent event on a later page, so stale events seen so far
            # prove nothing.
            ("truncated_and_only_stale_gmail_events",
             lambda: gmail_feed(activity("gmail", 30), nextPageToken=TOKEN)),
            ("truncation_marker_and_only_stale_gmail_events",
             lambda: gmail_feed(activity("gmail", 30), paginationTruncated=True)),
        ],
        "measured": [
            ("only_stale_gmail_events", lambda: gmail_feed(activity("gmail", 30), activity("gmail", 25)),
             {key: False, "gmailEventsRead": 2}),
            ("recent_gmail_events", lambda: gmail_feed(activity("gmail", 1), activity("gmail", 2)),
             {key: True, "gmailEventsRead": 2}),
            # A recent event already seen proves True; the count is from part of the feed, so None.
            ("truncated_but_a_recent_event_seen", lambda: gmail_feed(activity("gmail", 1), nextPageToken=TOKEN),
             {key: True, "gmailEventsRead": None}),
            ("truncation_marker_but_a_recent_event_seen",
             lambda: gmail_feed(activity("gmail", 1), activity("gmail", 2), paginationTruncated="true"),
             {key: True, "gmailEventsRead": None}),
        ],
    }


LICENSES = "licensing#licenseAssignmentList"
OTHER_PRODUCT = {"productId": "Other-Product", "skuId": "1", "userId": "synthetic-user-1"}
WORKSPACE_LICENCE = {"productId": "Google-Apps", "skuId": "1010020027", "userId": "synthetic-user-1"}
PROXY_NO_SKU = {"policyQuery": {"query": "entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('x'))"}}

MFA_KEYS = ("isMFAEnforcedForUsers", "totalUsers", "mfaEnrolledUsers")
ENFORCED = {"id": "synthetic-user-1", "isEnforcedIn2Sv": "True", "isEnrolledIn2Sv": "True"}
NOT_ENFORCED = {"id": "synthetic-user-2", "isEnforcedIn2Sv": "False", "isEnrolledIn2Sv": "False"}
SUSPENDED = {"id": "synthetic-user-3", "suspended": "True", "isEnforcedIn2Sv": "False"}
NO_FIELD = {"id": "synthetic-user-4"}
NULL_FIELD = {"id": "synthetic-user-5", "isEnforcedIn2Sv": None}
SUSPENDED_NO_FIELD = {"id": "synthetic-user-6", "suspended": "True"}


def users(*members, **extra):
    body = {"users": list(members)}
    body.update(extra)
    return body


def sso_assignments(*items, **extra):
    inner = {"inboundSsoAssignments": list(items)}
    inner.update(extra)
    return inner


NO_PROFILES = {"inboundSamlSsoProfiles": []}
ROOT = "orgUnits/synthetic-root"
SAML_ASSIGNMENT = {"ssoMode": "SAML_SSO", "targetOrgUnit": ROOT,
                   "samlSsoInfo": {"inboundSamlSsoProfile": "inboundSamlSsoProfiles/synthetic-1"}}
OIDC_ASSIGNMENT = {"ssoMode": "OIDC_SSO", "targetOrgUnit": ROOT}
OFF_ASSIGNMENT = {"ssoMode": "SSO_OFF", "targetOrgUnit": ROOT}
SAML_PROFILE = {"name": "inboundSamlSsoProfiles/synthetic-1",
                "idpConfig": {"singleSignOnServiceUri": "https://idp-synthetic/sso"}}
LEGACY_OFF = {"idpInfo": [{"@name": "enableSSO", "@value": "false"}]}
LEGACY_NO_ENABLE = {"idpInfo": [{"@name": "samlSignonUri", "@value": "https://idp-synthetic/sso"}]}


def app_consent(level, org_unit="orgUnits/synthetic-root"):
    return {"type": "ADMIN", "policyQuery": {"orgUnit": org_unit},
            "setting": {"type": "settings/api_controls.unconfigured_third_party_apps",
                        "value": {"accessLevel": level}}}


def app_consent_without_a_level(org_unit="orgUnits/synthetic-root"):
    return {"type": "ADMIN", "policyQuery": {"orgUnit": org_unit},
            "setting": {"type": "settings/api_controls.unconfigured_third_party_apps", "value": {}}}


OTHER_API_CONTROL = {"type": "SYSTEM", "policyQuery": {"orgUnit": "orgUnits/synthetic-root"},
                     "setting": {"type": "settings/api_controls.internal_apps", "value": {"trustInternalApps": True}}}


def ou_query(ou):
    return "entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('" + ou.split("/")[1] + "'))"


def settings_policy(setting_type, value, ou="orgUnits/synthetic-root", ptype="ADMIN", order="201.1"):
    return {"name": "policies/synthetic-1", "customer": "customers/synthetic",
            "policyQuery": {"orgUnit": ou, "sortOrder": order, "query": ou_query(ou)},
            "setting": {"type": "settings/" + setting_type, "value": value}, "type": ptype}


def forwarding(enable):
    return settings_policy("gmail.auto_forwarding", {"enableAutoForwarding": enable})


def less_secure(allow):
    return settings_policy("security.less_secure_apps", {"allowLessSecureApps": allow})


SYSTEM_GMAIL_DEFAULT = settings_policy("gmail.confidential_mode", {"enableConfidentialMode": "True"},
                                       ptype="SYSTEM", order="101.1")
ADMIN_FEED_EVENT = {"kind": "admin#reports#activity",
                    "id": {"time": "2026-10-01T16:37:00.014Z", "applicationName": "admin"}, "events": []}

# ---------------------------------------------------------------------------------------------
# One spec per transform: the criterion keys it owns, the extra bodies that prove nothing, and the
# measured bodies (with the values they must still produce).
# ---------------------------------------------------------------------------------------------

SPECS = [
    policy_family("issafelinksenabled", "isSafeLinksEnabled", "gmail.links_and_external_images",
                  ["enableShortenerScanning", "enableAggressiveWarningsOnUntrustedLinks"]),
    policy_family("issafeattachmentsenabled", "isSafeAttachmentsEnabled", "gmail.email_attachment_safety",
                  ["enableEncryptedAttachmentProtection", "enableAttachmentWithScriptsProtection",
                   "enableAnomalousAttachmentProtection"]),
    policy_family("ismacroblockingenabled", "isMacroBlockingEnabled", "gmail.email_attachment_safety",
                  ["enableAttachmentWithScriptsProtection"]),
    policy_family("isemailfilteringenabled", "isEmailFilteringEnabled", "gmail.enhanced_pre_delivery_message_scanning",
                  ["enableImprovedSuspiciousContentDetection"]),
    policy_family("isurlrewriteenabled", "isURLRewriteEnabled", "gmail.links_and_external_images",
                  ["enableShortenerScanning", "enableAggressiveWarningsOnUntrustedLinks"],
                  counts=("linkPolicyCount", "enabledPolicyCount")),
    {
        "name": "isantiphishingenabled",
        "keys": ("isEmailSecurityEnabled", "isAntiPhishingEnabled"),
        "unmeasured": [
            ("empty_policy_list", lambda: {"policies": []}),
            ("list_without_policy_records", lambda: {"policies": ["junk"]}),
            ("no_policies_key", lambda: {"items": []}),
            ("failed_input_validation",
             lambda: {"data": phishing(SPOOF_ON), "validation": {"status": "failed", "errors": ["x"], "warnings": []}}),
            ("truncated_list_all_on_so_far", lambda: phishing(SPOOF_ON, nextPageToken=TOKEN)),
            ("truncated_list_without_the_settings", lambda: phishing({"other": True}, nextPageToken=TOKEN)),
            ("truncation_marker_all_on_so_far", lambda: phishing(SPOOF_ON, paginationTruncated=True)),
            ("a_spoofing_setting_missing", lambda: phishing(SPOOF_ONE_MISSING)),
            ("a_spoofing_setting_null", lambda: phishing(SPOOF_ONE_NULL)),
            ("truncated_and_a_spoofing_setting_missing", lambda: phishing(SPOOF_ONE_MISSING, nextPageToken=TOKEN)),
            ("truncated_but_a_setting_is_off", lambda: phishing(SPOOF_OFF, nextPageToken=TOKEN)),
            ("truncation_marker_but_a_setting_is_off", lambda: phishing(SPOOF_OFF, paginationTruncated="true")),
            ("override_in_force_without_spoofing_settings_over_a_default_on",
             lambda: {"policies": [spoofing_policy(SPOOF_ON, "1.0", "SYSTEM"), spoofing_policy({}, "5.0", "ADMIN")]}),
            ("override_in_force_with_only_other_spoofing_keys_over_a_default_on",
             lambda: {"policies": [spoofing_policy(SPOOF_ON, "1.0", "SYSTEM"),
                                   spoofing_policy({"detectUnauthenticatedEmails": True}, "5.0", "ADMIN")]}),
        ],
        "measured": [
            ("a_spoofing_setting_off", lambda: phishing(SPOOF_OFF),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False, "policyDetails": [SPOOF_OFF]}),
            ("complete_list_without_the_settings", lambda: phishing({"other": True}),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False, "policyDetails": []}),
            ("override_on_supersedes_a_default_that_is_off",
             lambda: {"policies": [spoofing_policy(SPOOF_OFF, "1.0", "SYSTEM"), spoofing_policy(SPOOF_ON, "201.1", "ADMIN")]},
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": True, "policyDetails": [SPOOF_ON]}),
            ("override_off_supersedes_a_default_that_is_on",
             lambda: {"policies": [spoofing_policy(SPOOF_ON, "1.0", "SYSTEM"), spoofing_policy(SPOOF_OFF, "201.1", "ADMIN")]},
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False, "policyDetails": [SPOOF_OFF]}),
            ("a_setting_the_string_false_reads_as_off", lambda: phishing(SPOOF_STRING_OFF),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False}),
            ("a_setting_off_and_another_missing", lambda: phishing({"detectDomainNameSpoofing": False}),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False}),
            ("all_on", lambda: phishing(SPOOF_ON),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": True, "policyDetails": [SPOOF_ON]}),
            ("all_on_as_strings", lambda: phishing(SPOOF_STRING_ON),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": True}),
        ],
    },
    logging_spec("isemailloggingenabled", "isEmailLoggingEnabled"),
    logging_spec("isemailsecurityloggingenabled", "isEmailSecurityLoggingEnabled"),
    {
        "name": "confirmedlicensepurchased",
        "keys": ("confirmedLicensePurchased",),
        "unmeasured": [
            ("empty_assignment_list", lambda: {"kind": LICENSES, "items": []}),
            ("assignments_without_records", lambda: {"kind": LICENSES, "items": ["junk"]}),
            ("truncated_without_a_workspace_licence",
             lambda: {"kind": LICENSES, "items": [OTHER_PRODUCT], "nextPageToken": TOKEN}),
            ("empty_policy_proxy", lambda: {"policies": {"policies": []}}),
            ("truncated_policy_proxy",
             lambda: {"policies": {"policies": [PROXY_NO_SKU], "nextPageToken": TOKEN}}),
            ("policy_proxy_not_a_list", lambda: {"policies": "none"}),
            ("neither_shape", lambda: {"something": 1}),
        ],
        "measured": [
            ("no_workspace_licence", lambda: {"kind": LICENSES, "items": [OTHER_PRODUCT]},
             {"confirmedLicensePurchased": False, "workspaceAssignments": 0}),
            ("policy_proxy_without_a_workspace_licence", lambda: {"policies": {"policies": [PROXY_NO_SKU]}},
             {"confirmedLicensePurchased": False}),
            ("workspace_licence_assigned", lambda: {"kind": LICENSES, "items": [WORKSPACE_LICENCE]},
             {"confirmedLicensePurchased": True, "workspaceAssignments": 1}),
            ("truncated_but_a_workspace_licence_found",
             lambda: {"kind": LICENSES, "items": [WORKSPACE_LICENCE], "nextPageToken": TOKEN},
             {"confirmedLicensePurchased": True, "workspaceAssignments": None}),
            ("truncation_marker_but_a_workspace_licence_found",
             lambda: {"kind": LICENSES, "items": [WORKSPACE_LICENCE, WORKSPACE_LICENCE], "paginationTruncated": True},
             {"confirmedLicensePurchased": True, "workspaceAssignments": None}),
        ],
    },
    {
        "name": "ismfaenforcedforusers",
        "keys": MFA_KEYS,
        "unmeasured": [
            ("empty_user_list", lambda: users()),
            ("only_suspended_users", lambda: users(SUSPENDED)),
            ("truncated_user_list", lambda: users(ENFORCED, nextPageToken=TOKEN)),
            ("truncation_marker", lambda: users(ENFORCED, paginationTruncated=True)),
            ("truncation_marker_string", lambda: users(ENFORCED, paginationTruncated="true")),
            # A user already seen can prove False, but nothing seen so far proves True, and a user that is
            # suspended or states nothing proves nothing.
            ("truncated_and_the_only_user_not_enforced_is_suspended", lambda: users(ENFORCED, SUSPENDED, nextPageToken=TOKEN)),
            ("truncated_and_one_states_nothing", lambda: users(ENFORCED, NO_FIELD, nextPageToken=TOKEN)),
            ("no_users_key", lambda: {"kind": "admin#directory#users"}),
            ("users_not_a_list", lambda: {"users": "none"}),
            # A record that does not state enforcement is unknown, not "not enforced".
            ("the_only_active_user_states_nothing", lambda: users(NO_FIELD)),
            ("the_only_active_user_states_null", lambda: users(NULL_FIELD)),
            ("one_enforced_and_one_states_nothing", lambda: users(ENFORCED, NO_FIELD)),
        ],
        "measured": [
            ("an_active_user_not_enforced", lambda: users(ENFORCED, NOT_ENFORCED),
             {"isMFAEnforcedForUsers": False, "totalUsers": 2, "mfaEnrolledUsers": 1}),
            # A negative proven by a user already seen stays False when the list was cut short; the counts
            # come from part of the tenant, so they are None.
            ("truncated_but_an_active_user_not_enforced", lambda: users(ENFORCED, NOT_ENFORCED, nextPageToken=TOKEN),
             {"isMFAEnforcedForUsers": False, "totalUsers": None, "mfaEnrolledUsers": None}),
            ("truncation_marker_but_an_active_user_not_enforced",
             lambda: users(ENFORCED, NOT_ENFORCED, paginationTruncated=True),
             {"isMFAEnforcedForUsers": False, "totalUsers": None, "mfaEnrolledUsers": None}),
            ("truncation_marker_string_but_an_active_user_not_enforced",
             lambda: users(NOT_ENFORCED, paginationTruncated="true"),
             {"isMFAEnforcedForUsers": False, "totalUsers": None, "mfaEnrolledUsers": None}),
            ("truncated_not_enforced_and_one_states_nothing", lambda: users(NOT_ENFORCED, NO_FIELD, nextPageToken=TOKEN),
             {"isMFAEnforcedForUsers": False, "totalUsers": None, "mfaEnrolledUsers": None}),
            # One record that states not-enforced proves False, whatever the others say.
            ("one_not_enforced_and_one_states_nothing", lambda: users(NOT_ENFORCED, NO_FIELD),
             {"isMFAEnforcedForUsers": False, "totalUsers": 2, "mfaEnrolledUsers": 0}),
            ("a_suspended_user_stating_nothing_is_ignored", lambda: users(ENFORCED, SUSPENDED_NO_FIELD),
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
            ("every_active_user_enforced", lambda: users(ENFORCED, SUSPENDED),
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
            ("marker_present_but_not_set", lambda: users(ENFORCED, paginationTruncated=False),
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
            ("blank_next_page_token", lambda: users(ENFORCED, nextPageToken=""),
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
        ],
    },
    {
        "name": "mfa_transform",
        "keys": MFA_KEYS,
        "unmeasured": [
            ("empty_user_list", lambda: users()),
            ("users_without_records", lambda: users("junk")),
            ("truncated_user_list_none_enforced_yet", lambda: users(NOT_ENFORCED, nextPageToken=TOKEN)),
            ("no_users_and_no_flag", lambda: {"kind": "admin#directory#users"}),
            ("failed_input_validation",
             lambda: {"data": users(ENFORCED), "validation": {"status": "failed", "errors": ["x"], "warnings": []}}),
            ("empty_list_with_a_direct_flag_on", lambda: {"isMFAEnforcedForUsers": True, "users": []}),
            ("truncation_marker_none_enforced_yet",
             lambda: users(NOT_ENFORCED, paginationTruncated=True)),
            # The criterion is never read out of the body it judges: a vendor does not send it.
            ("direct_flag_on_alone", lambda: {"isMFAEnforcedForUsers": True}),
            ("direct_flag_off_alone", lambda: {"isMFAEnforcedForUsers": False}),
            ("direct_flag_as_the_string_false", lambda: {"isMFAEnforcedForUsers": "false"}),
            ("direct_flag_as_the_string_true", lambda: {"isMFAEnforcedForUsers": "True"}),
            ("direct_flag_in_the_raw_response", lambda: {"rawResponse": {"isMFAEnforcedForUsers": True}}),
            ("users_that_are_all_junk_beside_a_direct_flag",
             lambda: {"isMFAEnforcedForUsers": True, "users": ["junk", 7]}),
            # False only when every record states not-enforced; a record that states nothing could be enforced.
            ("no_user_states_enforcement", lambda: users(NO_FIELD)),
            ("a_user_states_null", lambda: users(NULL_FIELD)),
            ("none_enforced_and_one_states_nothing", lambda: users(NOT_ENFORCED, NO_FIELD)),
        ],
        "measured": [
            ("no_user_enforced", lambda: users(NOT_ENFORCED),
             {"isMFAEnforcedForUsers": False, "totalUsers": 1, "mfaEnrolledUsers": 0}),
            ("one_enforced_user", lambda: users(ENFORCED, NOT_ENFORCED),
             {"isMFAEnforcedForUsers": True, "totalUsers": 2, "mfaEnrolledUsers": 1}),
            # The verdict is proven by the user already seen; the counts come from part of the list, so
            # they are not reported as totals.
            ("truncated_but_a_user_is_enforced", lambda: users(ENFORCED, nextPageToken=TOKEN),
             {"isMFAEnforcedForUsers": True, "totalUsers": None, "mfaEnrolledUsers": None}),
            ("truncation_marker_but_a_user_is_enforced", lambda: users(ENFORCED, NOT_ENFORCED, paginationTruncated=True),
             {"isMFAEnforcedForUsers": True, "totalUsers": None, "mfaEnrolledUsers": None}),
            ("direct_flag_ignored_when_users_are_read", lambda: dict(users(NOT_ENFORCED), isMFAEnforcedForUsers=True),
             {"isMFAEnforcedForUsers": False, "totalUsers": 1, "mfaEnrolledUsers": 0}),
            ("users_in_the_raw_response", lambda: {"rawResponse": users(ENFORCED)},
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
            ("items_that_are_not_users_are_not_counted", lambda: users(ENFORCED, "junk", 7, None, NOT_ENFORCED),
             {"isMFAEnforcedForUsers": True, "totalUsers": 2, "mfaEnrolledUsers": 1}),
            ("one_enforced_and_one_states_nothing", lambda: users(ENFORCED, NO_FIELD),
             {"isMFAEnforcedForUsers": True, "totalUsers": 2, "mfaEnrolledUsers": 1}),
        ],
    },
    {
        "name": "isssoenabled",
        "keys": ("isSSOEnabled",),
        "unmeasured": [
            ("no_assignments_no_profiles_no_legacy",
             lambda: {"ssoAssignments": sso_assignments(), "ssoProfiles": NO_PROFILES}),
            ("truncated_assignments",
             lambda: {"ssoAssignments": sso_assignments({"ssoMode": "SSO_OFF"}, nextPageToken=TOKEN),
                      "ssoProfiles": NO_PROFILES}),
            ("assignments_without_records",
             lambda: {"ssoAssignments": sso_assignments("junk"), "ssoProfiles": NO_PROFILES}),
            ("organization_profile_unreadable",
             lambda: {"ssoAssignments": sso_assignments({"ssoMode": "DOMAIN_WIDE_SAML_IF_ENABLED",
                                                         "targetOrgUnit": "orgUnits/synthetic-root"}),
                      "ssoProfiles": NO_PROFILES}),
            ("legacy_feed_without_enable_flag", lambda: LEGACY_NO_ENABLE),
            ("legacy_feed_without_properties", lambda: {"idpInfo": []}),
            ("truncation_marker_on_the_assignments",
             lambda: {"ssoAssignments": sso_assignments(OFF_ASSIGNMENT, paginationTruncated=True),
                      "ssoProfiles": NO_PROFILES}),
            ("truncation_marker_string_on_the_assignments",
             lambda: {"ssoAssignments": sso_assignments(OFF_ASSIGNMENT, paginationTruncated="true"),
                      "ssoProfiles": NO_PROFILES}),
            # A SAML assignment whose profile is not on the page read could have its profile on the next one:
            # that is not a finding that SSO is off.
            ("truncated_profiles_without_the_assigned_profile",
             lambda: {"ssoAssignments": sso_assignments(SAML_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [], "nextPageToken": TOKEN}}),
            ("truncated_profiles_with_another_profile",
             lambda: {"ssoAssignments": sso_assignments(SAML_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [dict(SAML_PROFILE, name="inboundSamlSsoProfiles/other")],
                                      "nextPageToken": TOKEN}}),
            ("truncation_marker_on_the_profiles",
             lambda: {"ssoAssignments": sso_assignments(SAML_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [], "paginationTruncated": True}}),
            ("truncated_profiles_and_sso_off_assignment",
             lambda: {"ssoAssignments": sso_assignments(OFF_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [SAML_PROFILE], "nextPageToken": TOKEN}}),
            ("truncated_profiles_and_no_assignments",
             lambda: {"ssoAssignments": sso_assignments(),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [SAML_PROFILE], "nextPageToken": TOKEN}}),
        ],
        "measured": [
            # The verdict is proven by an assignment already seen, so truncation elsewhere does not withdraw it.
            ("truncated_assignments_but_oidc_found",
             lambda: {"ssoAssignments": sso_assignments(OIDC_ASSIGNMENT, nextPageToken=TOKEN), "ssoProfiles": NO_PROFILES},
             {"isSSOEnabled": True}),
            ("truncated_profiles_but_the_assigned_profile_found",
             lambda: {"ssoAssignments": sso_assignments(SAML_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [SAML_PROFILE], "nextPageToken": TOKEN}},
             {"isSSOEnabled": True}),
            ("complete_profiles_without_the_assigned_profile",
             lambda: {"ssoAssignments": sso_assignments(SAML_ASSIGNMENT),
                      "ssoProfiles": {"inboundSamlSsoProfiles": [dict(SAML_PROFILE, name="inboundSamlSsoProfiles/other")]}},
             {"isSSOEnabled": False}),
            ("legacy_sso_off", lambda: LEGACY_OFF, {"isSSOEnabled": False}),
            ("assignment_off_and_organization_profile_off",
             lambda: {"ssoAssignments": sso_assignments({"ssoMode": "SSO_OFF", "targetOrgUnit": "orgUnits/synthetic-root"}),
                      "ssoProfiles": NO_PROFILES, "legacySso": LEGACY_OFF}, {"isSSOEnabled": False}),
            ("oidc_assignment",
             lambda: {"ssoAssignments": sso_assignments({"ssoMode": "OIDC_SSO", "targetOrgUnit": "orgUnits/synthetic-root"}),
                      "ssoProfiles": NO_PROFILES}, {"isSSOEnabled": True}),
        ],
    },
    {
        "name": "isdnsconfigured",
        "keys": ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured"),
        "verdict_key": "isDNSConfigured",
        "unmeasured": [
            ("no_dmarc_dkim_or_spf_answer", lambda: {"note": "nothing here"}),
            ("failed_input_validation",
             lambda: {"data": {"DMARC": True, "DKIM": True, "SPF": True},
                      "validation": {"status": "failed", "errors": ["x"], "warnings": []}}),
        ],
        "measured": [
            ("no_records_found", lambda: {"DMARC": False, "DKIM": False, "SPF": False},
             {"isDNSConfigured": False, "isDMARCConfigured": False, "isDKIMConfigured": False, "isSPFConfigured": False}),
            ("one_record_missing", lambda: {"DMARC": True, "DKIM": True, "SPF": False},
             {"isDNSConfigured": False, "isDMARCConfigured": True, "isDKIMConfigured": True, "isSPFConfigured": False}),
            ("all_records_found", lambda: {"DMARC": True, "DKIM": True, "SPF": True},
             {"isDNSConfigured": True, "isDMARCConfigured": True, "isDKIMConfigured": True, "isSPFConfigured": True}),
            ("the_string_false_reads_as_not_found", lambda: {"DMARC": "False", "DKIM": "True", "SPF": "true"},
             {"isDNSConfigured": False, "isDMARCConfigured": False, "isDKIMConfigured": True, "isSPFConfigured": True}),
            ("record_text_is_a_found_record", lambda: {"DMARC": "v=DMARC1; p=reject", "DKIM": True, "SPF": "v=spf1 -all"},
             {"isDNSConfigured": True, "isDMARCConfigured": True, "isDKIMConfigured": True, "isSPFConfigured": True}),
        ],
        # A key the lookup did not report is None, never False, and the keys it did report keep their own
        # values. A reported record that is absent already proves isDNSConfigured False, and a missing key must
        # not mask it: the dataCollection error is set only when isDNSConfigured itself is None.
        "partial": [
            ("dkim_key_missing", lambda: {"DMARC": True, "SPF": True},
             {"isDNSConfigured": None, "isDMARCConfigured": True, "isDKIMConfigured": None, "isSPFConfigured": True}),
            ("spf_off_and_dkim_key_missing", lambda: {"DMARC": True, "SPF": False},
             {"isDNSConfigured": False, "isDMARCConfigured": True, "isDKIMConfigured": None, "isSPFConfigured": False}),
            ("dmarc_off_and_two_keys_missing", lambda: {"DMARC": False},
             {"isDNSConfigured": False, "isDMARCConfigured": False, "isDKIMConfigured": None, "isSPFConfigured": None}),
            ("only_dmarc_reported", lambda: {"DMARC": True},
             {"isDNSConfigured": None, "isDMARCConfigured": True, "isDKIMConfigured": None, "isSPFConfigured": None}),
            ("a_key_present_as_null", lambda: {"DMARC": True, "DKIM": None, "SPF": True},
             {"isDNSConfigured": None, "isDMARCConfigured": True, "isDKIMConfigured": None, "isSPFConfigured": True}),
        ],
    },
    {
        "name": "isappconsentrestricted",
        "keys": ("isAppConsentRestricted", "appConsentRestrictedPolicyPercentage"),
        "unmeasured": [
            ("empty_policy_list", lambda: {"policies": []}),
            ("setting_absent", lambda: {"policies": [OTHER_API_CONTROL]}),
            ("policies_not_a_list", lambda: {"policies": "none"}),
            ("truncated_list", lambda: {"policies": [app_consent("BLOCK_ALL")], "nextPageToken": TOKEN}),
            ("truncation_marker", lambda: {"policies": [app_consent("BLOCK_ALL")], "paginationTruncated": True}),
            # Nothing seen so far states open: a later page could, and none of what was read proves True.
            ("truncated_restricted_and_one_without_a_level",
             lambda: {"policies": [app_consent("BLOCK_ALL"), app_consent_without_a_level("orgUnits/synthetic-a")],
                      "nextPageToken": TOKEN}),
            # A matching policy that does not report its access level proves nothing about that policy.
            ("access_level_missing", lambda: {"policies": [app_consent_without_a_level()]}),
            ("one_restricted_and_one_without_a_level",
             lambda: {"policies": [app_consent("BLOCK_ALL"), app_consent_without_a_level("orgUnits/synthetic-a")]}),
        ],
        "measured": [
            ("unrestricted", lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": 0.0}),
            ("one_of_two_restricted",
             lambda: {"policies": [app_consent("BLOCK_ALL"), app_consent("ACCESS_LEVEL_UNSPECIFIED", "orgUnits/synthetic-a")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": 50.0}),
            ("block_all", lambda: {"policies": [app_consent("BLOCK_ALL")]},
             {"isAppConsentRestricted": True, "appConsentRestrictedPolicyPercentage": 100.0}),
            # A negative proven by a policy already seen stays False when the list was cut short; the share
            # of restricted policies is from part of the list, so it is None.
            ("truncated_but_a_policy_states_open",
             lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED")], "nextPageToken": TOKEN},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
            ("truncation_marker_but_a_policy_states_open",
             lambda: {"policies": [app_consent("BLOCK_ALL"), app_consent("ACCESS_LEVEL_UNSPECIFIED", "orgUnits/synthetic-a")],
                      "paginationTruncated": True},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
            ("truncation_marker_string_but_a_policy_states_open",
             lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED")], "paginationTruncated": "true"},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
            ("truncated_open_and_one_without_a_level",
             lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED"), app_consent_without_a_level("orgUnits/synthetic-a")],
                      "nextPageToken": TOKEN},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
            # A policy that states open already proves False; the share cannot be computed while another
            # policy states nothing, so it is None.
            ("one_open_and_one_without_a_level",
             lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED"),
                                   app_consent_without_a_level("orgUnits/synthetic-a")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
            ("one_open_one_restricted_and_one_without_a_level",
             lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED"), app_consent("BLOCK_ALL", "orgUnits/synthetic-b"),
                                   app_consent_without_a_level("orgUnits/synthetic-a")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": None}),
        ],
    },
    # The next three already answered None with a dataCollection error. They are covered here so the
    # whole folder is held to the same rule, and so nothing later loosens them.
    {
        "name": "isautoforwarddisabled",
        "keys": ("isAutoForwardDisabled",),
        "unmeasured": [
            ("empty_policy_list", lambda: {"policies": []}),
            ("complete_list_without_a_forwarding_policy", lambda: {"policies": [SYSTEM_GMAIL_DEFAULT]}),
            ("truncated_list", lambda: {"policies": [forwarding("False")], "nextPageToken": TOKEN}),
        ],
        "measured": [
            ("forwarding_allowed", lambda: {"policies": [SYSTEM_GMAIL_DEFAULT, forwarding("True")]},
             {"isAutoForwardDisabled": False}),
            ("forwarding_off", lambda: {"policies": [SYSTEM_GMAIL_DEFAULT, forwarding("False")]},
             {"isAutoForwardDisabled": True}),
        ],
    },
    {
        "name": "islegacyauthblocked",
        "keys": ("isLegacyAuthBlocked",),
        "unmeasured": [
            ("empty_policy_list", lambda: {"policies": []}),
            ("list_without_any_security_setting", lambda: {"policies": [SYSTEM_GMAIL_DEFAULT]}),
            ("truncated_list", lambda: {"policies": [less_secure("False")], "nextPageToken": TOKEN}),
        ],
        "measured": [
            ("less_secure_apps_allowed", lambda: {"policies": [less_secure("True")]}, {"isLegacyAuthBlocked": False}),
            ("less_secure_apps_off", lambda: {"policies": [less_secure("False")]}, {"isLegacyAuthBlocked": True}),
        ],
    },
    {
        "name": "isunifiedauditloggingenabled",
        "keys": ("isUnifiedAuditLoggingEnabled",),
        "unmeasured": [
            ("empty_feed", lambda: gmail_feed()),
            ("gmail_events_only", lambda: gmail_feed(activity("gmail", 1))),
            ("not_a_reports_feed", lambda: {"policies": []}),
        ],
        # This transform has no False path: it answers True or Not evaluated.
        "measured": [
            ("admin_events_read", lambda: gmail_feed(ADMIN_FEED_EVENT), {"isUnifiedAuditLoggingEnabled": True}),
        ],
    },
]


class GoogleEmailSecurityNotEvaluated(unittest.TestCase):
    def assert_not_evaluated(self, spec, body):
        out = load(spec["name"]).transform(body)
        inner = out["transformedResponse"]
        for key in spec["keys"]:
            self.assertIn(key, inner)
            self.assertIsNone(inner[key], "%s answered %r for an unreadable read" % (key, inner[key]))
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e.strip() for e in collection["errors"]))

    def assert_partial(self, spec, body, expected):
        """Some keys are measured and some are None. The combined answer decides the dataCollection error."""
        out = load(spec["name"]).transform(body)
        inner = out["transformedResponse"]
        for key in expected:
            self.assertIn(key, inner)
            if isinstance(expected[key], bool):
                self.assertIs(inner[key], expected[key], "%s: %r" % (key, inner[key]))
            else:
                self.assertIsNone(inner[key], "%s: %r" % (key, inner[key]))
        collection = out["additionalInfo"]["dataCollection"]
        if expected[spec["verdict_key"]] is None:
            self.assertEqual(collection["status"], "error")
            self.assertTrue(collection["errors"])
        else:
            self.assertEqual(collection["status"], "success", "a measured verdict must not be hidden")
            self.assertEqual(collection["errors"], [])

    def assert_measured(self, spec, body, expected):
        out = load(spec["name"]).transform(body)
        inner = out["transformedResponse"]
        for key in expected:
            self.assertIn(key, inner)
            if isinstance(expected[key], bool):
                self.assertIs(inner[key], expected[key], "%s: %r" % (key, inner[key]))
            else:
                self.assertEqual(inner[key], expected[key])
        # A measured answer is a successful read: no dataCollection error to mask it.
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "success")
        self.assertEqual(collection["errors"], [])


def _partial_test(spec, factory, expected):
    def test(self):
        self.assert_partial(spec, factory(), expected)
    return test


def _unmeasured_test(spec, factory):
    def test(self):
        self.assert_not_evaluated(spec, factory())
    return test


def _measured_test(spec, factory, expected):
    def test(self):
        self.assert_measured(spec, factory(), expected)
    return test


for _spec in SPECS:
    for _label, _factory in COMMON + _spec["unmeasured"]:
        setattr(GoogleEmailSecurityNotEvaluated, "test_%s_%s_is_not_evaluated" % (_spec["name"], _label),
                _unmeasured_test(_spec, _factory))
    for _label, _factory, _expected in _spec["measured"]:
        setattr(GoogleEmailSecurityNotEvaluated, "test_%s_%s_stays_measured" % (_spec["name"], _label),
                _measured_test(_spec, _factory, _expected))
    for _label, _factory, _expected in _spec.get("partial", []):
        setattr(GoogleEmailSecurityNotEvaluated, "test_%s_%s_is_partly_not_evaluated" % (_spec["name"], _label),
                _partial_test(_spec, _factory, _expected))


class TruncatedReadsGiveNoTotals(unittest.TestCase):
    """A summary or count taken from part of a list must not look like a total."""

    def summary(self, name, body):
        return load(name).transform(body)["additionalInfo"]["transformation"]["inputSummary"]

    def test_licence_summary_has_no_assignment_total(self):
        summary = self.summary("confirmedlicensepurchased",
                               {"kind": LICENSES, "items": [WORKSPACE_LICENCE], "nextPageToken": TOKEN})
        self.assertIsNone(summary["workspaceAssignments"])
        self.assertTrue(summary["morePages"])

    def test_licence_summary_keeps_the_total_for_a_complete_list(self):
        summary = self.summary("confirmedlicensepurchased", {"kind": LICENSES, "items": [WORKSPACE_LICENCE]})
        self.assertEqual(summary["workspaceAssignments"], 1)

    def test_logging_summary_has_no_event_total(self):
        for name in ("isemailloggingenabled", "isemailsecurityloggingenabled"):
            summary = self.summary(name, gmail_feed(activity("gmail", 1), nextPageToken=TOKEN))
            self.assertNotIn("items", summary, name)
            self.assertTrue(summary["truncated"], name)


class EverySpecIsComplete(unittest.TestCase):
    def test_every_transform_in_the_folder_is_covered(self):
        covered = set(spec["name"] for spec in SPECS)
        on_disk = set()
        for entry in os.listdir(HERE):
            if entry.endswith(".py") and not entry.startswith("test_") and entry != "__init__.py":
                on_disk.add(entry[:-3])
        self.assertEqual(sorted(on_disk - covered), [])
        self.assertEqual(sorted(covered - on_disk), [])


if __name__ == "__main__":
    unittest.main()
