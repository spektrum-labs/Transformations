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

def gmail_policy(setting_type, value, org_unit="orgUnits/synthetic-root"):
    return {"name": "policies/synthetic-1", "type": "ADMIN",
            "policyQuery": {"orgUnit": org_unit, "sortOrder": "201.1"},
            "setting": {"type": "settings/" + setting_type, "value": value}}


OTHER_GMAIL = gmail_policy("gmail.mail_delegation", {"enableMailDelegation": False})


def policy_family(name, key, setting_type, fields):
    """The four Gmail-policy transforms and the link check share one rule: every policy for the
    setting must have every required field on."""
    all_on = dict((f, True) for f in fields)
    all_off = dict((f, False) for f in fields)
    one_off = dict(all_on)
    one_off[fields[0]] = False
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
        ],
        "measured": [
            ("setting_off", lambda: {"policies": [gmail_policy(setting_type, all_off)]}, {key: False}),
            ("one_of_two_policies_off",
             lambda: {"policies": [gmail_policy(setting_type, all_on, "orgUnits/synthetic-a"),
                                   gmail_policy(setting_type, one_off, "orgUnits/synthetic-b")]}, {key: False}),
            ("complete_list_without_the_setting", lambda: {"policies": [OTHER_GMAIL]}, {key: False}),
            ("truncated_but_a_policy_is_off",
             lambda: {"policies": [gmail_policy(setting_type, one_off)], "nextPageToken": TOKEN}, {key: False}),
            ("all_on", lambda: {"policies": [gmail_policy(setting_type, all_on)]}, {key: True}),
            ("bare_list_all_on", lambda: [gmail_policy(setting_type, all_on)], {key: True}),
        ],
    }


def phishing(value, **extra):
    body = {"policies": [{"setting": {"value": value}}]}
    body.update(extra)
    return body


SPOOF_ON = {"detectDomainNameSpoofing": True, "detectEmployeeNameSpoofing": True}
SPOOF_OFF = {"detectDomainNameSpoofing": False, "detectEmployeeNameSpoofing": True}


def when(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def gmail_feed(*items):
    body = {"kind": "admin#reports#activities"}
    if items:
        body["items"] = list(items)
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
        ],
        "measured": [
            ("only_stale_gmail_events", lambda: gmail_feed(activity("gmail", 30), activity("gmail", 25)), {key: False}),
            ("recent_gmail_events", lambda: gmail_feed(activity("gmail", 1)), {key: True}),
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


def users(*members, **extra):
    body = {"users": list(members)}
    body.update(extra)
    return body


def sso_assignments(*items, **extra):
    inner = {"inboundSsoAssignments": list(items)}
    inner.update(extra)
    return inner


NO_PROFILES = {"inboundSamlSsoProfiles": []}
LEGACY_OFF = {"idpInfo": [{"@name": "enableSSO", "@value": "false"}]}
LEGACY_NO_ENABLE = {"idpInfo": [{"@name": "samlSignonUri", "@value": "https://idp-synthetic/sso"}]}


def app_consent(level, org_unit="orgUnits/synthetic-root"):
    return {"type": "ADMIN", "policyQuery": {"orgUnit": org_unit},
            "setting": {"type": "settings/api_controls.unconfigured_third_party_apps",
                        "value": {"accessLevel": level}}}


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
                  ["enableShortenerScanning", "enableAggressiveWarningsOnUntrustedLinks"]),
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
        ],
        "measured": [
            ("a_spoofing_setting_off", lambda: phishing(SPOOF_OFF),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False}),
            ("complete_list_without_the_settings", lambda: phishing({"other": True}),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False}),
            ("truncated_but_a_setting_is_off", lambda: phishing(SPOOF_OFF, nextPageToken=TOKEN),
             {"isEmailSecurityEnabled": True, "isAntiPhishingEnabled": False}),
            ("all_on", lambda: phishing(SPOOF_ON),
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
             {"confirmedLicensePurchased": False}),
            ("policy_proxy_without_a_workspace_licence", lambda: {"policies": {"policies": [PROXY_NO_SKU]}},
             {"confirmedLicensePurchased": False}),
            ("workspace_licence_assigned", lambda: {"kind": LICENSES, "items": [WORKSPACE_LICENCE]},
             {"confirmedLicensePurchased": True}),
            ("truncated_but_a_workspace_licence_found",
             lambda: {"kind": LICENSES, "items": [WORKSPACE_LICENCE], "nextPageToken": TOKEN},
             {"confirmedLicensePurchased": True}),
        ],
    },
    {
        "name": "ismfaenforcedforusers",
        "keys": MFA_KEYS,
        "unmeasured": [
            ("empty_user_list", lambda: users()),
            ("only_suspended_users", lambda: users(SUSPENDED)),
            ("truncated_user_list", lambda: users(ENFORCED, nextPageToken=TOKEN)),
            ("no_users_key", lambda: {"kind": "admin#directory#users"}),
            ("users_not_a_list", lambda: {"users": "none"}),
        ],
        "measured": [
            ("an_active_user_not_enforced", lambda: users(ENFORCED, NOT_ENFORCED),
             {"isMFAEnforcedForUsers": False, "totalUsers": 2, "mfaEnrolledUsers": 1}),
            ("every_active_user_enforced", lambda: users(ENFORCED, SUSPENDED),
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
            ("empty_list_withdraws_a_direct_flag", lambda: {"isMFAEnforcedForUsers": True, "users": []}),
        ],
        "measured": [
            ("no_user_enforced", lambda: users(NOT_ENFORCED),
             {"isMFAEnforcedForUsers": False, "totalUsers": 1, "mfaEnrolledUsers": 0}),
            ("one_enforced_user", lambda: users(ENFORCED, NOT_ENFORCED),
             {"isMFAEnforcedForUsers": True, "totalUsers": 2, "mfaEnrolledUsers": 1}),
            ("truncated_but_a_user_is_enforced", lambda: users(ENFORCED, nextPageToken=TOKEN),
             {"isMFAEnforcedForUsers": True, "totalUsers": 1, "mfaEnrolledUsers": 1}),
            ("direct_flag_off", lambda: {"isMFAEnforcedForUsers": False}, {"isMFAEnforcedForUsers": False}),
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
        ],
        "measured": [
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
        ],
        "measured": [
            ("unrestricted", lambda: {"policies": [app_consent("ACCESS_LEVEL_UNSPECIFIED")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": 0.0}),
            ("one_of_two_restricted",
             lambda: {"policies": [app_consent("BLOCK_ALL"), app_consent("ACCESS_LEVEL_UNSPECIFIED", "orgUnits/synthetic-a")]},
             {"isAppConsentRestricted": False, "appConsentRestrictedPolicyPercentage": 50.0}),
            ("block_all", lambda: {"policies": [app_consent("BLOCK_ALL")]},
             {"isAppConsentRestricted": True, "appConsentRestrictedPolicyPercentage": 100.0}),
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
