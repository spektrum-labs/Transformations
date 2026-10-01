"""Tests for isssoenabled_entra.py (Microsoft Entra ID isSSOEnabled).

Fixtures follow the Microsoft Graph v1.0 response shapes for
GET /servicePrincipals?$select=... and GET /domains?$select=..., including the engine
wrappers (apiResponse / rawResponse / Output) the Integration-Service puts around them.
"""

import importlib.util
import json
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isssoenabled_entra.py")
LEGACY_TRANSFORMATION_PATH = Path(__file__).with_name("isssoenabled.py")
KEY = "isSSOEnabled"
MICROSOFT_SERVICES = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
CUSTOMER_TENANT = "0b6c2f3e-9a51-4d7e-8f2a-3c1d5e6f7a8b"


def load_transformation(path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def graph_list(context, rows):
    return {"@odata.context": f"https://graph.microsoft.com/v1.0/$metadata#{context}", "value": rows}


def sp(name, mode, owner=CUSTOMER_TENANT, enabled=True, sp_type="Application"):
    return {
        "id": "sp-" + name.lower().replace(" ", "-"),
        "appId": "app-" + name.lower().replace(" ", "-"),
        "displayName": name,
        "preferredSingleSignOnMode": mode,
        "accountEnabled": enabled,
        "appOwnerOrganizationId": owner,
        "servicePrincipalType": sp_type,
    }


def domain(name, auth_type):
    return {"id": name, "authenticationType": auth_type, "isVerified": True, "isDefault": False}


FIRST_PARTY_SPS = [
    sp("Microsoft Graph", None, owner=MICROSOFT_SERVICES),
    sp("Office 365 Exchange Online", None, owner=MICROSOFT_SERVICES),
    sp("Microsoft Teams", None, owner=MICROSOFT_SERVICES),
]
MANAGED_DOMAINS = [
    domain("contoso.onmicrosoft.com", "Managed"),
    domain("contoso.com", "Managed"),
]
BUILT_IN_PROVIDERS = graph_list("identityProviders", [
    {"@odata.type": "#microsoft.graph.builtInIdentityProvider", "id": "AADSignup-OAUTH",
     "displayName": "Azure Active Directory Sign up", "identityProviderType": "AADSignup", "state": None},
    {"@odata.type": "#microsoft.graph.builtInIdentityProvider", "id": "MSASignup-OAUTH",
     "displayName": "Microsoft Account", "identityProviderType": "MicrosoftAccount", "state": None},
    {"@odata.type": "#microsoft.graph.builtInIdentityProvider", "id": "EmailOtpSignup-OAUTH",
     "displayName": "Email One Time Passcode", "identityProviderType": "EmailOTP", "state": None},
])


def combined(sps=None, domains=None):
    body = {}
    if sps is not None:
        body["servicePrincipals"] = graph_list("servicePrincipals", sps)
    if domains is not None:
        body["domains"] = graph_list("domains", domains)
    return body


class EntraSSOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation(TRANSFORMATION_PATH, "isssoenabled_entra")

    def info(self, response):
        return response["additionalInfo"]

    def assert_fail_with_error(self, response):
        self.assertIs(response["transformedResponse"][KEY], False)
        info = self.info(response)
        self.assertTrue(
            info["dataCollection"]["status"] == "error" or info["transformation"]["status"] == "error",
            "a no-evidence false must carry a dataCollection or transformation error",
        )

    # --- passes ---------------------------------------------------------------

    def test_saml_enterprise_app_passes(self):
        response = self.t.transform(combined(
            FIRST_PARTY_SPS + [sp("Salesforce", "saml"), sp("Internal HR Portal", None)],
            MANAGED_DOMAINS,
        ))
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["ssoApplicationCount"], 1)
        self.assertIn("Salesforce", response["additionalInfo"]["evaluation"]["passReasons"][0])
        self.assertEqual(self.info(response)["dataCollection"]["status"], "success")
        self.assertEqual(self.info(response)["metadata"]["schemaVersion"], "2.0")

    def test_oidc_and_password_modes_pass(self):
        for mode in ["oidc", "password"]:
            response = self.t.transform(combined([sp("Gallery App", mode)], MANAGED_DOMAINS))
            self.assertIs(response["transformedResponse"][KEY], True, mode)

    def test_federated_domain_passes(self):
        response = self.t.transform(combined(
            FIRST_PARTY_SPS,
            MANAGED_DOMAINS + [domain("corp.contoso.com", "Federated")],
        ))
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["federatedDomainCount"], 1)

    def test_engine_wrappers_are_unwrapped(self):
        body = {
            "servicePrincipals": {"apiResponse": {"rawResponse": graph_list(
                "servicePrincipals", [sp("Workday", "saml")])}},
            "domains": {"rawResponse": graph_list("domains", MANAGED_DOMAINS)},
        }
        response = self.t.transform({"Output": body})
        self.assertIs(response["transformedResponse"][KEY], True)

    def test_json_string_input(self):
        response = self.t.transform(json.dumps(combined([sp("Zoom", "saml")], MANAGED_DOMAINS)))
        self.assertIs(response["transformedResponse"][KEY], True)

    def test_bare_service_principal_list(self):
        response = self.t.transform(graph_list("servicePrincipals", [sp("ServiceNow", "saml")]))
        self.assertIs(response["transformedResponse"][KEY], True)

    def test_sso_app_found_while_domains_errored_still_passes_on_evidence(self):
        body = combined([sp("Salesforce", "saml")])
        body["domains"] = {"error": {"code": "Authorization_RequestDenied",
                                     "message": "Insufficient privileges to complete the operation."}}
        response = self.t.transform(body)
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertTrue(self.info(response)["evaluation"]["additionalFindings"])

    # --- genuine fails ---------------------------------------------------------

    def test_only_non_sso_apps_fails(self):
        response = self.t.transform(combined(
            FIRST_PARTY_SPS + [sp("Internal API", None), sp("Legacy Tool", "notSupported")],
            MANAGED_DOMAINS,
        ))
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.info(response)["dataCollection"]["status"], "success")
        self.assertTrue(self.info(response)["evaluation"]["failReasons"])

    def test_microsoft_first_party_app_with_sso_mode_does_not_count(self):
        response = self.t.transform(combined(
            [sp("Microsoft First Party", "saml", owner=MICROSOFT_SERVICES)], MANAGED_DOMAINS,
        ))
        self.assertIs(response["transformedResponse"][KEY], False)

    def test_disabled_saml_app_does_not_count(self):
        response = self.t.transform(combined([sp("Old SAML App", "saml", enabled=False)], MANAGED_DOMAINS))
        self.assertIs(response["transformedResponse"][KEY], False)

    def test_built_in_identity_providers_only_is_false(self):
        """The old check passed on exactly this body; it is not SSO evidence."""
        response = self.t.transform(BUILT_IN_PROVIDERS)
        self.assert_fail_with_error(response)
        legacy = load_transformation(LEGACY_TRANSFORMATION_PATH, "isssoenabled_legacy")
        self.assertIs(legacy.transform(BUILT_IN_PROVIDERS)["transformedResponse"][KEY], True,
                      "documents the false pass this file replaces")

    # --- fail closed -----------------------------------------------------------

    def test_empty_lists_fail_with_error(self):
        self.assert_fail_with_error(self.t.transform(combined([], [])))

    def test_empty_bare_list_fails_with_error(self):
        self.assert_fail_with_error(self.t.transform(graph_list("servicePrincipals", [])))

    def test_no_evidence_bodies_fail_with_error(self):
        for body in [None, {}, "{}", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}, []]:
            self.assert_fail_with_error(self.t.transform(body))

    def test_graph_error_body_fails(self):
        body = {"error": {"code": "Authorization_RequestDenied",
                          "message": "Insufficient privileges to complete the operation.",
                          "innerError": {"date": "2026-10-01T14:00:00", "request-id": "r1"}}}
        response = self.t.transform(body)
        self.assert_fail_with_error(response)
        self.assertEqual(self.info(response)["dataCollection"]["status"], "error")
        self.assertIn("403", self.info(response)["dataCollection"]["errors"][0])

    def test_both_sources_error_fails(self):
        denied = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
        response = self.t.transform({"servicePrincipals": denied, "domains": denied})
        self.assert_fail_with_error(response)
        self.assertEqual(len(self.info(response)["dataCollection"]["errors"]), 2)

    def test_sp_error_with_managed_domains_is_false_with_error(self):
        body = combined(None, MANAGED_DOMAINS)
        body["servicePrincipals"] = {"statusCode": 403, "error": "Forbidden"}
        response = self.t.transform(body)
        self.assert_fail_with_error(response)
        self.assertEqual(self.info(response)["dataCollection"]["status"], "error")

    def test_error_envelopes_fail(self):
        for body in [
            {"PSError": "401 Unauthorized"},
            {"statusCode": 401, "error": "Unauthorized"},
            {"status_code": 401, "error": "Unauthorized"},
            {"error": {"statusCode": 401, "message": "Unauthorized"}},
            {"statusCode": 403, "error": "Forbidden"},
            {"status": "error", "message": "Integration call failed"},
            {"error": {"type": "authentication_error", "message": "invalid credentials"}},
        ]:
            response = self.t.transform(body)
            self.assert_fail_with_error(response)
            self.assertEqual(self.info(response)["dataCollection"]["status"], "error", body)

    def test_malformed_json_fails(self):
        self.assert_fail_with_error(self.t.transform("{not-json"))


if __name__ == "__main__":
    unittest.main()
