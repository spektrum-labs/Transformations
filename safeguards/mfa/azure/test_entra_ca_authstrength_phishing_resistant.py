"""isCAAuthStrengthPhishingResistantRequired (entra_ca_authstrength_phishing_resistant.py) on
GET /v1.0/identity/conditionalAccess/policies.

REAL mirrors the shape of a customer tenant's CA list stored 2026-09-30 (Azure AD One-Click): an enabled policy for
one group that requires a custom strength allowing windowsHelloForBusiness, fido2, deviceBasedPush, a one-time TAP
and password + Authenticator push, plus a report-only built-in "Phishing-resistant MFA" policy. Ids and names are
replaced. It must read False for both results. Each case runs as plain Python and in the Token-Service sandbox
replica.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("entra_ca_authstrength_phishing_resistant.py")
ROOT = PATH.resolve().parents[3]
KEY = "isCAAuthStrengthPhishingResistantRequired"
ADMIN = "isCAAuthStrengthPhishingResistantRequiredForAdmins"
ROLES = [
    "62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "29232cdf-9323-42fd-ade2-1d097af3e4de", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "fe930be7-5e62-47db-91af-98c3a49a38b1", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814"]
PR = ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]


def strength(combos, sid="00000000-0000-0000-0000-000000000004", kind="builtIn"):
    return {"id": sid, "createdDateTime": "2021-12-01T08:00:00Z", "modifiedDateTime": "2021-12-01T08:00:00Z",
            "displayName": "Phishing-resistant MFA", "description": "", "policyType": kind, "requirementsSatisfied": "mfa",
            "allowedCombinations": list(combos), "combinationConfigurations": []}


def pol(users=(), roles=(), groups=(), state="enabled", combos=PR, apps=("All",), builtin=(), operator="OR",
        exclude_users=("00000000-0000-0000-0000-00000000b001",), exclude_groups=(), exclude_roles=(), guests_excluded=None,
        locations=None, client=("all",), platforms=None, risk=(), the_strength="default", name="Require phishing-resistant MFA"):
    return {
        "id": "11111111-0000-0000-0000-000000000001", "displayName": name, "state": state,
        "createdDateTime": "2025-07-24T03:53:44Z", "modifiedDateTime": "2025-08-11T19:10:55Z", "templateId": None,
        "conditions": {
            "userRiskLevels": [], "signInRiskLevels": list(risk), "clientAppTypes": list(client),
            "servicePrincipalRiskLevels": [], "insiderRiskLevels": None, "platforms": platforms, "locations": locations,
            "devices": None, "clientApplications": None, "authenticationFlows": None,
            "applications": {"includeApplications": list(apps), "excludeApplications": [], "includeUserActions": [],
                             "includeAuthenticationContextClassReferences": [], "applicationFilter": None},
            "users": {"includeUsers": list(users), "excludeUsers": list(exclude_users), "includeGroups": list(groups),
                      "excludeGroups": list(exclude_groups), "includeRoles": list(roles), "excludeRoles": list(exclude_roles),
                      "includeGuestsOrExternalUsers": None, "excludeGuestsOrExternalUsers": guests_excluded}},
        "grantControls": {"operator": operator, "builtInControls": list(builtin), "customAuthenticationFactors": [],
                          "termsOfUse": [],
                          "authenticationStrength": strength(combos) if the_strength == "default" else the_strength},
        "sessionControls": None}


def body(*policies):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
            "value": list(policies)}


REAL = body(
    pol(groups=["22222222-0000-0000-0000-000000000001"], name="Group sign-in strength",
        combos=["windowsHelloForBusiness", "fido2", "deviceBasedPush", "temporaryAccessPassOneTime",
                "password,microsoftAuthenticatorPush"]),
    pol(users=["All"], state="enabledForReportingButNotEnforced", name="Report-only phishing-resistant"),
    pol(users=["All"], builtin=["mfa"], the_strength=None, name="MFA for all users"))


def load():
    spec = importlib.util.spec_from_file_location("entra_ca_authstrength_phishing_resistant", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_caas", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


class CAAuthStrengthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, b):
        return self.t.transform(copy.deepcopy(b))

    def values(self, b):
        out = self.run_t(b)["transformedResponse"]
        return out[KEY], out[ADMIN]

    def assert_unevaluated(self, b):
        res = self.run_t(b)
        self.assertIsNone(res["transformedResponse"][KEY])
        self.assertIsNone(res["transformedResponse"][ADMIN])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")

    def test_real_fails_all_users_admins_not_proven(self):
        # the group-scoped strength allows deviceBasedPush, so it is weak: both FAIL
        res = self.run_t(REAL)
        self.assertEqual((res["transformedResponse"][KEY], res["transformedResponse"][ADMIN]), (False, False))
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")

    def test_envelopes_read_the_same(self):
        for b in ({"apiResponse": REAL}, {"response": {"result": REAL}}, json.dumps(REAL), json.dumps(REAL).encode(),
                  {"data": REAL, "validation": {"status": "unknown"}}, REAL["value"]):
            with self.subTest(b=str(b)[:30]):
                self.assertEqual(self.values(b), (False, False))

    def test_all_users_phishing_resistant_passes_both(self):
        self.assertEqual(self.values(body(pol(users=["All"]))), (True, True))
        for combos in (["fido2"], ["windowsHelloForBusiness", "fido2"], ["x509CertificateMultiFactor"]):
            with self.subTest(combos=combos):
                self.assertEqual(self.values(body(pol(users=["All"], combos=combos))), (True, True))

    def test_admin_roles_pass_admins_only(self):
        self.assertEqual(self.values(body(pol(roles=ROLES))), (False, True))
        self.assertEqual(self.values(body(pol(roles=ROLES[:7]), pol(roles=ROLES[7:]))), (False, True))
        self.assertEqual(self.values(body(pol(roles=ROLES[:13]))), (False, False))
        self.assertEqual(self.values(body(pol(roles=ROLES[:13]), pol(groups=["g"], apps=[]))), (False, None))

    def test_weak_combination_in_strength_does_not_count(self):
        for extra in ("deviceBasedPush", "password,microsoftAuthenticatorPush", "temporaryAccessPassOneTime",
                      "federatedMultiFactor", "x509CertificateSingleFactor", "password,sms"):
            with self.subTest(extra=extra):
                self.assertEqual(self.values(body(pol(users=["All"], roles=ROLES, combos=PR + [extra]))), (False, False))

    def test_or_alternative_does_not_count(self):
        for builtin in (["mfa"], ["compliantDevice"], ["domainJoinedDevice"]):
            with self.subTest(builtin=builtin):
                self.assertEqual(self.values(body(pol(users=["All"], builtin=builtin))), (False, False))
        self.assertEqual(self.values(body(pol(users=["All"], builtin=["compliantDevice"], operator="AND"))), (True, True))

    def test_not_enforced_does_not_count(self):
        for state in ("enabledForReportingButNotEnforced", "disabled"):
            with self.subTest(state=state):
                self.assertEqual(self.values(body(pol(users=["All"], state=state))), (False, False))

    def test_narrowed_policy_fails_all_users_admins_not_proven(self):
        for p in (pol(users=["All"], apps=["00000003-0000-0ff1-ce00-000000000000"]),
                  pol(users=["All"], client=["browser"]), pol(users=["All"], risk=["high"]),
                  pol(users=["All"], platforms={"includePlatforms": ["android"], "excludePlatforms": []}),
                  pol(users=["All"], locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})):
            with self.subTest(p=str(p["conditions"])[:60]):
                self.assertEqual(self.values(body(p)), (False, None))

    def test_group_or_pim_scoped_strength_leaves_admins_unevaluated(self):
        # a phishing-resistant strength for an admin group or for PIM elevation (authentication context) may cover
        # the admins; the read cannot map groups to roles, so the admin result is None, never a proven FAIL
        group = body(pol(groups=["33333333-0000-0000-0000-000000000001"]))
        pim = body(pol(users=["44444444-0000-0000-0000-000000000001"], apps=[]))
        for b in (group, pim):
            with self.subTest(b=str(b)[:20]):
                out = self.run_t(b)["transformedResponse"]
                self.assertIs(out[KEY], False)
                self.assertIsNone(out[ADMIN])
        self.assertEqual(self.values(body(pol(groups=["g"], combos=PR + ["deviceBasedPush"]))), (False, False))

    def test_emergency_access_exclusions_are_bounded_and_named(self):
        res = self.run_t(body(pol(users=["All"], exclude_users=["bg-1", "bg-2"])))
        self.assertEqual((res["transformedResponse"][KEY], res["transformedResponse"][ADMIN]), (True, True))
        self.assertEqual(res["transformedResponse"]["excludedEmergencyAccessAccounts"], ["bg-1", "bg-2"])
        self.assertTrue(res["additionalInfo"]["evaluation"]["passReasons"][0].startswith(
            "PASS with 2 excluded emergency-access accounts: bg-1, bg-2"))
        res = self.run_t(body(pol(roles=ROLES, exclude_users=["bg-9"])))
        self.assertEqual((res["transformedResponse"][KEY], res["transformedResponse"][ADMIN]), (False, True))
        self.assertTrue(res["additionalInfo"]["evaluation"]["passReasons"][0].startswith("PASS with 1 excluded"))
        # more than 2 on one policy, or in total across policies: not proven
        self.assert_unevaluated(body(pol(users=["All"], exclude_users=["a", "b", "c"])))
        self.assert_unevaluated(body(pol(users=["All"], exclude_users=["a", "b"]), pol(users=["All"], exclude_users=["c"])))
        self.assertEqual(self.values(body(pol(roles=ROLES[:7], exclude_users=["a", "b"]),
                                          pol(roles=ROLES[7:], exclude_users=["c"]))), (False, None))

    def test_group_guest_or_role_exclusions_are_not_proven(self):
        guests = {"guestOrExternalUserTypes": "b2bCollaborationGuest", "externalTenants": {"membershipKind": "all"}}
        self.assert_unevaluated(body(pol(users=["All"], exclude_groups=["g"])))
        self.assert_unevaluated(body(pol(users=["All"], guests_excluded=guests)))
        self.assertEqual(self.values(body(pol(roles=ROLES, guests_excluded=guests))), (False, None))
        self.assertEqual(self.values(body(pol(roles=ROLES, exclude_groups=["g"]))), (False, None))
        # ANY excluded role (admin or not) leaves coverage unproven
        reports_reader = "4a5d8f65-41da-4de4-8968-e035b65339cf"
        self.assert_unevaluated(body(pol(users=["All"], exclude_roles=[ROLES[0]])))
        self.assert_unevaluated(body(pol(users=["All"], exclude_roles=[reports_reader])))
        self.assertEqual(self.values(body(pol(roles=ROLES, exclude_roles=[ROLES[3]]))), (False, None))
        self.assertEqual(self.values(body(pol(roles=ROLES, exclude_roles=[reports_reader]))), (False, None))

    def test_no_evidence_or_partial_is_not_evaluated(self):
        paged = copy.deepcopy(REAL)
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
        no_combos = body(pol(users=["All"], the_strength={"id": "x", "displayName": "custom"}))
        bad_users = body(pol(users=["All"]))
        bad_users["value"][0]["conditions"]["users"]["excludeUsers"] = "nope"
        for b in (None, {}, [], "", "null", "not json", b"", 0, {"value": []}, {"value": None}, paged, no_combos,
                  bad_users, {"value": ["x"]},
                  {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
                  {"data": REAL, "validation": {"status": "failed"}}):
            with self.subTest(b=str(b)[:50]):
                self.assert_unevaluated(b)

    def test_unreadable_policy_does_not_block_a_proven_pass(self):
        no_combos = pol(users=["All"], the_strength={"id": "x"}, name="odd")
        self.assertEqual(self.values(body(no_combos, pol(users=["All"]))), (True, True))


try:
    import RestrictedPython  # noqa: F401

    class CAAuthStrengthSandboxTests(CAAuthStrengthTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
