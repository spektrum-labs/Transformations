"""Azure AD isAdminMFAPhishingResistant (isadminmfaphishingresistant.py).

Two bodies:
- GET /v1.0/security/secureScores?$top=1 (getRecentSecureScores, today's wiring). REAL_SCORE has the Graph
  secureScore shape with AdminMFAV2 at 50% (1 of 2 admins protected). It must read False. AdminMFAV2 at 100% used
  to read True; MFA of any kind is not phishing-resistant MFA, so it now reads None.
- GET /v1.0/policies/authenticationMethodsPolicy (getAuthenticationMethodsPolicy): never True; email OTP FAILS.
- GET /v1.0/identity/conditionalAccess/policies (getConditionalAccessPolicies): the only body that can prove the
  requirement; True or None, never False.
Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isadminmfaphishingresistant.py")
ROOT = PATH.resolve().parents[3]
KEY = "isAdminMFAPhishingResistant"


def control(pct, count="1", total="2", name="AdminMFAV2"):
    return {"controlCategory": "Identity", "controlName": name, "description": "Ensure MFA for admin roles",
            "score": 10.0 * pct / 100 if isinstance(pct, (int, float)) else None, "scoreInPercentage": pct, "implementationStatus": "",
            "lastSynced": "2026-10-02T00:00:00Z", "count": count, "total": total}


def score_body(*controls):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/secureScores",
            "value": [{"id": "tenant_2026-10-02", "azureTenantId": "00000000-0000-0000-0000-000000000001",
                       "activeUserCount": 40, "createdDateTime": "2026-10-02T00:00:00Z", "currentScore": 41.2,
                       "enabledServices": ["HasExchange"], "maxScore": 200.0,
                       "controlScores": [control(100.0, name="BlockLegacyAuthentication")] + list(controls)}]}


REAL_SCORE = score_body(control(50.0))


def target(gid="all_users"):
    return {"targetType": "group", "id": gid, "isRegistrationRequired": False}


def cfg(mid, state, targets=None, **extra):
    c = {"@odata.type": "#microsoft.graph." + mid[0].lower() + mid[1:] + "AuthenticationMethodConfiguration",
         "id": mid, "state": state, "excludeTargets": [], "includeTargets": [target()] if targets is None else targets}
    c.update(extra)
    return c


MULTI = {"x509CertificateAuthenticationDefaultMode": "x509CertificateMultiFactor", "rules": []}


def policy(enabled=(), migration="migrationComplete", **extra_cfg):
    ids = ["Fido2", "MicrosoftAuthenticator", "Sms", "TemporaryAccessPass", "SoftwareOath", "Voice", "Email",
           "X509Certificate"]
    configs = []
    for mid in ids:
        c = cfg(mid, "enabled" if mid in enabled else "disabled", [] if mid == "Email" else None)
        if mid == "TemporaryAccessPass":
            c["maximumLifetimeInMinutes"] = 480
        if mid == "X509Certificate":
            c["authenticationModeConfiguration"] = MULTI
        c.update(extra_cfg.get(mid, {}))
        configs.append(c)
    return {"id": "authenticationMethodsPolicy", "policyMigrationState": migration,
            "authenticationMethodConfigurations": configs}


ADMIN_ROLE_IDS = [
    "62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "29232cdf-9323-42fd-ade2-1d097af3e4de", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "fe930be7-5e62-47db-91af-98c3a49a38b1", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814"]
PR_STRENGTH = {"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA", "policyType": "builtIn",
               "requirementsSatisfied": "mfa", "allowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"],
               "combinationConfigurations": []}


def ca_policy(users=(), roles=(), state="enabled", combos=None, apps=("All",), builtin=(), exclude_groups=(),
              exclude_roles=(), strength="default"):
    s = dict(PR_STRENGTH)
    if combos is not None:
        s["allowedCombinations"] = list(combos)
    return {"id": "p", "displayName": "Admins phishing-resistant", "state": state,
            "conditions": {"clientAppTypes": ["all"], "platforms": None, "locations": None, "signInRiskLevels": [],
                           "userRiskLevels": [], "servicePrincipalRiskLevels": [],
                           "applications": {"includeApplications": list(apps), "excludeApplications": []},
                           "users": {"includeUsers": list(users), "excludeUsers": ["breakglass1"], "includeGroups": [],
                                     "excludeGroups": list(exclude_groups), "includeRoles": list(roles),
                                     "excludeRoles": list(exclude_roles), "includeGuestsOrExternalUsers": None,
                                     "excludeGuestsOrExternalUsers": None}},
            "grantControls": {"operator": "OR", "builtInControls": list(builtin), "customAuthenticationFactors": [],
                              "termsOfUse": [], "authenticationStrength": s if strength == "default" else strength}}


def ca_body(*policies):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
            "value": list(policies)}


def load():
    spec = importlib.util.spec_from_file_location("aad_isadminmfaphishingresistant", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_aad_admin", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


class AadAdminPhishResistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, body):
        return self.t.transform(copy.deepcopy(body))

    def value(self, body):
        return self.run_t(body)["transformedResponse"][KEY]

    def assert_unevaluated(self, body):
        res = self.run_t(body)
        self.assertIsNone(res["transformedResponse"][KEY])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")
        return res

    # Secure Score (today's wiring)
    def test_real_score_below_100_fails(self):
        res = self.run_t(REAL_SCORE)
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertEqual(res["transformedResponse"]["scoreInPercentage"], 50.0)
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")

    def test_score_100_is_not_evaluated_never_true(self):
        # the old file returned True here: admin MFA of any kind was called phishing-resistant
        for pct in (100.0, 100, "100"):
            with self.subTest(pct=pct):
                self.assert_unevaluated(score_body(control(pct)))

    def test_score_wrappers_read_the_same(self):
        for body in ({"apiResponse": REAL_SCORE}, {"response": {"result": REAL_SCORE}}, json.dumps(REAL_SCORE),
                     {"data": REAL_SCORE, "validation": {"status": "unknown"}}):
            with self.subTest(body=str(body)[:30]):
                self.assertIs(self.value(body), False)

    def test_score_no_evidence_is_not_evaluated(self):
        for body in (score_body(), score_body(control(50.0), control(40.0)), score_body(control(None)),
                     score_body(control("abc")), score_body(control(150.0)), {"value": []}, {"value": ["x"]},
                     {"PSError": "Response status code does not indicate success: 403 (Forbidden)."},
                     {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
                     {"data": REAL_SCORE, "validation": {"status": "failed"}}):
            with self.subTest(body=str(body)[:60]):
                self.assert_unevaluated(body)

    # authentication methods policy: never True; FAIL only on email OTP (J.J. 3 Oct)
    def test_policy_never_passes(self):
        # review MEDIUM 1: FIDO2 enabled (even for all users) does not prove admins must use it
        for enabled in (["Fido2"], ["X509Certificate"], ["Fido2", "TemporaryAccessPass"]):
            with self.subTest(enabled=enabled):
                self.assert_unevaluated(policy(enabled))
        group_only = policy(["Fido2"], Fido2={"includeTargets": [target("00000000-0000-0000-0000-0000000000aa")]})
        self.assert_unevaluated(group_only)

    def test_policy_guest_only_email_fails(self):
        # J.J. 3 Oct 00:55 ET: guest-only email OTP FAILS
        res = self.run_t(policy(["Fido2", "Email"]))
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertIs(res["transformedResponse"]["emailOtpGuestsOnly"], True)
        self.assertIs(self.value(policy(["Email"], Email={"includeTargets": [target()]})), False)
        self.assertIs(self.value(policy(["Email"], migration="preMigration")), False)

    def test_policy_nothing_enabled_or_legacy_is_not_evaluated(self):
        # review MEDIUM 2: nothing enabled, preMigration or partial migration reads None, not False
        self.assert_unevaluated(policy([]))
        for state in ("preMigration", "migrationInProgress", "", None):
            with self.subTest(state=state):
                self.assert_unevaluated(policy(["Sms"], migration=state))
                self.assert_unevaluated(policy([], migration=state))

    def test_policy_no_fido_or_cba_is_not_a_fail(self):
        # Windows Hello for Business is not in this policy, so missing FIDO2/CBA is never a FAIL
        self.assert_unevaluated(policy(["MicrosoftAuthenticator", "SoftwareOath"]))
        self.assert_unevaluated(policy(["Sms", "Voice"]))

    def test_policy_partial_bodies_are_not_evaluated(self):
        partial = policy(["Fido2"])
        partial["authenticationMethodConfigurations"][3].pop("state")
        paged = policy(["Email"])
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
        truncated = policy(["Email"])
        truncated["authenticationMethodConfigurations"] = [c for c in truncated["authenticationMethodConfigurations"] if c["id"] == "Email"]
        for b in (partial, paged, truncated, {"authenticationMethodConfigurations": []}):
            with self.subTest(b=str(b)[:40]):
                self.assert_unevaluated(b)

    # Conditional Access: the only body that can prove the requirement
    def test_ca_admin_roles_with_phishing_resistant_strength_passes(self):
        res = self.run_t(ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS))))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertIs(self.value(ca_body(ca_policy(users=["All"]))), True)
        self.assertIs(self.value(ca_body(ca_policy(roles=ADMIN_ROLE_IDS[:7]), ca_policy(roles=ADMIN_ROLE_IDS[7:]))), True)

    def test_ca_not_proven_is_not_evaluated_never_false(self):
        for body in (ca_body(ca_policy(roles=ADMIN_ROLE_IDS[:13])),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), combos=["fido2", "deviceBasedPush"])),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), state="enabledForReportingButNotEnforced")),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), apps=["00000002-0000-0ff1-ce00-000000000000"])),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), builtin=["compliantDevice"])),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), exclude_groups=["g1"])),
                     ca_body(ca_policy(users=["All"], exclude_roles=[ADMIN_ROLE_IDS[0]])),
                     ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS), strength=None)),
                     {"value": []}):
            with self.subTest(body=str(body)[:80]):
                self.assert_unevaluated(body)

    def test_ca_paged_or_unreadable_is_not_evaluated(self):
        paged = ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS)))
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
        self.assert_unevaluated(paged)
        broken = ca_body(ca_policy(roles=list(ADMIN_ROLE_IDS)))
        broken["value"][0]["grantControls"]["authenticationStrength"]["allowedCombinations"] = None
        self.assert_unevaluated(broken)

    def test_garbage_is_not_evaluated(self):
        for body in (None, {}, [], "", "null", "not json", b"", 0, [1, 2]):
            with self.subTest(body=body):
                self.assert_unevaluated(body)


try:
    import RestrictedPython  # noqa: F401

    class AadAdminPhishResistantSandboxTests(AadAdminPhishResistantTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
