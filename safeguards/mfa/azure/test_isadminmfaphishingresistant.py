"""Azure AD isAdminMFAPhishingResistant (isadminmfaphishingresistant.py).

Two bodies:
- GET /v1.0/security/secureScores?$top=1 (getRecentSecureScores, today's wiring). REAL_SCORE has the Graph
  secureScore shape with AdminMFAV2 at 50% (1 of 2 admins protected). It must read False. AdminMFAV2 at 100% used
  to read True; MFA of any kind is not phishing-resistant MFA, so it now reads None.
- GET /v1.0/policies/authenticationMethodsPolicy (getAuthenticationMethodsPolicy, the re-point).
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

    # authentication methods policy (re-point)
    def test_policy_resistant_only_passes(self):
        self.assertIs(self.value(policy(["Fido2"])), True)
        self.assertIs(self.value(policy(["X509Certificate"])), True)
        self.assertIs(self.value(policy(["Fido2", "TemporaryAccessPass"])), True)  # bounded TAP allowed (#833)
        self.assertIs(self.value(policy(["Fido2", "Email"])), True)  # guest-only email cannot reach an admin

    def test_policy_no_resistant_method_fails(self):
        self.assertIs(self.value(policy(["MicrosoftAuthenticator", "SoftwareOath"])), False)
        self.assertIs(self.value(policy(["Sms"], migration="preMigration")), False)

    def test_policy_mixed_is_not_evaluated(self):
        # admins may be held to an authentication strength the policy does not show
        for extra in ("MicrosoftAuthenticator", "Sms", "SoftwareOath", "Voice"):
            with self.subTest(extra=extra):
                self.assert_unevaluated(policy(["Fido2", extra]))
        self.assert_unevaluated(policy(["Fido2", "TemporaryAccessPass"], TemporaryAccessPass={"maximumLifetimeInMinutes": None}))

    def test_policy_cba_single_factor_is_not_resistant(self):
        single = {"x509CertificateAuthenticationDefaultMode": "x509CertificateSingleFactor", "rules": []}
        self.assertIs(self.value(policy(["X509Certificate"], X509Certificate={"authenticationModeConfiguration": single})), False)
        self.assert_unevaluated(policy(["X509Certificate"], X509Certificate={"authenticationModeConfiguration": None}))

    def test_policy_migration_must_be_complete(self):
        for state in ("preMigration", "migrationInProgress", "", None, "unknownFutureValue"):
            with self.subTest(state=state):
                self.assert_unevaluated(policy(["Fido2"], migration=state))

    def test_policy_external_and_partial_are_not_evaluated(self):
        body = policy(["Fido2"])
        body["authenticationMethodConfigurations"].append(
            {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "1111", "displayName": "Cisco Duo",
             "state": "enabled", "includeTargets": [target()]})
        self.assert_unevaluated(body)
        partial = policy(["Fido2"])
        partial["authenticationMethodConfigurations"][3].pop("state")
        paged = policy(["Fido2"])
        paged["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
        truncated = policy(["Fido2"])
        truncated["authenticationMethodConfigurations"] = truncated["authenticationMethodConfigurations"][:1]
        for b in (partial, paged, truncated, {"authenticationMethodConfigurations": []}):
            with self.subTest(b=str(b)[:40]):
                self.assert_unevaluated(b)

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
