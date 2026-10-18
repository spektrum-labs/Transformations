"""Seven Okta MFA criteria that only a per-user read can answer (Integration-Service workflows
getUserMfaPosture and getAdminMfaPosture): mfaDeviceEnrollmentPercentage, mfaEnforcementCoveragePercentage,
desktopAuthenticatorEnrollmentPercentage, webAuthnCredentialAdoptionPercentage, smsFactorEnabledUsersCount,
inactiveMfaFactorsCount and superAdminMfaEnrollmentPercentage.

Every test runs twice: against the plain module and against the same file compiled by the RestrictedPython
replica in tools/, which is how Token-Service runs it. All data is synthetic: ids, logins and domains are
invented, and the shapes copy Okta's listUsers, listFactors, listUsersWithRoleAssignments and
listAssignedRolesForUser responses as the IS workflow runner assembles them.

The rule every Unevaluated test checks: the value is None AND dataCollection.status is "error" with a
non-empty errors list. Token-Service grades any other None as Failed.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[2]
FIX = HERE / "fixtures"

PERCENT_KEYS = ["mfaDeviceEnrollmentPercentage", "mfaEnforcementCoveragePercentage",
                "desktopAuthenticatorEnrollmentPercentage", "webAuthnCredentialAdoptionPercentage"]
COUNT_KEYS = ["smsFactorEnabledUsersCount", "inactiveMfaFactorsCount"]
USER_KEYS = PERCENT_KEYS + COUNT_KEYS
ADMIN_KEY = "superAdminMfaEnrollmentPercentage"
ALL_KEYS = USER_KEYS + [ADMIN_KEY]


def plain(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + name, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (name + ".py")).read_text(), "<transformation>")["transform"]


def fixture(name):
    return json.loads((FIX / name).read_text())


USERS_FIX = "okta_user_mfa_posture_synthetic.json"
ADMINS_FIX = "okta_admin_mfa_posture_synthetic.json"


class Base(unittest.TestCase):
    def run_both(self, key, body):
        out = []
        for loader in (plain, sandboxed):
            out.append(loader(key)(copy.deepcopy(body)))
        self.assertEqual(out[0]["transformedResponse"], out[1]["transformedResponse"])
        return out[0]

    def value(self, key, body):
        return self.run_both(key, body)["transformedResponse"][key]

    def assert_unevaluated(self, key, body, words=None):
        result = self.run_both(key, body)
        self.assertIsNone(result["transformedResponse"][key])
        dc = result["additionalInfo"]["dataCollection"]
        self.assertEqual(dc["status"], "error")
        self.assertTrue(dc["errors"] and dc["errors"][0])
        if words:
            self.assertIn(words, dc["errors"][0])


class TestUserFixture(Base):
    """Synthetic org: 5 active users, every factor read, list complete."""

    def test_device_enrollment_counts_sms_but_not_email_or_question(self):
        # u1 webauthn, u2 sms only, u3 email+question only, u4 push (pending) + totp, u5 nothing
        self.assertEqual(self.value("mfaDeviceEnrollmentPercentage", fixture(USERS_FIX)), 60.0)

    def test_enforcement_coverage_excludes_weak_factors(self):
        # strong ACTIVE: u1 webauthn, u4 totp
        self.assertEqual(self.value("mfaEnforcementCoveragePercentage", fixture(USERS_FIX)), 40.0)

    def test_desktop_counts_windows_or_macos_platform_only(self):
        # u1 has signed_nonce on MACOS; u4's push is IOS
        self.assertEqual(self.value("desktopAuthenticatorEnrollmentPercentage", fixture(USERS_FIX)), 20.0)

    def test_webauthn_adoption(self):
        self.assertEqual(self.value("webAuthnCredentialAdoptionPercentage", fixture(USERS_FIX)), 20.0)

    def test_sms_users_counted_when_the_read_is_complete(self):
        self.assertEqual(self.value("smsFactorEnabledUsersCount", fixture(USERS_FIX)), 1)

    def test_inactive_factors_counted(self):
        # u4 push PENDING_ACTIVATION
        self.assertEqual(self.value("inactiveMfaFactorsCount", fixture(USERS_FIX)), 1)

    def test_success_states_coverage(self):
        result = self.run_both("mfaEnforcementCoveragePercentage", fixture(USERS_FIX))
        summary = result["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual(summary["usersRead"], 5)
        self.assertFalse(summary["sampled"])
        self.assertEqual(result["additionalInfo"]["dataCollection"]["status"], "success")
        reasons = result["additionalInfo"]["evaluation"]["failReasons"]
        self.assertIn("Read the factors of 5 of 5 active Okta users", reasons[0])

    def test_all_users_strong_passes_with_100(self):
        body = fixture(USERS_FIX)
        body["userFactors"] = [[{"factorType": "webauthn", "status": "ACTIVE"}] for _ in body["users"]]
        result = self.run_both("mfaEnforcementCoveragePercentage", body)
        self.assertEqual(result["transformedResponse"]["mfaEnforcementCoveragePercentage"], 100.0)
        self.assertTrue(result["additionalInfo"]["evaluation"]["passReasons"])

    def test_none_strong_reads_zero_not_none(self):
        body = fixture(USERS_FIX)
        body["userFactors"] = [[{"factorType": "sms", "status": "ACTIVE"}] for _ in body["users"]]
        self.assertEqual(self.value("mfaEnforcementCoveragePercentage", body), 0.0)
        self.assertEqual(self.value("smsFactorEnabledUsersCount", body), 5)

    def test_wrapped_in_api_response_is_read(self):
        self.assertEqual(self.value("mfaEnforcementCoveragePercentage", {"apiResponse": fixture(USERS_FIX)}), 40.0)
        self.assertEqual(self.value("mfaEnforcementCoveragePercentage", json.dumps(fixture(USERS_FIX))), 40.0)


def sampled(cap=2, truncated=False):
    body = fixture(USERS_FIX)
    body["userFactors"] = body["userFactors"][:cap]
    body["iterateStats"]["userFactors"].update({"itemsProcessed": cap, "iterateTruncated": True})
    body["iterateTruncated"] = True
    if truncated:
        body["paginationStats"]["users"]["paginationTruncated"] = True
        body["paginationTruncated"] = True
    return body


class TestSampling(Base):
    def test_percentages_use_users_read_and_say_it_is_a_sample(self):
        body = sampled(cap=2, truncated=True)
        result = self.run_both("mfaEnforcementCoveragePercentage", body)
        self.assertEqual(result["transformedResponse"]["mfaEnforcementCoveragePercentage"], 50.0)
        summary = result["additionalInfo"]["transformation"]["inputSummary"]
        self.assertTrue(summary["sampled"])
        self.assertFalse(summary["userListComplete"])
        self.assertEqual(summary["usersNotAttempted"], 3)
        text = (result["additionalInfo"]["evaluation"]["passReasons"] + result["additionalInfo"]["evaluation"]["failReasons"])[0]
        self.assertIn("2 of 5 or more active Okta users", text)
        self.assertIn("not every user", text)

    def test_counts_refuse_a_sample(self):
        for key in COUNT_KEYS:
            self.assert_unevaluated(key, sampled(), "every active user")

    def test_counts_refuse_a_cut_off_user_list_even_when_every_listed_user_was_read(self):
        body = fixture(USERS_FIX)
        body["paginationStats"]["users"]["paginationTruncated"] = True
        for key in COUNT_KEYS:
            self.assert_unevaluated(key, body, "every active user")

    def test_counts_refuse_when_the_build_cannot_say_whether_the_list_is_complete(self):
        body = fixture(USERS_FIX)
        del body["paginationStats"]
        for key in COUNT_KEYS:
            self.assert_unevaluated(key, body, "every active user")
        self.assertEqual(self.value("mfaEnforcementCoveragePercentage", body), 40.0)

    def test_one_unreadable_user_in_ten_is_disclosed_not_fatal_for_percentages(self):
        body = fixture(USERS_FIX)
        users = [copy.deepcopy(body["users"][0]) for _ in range(10)]
        for i in range(10):
            users[i]["id"] = "00uSYN" + str(i)
        factors = [[{"factorType": "webauthn", "status": "ACTIVE"}] for _ in range(10)]
        factors[3] = {"error": True, "statusCode": 404, "item": "00uSYN3", "errorType": "vendorError"}
        body.update({"users": users, "userFactors": factors, "itemErrors": 1})
        body["iterateStats"]["userFactors"] = {"itemsTotal": 10, "itemsProcessed": 10, "itemErrors": 1,
                                               "iterateTruncated": False}
        self.assertEqual(self.value("webAuthnCredentialAdoptionPercentage", body), 100.0)
        for key in COUNT_KEYS:
            self.assert_unevaluated(key, body, "every active user")
        factors[4] = {"error": True, "statusCode": 429, "item": "00uSYN4", "errorType": "rateLimited"}
        body["iterateStats"]["userFactors"]["itemErrors"] = 2
        self.assert_unevaluated("webAuthnCredentialAdoptionPercentage", body, "more than 10%")


class TestUserFailClosed(Base):
    def cases(self):
        base = fixture(USERS_FIX)
        no_stats = copy.deepcopy(base)
        del no_stats["iterateStats"]
        misaligned = copy.deepcopy(base)
        misaligned["userFactors"] = misaligned["userFactors"][:3]
        wrong_total = copy.deepcopy(base)
        wrong_total["iterateStats"]["userFactors"]["itemsTotal"] = 9
        inactive_user = copy.deepcopy(base)
        inactive_user["users"][0]["status"] = "SUSPENDED"
        all_errors = copy.deepcopy(base)
        all_errors["userFactors"] = [{"error": True, "statusCode": 403, "item": u["id"]} for u in base["users"]]
        return [
            ({}, None), (None, None), ("{}", None), ([], None),
            ({"errorCode": "E0000006", "errorSummary": "You do not have permission"}, "Okta returned an error"),
            ({"statusCode": 401}, "HTTP 401"),
            (dict(base, users=[]), "no active users"),
            (dict(base, users="x"), "missing or unreadable"),
            (no_stats, "fan-out counts"),
            (misaligned, "line up"),
            (wrong_total, "counted 9"),
            (inactive_user, "not ACTIVE"),
            (all_errors, "No user's factors"),
        ]

    def test_every_unreadable_shape_is_unevaluated_never_a_verdict(self):
        for key in USER_KEYS:
            for body, words in self.cases():
                with self.subTest(key=key, body=str(body)[:60]):
                    self.assert_unevaluated(key, body, words)

    def test_garbage_input_is_a_transformation_error_not_a_verdict(self):
        for key in ALL_KEYS:
            self.assert_unevaluated(key, "not json")


class TestSuperAdmin(Base):
    def test_super_admin_share_ignores_other_admins_and_weak_factors(self):
        # 4 assignees: a1 SUPER_ADMIN webauthn; a2 SUPER_ADMIN sms only; a3 ORG_ADMIN nothing;
        # a4 SUPER_ADMIN via group + READ_ONLY_ADMIN, push ACTIVE
        result = self.run_both(ADMIN_KEY, fixture(ADMINS_FIX))
        self.assertEqual(result["transformedResponse"][ADMIN_KEY], 66.7)
        self.assertEqual(result["additionalInfo"]["transformation"]["inputSummary"]["superAdmins"], 3)
        self.assertIn("00uSYNADM2", result["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_every_super_admin_strong_reads_100(self):
        body = fixture(ADMINS_FIX)
        body["assigneeFactors"][1] = [{"factorType": "token:software:totp", "status": "ACTIVE"}]
        self.assertEqual(self.value(ADMIN_KEY, body), 100.0)

    def cases(self):
        base = fixture(ADMINS_FIX)
        nxt = copy.deepcopy(base)
        nxt["roleAssignees"]["_links"]["next"] = {"href": "https://synthetic.okta.example/api/v1/iam/assignees/users?after=x"}
        cut = copy.deepcopy(base)
        cut["paginationStats"]["roleAssignees"]["paginationTruncated"] = True
        capped = copy.deepcopy(base)
        capped["iterateTruncated"] = True
        role_err = copy.deepcopy(base)
        role_err["assigneeRoles"][2] = {"error": True, "statusCode": 403, "item": "00uSYNADM3"}
        factor_err = copy.deepcopy(base)
        factor_err["assigneeFactors"][0] = {"error": True, "statusCode": 429, "item": "00uSYNADM1"}
        no_super = copy.deepcopy(base)
        no_super["assigneeRoles"] = [[{"type": "ORG_ADMIN", "status": "ACTIVE"}] for _ in base["assigneeRoles"]]
        no_stats = copy.deepcopy(base)
        del no_stats["iterateStats"]["assigneeFactors"]
        return [
            ({}, None), (None, None), ("{}", None),
            ({"errorCode": "E0000006", "errorSummary": "Forbidden"}, "Okta returned an error"),
            (dict(base, roleAssignees={"errorCode": "E0000006", "errorSummary": "Forbidden"}), "Okta returned an error"),
            (dict(base, roleAssignees={"value": []}), "no users with admin roles"),
            (nxt, "cut off"), (cut, "cut off"), (capped, "100"),
            (role_err, "roles of 1"), (factor_err, "factors could not be read"),
            (no_super, "No super administrator"), (no_stats, "fan-out counts"),
        ]

    def test_every_unreadable_shape_is_unevaluated(self):
        for body, words in self.cases():
            with self.subTest(body=str(body)[:60]):
                self.assert_unevaluated(ADMIN_KEY, body, words)

    def test_a_failed_factor_read_of_a_non_super_admin_does_not_block(self):
        body = fixture(ADMINS_FIX)
        body["assigneeFactors"][2] = {"error": True, "statusCode": 404, "item": "00uSYNADM3"}
        self.assertEqual(self.value(ADMIN_KEY, body), 66.7)


class TestNoCustomerData(unittest.TestCase):
    def test_fixtures_are_synthetic(self):
        for name in (USERS_FIX, ADMINS_FIX):
            text = (FIX / name).read_text()
            self.assertIn("synthetic", text)
            self.assertNotIn("@spektrum", text.lower())


if __name__ == "__main__":
    unittest.main()
