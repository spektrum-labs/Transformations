"""isAdminMFAPhishingResistant: coverage of administrators, from getAdminAuthenticatorPosture.

Product decision, Josh, 5 Oct 2026: report the share of administrators with a phishing-resistant
authenticator enrolled, and FAIL below 100%.

Shapes are taken from Okta's Management API specification, not invented:
  * /api/v1/iam/assignees/users -> RoleAssignedUsersResponseExample:
        {"value": [{"id": "00u118oQYT4TBGuay0g4", "orn": "...", "_links": {...}}], "_links": {"next": ...}}
  * /api/v1/users/{id}/authenticator-enrollments -> AuthenticatorEnrollmentResponseListAll:
        [{"type": "email", "id": "eae4za57...", "key": "okta_email", "status": "ACTIVE", ...}, ...]
and the merged-workflow markers from Integration-Service src/utils/iterate_options.py:
  * a failed per-admin read under continueOnItemError is
        {"error": True, "statusCode": 403, "item": "<userId>", "errorType": "vendorError"}
  * iterateTruncated / iterateStats.<key>, paginationTruncated / paginationStats.<key>

These shapes have NOT yet been seen from a live tenant: the workflow is not applied to production.
Anything unexpected answers "not evaluated" rather than a verdict.
"""
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isAdminMFAPhishingResistant.py")
KEY = "isAdminMFAPhishingResistant"
PCT = "adminPhishResistantCoveragePercentage"
ROOT = PATH.resolve().parents[3]


def load():
    spec = importlib.util.spec_from_file_location("okta_admin_mfa_cov", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("rs_okta_cov", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def enrol(key, status="ACTIVE"):
    return {"type": "app", "id": "e_" + key, "key": key, "status": status, "name": key}


def admins(*ids):
    return {"value": [{"id": i, "orn": "orn:okta:x:users:" + i, "_links": {}} for i in ids], "_links": {}}


def body(ids, enrollments, list_complete=True, **extra):
    data = {"adminAssignees": admins(*ids), "adminEnrollments": enrollments,
            "paginationStats": {"adminAssignees": {"paginationTruncated": not list_complete}},
            "iterateStats": {"adminEnrollments": {"itemsTotal": len(ids), "itemsProcessed": len(enrollments),
                                                  "itemErrors": 0, "iterateTruncated": False}}}
    if not list_complete:
        data["paginationTruncated"] = True
    data.update(extra)
    return data


def item_error(user_id, status=403):
    return {"error": True, "statusCode": status, "item": user_id, "errorType": "vendorError"}


def run(data):
    r = load().transform(data)
    return r["transformedResponse"].get(KEY), r["transformedResponse"].get(PCT), r


def summary(r):
    return r["additionalInfo"]["transformation"]["inputSummary"]


def reasons(r):
    ev = r["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"])


class TheVerdict(unittest.TestCase):
    def test_every_admin_covered_passes_at_100(self):
        verdict, pct, _ = run(body(["a", "b"], [[enrol("webauthn")], [enrol("smart_card_idp"), enrol("okta_email")]]))
        self.assertIs(verdict, True)
        self.assertEqual(pct, 100.0)

    def test_one_uncovered_admin_fails_with_the_percentage(self):
        verdict, pct, r = run(body(["a", "b", "c", "d"], [[enrol("webauthn")], [enrol("webauthn")],
                                                          [enrol("webauthn")], [enrol("phone_number")]]))
        self.assertIs(verdict, False)
        self.assertEqual(pct, 75.0)
        self.assertIn("1 of 4 administrators", reasons(r))
        self.assertIn("75.0%", reasons(r))

    def test_the_uncovered_admin_is_identified_in_the_summary(self):
        _, _, r = run(body(["a", "b"], [[enrol("webauthn")], [enrol("okta_email")]]))
        self.assertEqual(r["additionalInfo"]["transformation"]["inputSummary"]["uncoveredAdminIds"], ["b"])

    def test_fastpass_counts_as_phishing_resistant(self):
        verdict, _, _ = run(body(["a"], [[enrol("okta_verify_fastpass")]]))
        self.assertIs(verdict, True)

    def test_an_inactive_resistant_enrollment_does_not_count(self):
        verdict, _, _ = run(body(["a"], [[enrol("webauthn", status="INACTIVE"), enrol("okta_password")]]))
        self.assertIs(verdict, False)
        # With nothing ACTIVE at all the admin is noActive (see EnrollmentShapes): never True, never False.
        self.assertIsNone(run(body(["a"], [[enrol("webauthn", status="INACTIVE")]]))[0])

    def test_phishable_factors_alone_are_uncovered(self):
        for key in ("phone_number", "okta_email", "security_question", "google_otp", "okta_password",
                    "yubikey_token", "rsa_token", "symantec_vip", "custom_otp", "onprem_mfa"):
            with self.subTest(key=key):
                verdict, _, _ = run(body(["a"], [[enrol(key)]]))
                self.assertIs(verdict, False)


class WhatCannotBeClaimed(unittest.TestCase):
    def test_okta_verify_aggregate_is_indeterminate_not_uncovered(self):
        """Okta does not say whether the aggregate enrollment is FastPass or push."""
        verdict, pct, r = run(body(["a"], [[enrol("okta_verify")]]))
        self.assertIsNone(verdict)
        self.assertIn("Okta Verify", reasons(r))

    def test_security_key_is_indeterminate(self):
        verdict, _, _ = run(body(["a"], [[enrol("security_key")]]))
        self.assertIsNone(verdict)

    def test_an_unclassified_authenticator_is_indeterminate_not_uncovered(self):
        """Unclear data reads not evaluated, never a fail (J.J., 3 Oct 2026)."""
        for key in ("duo", "external_idp", "custom_app", "some_future_key"):
            with self.subTest(key=key):
                verdict, _, _ = run(body(["a"], [[enrol("okta_password"), enrol(key)]]))
                self.assertIsNone(verdict)

    def test_an_uncovered_admin_still_fails_alongside_an_indeterminate_one(self):
        """One uncovered admin proves coverage is below 100%."""
        verdict, _, _ = run(body(["a", "b"], [[enrol("okta_verify")], [enrol("phone_number")]]))
        self.assertIs(verdict, False)

    def test_a_truncated_admin_list_cannot_claim_100(self):
        verdict, pct, r = run(body(["a"], [[enrol("webauthn")]], list_complete=False))
        self.assertIsNone(verdict)
        # A threshold token must not read a partial 100% as coverage; the figure stays in inputSummary.
        self.assertIsNone(pct)
        self.assertEqual(summary(r)[PCT], 100.0)
        self.assertIs(summary(r)["adminCoverageComplete"], False)
        self.assertIn("cut off", reasons(r))

    def test_a_truncated_list_still_fails_on_a_known_uncovered_admin(self):
        verdict, pct, r = run(body(["a", "b"], [[enrol("webauthn")], [enrol("okta_email")]], list_complete=False))
        self.assertIs(verdict, False)
        self.assertIsNone(pct)
        self.assertEqual(summary(r)[PCT], 50.0)
        self.assertIn("may be lower still", reasons(r))

    def test_capped_enrollment_reads_cannot_claim_100(self):
        data = body(["a", "b"], [[enrol("webauthn")]], iterateTruncated=True)
        verdict, _, _ = run(data)
        self.assertIsNone(verdict)

    def test_an_unreadable_admin_cannot_claim_100(self):
        verdict, _, r = run(body(["a", "b"], [[enrol("webauthn")], item_error("b")]))
        self.assertIsNone(verdict)
        self.assertIn("could not be read", reasons(r))

    def test_an_unreadable_admin_does_not_hide_an_uncovered_one(self):
        verdict, _, _ = run(body(["a", "b", "c"], [item_error("a"), [enrol("okta_email")], [enrol("webauthn")]]))
        self.assertIs(verdict, False)

    def test_an_old_is_build_without_pagination_stats_cannot_claim_100(self):
        data = body(["a"], [[enrol("webauthn")]])
        del data["paginationStats"]
        verdict, _, r = run(data)
        self.assertIsNone(verdict)
        self.assertIn("did not report", reasons(r))


class EnrollmentShapes(unittest.TestCase):
    def test_an_enrollment_with_no_status_is_unreadable_not_uncovered(self):
        verdict, pct, r = run(body(["a"], [[{"key": "webauthn"}]]))
        self.assertIsNone(verdict)
        self.assertIsNone(pct)
        self.assertEqual(summary(r)["adminsUnreadable"], 1)

    def test_an_undocumented_status_is_unreadable(self):
        for status in ("SOMETHING_NEW", "", None):
            with self.subTest(status=status):
                entry = enrol("okta_email")
                entry["status"] = status
                self.assertIsNone(run(body(["a"], [[entry]]))[0])

    def test_status_casing_is_tolerated(self):
        self.assertIs(run(body(["a"], [[enrol("webauthn", status="active")]]))[0], True)

    def test_an_admin_with_no_active_enrollment_is_not_uncovered(self):
        # Suspended or deprovisioned users keep admin roles and often hold no ACTIVE enrollment.
        for listed in ([], [enrol("okta_email", status="INACTIVE")]):
            with self.subTest(listed=listed):
                verdict, pct, r = run(body(["a", "b"], [[enrol("webauthn")], listed]))
                self.assertIsNone(verdict)
                self.assertIsNone(pct)
                self.assertEqual(summary(r)["adminsWithNoActiveEnrollment"], 1)
                self.assertEqual(summary(r)["uncoveredAdminIds"], [])
                self.assertIn("no ACTIVE authenticator enrollment", reasons(r))

    def test_an_admin_with_no_active_enrollment_does_not_hide_an_uncovered_one(self):
        verdict, _, r = run(body(["a", "b"], [[], [enrol("okta_email")]]))
        self.assertIs(verdict, False)
        self.assertEqual(summary(r)["uncoveredAdminIds"], ["b"])

    def test_an_error_envelope_slot_is_unreadable_not_uncovered(self):
        for slot in ({"vendorErrorAsResponse": {"status": 403}, "value": []}, {"errorCode": "E0000006", "data": []}):
            with self.subTest(slot=slot):
                verdict, _, r = run(body(["a", "b"], [[enrol("webauthn")], slot]))
                self.assertIsNone(verdict)
                self.assertEqual(summary(r)["adminsUnreadable"], 1)

    def test_a_row_with_no_id_is_unreadable_and_never_named(self):
        data = body(["a"], [[enrol("okta_email")]])
        data["adminAssignees"] = {"value": [{}], "_links": {}}
        verdict, _, r = run(data)
        self.assertIsNone(verdict)
        self.assertNotIn("", summary(r)["uncoveredAdminIds"])

    def test_percentage_is_floored_so_only_a_true_100_reads_100(self):
        ids = ["u" + str(i) for i in range(2000)]
        slots = [[enrol("webauthn")] for _ in range(1999)] + [[enrol("okta_email")]]
        verdict, pct, r = run(body(ids, slots))
        self.assertIs(verdict, False)
        self.assertEqual(pct, 99.9)
        self.assertNotIn("100.0%", reasons(r))


class IndexAlignment(unittest.TestCase):
    def assert_no_verdict(self, data):
        verdict, pct, r = run(data)
        self.assertIsNone(verdict)
        self.assertIsNone(pct)
        self.assertIn("out of line", reasons(r))
        self.assertNotIn("uncoveredAdminIds", summary(r))

    def test_more_slots_than_admins(self):
        self.assert_no_verdict(body(["a"], [[enrol("okta_email")], [enrol("webauthn")]]))

    def test_fewer_slots_than_admins_without_a_read_cap(self):
        self.assert_no_verdict(body(["a", "b"], [[enrol("okta_email")]]))

    def test_items_total_disagrees_with_the_admin_list(self):
        data = body(["a", "b"], [[enrol("okta_email")], [enrol("webauthn")]])
        data["iterateStats"]["adminEnrollments"]["itemsTotal"] = 3
        self.assert_no_verdict(data)

    def test_an_item_error_naming_another_user(self):
        self.assert_no_verdict(body(["a", "b"], [item_error("b"), [enrol("okta_email")]]))

    def test_an_enrollment_linking_to_another_user(self):
        stray = enrol("okta_email")
        stray["_links"] = {"self": {"href": "https://x.okta.com/api/v1/users/b/authenticator-enrollments/e1"}}
        self.assert_no_verdict(body(["a", "b"], [[stray], [enrol("webauthn")]]))

    def test_an_enrollment_linking_to_its_own_admin_is_fine(self):
        own = enrol("okta_email")
        own["_links"] = {"self": {"href": "https://x.okta.com/api/v1/users/a/authenticator-enrollments/e1"}}
        self.assertIs(run(body(["a"], [[own]]))[0], False)


class SameKeysOnEveryPath(unittest.TestCase):
    def test_coverage_keys_are_present_on_every_coverage_return(self):
        cases = [
            body(["a"], [[enrol("webauthn")]]),                                # True
            body(["a"], [[enrol("okta_email")]]),                               # False
            body(["a"], [[enrol("okta_verify")]]),                              # not evaluated, indeterminate
            body(["a", "b"], [[enrol("okta_email")]]),                          # not evaluated, misaligned
            {"adminEnrollments": []},                                           # not evaluated, no admin list
            {"adminAssignees": admins("a"), "adminEnrollments": None},          # not evaluated, no enrollments
            body([], []),                                                       # not evaluated, no admins
        ]
        for data in cases:
            with self.subTest(data=data):
                out = run(data)[2]["transformedResponse"]
                for k in (PCT, "adminsAssessed", "adminsCovered"):
                    self.assertIn(k, out)
                if out[KEY] is None:
                    self.assertIsNone(out[PCT])

    def test_not_evaluated_carries_the_counts(self):
        out = run(body(["a", "b"], [[enrol("webauthn")], [enrol("okta_verify")]]))[2]["transformedResponse"]
        self.assertEqual((out["adminsAssessed"], out["adminsCovered"]), (2, 1))


class Messages(unittest.TestCase):
    def test_indeterminate_message_does_not_claim_every_admin_is_covered(self):
        _, _, r = run(body(["a"], [[enrol("okta_verify")]]))
        self.assertNotIn("Every administrator assessed", reasons(r))
        self.assertIn("0 of 1 administrators assessed have a phishing-resistant authenticator and none is known "
                      "to lack one", reasons(r))

    def test_capped_reads_with_no_unreadable_slot_say_capped(self):
        data = body(["a"], [[enrol("webauthn")]], iterateTruncated=True)
        text = reasons(run(data)[2])
        self.assertIn("capped", text)
        self.assertNotIn("0 administrator(s)", text)

    def test_every_admin_unreadable_does_not_say_every_admin_is_covered(self):
        text = reasons(run(body(["a"], [item_error("a")]))[2])
        self.assertNotIn("Every administrator assessed", text)
        self.assertIn("No administrator's enrollments could be assessed", text)


class UnreadableBodies(unittest.TestCase):
    def test_no_admin_list(self):
        verdict, _, r = run({"adminEnrollments": []})
        self.assertIsNone(verdict)
        self.assertIn("okta.roles.read", reasons(r))

    def test_admin_list_was_an_error(self):
        verdict, _, _ = run({"adminAssignees": {"errorCode": "E0000006"}, "adminEnrollments": []})
        self.assertIsNone(verdict)

    def test_no_admins_at_all(self):
        verdict, _, _ = run(body([], []))
        self.assertIsNone(verdict)

    def test_enrollments_missing(self):
        verdict, _, _ = run({"adminAssignees": admins("a"), "adminEnrollments": None})
        self.assertIsNone(verdict)

    def test_nothing_unreadable_returns_true(self):
        for data in ({"adminEnrollments": []}, {"adminAssignees": admins("a"), "adminEnrollments": None},
                     body(["a"], [item_error("a")])):
            self.assertIsNot(run(data)[0], True)


class TheOrgFactorPathIsUntouched(unittest.TestCase):
    """Without adminEnrollments the file behaves exactly as before, so merging changes nothing until a
    definition is switched to getAdminAuthenticatorPosture."""

    def test_an_org_factor_list_still_takes_the_old_path(self):
        factors = [{"factorType": "webauthn", "provider": "FIDO", "status": "ACTIVE"}]
        r = load().transform(factors)
        self.assertNotIn(PCT, r["transformedResponse"])
        self.assertIs(r["transformedResponse"][KEY], True)


class RunsUnderTheSandbox(unittest.TestCase):
    def setUp(self):
        self.transform = SandboxModule().transform

    def test_pass_fail_and_unevaluated(self):
        self.assertIs(self.transform(body(["a"], [[enrol("webauthn")]]))["transformedResponse"][KEY], True)
        self.assertIs(self.transform(body(["a"], [[enrol("okta_email")]]))["transformedResponse"][KEY], False)
        self.assertIsNone(self.transform(body(["a"], [[enrol("okta_verify")]]))["transformedResponse"][KEY])


if __name__ == "__main__":
    unittest.main()
