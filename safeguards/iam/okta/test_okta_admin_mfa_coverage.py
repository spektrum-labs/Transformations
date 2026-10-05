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
        verdict, _, _ = run(body(["a"], [[enrol("webauthn", status="INACTIVE")]]))
        self.assertIs(verdict, False)

    def test_phishable_factors_alone_are_uncovered(self):
        for key in ("phone_number", "okta_email", "security_question", "google_otp", "okta_password"):
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

    def test_an_uncovered_admin_still_fails_alongside_an_indeterminate_one(self):
        """One uncovered admin proves coverage is below 100%."""
        verdict, _, _ = run(body(["a", "b"], [[enrol("okta_verify")], [enrol("phone_number")]]))
        self.assertIs(verdict, False)

    def test_a_truncated_admin_list_cannot_claim_100(self):
        verdict, pct, r = run(body(["a"], [[enrol("webauthn")]], list_complete=False))
        self.assertIsNone(verdict)
        self.assertEqual(pct, 100.0)
        self.assertIn("cut off", reasons(r))

    def test_a_truncated_list_still_fails_on_a_known_uncovered_admin(self):
        verdict, _, r = run(body(["a", "b"], [[enrol("webauthn")], [enrol("okta_email")]], list_complete=False))
        self.assertIs(verdict, False)
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
