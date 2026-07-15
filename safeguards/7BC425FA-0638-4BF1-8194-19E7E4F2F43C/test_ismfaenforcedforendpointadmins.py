import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("ismfaenforcedforendpointadmins.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location(
        "ismfaenforcedforendpointadmins",
        TRANSFORMATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(*, state="enabled", users=None, applications=None, grant_controls=None):
    return {
        "displayName": "Require MFA for Microsoft access",
        "state": state,
        "conditions": {
            "users": users or {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "excludeGroups": [],
                "excludeRoles": [],
            },
            "applications": applications or {
                "includeApplications": ["All"],
                "excludeApplications": [],
            },
        },
        "grantControls": grant_controls or {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }


class EndpointAdministratorMfaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transformation = load_transformation()

    def evaluate(self, policies):
        return self.transformation.transform({"value": policies})

    def test_enabled_all_users_all_apps_mfa_policy_passes(self):
        response = self.evaluate([policy()])

        self.assertTrue(
            response["transformedResponse"]["isSSOEnabled"]
        )
        self.assertEqual(
            response["transformedResponse"]["matchingPolicies"],
            1,
        )

    def test_report_only_policy_does_not_pass(self):
        response = self.evaluate([
            policy(state="enabledForReportingButNotEnforced"),
        ])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_user_exclusion_does_not_prove_all_admins_are_protected(self):
        response = self.evaluate([
            policy(users={
                "includeUsers": ["All"],
                "excludeUsers": ["break-glass-user"],
                "excludeGroups": [],
                "excludeRoles": [],
            }),
        ])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_application_exclusion_does_not_prove_defender_is_protected(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["All"],
                "excludeApplications": ["excluded-app"],
            }),
        ])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_or_policy_with_an_alternative_control_does_not_require_mfa(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": ["mfa", "compliantDevice"],
            }),
        ])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_identity_provider_records_do_not_count_as_mfa_evidence(self):
        response = self.evaluate([{
            "id": "EmailOtpSignup-OAUTH",
            "displayName": "Email One Time Passcode",
        }])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )


if __name__ == "__main__":
    unittest.main()
