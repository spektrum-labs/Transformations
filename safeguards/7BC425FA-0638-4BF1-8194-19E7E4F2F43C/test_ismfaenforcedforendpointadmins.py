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

    def test_microsoft_admin_portals_policy_passes(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["MicrosoftAdminPortals"],
                "excludeApplications": [],
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_defender_portal_policy_passes(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": [
                    "80ccca67-54bd-44ab-8625-4b79c4dc7775",
                ],
                "excludeApplications": [],
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_defender_application_exclusion_does_not_prove_protection(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["All"],
                "excludeApplications": ["MicrosoftAdminPortals"],
            }),
        ])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_unrelated_application_exclusion_keeps_defender_covered(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["All"],
                "excludeApplications": ["unrelated-app"],
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_complete_defender_admin_role_coverage_passes(self):
        response = self.evaluate([
            policy(users={
                "includeUsers": [],
                "includeRoles": list(
                    self.transformation.DEFENDER_ADMIN_ROLE_IDS
                ),
                "excludeUsers": [],
                "excludeGroups": [],
                "excludeRoles": [],
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_partial_defender_admin_role_coverage_does_not_pass(self):
        response = self.evaluate([
            policy(users={
                "includeUsers": [],
                "includeRoles": [
                    self.transformation.DEFENDER_ADMIN_ROLE_IDS[0],
                ],
                "excludeUsers": [],
                "excludeGroups": [],
                "excludeRoles": [],
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_builtin_mfa_authentication_strength_passes(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": [],
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000004",
                    "displayName": "Phishing-resistant MFA",
                },
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_explicit_mfa_custom_authentication_strength_passes(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": [],
                "authenticationStrength": {
                    "id": "custom-strength",
                    "requirementsSatisfied": "mfa",
                },
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_unknown_custom_authentication_strength_does_not_pass(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": [],
                "authenticationStrength": {
                    "id": "custom-strength",
                },
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_authentication_strength_without_operator_does_not_pass(self):
        response = self.evaluate([
            policy(grant_controls={
                "builtInControls": [],
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000004",
                },
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_scalar_builtin_control_does_not_pass(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": "compliantDevice",
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000004",
                },
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_or_authentication_strength_with_alternative_control_does_not_pass(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "OR",
                "builtInControls": ["compliantDevice"],
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000004",
                },
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_and_authentication_strength_with_additional_control_passes(self):
        response = self.evaluate([
            policy(grant_controls={
                "operator": "AND",
                "builtInControls": ["compliantDevice"],
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000004",
                },
            }),
        ])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

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

    def test_browser_client_condition_still_covers_the_defender_console(self):
        candidate = policy()
        candidate["conditions"]["clientAppTypes"] = ["browser"]

        response = self.evaluate([candidate])

        self.assertTrue(response["transformedResponse"]["isSSOEnabled"])

    def test_location_condition_does_not_prove_universal_admin_mfa(self):
        candidate = policy()
        candidate["conditions"]["locations"] = {
            "includeLocations": ["trusted-location"],
        }

        response = self.evaluate([candidate])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_scalar_application_exclusion_does_not_pass(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["All"],
                "excludeApplications": "MicrosoftAdminPortals",
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_empty_application_filter_does_not_pass(self):
        response = self.evaluate([
            policy(applications={
                "includeApplications": ["All"],
                "excludeApplications": [],
                "applicationFilter": {},
            }),
        ])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])

    def test_identity_provider_records_do_not_count_as_mfa_evidence(self):
        response = self.evaluate([{
            "id": "EmailOtpSignup-OAUTH",
            "displayName": "Email One Time Passcode",
        }])

        self.assertFalse(
            response["transformedResponse"]["isSSOEnabled"]
        )

    def test_empty_policy_list_is_a_valid_failed_evaluation(self):
        response = self.evaluate([])

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])
        self.assertEqual(
            response["additionalInfo"]["dataCollection"]["status"],
            "success",
        )
        self.assertEqual(
            response["additionalInfo"]["transformation"]["status"],
            "success",
        )

    def test_api_error_is_not_reported_as_a_valid_empty_policy_list(self):
        response = self.transformation.transform({
            "PSError": "403 Forbidden",
        })

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])
        self.assertEqual(
            response["additionalInfo"]["dataCollection"]["status"],
            "error",
        )
        self.assertTrue(response["additionalInfo"]["dataCollection"]["errors"])

    def test_missing_policy_collection_is_a_transformation_error(self):
        response = self.transformation.transform({})

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])
        self.assertEqual(
            response["additionalInfo"]["transformation"]["status"],
            "error",
        )

    def test_malformed_json_is_a_transformation_error(self):
        response = self.transformation.transform("{not-json")

        self.assertFalse(response["transformedResponse"]["isSSOEnabled"])
        self.assertEqual(
            response["additionalInfo"]["transformation"]["status"],
            "error",
        )


if __name__ == "__main__":
    unittest.main()
