import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isantiphishingenabled_oneclick.py")
LEGACY_TRANSFORMATION_PATH = Path(__file__).with_name("isantiphishingenabled.py")


def load_transformation(path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def without_timestamp(response):
    response["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return response


class MicrosoftOneClickAntiPhishingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transformation = load_transformation(
            TRANSFORMATION_PATH,
            "isantiphishingenabled_oneclick",
        )
        cls.legacy_transformation = load_transformation(
            LEGACY_TRANSFORMATION_PATH,
            "isantiphishingenabled",
        )

    def test_exchange_role_failure_explains_optional_completion(self):
        response = self.transformation.transform({
            "Success": True,
            "Output": {
                "success": False,
                "PSError": (
                    "Failed to connect to Exchange Online: The role assigned to application "
                    "example-client isn't supported in this scenario. Please check online "
                    "documentation for assigning correct Directory Roles to Azure AD Application "
                    "for EXO App-Only Authentication."
                ),
            },
            "Error": "",
        })

        evaluation = response["additionalInfo"]["evaluation"]
        self.assertEqual(
            evaluation["failReasons"],
            ["Exchange access is required for this check."],
        )
        self.assertEqual(
            evaluation["recommendations"],
            ["Complete Exchange access in Microsoft One-Click, then re-evaluate this check."],
        )
        self.assertFalse(response["transformedResponse"]["isAntiPhishingEnabled"])

    def test_unrelated_error_keeps_generic_existing_copy(self):
        input_data = {"Output": {"PSError": "Request timed out"}}
        response = self.transformation.transform(input_data)

        evaluation = response["additionalInfo"]["evaluation"]
        self.assertEqual(
            evaluation["failReasons"],
            ["Could not retrieve data from Microsoft 365"],
        )
        self.assertEqual(
            evaluation["recommendations"],
            ["Check Microsoft 365 credentials and configuration"],
        )
        self.assertEqual(
            without_timestamp(response),
            without_timestamp(self.legacy_transformation.transform(input_data)),
        )

    def test_enabled_policy_behavior_is_unchanged(self):
        input_data = {
            "Output": {"policies": [{"Name": "Default", "Enabled": True}]},
        }
        response = self.transformation.transform(input_data)

        self.assertTrue(response["transformedResponse"]["isAntiPhishingEnabled"])
        self.assertEqual(
            response["additionalInfo"]["evaluation"]["passReasons"],
            ["1 anti-phishing policy/policies enabled: Default"],
        )
        self.assertEqual(
            without_timestamp(response),
            without_timestamp(self.legacy_transformation.transform(input_data)),
        )


if __name__ == "__main__":
    unittest.main()
