import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isantiphishingenabled_oneclick.py")
LEGACY_TRANSFORMATION_PATH = Path(__file__).with_name("isantiphishingenabled.py")

KEY = "isAntiPhishingEnabled"
EXCHANGE_ACCESS_ERROR = "Could not connect to Microsoft 365: Exchange access is not complete"
# A synthetic, non-UUID application id that contains "401" and "404": the generic parser would read these as HTTP codes.
EXAMPLE_APP_ID = "example-app-401-404"
EXCHANGE_ROLE_ERROR = (
    "Failed to connect to Exchange Online: The role assigned to application " + EXAMPLE_APP_ID + " "
    "isn't supported in this scenario. Please check online documentation for assigning "
    "correct Directory Roles to Azure AD Application for EXO App-Only Authentication."
)


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

    def test_exchange_role_failure_asks_to_complete_exchange_access(self):
        response = self.transformation.transform({
            "Success": True,
            "Output": {"success": False, "PSError": EXCHANGE_ROLE_ERROR},
            "Error": "",
        })

        evaluation = response["additionalInfo"]["evaluation"]
        self.assertEqual(evaluation["failReasons"], ["Exchange access is required for this check."])
        self.assertEqual(
            evaluation["recommendations"],
            ["Complete Exchange access in Microsoft One-Click, then re-evaluate this check."],
        )
        # Never a False beside an error: the check carries no value at all.
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["metadata"]["schemaVersion"], "2.0")

    def test_exchange_role_failure_is_a_data_collection_error_that_names_the_missing_role(self):
        """The platform grades a data collection error Not evaluated; the errorCode says what to grant."""
        response = self.transformation.transform({"Output": {"PSError": EXCHANGE_ROLE_ERROR}})

        collection = response["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertEqual(collection["errors"], [EXCHANGE_ACCESS_ERROR])
        # The vendor text (which names the application) is not echoed, and an id digit run is not read as an HTTP code.
        self.assertNotIn(EXAMPLE_APP_ID, collection["errors"][0])
        self.assertNotIn("HTTP", collection["errors"][0])
        self.assertEqual(collection["errorCode"], "scope_not_granted")
        self.assertIn("Global Reader", collection["requiredScope"])
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "success")

    def test_exchange_role_failure_is_recognised_in_each_response_wrapper(self):
        for wrapper in ("Output", "response", "result", "apiResponse", "api_response"):
            with self.subTest(wrapper=wrapper):
                response = self.transformation.transform({wrapper: {"PSError": EXCHANGE_ROLE_ERROR}})
                self.assertEqual(
                    response["additionalInfo"]["evaluation"]["failReasons"],
                    ["Exchange access is required for this check."],
                )
                self.assertIsNone(response["transformedResponse"][KEY])

    def test_exchange_role_failure_is_recognised_from_a_json_string_and_bytes(self):
        body = '{"Output": {"PSError": "%s"}}' % EXCHANGE_ROLE_ERROR
        for payload in (body, body.encode("utf-8")):
            with self.subTest(kind=type(payload).__name__):
                response = self.transformation.transform(payload)
                self.assertEqual(
                    response["additionalInfo"]["evaluation"]["recommendations"],
                    ["Complete Exchange access in Microsoft One-Click, then re-evaluate this check."],
                )

    def test_unrelated_errors_keep_the_generic_copy_and_differ_from_the_legacy_file_only_in_the_value(self):
        """Same copy and collection error as the legacy file; the criterion carries no value (legacy says False)."""
        for raw_error in (
            "Request timed out",
            "Failed to connect to Exchange Online: Request timed out",
            "Access denied (HTTP 403)",
            "",
        ):
            with self.subTest(error=raw_error):
                input_data = {"Output": {"PSError": raw_error}}
                response = self.transformation.transform(input_data)
                legacy = self.legacy_transformation.transform(input_data)
                evaluation = response["additionalInfo"]["evaluation"]
                self.assertEqual(evaluation["failReasons"], ["Could not retrieve data from Microsoft 365"])
                self.assertNotIn("Complete Exchange access", " ".join(evaluation["recommendations"]))
                self.assertIsNone(response["transformedResponse"][KEY])
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertNotIn("errorCode", response["additionalInfo"]["dataCollection"])
                self.assertEqual(response["additionalInfo"]["dataCollection"], legacy["additionalInfo"]["dataCollection"])
                self.assertEqual(evaluation, legacy["additionalInfo"]["evaluation"])

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
        legacy = self.legacy_transformation.transform(input_data)
        self.assertEqual(
            response["transformedResponse"]["isAntiPhishingEnabled"],
            legacy["transformedResponse"]["isAntiPhishingEnabled"],
        )
        self.assertNotIn("policyDetails", response["transformedResponse"])

    def test_disabled_policy_returns_a_valid_failure(self):
        response = self.transformation.transform({
            "Output": {"policies": [{"Name": "Disabled", "Enabled": False}]},
        })

        self.assertFalse(response["transformedResponse"]["isAntiPhishingEnabled"])
        self.assertEqual(
            response["additionalInfo"]["evaluation"]["failReasons"],
            ["No anti-phishing policies are enabled"],
        )

    def test_an_empty_list_that_was_read_is_a_stated_negative(self):
        response = self.transformation.transform({"Output": {"policies": []}})

        self.assertFalse(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(
            response["additionalInfo"]["transformation"]["inputSummary"]["totalPolicies"],
            0,
        )

    def test_a_missing_or_unreadable_policy_list_is_not_evaluated(self):
        """Nothing was read, so nothing is proved: no value and a data collection error, never a False."""
        for payload in ({"Output": {}}, {"Output": {"policies": None}}, {"Output": {"policies": "none"}}):
            with self.subTest(payload=payload):
                response = self.transformation.transform(payload)
                self.assertIsNone(response["transformedResponse"][KEY])
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertEqual(
                    response["additionalInfo"]["dataCollection"]["errors"],
                    ["Could not read anti-phishing policies"],
                )

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        response = self.transformation.transform("{not-json")

        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertEqual(response["additionalInfo"]["validation"]["status"], "unknown")
        self.assertTrue(response["additionalInfo"]["validation"]["errors"])

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.transformation.transform({
            "data": {"policies": [{"Name": "Default", "Enabled": True}]},
            "validation": {"status": "failed", "errors": ["bad shape"], "warnings": []},
        })

        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")

    def test_a_policy_the_code_cannot_read_is_not_evaluated_not_a_pass_or_a_fail(self):
        response = self.transformation.transform({"Output": {"policies": ["not-a-policy-object"]}})

        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
