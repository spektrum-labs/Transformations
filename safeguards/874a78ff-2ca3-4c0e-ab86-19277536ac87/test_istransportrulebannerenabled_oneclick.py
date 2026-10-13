import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("istransportrulebannerenabled_oneclick.py")
LEGACY_TRANSFORMATION_PATH = Path(__file__).with_name("istransportrulebannerenabled.py")

KEY = "isTransportRuleBannerEnabled"
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


def banner_rule(name="Example banner", state="Enabled", actions=None):
    return {
        "Name": name,
        "State": state,
        "Mode": "Enforce",
        "Actions": actions if actions is not None else ["PrependSubject Disclaimer example"],
    }


class MicrosoftOneClickTransportRuleBannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transformation = load_transformation(
            TRANSFORMATION_PATH,
            "istransportrulebannerenabled_oneclick",
        )
        cls.legacy_transformation = load_transformation(
            LEGACY_TRANSFORMATION_PATH,
            "istransportrulebannerenabled",
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
        self.assertIsNone(response["transformedResponse"][KEY])

    def test_exchange_role_failure_is_reported_as_a_data_collection_error(self):
        """A data collection error is what makes the platform grade the check Not evaluated, not failed."""
        response = self.transformation.transform({"Output": {"PSError": EXCHANGE_ROLE_ERROR}})

        collection = response["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertEqual(collection["errors"], [EXCHANGE_ACCESS_ERROR])
        # The vendor text (which names the application) is not echoed, and an id digit run is not read as an HTTP code.
        self.assertNotIn(EXAMPLE_APP_ID, collection["errors"][0])
        self.assertNotIn("HTTP", collection["errors"][0])
        # The platform and the CLI read this code to say "grant the role" rather than "fix the connection".
        self.assertEqual(collection["errorCode"], "scope_not_granted")
        self.assertIn("Global Reader", collection["requiredScope"])
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "success")
        # Never a False beside an error: the check carries no value at all.
        self.assertIsNone(response["transformedResponse"][KEY])

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

    def test_enabled_banner_rule_passes_the_same_as_the_legacy_file(self):
        input_data = {"Output": {"transportRules": [banner_rule()]}}
        response = self.transformation.transform(input_data)
        legacy = self.legacy_transformation.transform(input_data)

        self.assertTrue(response["transformedResponse"][KEY])
        self.assertEqual(
            response["additionalInfo"]["evaluation"]["passReasons"],
            ["Transport rule banner enabled via 1 rules: Example banner"],
        )
        self.assertEqual(response["transformedResponse"], legacy["transformedResponse"])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")

    def test_subject_prefix_rule_counts_as_a_banner(self):
        response = self.transformation.transform({
            "Output": {"transportRules": [banner_rule(actions=["PrependSubject SubjectPrefix [External]"])]},
        })
        self.assertTrue(response["transformedResponse"][KEY])

    def test_disabled_banner_rule_fails(self):
        response = self.transformation.transform({
            "Output": {"transportRules": [banner_rule(state="Disabled")]},
        })

        self.assertFalse(response["transformedResponse"][KEY])
        self.assertEqual(
            response["additionalInfo"]["evaluation"]["failReasons"],
            ["Found 1 banner rules but none are enabled"],
        )

    def test_no_banner_rule_fails(self):
        for rules in ([], [banner_rule(actions=["Quarantine"])], [{"Name": "No actions", "State": "Enabled"}]):
            with self.subTest(rules=rules):
                response = self.transformation.transform({"Output": {"transportRules": rules}})
                self.assertFalse(response["transformedResponse"][KEY])
                # A list that was read (an empty one included) is a stated negative, with no collection error.
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], [])
                self.assertEqual(
                    response["additionalInfo"]["evaluation"]["failReasons"],
                    ["No transport rules with Disclaimer or SubjectPrefix actions found"],
                )

    def test_missing_or_non_list_transport_rules_is_not_evaluated(self):
        """Only a list that was actually read gives the stated-negative False; anything else proved nothing."""
        for payload in (
            {"Output": {}},
            {"Output": {"transportRules": None}},
            {"Output": {"transportRules": {}}},
            {"Output": {"transportRules": {"Name": "a single rule, not a list"}}},
            {"Output": {"transportRules": "not a list"}},
            {"Output": {"somethingElse": []}},
            {"Output": []},
            [],
            "[]",
        ):
            with self.subTest(payload=payload):
                response = self.transformation.transform(payload)

                self.assertIsNone(response["transformedResponse"][KEY])
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], ["Could not read transport rules"])
                self.assertEqual(response["additionalInfo"]["transformation"]["status"], "success")

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        response = self.transformation.transform("{not-json")

        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
        self.assertTrue(response["additionalInfo"]["transformation"]["errors"])
        # The None must reach the evaluator as Not evaluated, which it reads from the collection status.
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.transformation.transform({
            "data": {"transportRules": [banner_rule()]},
            "validation": {"status": "failed", "errors": ["unexpected shape"], "warnings": []},
        })

        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Input validation failed"])

    def test_a_rule_the_code_cannot_read_is_not_evaluated_not_a_pass_or_a_fail(self):
        """The outer except: a rule entry that is not an object raises while the rules are read."""
        for rules in ([123], ["not an object"], [banner_rule(), None]):
            with self.subTest(rules=rules):
                response = self.transformation.transform({"Output": {"transportRules": rules}})

                self.assertIsNone(response["transformedResponse"][KEY])
                self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
