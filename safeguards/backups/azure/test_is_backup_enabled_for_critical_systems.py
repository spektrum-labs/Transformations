import importlib.util
import json
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("is_backup_enabled_for_critical_systems.py")
KEY = "isBackupEnabledForCriticalSystems"

ARM_ERROR = {"error": {"code": "AuthorizationFailed", "message": "The client does not have authorization to perform the action."}}


def load_transformation():
    spec = importlib.util.spec_from_file_location("azure_backup_critical_systems", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def item(name="vm-1", status="Healthy", state="Protected", **extra):
    properties = {
        "friendlyName": name,
        "protectionStatus": status,
        "protectionState": state,
        "workloadType": "VM",
        "sourceResourceId": "/subscriptions/<subscription>/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/" + name,
    }
    properties.update(extra)
    return {
        "id": "/vaults/example-vault/backupFabrics/Azure/protectedItems/" + name,
        "name": name,
        "type": "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems",
        "properties": properties,
    }


def page(*items, **extra):
    body = {"value": list(items)}
    body.update(extra)
    return body


class AzureBackupCriticalSystemsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transformation = load_transformation()

    def run_check(self, payload):
        return self.transformation.transform(payload)

    def assert_not_evaluated(self, response):
        """Never a False beside an error: no value, and a collection error so the platform grades it Not evaluated."""
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(response["additionalInfo"]["dataCollection"]["errors"])

    def assert_partial_pass(self, response, seen):
        """A pass proven by items that were seen: True stands, but any total would be an undercount, so none is given."""
        result = response["transformedResponse"]
        self.assertIs(result[KEY], True)
        self.assertIsNone(result["protectedItemsCount"])
        self.assertIsNone(result["totalItems"])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(
            response["additionalInfo"]["evaluation"]["passReasons"],
            [f"At least {seen} actively protected item(s) seen; not every protected items list could be read, so no total is given"],
        )

    # --- measured answers -------------------------------------------------------------------------------

    def test_an_actively_protected_item_passes(self):
        response = self.run_check({"protectedItems": [page(item("vm-1"), item("share-1", state="Protected"))]})

        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["protectedItemsCount"], 2)
        self.assertEqual(response["transformedResponse"]["totalItems"], 2)
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(response["additionalInfo"]["evaluation"]["passReasons"])

    def test_items_from_several_vaults_are_merged(self):
        response = self.run_check({"protectedItems": [page(), page(item("vm-2")), page(item("vm-3", status="Unhealthy", state="ProtectionError"))]})

        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["protectedItemsCount"], 1)
        self.assertEqual(response["transformedResponse"]["totalItems"], 2)

    def test_the_other_input_shapes_are_read_alike(self):
        body = page(item("vm-1"))
        for label, payload in (
            ("single page", body),
            ("wrapped in Output", {"Output": body}),
            ("protectedItems as one page", {"protectedItems": body}),
            ("protectedItems as list of lists", {"protectedItems": [[item("vm-1")]]}),
            ("enriched", {"data": {"protectedItems": [body]}, "validation": {"status": "passed", "errors": [], "warnings": []}}),
            ("json string", json.dumps({"protectedItems": [body]})),
            ("json bytes", json.dumps({"protectedItems": [body]}).encode("utf-8")),
        ):
            with self.subTest(shape=label):
                self.assertIs(self.run_check(payload)["transformedResponse"][KEY], True)

    def test_a_status_other_than_protected_does_not_count(self):
        for status, state in (("Unhealthy", "ProtectionError"), ("", "ProtectionStopped"), ("", "IRPending"), ("", "")):
            with self.subTest(status=status, state=state):
                response = self.run_check({"protectedItems": [page(item("vm-1", status=status, state=state))]})
                self.assertIs(response["transformedResponse"][KEY], False)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], [])

    def test_state_protected_counts_when_there_is_no_status(self):
        response = self.run_check({"protectedItems": [page(item("vm-1", status="", state="ProtectionConfigured"))]})
        self.assertIs(response["transformedResponse"][KEY], True)

    def test_a_vault_that_was_read_and_holds_no_protected_item_fails(self):
        """A list that came back (empty included) is a stated negative, not an unreadable body."""
        for payload in ({"protectedItems": [page()]}, {"protectedItems": [page(), page()]}, page()):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assertIs(response["transformedResponse"][KEY], False)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["No actively protected backup items found"])

    # --- Not evaluated ----------------------------------------------------------------------------------

    def test_no_vault_read_is_not_evaluated(self):
        """Zero vaults is ambiguous: none exist, or the subscription could not be read."""
        for payload in ({"protectedItems": []}, {"Output": {"protectedItems": []}}):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], ["No Recovery Services vault was read"])

    def test_a_body_that_is_not_the_protected_items_read_is_not_evaluated(self):
        for payload in (
            {},
            [],
            "[]",
            {"error": "HTTP 403 Forbidden"},
            ARM_ERROR,
            {"statusCode": 403, "message": "Forbidden"},
            {"protectedItems": None},
            {"protectedItems": "not a list"},
            {"protectedItems": 3},
            {"totalRecords": 0, "count": 0, "data": {"columns": [], "rows": []}},
            {"somethingElse": [page(item())]},
        ):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], ["Could not read protected items"])

    def test_a_vault_that_returned_an_error_is_not_a_fail(self):
        for payload in (
            {"protectedItems": [ARM_ERROR]},
            {"protectedItems": [ARM_ERROR, page()]},
            {"protectedItems": [{"value": "not a list"}]},
            {"protectedItems": [{"nothing": "here"}]},
            {"protectedItems": ["not an object"]},
            {"protectedItems": [None]},
        ):
            with self.subTest(payload=payload):
                response = self.run_check(payload)
                self.assert_not_evaluated(response)
                self.assertEqual(response["additionalInfo"]["dataCollection"]["errors"], ["Could not read every protected items list"])

    def test_a_proven_pass_survives_an_unreadable_vault(self):
        """True needs only one active item that was read; an error elsewhere cannot undo it."""
        response = self.run_check({"protectedItems": [ARM_ERROR, page(item("vm-1"))]})
        self.assert_partial_pass(response, 1)

        two_seen = self.run_check({"protectedItems": [ARM_ERROR, page(item("vm-1"), item("vm-2", status="Unhealthy", state="ProtectionError")), page(item("vm-3"))]})
        self.assert_partial_pass(two_seen, 2)

    def test_an_incomplete_list_is_not_a_fail_but_a_found_item_still_passes(self):
        incomplete = page(item("vm-1", status="Unhealthy", state="ProtectionError"), nextLink="https://example.invalid/next")
        self.assert_not_evaluated(self.run_check({"protectedItems": [incomplete]}))

        with_active = page(item("vm-1"), nextLink="https://example.invalid/next")
        self.assert_partial_pass(self.run_check({"protectedItems": [with_active]}), 1)

    def test_an_entry_the_code_cannot_read_is_not_a_fail(self):
        for entries in ([123], ["not an object"], [None], [{"name": "no properties"}], [{"name": "x", "properties": "not an object"}]):
            with self.subTest(entries=entries):
                response = self.run_check({"protectedItems": [{"value": entries}]})
                self.assert_not_evaluated(response)

        beside_an_active_item = {"protectedItems": [{"value": [123, item("vm-1")]}]}
        self.assert_partial_pass(self.run_check(beside_an_active_item), 1)

    def test_failed_input_validation_is_not_evaluated(self):
        response = self.run_check({
            "data": {"protectedItems": [page(item("vm-1"))]},
            "validation": {"status": "failed", "errors": ["unexpected shape"], "warnings": []},
        })

        self.assert_not_evaluated(response)
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], ["Input validation failed"])

    def test_malformed_json_is_not_evaluated_with_a_transformation_error(self):
        response = self.run_check("{not-json")

        self.assert_not_evaluated(response)
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
        self.assertTrue(response["additionalInfo"]["transformation"]["errors"])

    def test_a_long_exception_message_is_capped(self):
        """The exception text reaches the stored result, so a long one is cut."""
        class Unreadable(dict):
            def __contains__(self, key):
                raise ValueError("unreadable " * 100)

        response = self.run_check(Unreadable())

        self.assert_not_evaluated(response)
        errors = response["additionalInfo"]["transformation"]["errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0]), 200)
        fail_reasons = response["additionalInfo"]["evaluation"]["failReasons"]
        self.assertEqual(fail_reasons, ["Transformation error: " + errors[0]])

    def test_no_not_evaluated_answer_carries_a_value_beside_the_error(self):
        """The platform grades a collection error Not evaluated; a False beside it would still be stored as a result."""
        bodies = (
            {}, [], "{bad", {"protectedItems": []}, {"protectedItems": [ARM_ERROR]}, {"protectedItems": [{"value": [1]}]},
            {"data": {}, "validation": {"status": "failed", "errors": [], "warnings": []}},
        )
        for body in bodies:
            with self.subTest(body=body):
                response = self.run_check(body)
                self.assertEqual(response["transformedResponse"], {KEY: None})
                self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
