"""Azure backup: a vault that exists is not evidence of encryption or of backup.

isBackupEncrypted answered True whenever any vault row came back. It is now True only when every vault
row states a recognised encryption mode, None when a row states none, and False when Azure reports a vault's
customer-managed key state as Inconsistent (Azure Backup has no unencrypted mode, so that is the one
negative these rows can show).

isBackupEnabled (here and in the 729cebc6 copy) answered True for any non-empty Resource Graph vault table,
which lists vaults and their diagnostic settings. It is now True only when a protected item is actively
protected, False when the protected items were read whole and none is active, and None for vault rows,
partial pages and errors. Rows follow the getBackupVaultEncryptionStatus column order. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SAFEGUARDS = os.path.dirname(os.path.dirname(HERE))
ENABLED_PATHS = [
    ("azure", os.path.join(HERE, "isbackupenabled.py")),
    ("729", os.path.join(SAFEGUARDS, "729cebc6-8abd-4511-ac85-1455a690eebe", "isbackupenabled.py")),
]

SUB = "00000000-0000-0000-0000-000000000000"
VALIDATION = {"status": "passed", "errors": [], "warnings": []}


def load(label, path):
    spec = importlib.util.spec_from_file_location("false_pass_" + label, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def vault_row(mode, name="vault-1", kind="microsoft.recoveryservices/vaults"):
    # name, type, subscriptionId, resourceGroup, location, encryptionMode, state, infrastructureEncryption,
    # keyUri, kekIdentityType, kekIdentityId
    return [name, kind, SUB, "rg-backup", "eastus", mode, "", "", "", "", ""]


def encryption_body(rows):
    return {"data": {"columns": [{"name": "name"}, {"name": "type"}, {"name": "subscriptionId"},
                                 {"name": "resourceGroup"}, {"name": "location"}, {"name": "encryptionMode"}],
                     "rows": rows, "totalRecords": len(rows)}, "validation": VALIDATION}


class AzureBackupEncrypted(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load("encrypted", os.path.join(HERE, "is_backup_encrypted.py"))

    def run_body(self, body):
        out = self.module.transform(body)
        return out["transformedResponse"]["isBackupEncrypted"], out["additionalInfo"]["dataCollection"], out

    def assert_not_evaluated(self, body):
        value, collection, _ = self.run_body(body)
        self.assertIsNone(value)
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_every_vault_states_a_mode_is_true(self):
        value, collection, out = self.run_body(encryption_body([vault_row("CMK"), vault_row("PMK", "vault-2")]))
        self.assertIs(value, True)
        self.assertEqual(collection["status"], "success")
        self.assertEqual(out["transformedResponse"]["cmkVaults"], 1)

    def test_dict_rows_and_data_protection_states_are_read(self):
        rows = [{"name": "bv-1", "encryptionMode": "Disabled"}, {"name": "bv-2", "encryptionMode": "enabled"},
                {"name": "rs-1", "encryptionMode": "cmk"}]
        value, _, _ = self.run_body(encryption_body(rows))
        self.assertIs(value, True)

    def test_inconsistent_vault_is_a_real_false(self):
        value, collection, out = self.run_body(encryption_body([vault_row("PMK"), vault_row("Inconsistent", "vault-2")]))
        self.assertIs(value, False)
        self.assertEqual(collection["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])

    def test_a_vault_row_with_no_recognised_mode_is_not_evaluated(self):
        for name, row in (
            ("unknown_mode", vault_row("Unknown")),
            ("empty_mode", vault_row("")),
            ("null_mode", vault_row(None)),
            ("other_word", vault_row("error")),
            ("short_row", ["vault-1", "microsoft.recoveryservices/vaults"]),
            ("dict_without_mode", {"name": "vault-1"}),
        ):
            with self.subTest(row=name):
                self.assert_not_evaluated(encryption_body([row]))

    def test_one_unreadable_vault_among_good_ones_is_not_evaluated(self):
        self.assert_not_evaluated(encryption_body([vault_row("CMK"), vault_row("Unknown", "vault-2")]))

    def test_a_stated_inconsistent_vault_beats_an_unreadable_one(self):
        value, _, _ = self.run_body(encryption_body([vault_row("Unknown"), vault_row("Inconsistent", "vault-2")]))
        self.assertIs(value, False)

    def test_empty_or_error_bodies_are_not_evaluated(self):
        for name, body in (
            ("empty_object", {}),
            ("none", None),
            ("empty_rows", encryption_body([])),
            ("error_envelope", {"error": {"code": "AuthorizationFailed", "message": "denied"}}),
            ("rows_not_a_list", {"data": {"rows": "none"}}),
            ("non_row_entries", encryption_body([None, 5])),
        ):
            with self.subTest(body=name):
                self.assert_not_evaluated(body)

    def test_exception_is_not_evaluated(self):
        self.assert_not_evaluated(Poisoned())


def protected_page(*statuses, next_link=None):
    page = {"value": [{"name": "item-%d" % i, "properties": {"protectionStatus": status}} for i, status in enumerate(statuses)]}
    if next_link:
        page["nextLink"] = next_link
    return page


class AzureBackupEnabled(unittest.TestCase):
    def run_body(self, label, path, body):
        out = load(label, path).transform(body)
        return out["transformedResponse"]["isBackupEnabled"], out["additionalInfo"]["dataCollection"], out

    def test_an_actively_protected_item_is_true(self):
        for label, path in ENABLED_PATHS:
            with self.subTest(copy=label):
                value, collection, out = self.run_body(label, path, {"protectedItems": [protected_page("Healthy")]})
                self.assertIs(value, True)
                self.assertEqual(collection["status"], "success")
                self.assertTrue(out["additionalInfo"]["evaluation"]["passReasons"])

    def test_protected_items_read_whole_with_none_active_is_a_real_false(self):
        for label, path in ENABLED_PATHS:
            with self.subTest(copy=label):
                value, collection, out = self.run_body(label, path, {"protectedItems": [protected_page("Unhealthy", "Stopped")]})
                self.assertIs(value, False)
                self.assertEqual(collection["status"], "success")
                self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])

    def test_a_stopped_item_with_a_healthy_status_is_not_protected(self):
        # Recovery Services keeps protectionStatus Healthy on an item whose backup was stopped with data
        # retained; the lifecycle in protectionState is what says nothing is being backed up.
        def item(name, **props):
            return {"value": [{"name": name, "properties": props}]}
        cases = (
            ("stopped_healthy", [item("a", protectionStatus="Healthy", protectionState="ProtectionStopped")], False),
            ("paused_healthy", [item("a", protectionStatus="Healthy", protectionState="ProtectionPaused")], False),
            ("error_healthy", [item("a", protectionStatus="Healthy", protectionState="ProtectionError")], False),
            ("protected_unhealthy", [item("a", protectionStatus="Unhealthy", protectionState="Protected")], True),
            ("protected_healthy", [item("a", protectionStatus="Healthy", protectionState="Protected")], True),
            ("stopped_plus_protected", [item("a", protectionStatus="Healthy", protectionState="ProtectionStopped"),
                                        item("b", protectionStatus="Healthy", protectionState="Protected")], True),
        )
        for label, path in ENABLED_PATHS:
            for name, pages, expected in cases:
                with self.subTest(copy=label, case=name):
                    value, collection, _ = self.run_body(label, path, {"protectedItems": pages})
                    self.assertIs(value, expected)
                    self.assertEqual(collection["status"], "success")

    def test_vault_rows_prove_a_vault_exists_not_a_backup(self):
        bodies = (
            ("rows_of_lists", {"data": {"rows": [["vault-1"]]}}),
            ("diagnostic_settings_rows", {"data": {"columns": [{"name": "vaultType"}], "rows": [
                {"vaultType": "RecoveryServicesVault", "name": "vault-1", "resourceGroup": "rg-backup",
                 "subscriptionId": SUB, "location": "eastus", "logCategories": ["AzureBackupReport"]}]}}),
        )
        for label, path in ENABLED_PATHS:
            for name, body in bodies:
                with self.subTest(copy=label, body=name):
                    value, collection, out = self.run_body(label, path, body)
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")
                    self.assertIn("vault exists", collection["errors"][0])
                    self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_partial_or_unreadable_pages_with_no_active_item_are_not_evaluated(self):
        bodies = (
            ("next_link", {"protectedItems": [protected_page("Stopped", next_link="https://example.invalid/page2")]}),
            ("error_page", {"protectedItems": [{"error": {"code": "AuthorizationFailed"}}]}),
            ("no_vault_read", {"protectedItems": []}),
            ("entry_without_properties", {"protectedItems": [{"value": [{"name": "item-1"}]}]}),
        )
        for label, path in ENABLED_PATHS:
            for name, body in bodies:
                with self.subTest(copy=label, body=name):
                    value, collection, _ = self.run_body(label, path, body)
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])

    def test_an_active_item_seen_still_proves_enabled_when_another_page_failed(self):
        body = {"protectedItems": [protected_page("Healthy"), {"error": {"code": "Throttled"}}]}
        for label, path in ENABLED_PATHS:
            with self.subTest(copy=label):
                value, _, _ = self.run_body(label, path, body)
                self.assertIs(value, True)

    def test_empty_error_and_raising_bodies_are_not_evaluated(self):
        bodies = (("empty_object", {}), ("none", None), ("empty_json_string", "{}"),
                  ("error_envelope", {"error": {"code": "Unauthorized"}}), ("poisoned", Poisoned()))
        for label, path in ENABLED_PATHS:
            for name, body in bodies:
                with self.subTest(copy=label, body=name):
                    value, collection, _ = self.run_body(label, path, body)
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])


if __name__ == "__main__":
    unittest.main()
