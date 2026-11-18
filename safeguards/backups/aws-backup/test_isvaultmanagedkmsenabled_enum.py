"""isVaultManagedKMSEnabled (AWS Backup): match the documented EncryptionKeyType values (ENG-1351).

AWS documents CUSTOMER_MANAGED_KMS_KEY and AWS_OWNED_KMS_KEY. The transform used to match the
undocumented string CUSTOMER_MANAGED, so a real customer-managed vault could never pass.
Synthetic fixtures only.
"""
import importlib.util
import unittest
from pathlib import Path


def load():
    spec = importlib.util.spec_from_file_location("aws_backup_kms_eng1351",
                                                  Path(__file__).with_name("isVaultManagedKMSEnabled.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vault(name, key_type):
    v = {"BackupVaultName": name,
         "BackupVaultArn": "arn:aws:backup:us-east-1:000000000000:backup-vault:" + name,
         "EncryptionKeyArn": "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"}
    if key_type is not None:
        v["EncryptionKeyType"] = key_type
    return v


def body(*vaults):
    return {"result": {"BackupVaultList": list(vaults)}}


class VaultKmsEnum(unittest.TestCase):
    mod = load()

    def verdict(self, payload):
        out = self.mod.transform(payload)
        return out["transformedResponse"]["isVaultManagedKMSEnabled"], out["additionalInfo"]["dataCollection"]["status"]

    def test_documented_customer_managed_passes(self):
        self.assertEqual(self.verdict(body(vault("vault-a", "CUSTOMER_MANAGED_KMS_KEY"))), (True, "success"))

    def test_documented_aws_owned_fails(self):
        self.assertEqual(self.verdict(body(vault("vault-a", "AWS_OWNED_KMS_KEY"))), (False, "success"))

    def test_one_aws_owned_vault_fails_a_mixed_estate(self):
        self.assertEqual(self.verdict(body(vault("vault-a", "CUSTOMER_MANAGED_KMS_KEY"),
                                           vault("vault-b", "AWS_OWNED_KMS_KEY"))), (False, "success"))

    def test_undocumented_customer_managed_string_does_not_pass(self):
        value, status = self.verdict(body(vault("vault-a", "CUSTOMER_MANAGED")))
        self.assertIsNone(value)
        self.assertEqual(status, "error")

    def test_missing_key_type_is_not_evaluated(self):
        value, status = self.verdict(body(vault("vault-a", "CUSTOMER_MANAGED_KMS_KEY"), vault("vault-b", None)))
        self.assertIsNone(value)
        self.assertEqual(status, "error")

    def test_no_vaults_is_not_evaluated(self):
        value, status = self.verdict(body())
        self.assertIsNone(value)
        self.assertEqual(status, "error")


if __name__ == "__main__":
    unittest.main()
