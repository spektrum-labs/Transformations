import base64
import importlib.util
import json
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isBackupEncrypted.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location("idrive_isbackupencrypted", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def company(flag=None, raw=None):
    if raw is None:
        cfg = {"desktopAppStatus": 1, "token": "synthetic"}
        if flag is not None:
            cfg["encryptionRequired"] = flag
        raw = base64.b64encode(json.dumps(cfg).encode()).decode()
    return {"name": "Example Co", "configuration_id": raw}


def value(body):
    return load_transformation().transform(body)["transformedResponse"]["isBackupEncrypted"]


class IsBackupEncryptedTest(unittest.TestCase):
    def test_private_key_required_is_encrypted(self):
        self.assertIs(value({"result": company(True)}), True)

    def test_default_key_is_still_aes256_encrypted(self):
        out = load_transformation().transform({"result": company(False)})
        self.assertIs(out["transformedResponse"]["isBackupEncrypted"], True)
        self.assertIn("default key", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_list_body_uses_first_company(self):
        self.assertIs(value([company(False)]), True)

    def test_missing_configuration_id_is_no_evidence(self):
        self.assertIsNone(value({"result": {"name": "Example Co"}}))

    def test_flag_absent_from_decoded_config_is_no_evidence(self):
        self.assertIsNone(value({"result": company(None)}))

    def test_undecodable_configuration_id_is_no_evidence(self):
        self.assertIsNone(value({"result": company(raw="!!!not-base64!!!")}))

    def test_empty_and_error_bodies_are_no_evidence(self):
        for body in ({}, None, "", {"error": "invalid_token"}, {"status": 401, "message": "Unauthorized"}):
            self.assertIsNone(value(body), body)


if __name__ == "__main__":
    unittest.main()
