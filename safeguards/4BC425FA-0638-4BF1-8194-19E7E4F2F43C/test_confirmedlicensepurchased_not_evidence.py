"""AWS confirmedLicensePurchased is Not evaluated: AWS emits no licence field.

licensePurchased is synthesised by the connector from the first DB instance of an RDS DescribeDBInstances
call, so a true there only says the call returned an instance. The check must never pass on it, and an
absent field must not become a fail either: every body gives None plus a dataCollection error that says
why. A pass or a fail is not reachable from the AWS response. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "confirmedLicensePurchased"


def load():
    spec = importlib.util.spec_from_file_location("aws_confirmedlicensepurchased", os.path.join(HERE, "confirmedlicensepurchased.py"))
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


class AwsLicenceIsNotEvaluated(unittest.TestCase):
    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][KEY])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_synthesised_true_is_not_a_pass(self):
        out = load().transform({"licensePurchased": True, "rawResponse": {"DescribeDBInstancesResponse": {}}})
        self.assert_not_evaluated(out)
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])
        self.assertIn("not licence evidence", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_synthesised_false_or_absent_is_not_a_fail(self):
        for name, body in (("false", {"licensePurchased": False}), ("absent", {"rawResponse": {}})):
            with self.subTest(body=name):
                out = load().transform(body)
                self.assert_not_evaluated(out)
                self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])

    def test_empty_or_error_bodies_are_not_evaluated(self):
        for name, body in (
            ("empty_object", {}),
            ("none", None),
            ("empty_json_string", "{}"),
            ("error_envelope", {"ErrorResponse": {"Error": {"Code": "AccessDenied"}}}),
            ("unrelated_json", {"unrelated": "json"}),
            ("list", []),
        ):
            with self.subTest(body=name):
                self.assert_not_evaluated(load().transform(body))

    def test_failed_validation_is_not_evaluated(self):
        body = {"data": {"licensePurchased": True}, "validation": {"status": "failed", "errors": ["bad"], "warnings": []}}
        self.assert_not_evaluated(load().transform(body))

    def test_exception_is_not_evaluated(self):
        self.assert_not_evaluated(load().transform(Poisoned()))


if __name__ == "__main__":
    unittest.main()
