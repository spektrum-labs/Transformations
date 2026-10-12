"""A criterion these transforms return as None must reach the evaluator as not evaluated.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is
"error" (which create_response sets only from a non-empty api_errors). Each body below proves
nothing about the estate, so each transform must answer None AND say so. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("nne_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


CASES = [
    ('backupsuccessratepercentage', ('backupSuccessRatePercentage',), 'empty_dict', lambda: {}),
    ('backupsuccessratepercentage', ('backupSuccessRatePercentage',), 'poisoned', lambda: Poisoned()),
]

ENVELOPED = [
    ('isbackupenabled', 'isBackupEnabled'),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased'),
    ('isdeletionretentionperiodenforced', 'isDeletionRetentionPeriodEnforced'),
]
NO_EVIDENCE = [
    ('empty_dict', lambda: {}),
    ('poisoned', lambda: Poisoned()),
    ('empty_list', lambda: []),
    ('null', lambda: None),
    ('not_available', lambda: {"status": "Not Available"}),
    ('refusal_401', lambda: {"error": True, "statusCode": 401, "message": "Unauthorized"}),
]
for env_name, env_key in ENVELOPED:
    for case_name, case_body in NO_EVIDENCE:
        CASES.append((env_name, (env_key,), case_name, case_body))


def domain(**extra):
    d = {"backupStats": {"activeServicesCount": 10, "activeServicesWithRecentBackupCount": 10},
         "domain": "example.com", "saasCustomerId": 1, "organizationId": 1, "seatsUsed": 5,
         "externalSubscriptionId": "Classic:1", "retentionType": "ICR"}
    d.update(extra)
    return [d]


# (file, key, body, expected value) -- every one is a readable body, so status is "success".
MEASURED = [
    ('isbackupenabled', 'isBackupEnabled', lambda: domain(), True),
    ('isbackupenabled', 'isBackupEnabled',
     lambda: domain(backupStats={"activeServicesCount": 10, "activeServicesWithRecentBackupCount": 0}), False),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', lambda: domain(), True),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', lambda: domain(seatsUsed=0), False),
    ('isdeletionretentionperiodenforced', 'isDeletionRetentionPeriodEnforced', lambda: domain(), True),
]


class NoneReadsAsNotEvaluated(unittest.TestCase):
    def test_none_carries_a_data_collection_error(self):
        for name, criteria, case, body in CASES:
            with self.subTest(transform=name, body=case):
                out = load(name).transform(body())
                inner = out.get("transformedResponse", out)
                present = [k for k in criteria if k in inner]
                self.assertTrue(present, "no criterion in the output")
                for key in present:
                    self.assertIsNone(inner[key])
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "error")
                self.assertTrue(collection["errors"])
                self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))


class MeasuredAnswersStayGraded(unittest.TestCase):
    def test_a_readable_body_keeps_its_value_and_reports_success(self):
        for name, key, body, expected in MEASURED:
            with self.subTest(transform=name, expected=expected):
                out = load(name).transform(body())
                self.assertIs(out["transformedResponse"][key], expected)
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "success")
                self.assertEqual(collection["errors"], [])

    def test_time_based_retention_is_not_measured(self):
        out = load('isdeletionretentionperiodenforced').transform(domain(retentionType="TBR"))
        self.assertIsNone(out["transformedResponse"]['isDeletionRetentionPeriodEnforced'])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
