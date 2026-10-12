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
    ('failedbackupjobscount', ('failedBackupJobsCount',), 'empty_dict', lambda: {}),
    ('failedbackupjobscount', ('failedBackupJobsCount',), 'poisoned', lambda: Poisoned()),
    ('localstorageutilizationpercentage', ('localStorageUtilizationPercentage',), 'empty_dict', lambda: {}),
    ('localstorageutilizationpercentage', ('localStorageUtilizationPercentage',), 'poisoned', lambda: Poisoned()),
    ('staleprotectionjobscount', ('staleProtectionJobsCount',), 'empty_dict', lambda: {}),
    ('staleprotectionjobscount', ('staleProtectionJobsCount',), 'poisoned', lambda: Poisoned()),
]

ENVELOPED = [
    ('confirmedlicensepurchased', 'confirmedLicensePurchased'),
    ('isbackupenabled', 'isBackupEnabled'),
    ('isbackupencrypted', 'isBackupEncrypted'),
    ('isbackupimmutable', 'isBackupImmutable'),
    ('isbackuploggingenabled', 'isBackupLoggingEnabled'),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled'),
    ('isdatalockcompliancemodeenabled', 'isDataLockComplianceModeEnabled'),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256'),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured'),
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


def page(items):
    return {"offset": 0, "limit": 10000, "results": items}


def job(enabled=True, kind="Daily"):
    return {"id": "j1", "name": "Mail", "isEnabled": enabled, "schedulePolicy": {"type": kind}}


def repo(enc=True, imm=True, gov=False):
    return {"id": "r1", "name": "s3", "objectStorageEncryptionEnabled": enc,
            "objectStorage": {"id": "o1", "enableImmutability": imm, "enableImmutabilityGovernanceMode": gov}}


# (file, key, body, expected value) -- every one is a readable body, so status is "success".
MEASURED = [
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', lambda: {"status": "Valid", "type": "Subscription"}, True),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', lambda: {"status": "Valid", "type": "Evaluation"}, False),
    ('isbackupenabled', 'isBackupEnabled', lambda: page([job()]), True),
    ('isbackupenabled', 'isBackupEnabled', lambda: page([job(enabled=False)]), False),
    ('isbackupencrypted', 'isBackupEncrypted', lambda: page([repo()]), True),
    ('isbackupencrypted', 'isBackupEncrypted', lambda: page([repo(enc=False)]), False),
    ('isbackupimmutable', 'isBackupImmutable', lambda: page([repo()]), True),
    ('isbackupimmutable', 'isBackupImmutable', lambda: page([repo(imm=False)]), False),
    ('isbackuploggingenabled', 'isBackupLoggingEnabled', lambda: {"keepAllsessions": True}, True),
    ('isbackuploggingenabled', 'isBackupLoggingEnabled', lambda: {"keepAllsessions": False, "keeponlyLast": 1}, False),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled', lambda: {"jobs": page([job()]), "copyJobs": page([])}, True),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled',
     lambda: {"jobs": page([job(kind="ManualOnly")]), "copyJobs": page([])}, False),
    ('isdatalockcompliancemodeenabled', 'isDataLockComplianceModeEnabled', lambda: page([repo()]), True),
    ('isdatalockcompliancemodeenabled', 'isDataLockComplianceModeEnabled', lambda: page([repo(gov=True)]), False),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256', lambda: page([repo()]), True),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256', lambda: page([repo(enc=False)]), False),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured',
     lambda: {"enableNotification": True, "notifyOnFailure": True, "to": "ops@example.com"}, True),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured',
     lambda: {"enableNotification": False}, False),
]

# Readable bodies missing the one field the check needs: not measured.
FIELD_ABSENT = [
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', lambda: {"licenseID": "x"}),
    ('isbackupenabled', 'isBackupEnabled', lambda: page([{"id": "j1", "name": "Mail"}])),
    ('isbackuploggingenabled', 'isBackupLoggingEnabled', lambda: {"keeponlyLast": 8}),
    ('isbackuploggingenabled', 'isBackupLoggingEnabled', lambda: {"keepAllsessions": False}),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured', lambda: {"to": "ops@example.com"}),
]
for absent_name, absent_key, absent_body in FIELD_ABSENT:
    CASES.append((absent_name, (absent_key,), 'field_absent', absent_body))


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


if __name__ == "__main__":
    unittest.main()
