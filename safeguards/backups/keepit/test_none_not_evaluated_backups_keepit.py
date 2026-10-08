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
    ('staleprotectionjobscount', ('staleProtectionJobsCount',), 'empty_dict', lambda: {}),
    ('staleprotectionjobscount', ('staleProtectionJobsCount',), 'poisoned', lambda: Poisoned()),
]

ENVELOPED = [
    ('isbackupenabled', 'isBackupEnabled'),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled'),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased'),
    ('isinfinitecloudretentionenabled', 'isInfiniteCloudRetentionEnabled'),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible'),
    ('issamlenforced', 'isSAMLEnforced'),
    ('isssoenabled', 'isSSOEnabled'),
    ('isdatasovereigntyregionenforced', 'isDataSovereigntyRegionEnforced'),
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


def connector(**extra):
    c = {"guid": "aaaa-bbbb", "name": "Workspace Backup", "type": "gsuite"}
    c.update(extra)
    return {"devices": {"cloud": c}}


def resources(**limits):
    return {"resources": {"resource": [{"name": k.replace("_", "-"), "limit": v} for k, v in limits.items()]}}


def merged(*parts):
    out = {}
    for part in parts:
        out.update(part)
    return out


def sso(**flags):
    c = {"guid": "sso-1", "name": "IdP"}
    c.update(flags)
    return {"configurations": {"configuration": c}}


FINISHED_JOB = {"type": "backup", "state": "successful", "started": "2026-09-24T01:00:05Z",
                "succeeded": "2026-09-24T01:20:00Z"}

# (file, key, body, expected value) -- every one is a readable body, so status is "success".
MEASURED = [
    ('isbackupenabled', 'isBackupEnabled', lambda: connector(enabled="true"), True),
    ('isbackupenabled', 'isBackupEnabled', lambda: connector(enabled="false"), False),
    ('isbackupenabled', 'isBackupEnabled', lambda: {"devices": None}, False),
    ('isssoenabled', 'isSSOEnabled', lambda: sso(enabled="true", apply_self="true"), True),
    ('isssoenabled', 'isSSOEnabled', lambda: {"configurations": None}, False),
    ('issamlenforced', 'isSAMLEnforced',
     lambda: sso(enabled="true", optional="false", apply_self="true", apply_subaccounts="true"), True),
    ('issamlenforced', 'isSAMLEnforced', lambda: sso(enabled="true", optional="true", apply_self="true"), False),
    ('issamlenforced', 'isSAMLEnforced', lambda: {"configurations": None}, False),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased',
     lambda: {"user": {"enabled": "true", "subscribed": "true", "product": "prod-1"}}, "confirmed"),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased',
     lambda: {"user": {"enabled": "true", "subscribed": "false", "product": "prod-1"}}, "unconfirmed"),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled',
     lambda: merged(connector(), {"deviceAttributes": [{"attributes": None}]}, resources(backup_interval="PT8H")), True),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled',
     lambda: merged(connector(), {"deviceAttributes": [{"attributes": {"attribute": {"name": "disable_auto_backup", "value": "true"}}}]},
                    resources(backup_interval="PT8H")), False),
    ('isdatasovereigntyregionenforced', 'isDataSovereigntyRegionEnforced', lambda: resources(multigeo="false"), True),
    ('isdatasovereigntyregionenforced', 'isDataSovereigntyRegionEnforced', lambda: resources(multigeo="true"), False),
    ('isdeletionretentionperiodenforced', 'isDeletionRetentionPeriodEnforced',
     lambda: merged(connector(), resources(generic_snapshot_retention="P1Y")), True),
    ('isdeletionretentionperiodenforced', 'isDeletionRetentionPeriodEnforced',
     lambda: merged(connector(), resources(generic_snapshot_retention="P14D")), False),
    ('isinfinitecloudretentionenabled', 'isInfiniteCloudRetentionEnabled',
     lambda: merged(connector(), resources(generic_snapshot_retention="P99Y")), True),
    ('isinfinitecloudretentionenabled', 'isInfiniteCloudRetentionEnabled',
     lambda: merged(connector(), resources(generic_snapshot_retention="P6M")), False),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible',
     lambda: merged(connector(), {"deviceJobs": [{"jobs": {"job": FINISHED_JOB}}]}), True),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible',
     lambda: merged(connector(), {"deviceJobs": [{"jobs": None}]}), False),
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
                self.assertEqual(out["transformedResponse"][key], expected)
                self.assertIs(type(out["transformedResponse"][key]), type(expected))
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "success")
                self.assertEqual(collection["errors"], [])


if __name__ == "__main__":
    unittest.main()
