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
]

# The graded legacy rows (QC F-backup-27): each answered a bare {key: False, "reason": ...} with no
# additionalInfo, so a body that proves nothing was graded as Failed.
ENVELOPED = [
    ('arebackupstested', 'areBackupsTested'),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased'),
    ('isauditlogforwardingenabled', 'isAuditLogForwardingEnabled'),
    ('isbackupenabled', 'isBackupEnabled'),
    ('isbackupencrypted', 'isBackupEncrypted'),
    ('isbackuptested', 'isBackupTested'),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled'),
    ('iscloudtierencryptionenabled', 'isCloudTierEncryptionEnabled'),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256'),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible'),
    ('ism365backupcoverageenabled', 'isM365BackupCoverageEnabled'),
    ('ismfaenforcedforusers', 'isMFAEnforcedForUsers'),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured'),
    ('isprotectionpolicyrpowithinsla', 'isProtectionPolicyRPOWithinSLA'),
    ('isssoenabled', 'isSSOEnabled'),
]

UNMEASURED_BODIES = [
    ('empty_dict', lambda: {}),
    ('poisoned', lambda: Poisoned()),
    ('empty_list', lambda: []),
    ('null', lambda: None),
    ('not_available', lambda: {"status": "Not Available"}),
    ('refusal_401', lambda: {"error": True, "statusCode": 401, "message": "Unauthorized"}),
]

for _name, _key in ENVELOPED:
    for _case, _body in UNMEASURED_BODIES:
        CASES.append((_name, (_key,), _case, _body))


def job(status, i=0, kind="Backup"):
    return {"jobSummary": {"jobId": 1000 + i, "jobType": kind, "status": status,
                           "jobStartTime": 1790000000 + i, "jobEndTime": 1790000600 + i,
                           "subclient": {"clientName": "fs%02d" % i, "subclientName": "default"}}}


def jobs(statuses, kind="Backup"):
    return {"totalRecordsWithoutPaging": len(statuses), "jobs": [job(s, i, kind) for i, s in enumerate(statuses)]}


def plan(i, kind="Server", status="ENABLED", rpo=1440, entities=3):
    return {"plan": {"id": i, "name": "plan-%d" % i}, "planType": kind, "status": status, "RPO": rpo,
            "associatedEntities": entities}


def pool(i, encrypt=True, cipher="AES", length=256):
    return {"id": i, "name": "pool-%d" % i, "encryption": {"encrypt": encrypt, "cipher": cipher, "keyLength": length}}


def storage(disk, cloud):
    return {"diskStorage": [{"id": p["id"], "name": p["name"]} for p in disk], "diskStorageDetails": disk,
            "cloudStorage": [{"id": p["id"], "name": p["name"]} for p in cloud], "cloudStorageDetails": cloud}


def alert(channels=("EMAIL",)):
    detail = {"id": 7, "alertSummary": {"criteria": {"name": "Backup Job Failed"}}, "associations": [{"clientId": 1}],
              "alertTarget": {"sendAlertTo": list(channels), "recipients": {"to": [{"email": "ops@example.com"}]}}}
    return {"alertDefinitions": [{"id": 7, "enabled": True}], "alertDefinitionDetails": [detail]}


SYSLOG = {"enabled": True, "hostname": "syslog.example.com", "forwardToSyslog": {"audit": True}}

# (transform, key, case, body, expected): a well-formed body that answers the question.
MEASURED = [
    ('arebackupstested', 'areBackupsTested', 'pass', lambda: jobs(["Completed"], "Restore"), True),
    ('arebackupstested', 'areBackupsTested', 'fail', lambda: jobs(["Failed"], "Restore"), False),
    ('isbackuptested', 'isBackupTested', 'pass', lambda: jobs(["Completed"], "Restore"), True),
    ('isbackuptested', 'isBackupTested', 'fail', lambda: jobs([], "Restore"), False),
    ('isbackupenabled', 'isBackupEnabled', 'pass', lambda: jobs(["Completed"]), True),
    ('isbackupenabled', 'isBackupEnabled', 'fail', lambda: jobs(["Failed", "Killed"]), False),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible', 'pass', lambda: jobs(["Completed", "Failed"]), True),
    ('isjobexecutionlogaccessible', 'isJobExecutionLogAccessible', 'fail',
     lambda: {"totalRecordsWithoutPaging": 1, "jobs": [{"jobSummary": {"jobId": 1, "status": "Completed"}}]}, False),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', 'pass', lambda: {"licenseMode": "PRODUCTION", "expiryDate": 0}, True),
    ('confirmedlicensepurchased', 'confirmedLicensePurchased', 'fail', lambda: {"licenseMode": "EVALUATION"}, False),
    ('isauditlogforwardingenabled', 'isAuditLogForwardingEnabled', 'pass', lambda: dict(SYSLOG), True),
    ('isauditlogforwardingenabled', 'isAuditLogForwardingEnabled', 'fail', lambda: dict(SYSLOG, enabled=False), False),
    ('ismfaenforcedforusers', 'isMFAEnforcedForUsers', 'pass', lambda: {"twoFactorAuthenticationInfo": {"mode": 1}}, True),
    ('ismfaenforcedforusers', 'isMFAEnforcedForUsers', 'fail', lambda: {"twoFactorAuthenticationInfo": {"mode": 0}}, False),
    ('isssoenabled', 'isSSOEnabled', 'pass', lambda: {"identityServers": [{"name": "idp", "type": "SAML"}]}, True),
    ('isssoenabled', 'isSSOEnabled', 'fail', lambda: {"identityServers": [{"name": "ad", "type": "AD"}]}, False),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled', 'pass', lambda: {"plans": [plan(1)]}, True),
    ('isbackuptypesscheduled', 'isBackupTypesScheduled', 'fail', lambda: {"plans": [plan(1, rpo=0)]}, False),
    ('isprotectionpolicyrpowithinsla', 'isProtectionPolicyRPOWithinSLA', 'pass', lambda: {"plans": [plan(1)]}, True),
    ('isprotectionpolicyrpowithinsla', 'isProtectionPolicyRPOWithinSLA', 'fail', lambda: {"plans": [plan(1, rpo=2880)]}, False),
    ('ism365backupcoverageenabled', 'isM365BackupCoverageEnabled', 'pass', lambda: {"plans": [plan(1, kind="Office365")]}, True),
    ('ism365backupcoverageenabled', 'isM365BackupCoverageEnabled', 'fail', lambda: {"plans": [plan(1)]}, False),
    ('isbackupencrypted', 'isBackupEncrypted', 'pass', lambda: storage([pool(1)], [pool(2)]), True),
    ('isbackupencrypted', 'isBackupEncrypted', 'fail', lambda: storage([pool(1, encrypt=False)], [pool(2)]), False),
    ('iscloudtierencryptionenabled', 'isCloudTierEncryptionEnabled', 'pass', lambda: storage([], [pool(2)]), True),
    ('iscloudtierencryptionenabled', 'isCloudTierEncryptionEnabled', 'fail', lambda: storage([], [pool(2, encrypt=False)]), False),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256', 'pass', lambda: storage([], [pool(2)]), True),
    ('isexternaltargetencryptionaes256', 'isExternalTargetEncryptionAES256', 'fail', lambda: storage([], [pool(2, length=128)]), False),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured', 'pass', lambda: alert(), True),
    ('ispolicyfailurenotificationconfigured', 'isPolicyFailureNotificationConfigured', 'fail',
     lambda: alert(channels=("LIVEFEEDS",)), False),
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
    def test_measured_value_with_success_status(self):
        for name, key, case, body, expected in MEASURED:
            with self.subTest(transform=name, body=case):
                out = load(name).transform(body())
                self.assertIs(out["transformedResponse"][key], expected, out)
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "success")
                self.assertEqual(collection["errors"], [])

    def test_every_enveloped_row_has_a_pass_and_a_fail(self):
        for name, key in ENVELOPED:
            seen = set(case for n, k, case, b, e in MEASURED if n == name)
            self.assertEqual(seen, {"pass", "fail"}, name)


if __name__ == "__main__":
    unittest.main()
