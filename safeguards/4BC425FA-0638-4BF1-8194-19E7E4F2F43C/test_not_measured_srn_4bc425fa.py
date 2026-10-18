"""A body that proves nothing must reach the evaluator as not evaluated, and a reading must still be graded.

Token-Service grades a criterion unless additionalInfo.dataCollection.status is "error". Every transform here
derives that status from its own criterion's value (`measured = value is not None`), so each no-evidence body
must answer None AND say so -- including the poisoned body, which drives the except branch. The measured cases
pin that a real negative stays a graded False. Bodies are synthetic, shaped like the getBackups,
isBackupTested and isBackupImmutable workflow responses Integration-Service returns (XML parsed to JSON:
an empty element is None, one child is a dict, several are a list).
"""
import copy
import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("nm_" + name, os.path.join(HERE, name + ".py"))
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


NOW = datetime.now(timezone.utc)
RECENT = (NOW - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

BACKUPS = {"result": {
    "dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {"DescribeDBInstanceAutomatedBackupsResult": {
        "DBInstanceAutomatedBackups": {"DBInstanceAutomatedBackup": {
            "DBInstanceIdentifier": "db-synthetic", "BackupRetentionPeriod": "7", "Encrypted": "true",
            "Status": "active", "Region": "us-east-1",
            "DBInstanceArn": "arn:aws:rds:us-east-1:000000000000:db:db-synthetic",
            "RestoreWindow": {"EarliestTime": RECENT, "LatestTime": RECENT}}}}}},
    "dbManualSnapshots": {"DescribeDBSnapshotsResponse": {"DescribeDBSnapshotsResult": {
        "DBSnapshots": {"DBSnapshot": [{"DBSnapshotIdentifier": "snap-synthetic", "Encrypted": "true",
                                        "SnapshotCreateTime": RECENT, "Status": "available"}]}}}},
    "volumeSnapshots": {"DescribeSnapshotsResponse": {"snapshotSet": None}},
}}


def backups(change):
    body = copy.deepcopy(BACKUPS)
    change(body["result"])
    return body


def no_backups(r):
    r["dbBackups"]["DescribeDBInstanceAutomatedBackupsResponse"]["DescribeDBInstanceAutomatedBackupsResult"]["DBInstanceAutomatedBackups"] = None
    r["dbManualSnapshots"]["DescribeDBSnapshotsResponse"]["DescribeDBSnapshotsResult"]["DBSnapshots"] = None


def no_manual(r):
    r["dbManualSnapshots"]["DescribeDBSnapshotsResponse"]["DescribeDBSnapshotsResult"]["DBSnapshots"] = None


def restore_event(error_code=None):
    detail = {"eventName": "RestoreDBInstanceFromDBSnapshot"}
    if error_code:
        detail["errorCode"] = error_code
    return {"EventName": "RestoreDBInstanceFromDBSnapshot", "EventTime": RECENT, "Username": "synthetic",
            "Resources": {"member": {"ResourceType": "AWS::RDS::DBInstance", "ResourceName": "db-restored"}},
            "CloudTrailEvent": json.dumps(detail)}


def lookup(events):
    return {"result": {"LookupEventsResponse": {"LookupEventsResult": {"Events": {"member": events} if events else None}}}}


NO_EVIDENCE = [
    ("empty_dict", lambda: {}),
    ("empty_list", lambda: []),
    ("null", lambda: None),
    ("not_available", lambda: {"status": "Not Available"}),
    ("refusal_403", lambda: {"error": True, "errorType": "Forbidden", "statusCode": 403, "message": "forbidden"}),
    ("aws_access_denied", lambda: {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}),
    ("poisoned", lambda: Poisoned()),
]

FILES = [
    ("isbackupenabled", "isBackupEnabled"),
    ("is_backup_logging_enabled", "isBackupLoggingEnabled"),
    ("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems"),
    ("is_backup_encrypted", "isBackupEncrypted"),
    ("is_backup_types_scheduled", "isBackupTypesScheduled"),
    ("backupfrequency", "backupFrequency"),
    ("isgeoredundant", "isGeoRedundant"),
    ("lastsuccessfulbackupage", "lastSuccessfulBackupAge"),
    ("is_backup_tested", "isBackupTested"),
    ("recoverytestcompleted", "recoveryTestCompleted"),
    ("is_backup_immutable", "isBackupImmutable"),
    ("confirmedlicensepurchased", "confirmedLicensePurchased"),
    ("issamlenforced", "isSAMLEnforced"),
]


class NotMeasuredIsNotEvaluated(unittest.TestCase):
    def assert_unmeasured(self, name, key, body):
        out = load(name).transform(body)
        self.assertIsNone(out["transformedResponse"][key])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def assert_measured(self, name, key, body, expected):
        out = load(name).transform(body)
        self.assertEqual(out["transformedResponse"][key], expected)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_no_evidence_body_is_none_with_error_status(self):
        for name, key in FILES:
            for case, body in NO_EVIDENCE:
                with self.subTest(transform=name, body=case):
                    self.assert_unmeasured(name, key, body())

    def test_a_reading_is_graded(self):
        for name, key in [("isbackupenabled", "isBackupEnabled"), ("is_backup_logging_enabled", "isBackupLoggingEnabled"),
                          ("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems"),
                          ("is_backup_encrypted", "isBackupEncrypted"), ("is_backup_types_scheduled", "isBackupTypesScheduled")]:
            with self.subTest(transform=name):
                self.assert_measured(name, key, BACKUPS, True)

    def test_an_account_with_no_backups_is_a_measured_false(self):
        for name, key in [("isbackupenabled", "isBackupEnabled"), ("is_backup_logging_enabled", "isBackupLoggingEnabled"),
                          ("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems"),
                          ("is_backup_types_scheduled", "isBackupTypesScheduled")]:
            with self.subTest(transform=name):
                self.assert_measured(name, key, backups(no_backups), False)

    def test_an_unencrypted_snapshot_is_a_measured_false(self):
        body = backups(lambda r: r["dbManualSnapshots"]["DescribeDBSnapshotsResponse"]["DescribeDBSnapshotsResult"]
                       ["DBSnapshots"]["DBSnapshot"][0].update(Encrypted="false"))
        self.assert_measured("is_backup_encrypted", "isBackupEncrypted", body, False)

    def test_a_partial_read_answers_only_when_what_it_read_decides(self):
        partial = backups(lambda r: r.pop("dbManualSnapshots"))
        # a backup was found in what was read, so enabled is evidenced
        self.assert_measured("isbackupenabled", "isBackupEnabled", partial, True)
        # "all encrypted" over a section that was never read is not a reading
        self.assert_unmeasured("is_backup_encrypted", "isBackupEncrypted", partial)
        nothing_read = backups(lambda r: (no_backups(r), r.pop("volumeSnapshots")))
        self.assert_unmeasured("isbackupenabled", "isBackupEnabled", nothing_read)
        self.assert_unmeasured("is_backup_types_scheduled", "isBackupTypesScheduled", backups(lambda r: r.pop("dbBackups")))

    def test_no_manual_snapshots_does_not_hide_the_automated_backups(self):
        # <DBSnapshots/> parses to None; reading .get on it used to raise into a False
        self.assert_measured("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems", backups(no_manual), True)

    def test_a_failed_restore_is_not_a_tested_backup(self):
        only_failed = lookup([restore_event("InvalidParameterCombination")])
        self.assert_measured("is_backup_tested", "isBackupTested", only_failed, False)
        self.assert_measured("recoverytestcompleted", "recoveryTestCompleted", only_failed, False)
        succeeded = lookup([restore_event(), restore_event("InvalidParameterCombination")])
        self.assert_measured("is_backup_tested", "isBackupTested", succeeded, True)
        self.assert_measured("recoverytestcompleted", "recoveryTestCompleted", succeeded, True)
        self.assert_measured("is_backup_tested", "isBackupTested", lookup([]), False)

    def test_license_status(self):
        self.assert_measured("confirmedlicensepurchased", "confirmedLicensePurchased", {"result": {"licensePurchased": True}}, True)
        self.assert_measured("confirmedlicensepurchased", "confirmedLicensePurchased", {"result": {"licensePurchased": False}}, False)

    def test_saml_providers(self):
        def providers(valid_until):
            return {"ListSAMLProvidersResponse": {"ListSAMLProvidersResult": {"SAMLProviderList": {"member": [
                {"Arn": "arn:aws:iam::000000000000:saml-provider/synthetic", "ValidUntil": valid_until}]}}}}
        self.assert_measured("issamlenforced", "isSAMLEnforced", providers("2099-01-01T00:00:00Z"), True)
        self.assert_measured("issamlenforced", "isSAMLEnforced", providers("2020-01-01T00:00:00Z"), False)
        # an account with no provider returns an empty <SAMLProviderList/>: a measured "none"
        none = {"ListSAMLProvidersResponse": {"ListSAMLProvidersResult": {"SAMLProviderList": None}}}
        self.assert_measured("issamlenforced", "isSAMLEnforced", none, False)

    def test_recovery_window_matches_cloudtrail_retention(self):
        self.assertEqual(load("recoverytestcompleted").WINDOW_DAYS, 90)


class PartialReadDoesNotAnswerForWhatItDidNotRead(unittest.TestCase):
    """is_backup_encrypted: a section that was never read has no answer, and a section that
    was read and holds an unencrypted item settles the top-level fail whatever else is missing.

    The three sub-flags are initialised True and are only ever LOWERED by finding an
    unencrypted item, so a section nothing scanned leaves its flag True -- True from missing
    data. The guard above the final response only fires when everything read was encrypted,
    so a real red elsewhere in the body used to carry the untouched flags out with it.
    """

    VALIDATION = {"status": "passed", "errors": [], "warnings": []}

    UNENCRYPTED_RDS = {"DescribeDBInstanceAutomatedBackupsResponse": {
        "DescribeDBInstanceAutomatedBackupsResult": {"DBInstanceAutomatedBackups": {
            "DBInstanceAutomatedBackup": [{"DBInstanceIdentifier": "prod-db", "Encrypted": "false"}]}}}}

    def run_it(self, data):
        return load("is_backup_encrypted").transform({"data": data, "validation": self.VALIDATION})

    def test_unread_section_does_not_report_encrypted(self):
        """An error envelope for volumeSnapshots must not yield isEbsBackupEncrypted True."""
        out = self.run_it({"dbBackups": self.UNENCRYPTED_RDS,
                           "volumeSnapshots": {"error": "AccessDenied"}})
        result = out["transformedResponse"]
        # what WAS read settles the fail
        self.assertIs(result["isBackupEncrypted"], False)
        self.assertIs(result["isAutoBackupEncrypted"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        # what was NOT read has no answer
        self.assertIsNone(result["isEbsBackupEncrypted"])
        self.assertIsNone(result["isManualBackupEncrypted"])

    def test_a_null_section_does_not_erase_a_red_it_never_touched(self):
        """"volumeSnapshots": null must not raise into the except branch and void the finding."""
        out = self.run_it({"dbBackups": self.UNENCRYPTED_RDS, "volumeSnapshots": None})
        result = out["transformedResponse"]
        self.assertIs(result["isBackupEncrypted"], False)
        self.assertIs(result["isAutoBackupEncrypted"], False)
        self.assertIsNone(result["isEbsBackupEncrypted"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertFalse(out["additionalInfo"]["transformation"]["errors"])

    def test_a_non_dict_section_is_treated_as_unread_not_as_an_error(self):
        out = self.run_it({"dbBackups": self.UNENCRYPTED_RDS, "volumeSnapshots": []})
        result = out["transformedResponse"]
        self.assertIs(result["isBackupEncrypted"], False)
        self.assertIsNone(result["isEbsBackupEncrypted"])
        self.assertFalse(out["additionalInfo"]["transformation"]["errors"])

    def test_all_sections_read_and_encrypted_still_passes_every_key(self):
        out = self.run_it({
            "dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {
                "DescribeDBInstanceAutomatedBackupsResult": {"DBInstanceAutomatedBackups": {
                    "DBInstanceAutomatedBackup": [{"DBInstanceIdentifier": "db1", "Encrypted": "true"}]}}}},
            "dbManualSnapshots": {"DescribeDBSnapshotsResponse": {
                "DescribeDBSnapshotsResult": {"DBSnapshots": {"DBSnapshot": []}}}},
            "volumeSnapshots": {"DescribeSnapshotsResponse": {"snapshotSet": {"item": []}}}})
        result = out["transformedResponse"]
        self.assertIs(result["isBackupEncrypted"], True)
        self.assertIs(result["isAutoBackupEncrypted"], True)
        self.assertIs(result["isManualBackupEncrypted"], True)
        self.assertIs(result["isEbsBackupEncrypted"], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_everything_read_was_encrypted_but_a_section_is_missing_is_not_measured(self):
        """The existing guard must survive: all-encrypted over a partial read answers nothing."""
        out = self.run_it({"dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {
            "DescribeDBInstanceAutomatedBackupsResult": {"DBInstanceAutomatedBackups": {
                "DBInstanceAutomatedBackup": [{"DBInstanceIdentifier": "db1", "Encrypted": "true"}]}}}}})
        self.assertIsNone(out["transformedResponse"]["isBackupEncrypted"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
