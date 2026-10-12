"""AWS isBackupTested counts only restores that succeeded.

An errored RestoreDBInstanceFromDBSnapshot call (CloudTrailEvent carries an errorCode) used to count as
a backup test, so a failed restore passed. Now only a successful restore is True, a restore history with
only errors is False, and a lookup that returned nothing readable is None plus a dataCollection error.
Bodies follow the CloudTrail LookupEvents query response as converted by Integration-Service. Synthetic
data only.
"""
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "isBackupTested"


def load():
    spec = importlib.util.spec_from_file_location("aws_is_backup_tested", os.path.join(HERE, "is_backup_tested.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def event(error_code=None, event_id="11111111-2222-3333-4444-555555555555", cloud_trail_event="default", resources=None):
    detail = {"eventVersion": "1.08", "eventSource": "rds.amazonaws.com", "eventName": "RestoreDBInstanceFromDBSnapshot",
              "awsRegion": "us-east-1", "requestParameters": {"dBInstanceIdentifier": "restore-test", "dBSnapshotIdentifier": "snap-1"}}
    if error_code:
        detail["errorCode"] = error_code
        detail["errorMessage"] = "The restore did not start"
    return {
        "EventId": event_id,
        "EventName": "RestoreDBInstanceFromDBSnapshot",
        "EventTime": "2026-09-01T12:00:00Z",
        "Username": "restore-operator",
        "EventSource": "rds.amazonaws.com",
        "Resources": resources if resources is not None else {"member": [
            {"ResourceType": "AWS::RDS::DBInstance", "ResourceName": "restore-test"}]},
        "CloudTrailEvent": json.dumps(detail) if cloud_trail_event == "default" else cloud_trail_event,
    }


def lookup(events, next_token=None):
    result = {"Events": {"member": events} if events else None}
    if next_token:
        result["NextToken"] = next_token
    return {"LookupEventsResponse": {"LookupEventsResult": result, "ResponseMetadata": {"RequestId": "req-1"}}}


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


class BackupTestedCountsOnlySuccessfulRestores(unittest.TestCase):
    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][KEY])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_one_successful_restore_is_true(self):
        out = load().transform(lookup([event()]))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_single_event_dict_member_is_true(self):
        body = {"LookupEventsResponse": {"LookupEventsResult": {"Events": {"member": event()}}}}
        self.assertIs(load().transform(body)["transformedResponse"][KEY], True)

    def test_a_success_beside_errors_is_true_and_the_errors_are_not_counted(self):
        out = load().transform(lookup([event("InvalidDBSnapshotState"), event()]))
        self.assertIs(out["transformedResponse"][KEY], True)
        info = out["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual((info["successfulRestores"], info["failedRestores"]), (1, 1))

    def test_only_errored_restores_is_a_real_false(self):
        out = load().transform(lookup([event("InvalidDBSnapshotState"), event("AccessDenied")]))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertIn("errored", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_lookup_with_no_restore_events_is_false(self):
        out = load().transform(lookup([]))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_events_without_a_db_instance_resource_are_not_restores(self):
        out = load().transform(lookup([event(resources={"member": [{"ResourceType": "AWS::S3::Bucket"}]})]))
        self.assertIs(out["transformedResponse"][KEY], False)

    def test_event_with_unreadable_outcome_is_not_a_pass(self):
        for raw in (None, "", "not json", "[]"):
            with self.subTest(cloud_trail_event=raw):
                self.assert_not_evaluated(load().transform(lookup([event(cloud_trail_event=raw)])))

    def test_more_pages_and_no_success_is_not_evaluated(self):
        self.assert_not_evaluated(load().transform(lookup([event("AccessDenied")], next_token="token-1")))
        self.assert_not_evaluated(load().transform(lookup([], next_token="token-1")))

    def test_more_pages_but_a_success_already_read_is_true(self):
        self.assertIs(load().transform(lookup([event()], next_token="token-1"))["transformedResponse"][KEY], True)

    def test_empty_or_error_body_is_not_evaluated(self):
        for name, body in (
            ("empty_object", {}),
            ("none", None),
            ("empty_json_string", "{}"),
            ("empty_lookup_response", {"LookupEventsResponse": {}}),
            ("lookup_response_none", {"LookupEventsResponse": None}),
            ("error_envelope", {"ErrorResponse": {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}}),
            ("unrelated_json", {"unrelated": "json"}),
        ):
            with self.subTest(body=name):
                self.assert_not_evaluated(load().transform(body))

    def test_failed_validation_is_not_evaluated(self):
        body = {"data": lookup([event()]), "validation": {"status": "failed", "errors": ["bad"], "warnings": []}}
        self.assert_not_evaluated(load().transform(body))

    def test_exception_is_not_evaluated(self):
        self.assert_not_evaluated(load().transform(Poisoned()))


if __name__ == "__main__":
    unittest.main()
