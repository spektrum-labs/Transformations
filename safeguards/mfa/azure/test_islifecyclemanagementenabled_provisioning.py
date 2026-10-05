"""Azure AD One-Click isLifeCycleManagementEnabled from Entra provisioning logs.

Fixtures follow GET https://graph.microsoft.com/v1.0/auditLogs/provisioning (provisioningObjectSummary,
https://learn.microsoft.com/en-us/graph/api/provisioningobjectsummary-list): an HR-inbound Workday disable,
an outbound SCIM delete, an admin on-demand run, a failed delete, group objects and stale events.
"""
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "aadlifecycle", Path(__file__).with_name("islifecyclemanagementenabled_provisioning.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

KEY = "isLifeCycleManagementEnabled"
CONTEXT = "https://graph.microsoft.com/v1.0/$metadata#auditLogs/provisioning"


def ts(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S") + ".1234567Z"


def event(action="disable", status="success", initiator="system", identity="User", days_ago=3,
          app="Workday to Microsoft Entra user provisioning", inbound=True, initiator_field="initiatorType"):
    entra = {"id": "e69d4bd2-2da2-483e-bc49-aad4080b91b3", "displayName": "Azure Active Directory", "details": {}}
    other = {"id": "d1e090e1-f2f4-4678-be44-6442ffff0621", "displayName": app, "details": {}}
    rec = {
        "id": "75b5b0ae-9fc5-8d0e-e0a9-7a6a4728de56",
        "activityDateTime": ts(days_ago),
        "tenantId": "74beb175-3b80-7b63-b9d5-6f0b76082b16",
        "jobId": "Workday2AAD.74beb1753b704b63b8d56f0b76082b16.10a7a801",
        "cycleId": "b6502552-018d-79bd-8869-a47194dc65c1",
        "changeId": "b6502552-018d-89bd-9969-b49194dc65c1",
        "provisioningAction": action,
        "durationInMilliseconds": 3236,
        "provisioningStatusInfo": {"status": status, "errorInformation": None},
        "provisioningSteps": [{"name": "EntryExportUpdate", "provisioningStepType": "export", "status": status,
                               "description": "User 'jdoe@contoso.com' was " + action + "d", "details": {}}],
        "servicePrincipal": {"id": "6cc35b93-185a-4485-a519-50c09549a3ad", "displayName": app},
        "sourceSystem": other if inbound else entra,
        "targetSystem": entra if inbound else other,
        "sourceIdentity": {"identityType": "Worker" if inbound else identity, "id": "21004",
                           "displayName": "Jane Doe", "details": {}},
        "targetIdentity": {"identityType": identity, "id": "5e6c9fae-ab4d-5239-8ad0-174391d110eb",
                           "displayName": "jdoe@contoso.com", "details": {}},
    }
    if initiator is not None:
        rec["initiatedBy"] = {"id": "", "displayName": "Azure AD Provisioning Service", initiator_field: initiator}
    return rec


def body(records, next_link=None, **extra):
    out = {"@odata.context": CONTEXT, "value": records}
    if next_link:
        out["@odata.nextLink"] = next_link
    out.update(extra)
    return out


def run(payload):
    out = m.transform(payload)
    return out["transformedResponse"][KEY], out


class PassCases(unittest.TestCase):
    def test_hr_inbound_disable_passes(self):
        value, out = run(body([event()]))
        self.assertIs(value, True)
        self.assertEqual(out["transformedResponse"]["automaticUserDeprovisionings"], 1)
        self.assertIn("Workday", out["additionalInfo"]["evaluation"]["passReasons"][0])
        self.assertEqual(out["additionalInfo"]["metadata"]["schemaVersion"], "2.0")
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_outbound_scim_delete_passes(self):
        value, _ = run(body([event(action="delete", inbound=False, app="Slack", identity="User")]))
        self.assertIs(value, True)

    def test_documented_initiating_type_spelling_and_application_initiator(self):
        value, _ = run(body([event(initiator="application", initiator_field="initiatingType")]))
        self.assertIs(value, True)

    def test_wrapped_string_input_passes(self):
        value, _ = run(json.dumps({"response": body([event()])}))
        self.assertIs(value, True)

    def test_enriched_input_passes(self):
        value, _ = run({"data": body([event()]), "validation": {"status": "passed", "errors": [], "warnings": []}})
        self.assertIs(value, True)

    def test_echoed_app_name_is_length_capped(self):
        _, out = run(body([event(app="<img src=x onerror=alert(1)>" + "A" * 500)]))
        names = out["additionalInfo"]["transformation"]["inputSummary"]["deprovisioningApps"]
        self.assertEqual(len(names[0]), 80)

    def test_mixed_feed_one_qualifier_is_enough(self):
        value, out = run(body([event(action="create"), event(status="failure"), event(days_ago=2)]))
        self.assertIs(value, True)
        excluded = out["additionalInfo"]["transformation"]["inputSummary"]["excluded"]
        self.assertEqual(excluded["notDeprovisioning"], 1)
        self.assertEqual(excluded["notSuccessful"], 1)


class FailCases(unittest.TestCase):
    def assert_false(self, payload):
        value, out = run(payload)
        self.assertIs(value, False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
        return out

    def test_no_provisioning_events_is_false(self):
        self.assert_false(body([]))

    def test_only_creates_and_updates_is_false(self):
        self.assert_false(body([event(action="create"), event(action="update")]))

    def test_failed_or_skipped_deprovisioning_is_false(self):
        out = self.assert_false(body([event(status="failure"), event(action="delete", status="skipped")]))
        self.assertIn("did not succeed", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_admin_on_demand_run_is_not_automatic(self):
        self.assert_false(body([event(initiator="user")]))

    def test_missing_initiator_is_not_counted(self):
        self.assert_false(body([event(initiator=None)]))

    def test_group_deprovisioning_is_not_a_leaver(self):
        self.assert_false(body([event(identity="Group", inbound=False, action="delete")]))

    def test_stale_event_outside_window_is_false(self):
        self.assert_false(body([event(days_ago=45)]))

    def test_unreadable_timestamp_is_not_counted(self):
        rec = event()
        rec["activityDateTime"] = "last tuesday"
        self.assert_false(body([rec]))


class UnevaluatedCases(unittest.TestCase):
    def assert_none(self, payload):
        value, out = run(payload)
        self.assertIsNone(value)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        return out

    def test_graph_403_is_unevaluated(self):
        out = self.assert_none({"error": {"code": "Authorization_RequestDenied",
                                          "message": "Insufficient privileges to complete the operation.",
                                          "innerError": {"date": "2026-10-01T12:00:00",
                                                         "request-id": "0d1c2b3a-0000-4000-8000-000000000000"}}})
        self.assertIn("AuditLog.Read.All", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_non_premium_tenant_is_unevaluated(self):
        self.assert_none({"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                                    "message": "Neither tenant is B2C or tenant doesn't have premium license"}})

    def test_status_code_403_is_unevaluated(self):
        self.assert_none({"statusCode": 403, "body": "Forbidden", "value": [event()]})

    def test_partial_read_with_next_link_is_unevaluated_even_with_a_qualifier(self):
        self.assert_none(body([event()], next_link="https://graph.microsoft.com/v1.0/auditLogs/provisioning?$skiptoken=abc"))

    def test_is_truncated_marker_is_unevaluated(self):
        self.assert_none(body([event()], truncated=True))
        self.assert_none(body([event()], pagination={"truncated": True, "scannedCount": 5000}))

    def test_no_value_list_is_unevaluated(self):
        self.assert_none({"@odata.context": CONTEXT})
        self.assert_none({"value": {"id": "x"}})

    def test_non_object_record_is_unevaluated(self):
        self.assert_none(body([event(), "junk"]))

    def test_no_evidence_bodies_never_pass(self):
        for payload in [None, {}, "", "{}", b"{}", [], {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
                        {"statusCode": 401, "error": "Unauthorized"}, {"status_code": 401, "error": "Unauthorized"},
                        {"error": {"statusCode": 401, "message": "Unauthorized"}}]:
            value, _ = run(payload)
            self.assertIsNot(value, True, payload)

    def test_validation_failed_is_unevaluated(self):
        self.assert_none({"data": body([event()]), "validation": {"status": "failed", "errors": ["x"], "warnings": []}})


if __name__ == "__main__":
    unittest.main()
