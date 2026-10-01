"""Windows Defender One-Click isRemovableMediaControlled reads Intune removable-storage policies via Graph $batch.

Fixtures follow Graph beta deviceManagement/deviceConfigurations?$expand=assignments and
deviceManagement/configurationPolicies?$expand=settings,assignments inside a $batch envelope.
"""
import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("mderemovable", Path(__file__).with_name("microsoft_endpoint_removablemedia.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

KEY = "isRemovableMediaControlled"
GROUP = {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "5f3c1e2a-0b9d-4c7e-8a61-2d4f9b0c7e15"}
EXCLUDE = {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "7a1d2e3f-4b5c-6d7e-8f90-a1b2c3d4e5f6"}
ALL_DEVICES = {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}


def assignments(*targets):
    return [{"id": "a" + str(i), "target": t} for i, t in enumerate(targets)]


def general_config(block, targets):
    return {"@odata.type": "#microsoft.graph.windows10GeneralConfiguration", "id": "b6c1-general",
            "displayName": "Win - Device restrictions", "storageBlockRemovableStorage": block,
            "cameraBlocked": False, "assignments": assignments(*targets)}


def custom_oma(oma_uri, value, targets, odata="#microsoft.graph.omaSettingInteger"):
    return {"@odata.type": "#microsoft.graph.windows10CustomConfiguration", "id": "c7d2-custom",
            "displayName": "Win - Custom OMA", "omaSettings": [
                {"@odata.type": odata, "displayName": "setting", "omaUri": oma_uri, "value": value}],
            "assignments": assignments(*targets)}


def device_control_policy(entry_type, targets):
    rule = "device_vendor_msft_defender_configuration_devicecontrol_policyrules_{0b5c7f1e}_ruledata"
    return {"id": "e1f2-dc", "name": "ASR - Device control", "platforms": "windows10", "technologies": "mdm,microsoftSense",
            "isAssigned": bool(targets),
            "settings": [{"id": "0", "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_defender_configuration_devicecontrol_policyrules_{0b5c7f1e}",
                "groupSettingCollectionValue": [{"children": [{
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                    "settingDefinitionId": rule,
                    "groupSettingCollectionValue": [{"children": [{
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": rule + "_entry_type",
                        "choiceSettingValue": {"value": rule + "_entry_type_" + entry_type, "children": []}}]}]}]}]}}],
            "assignments": assignments(*targets)}


def catalog_deny_write(targets):
    return {"id": "f3a4-catalog", "name": "Storage - deny write", "platforms": "windows10",
            "settings": [{"id": "0", "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_storage_removablediskdenywriteaccess",
                "choiceSettingValue": {"value": "device_vendor_msft_policy_config_storage_removablediskdenywriteaccess_1",
                                       "children": []}}}],
            "assignments": assignments(*targets)}


def batch(device_configs, config_policies, dc_status=200, cp_status=200, next_link=None):
    cp_body = {"@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/configurationPolicies",
               "value": config_policies}
    if next_link:
        cp_body["@odata.nextLink"] = next_link
    return {"responses": [
        {"id": "deviceConfigurations", "status": dc_status, "headers": {},
         "body": {"value": device_configs} if dc_status == 200 else
         {"error": {"code": "Forbidden", "message": "Application is not authorized to perform this operation."}}},
        {"id": "configurationPolicies", "status": cp_status, "headers": {}, "body": cp_body},
    ]}


class RemovableMedia(unittest.TestCase):
    def out(self, payload):
        return m.transform(payload)

    def verdict(self, payload):
        return self.out(payload)["transformedResponse"][KEY]

    def test_pass_device_restriction_block_assigned(self):
        out = self.out(batch([general_config(True, [GROUP])], []))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["additionalInfo"]["metadata"]["schemaVersion"], "2.0")

    def test_pass_device_control_deny_all_devices(self):
        out = self.out(batch([], [device_control_policy("deny", [ALL_DEVICES])]))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertIs(out["transformedResponse"]["coversAllDevices"], True)

    def test_pass_settings_catalog_and_oma_deny_write(self):
        self.assertIs(self.verdict(batch([], [catalog_deny_write([GROUP])])), True)
        oma = custom_oma("./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess", 1, [GROUP])
        self.assertIs(self.verdict({"value": [oma]}), True)
        admx = custom_oma("./Device/Vendor/MSFT/Policy/Config/ADMX_RemovableStorage/RemovableStorageClasses_DenyAll_Access_2",
                          "<enabled/>", [GROUP], odata="#microsoft.graph.omaSettingString")
        self.assertIs(self.verdict(json.dumps({"value": [admx]})), True)

    def test_fail_block_not_assigned_or_only_excluded(self):
        self.assertIs(self.verdict(batch([general_config(True, [])], [])), False)
        self.assertIs(self.verdict(batch([general_config(True, [EXCLUDE])], [])), False)

    def test_fail_audit_only_device_control(self):
        out = self.out(batch([], [device_control_policy("auditallowed", [ALL_DEVICES])]))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["auditOnlyPolicies"], ["ASR - Device control"])

    def test_fail_policies_that_do_not_restrict(self):
        self.assertIs(self.verdict(batch([general_config(False, [ALL_DEVICES])], [])), False)
        oma = custom_oma("./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess", 0, [GROUP])
        self.assertIs(self.verdict(batch([oma], [])), False)

    def test_empty_complete_read_is_false(self):
        out = self.out(batch([], []))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def assert_unevaluated(self, payload):
        out = self.out(payload)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        return out

    def test_error_bodies_are_unevaluated(self):
        self.assert_unevaluated({"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})
        self.assert_unevaluated(batch([general_config(True, [GROUP])], [], dc_status=403))
        self.assert_unevaluated({})
        self.assert_unevaluated(None)
        self.assert_unevaluated({"responses": []})

    def test_truncated_read_is_unevaluated(self):
        out = self.assert_unevaluated(batch([], [catalog_deny_write([GROUP])],
                                            next_link="https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$skiptoken=abc"))
        self.assertIn("partial", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_restricting_policy_without_assignments_is_unevaluated(self):
        policy = general_config(True, [GROUP])
        del policy["assignments"]
        self.assert_unevaluated(batch([policy], []))


if __name__ == "__main__":
    unittest.main()
