"""NinjaOne organization and policy checks judge only what applies to the devices in the (organization-filtered)
device list when the workflow supplies one, and everything they are given when it does not (synthetic data)."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("n1_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def verdict(name, body):
    return load(name)(body)["transformedResponse"]


# Org 10 is ours (devices in scope), org 20 is another tenant's (its devices were filtered out by df=org!=20).
DEVICES = [{"id": 1, "organizationId": 10, "policyId": 100, "rolePolicyId": 101},
           {"id": 2, "organizationId": 10, "policyId": [], "rolePolicyId": 102}]


def orgs(ours_mode, theirs_mode):
    return [{"id": 10, "name": "Ours", "nodeApprovalMode": ours_mode},
            {"id": 20, "name": "Other tenant", "nodeApprovalMode": theirs_mode}]


class TestAutoApproval:
    key = "isDeviceAutoApprovalDisabled"

    def test_out_of_scope_org_is_not_judged(self):
        out = verdict(self.key, {"devices": DEVICES, "organizations": orgs("MANUAL", "AUTOMATIC")})
        assert out[self.key] is True
        assert out["totalOrganizations"] == 1
        assert out["organizationsOutOfScope"] == 1

    def test_in_scope_org_still_fails(self):
        assert verdict(self.key, {"devices": DEVICES, "organizations": orgs("AUTOMATIC", "MANUAL")})[self.key] is False

    def test_bare_list_judges_every_org_as_before(self):
        out = verdict(self.key, orgs("MANUAL", "AUTOMATIC"))
        assert out[self.key] is False
        assert out["totalOrganizations"] == 2

    def test_no_device_in_scope_is_an_evaluated_fail(self):
        out = verdict(self.key, {"devices": [], "organizations": orgs("MANUAL", "MANUAL")})
        assert out[self.key] is False
        assert out["totalOrganizations"] == 0


CONDITIONS = {
    "isDeviceOfflineAlertingEnabled": {"type": "DEVICE_OFFLINE"},
    "isPatchAutoApprovalRestricted": {"type": "PATCH_APPROVAL", "approvalMode": "MANUAL"},
    "isPatchManagementEnabled": {"conditionType": "OS_PATCH_MANAGEMENT"},
    "isThirdPartyPatchManagementEnabled": {"type": "SOFTWARE_PATCH_MANAGEMENT", "enabled": True},
}


def policies(with_condition, parent_of_101=None):
    out = []
    for pid in (100, 101, 102, 200, 300):
        p = {"id": pid, "name": "policy %d" % pid, "nodeClass": "WINDOWS_WORKSTATION", "conditions": []}
        if pid == 101 and parent_of_101 is not None:
            p["parentPolicyId"] = parent_of_101
        out.append(p)
    for p in out:
        if p["id"] == with_condition[0]:
            p["conditions"] = [with_condition[1]]
    return out


@pytest.mark.parametrize("key", sorted(CONDITIONS))
class TestPolicyScope:
    def test_condition_on_out_of_scope_policy_is_not_counted(self, key):
        out = verdict(key, {"devices": DEVICES, "policies": policies((200, CONDITIONS[key]))})
        assert out[key] is False
        assert out["policiesOutOfScope"] == 2

    def test_same_policies_as_bare_list_are_all_judged(self, key):
        assert verdict(key, policies((200, CONDITIONS[key])))[key] is True

    @pytest.mark.parametrize("pid", [100, 101, 102])
    def test_policy_and_role_policy_of_a_device_count(self, key, pid):
        assert verdict(key, {"devices": DEVICES, "policies": policies((pid, CONDITIONS[key]))})[key] is True

    def test_parent_of_a_device_policy_counts(self, key):
        body = {"devices": DEVICES, "policies": policies((300, CONDITIONS[key]), parent_of_101=300)}
        out = verdict(key, body)
        assert out[key] is True
        assert out["policiesOutOfScope"] == 1

    def test_no_device_in_scope_is_an_evaluated_fail(self, key):
        assert verdict(key, {"devices": [], "policies": policies((100, CONDITIONS[key]))})[key] is False
