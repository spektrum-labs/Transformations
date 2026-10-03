"""isLegacyAuthBlocked reads Cloud Identity Policy API security.less_secure_apps policies (getLessSecureAppsPolicies).

Fixture shape mirrors a stored Workspace policy read (estate A, 2026-10-01), with every id, customer and
group replaced by synthetic values: Integration-Service stringifies scalars ("False", "201.00183"); the root
org unit carries a SYSTEM policy that allows less secure apps and a later ADMIN policy that turns them off;
two child org units and one group carry ADMIN policies that allow them.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("islegacyauthblocked.py")
KEY = "isLegacyAuthBlocked"
ROOT = "orgUnits/0000root0000a"


def load():
    spec = importlib.util.spec_from_file_location("islegacyauthblocked", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ou_query(ou):
    return "entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('" + ou.split("/")[1] + "'))"


def policy(allow, ou=ROOT, order="201.00183", ptype="ADMIN", group=None, query=None, name="policies/synthetic01"):
    pq = {"orgUnit": ou, "sortOrder": order}
    if group:
        pq["group"] = group
        pq["query"] = ("entity.groups.exists(group, group.group_id == groupId('" + group.split("/")[1] + "')) && "
                       + ou_query(ou))
    else:
        pq["query"] = ou_query(ou)
    if query is not None:
        pq["query"] = query
    value = {} if allow is None else {"allowLessSecureApps": allow}
    return {"name": name, "customer": "customers/C0synthetic", "policyQuery": pq,
            "setting": {"type": "settings/security.less_secure_apps", "value": value}, "type": ptype}


def other_setting(kind, value):
    return {"name": "policies/synthetic99", "customer": "customers/C0synthetic",
            "policyQuery": {"orgUnit": ROOT, "query": ou_query(ROOT), "sortOrder": "201.00022"},
            "setting": {"type": "settings/" + kind, "value": value}, "type": "SYSTEM"}


REAL = {"policies": [
    policy("False", order="201.00183"),
    policy("True", ou="orgUnits/0000child0001", order="203"),
    policy("True", order="201.00022", ptype="SYSTEM"),
    policy("True", group="groups/0000group0001", order="399.00018"),
    policy("True", ou="orgUnits/0000child0002", order="204"),
]}


def flipped():
    body = copy.deepcopy(REAL)
    for p in body["policies"]:
        if p["type"] == "ADMIN":
            p["setting"]["value"]["allowLessSecureApps"] = "False"
    return body


def ts_is_equals_true(value):
    """Token-Service isEquals true: only a real True passes."""
    return value is True


class LegacyAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, body):
        out = self.t.transform(body)
        return out["transformedResponse"][KEY], out

    def assert_unevaluated(self, body):
        value, out = self.run_t(body)
        self.assertIsNone(value, out)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertFalse(ts_is_equals_true(value))
        return out

    # real shape
    def test_real_shape_child_ous_and_group_allow_is_false(self):
        value, out = self.run_t(REAL)
        self.assertIs(value, False)
        self.assertEqual(out["transformedResponse"]["lessSecureAppsAllowedTargetCount"], 3)
        reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
        self.assertIn("orgUnits/0000child0001", reason)
        self.assertIn("group groups/0000group0001", reason)
        self.assertNotIn(ROOT + ";", reason)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_real_shape_as_string_bytes_and_wrapped(self):
        self.assertIs(self.run_t(json.dumps(REAL))[0], False)
        self.assertIs(self.run_t(json.dumps(REAL).encode("utf-8"))[0], False)
        self.assertIs(self.run_t({"result": {"apiResponse": copy.deepcopy(REAL)}})[0], False)
        self.assertIs(self.run_t({"_response_data": copy.deepcopy(REAL)})[0], False)

    # flipped
    def test_flipped_every_override_off_is_true(self):
        value, out = self.run_t(flipped())
        self.assertIs(value, True)
        self.assertTrue(ts_is_equals_true(value))
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["overriddenAllowingPolicies"], 1)

    def test_system_default_allow_without_admin_override_is_false(self):
        body = {"policies": [policy("True", order="201.00022", ptype="SYSTEM")]}
        self.assertIs(self.run_t(body)[0], False)

    def test_admin_off_with_lower_order_does_not_override(self):
        body = {"policies": [policy("False", order="201.00010"), policy("True", order="201.00022", ptype="SYSTEM")]}
        self.assertIs(self.run_t(body)[0], False)

    def test_root_off_does_not_cover_child_allow(self):
        body = {"policies": [policy("False", order="250"), policy("True", ou="orgUnits/0000child0001", order="203")]}
        self.assertIs(self.run_t(body)[0], False)

    def test_native_booleans_accepted(self):
        body = {"policies": [policy(False, order="201.00183"), policy(True, order="201.00022", ptype="SYSTEM")]}
        self.assertIs(self.run_t(body)[0], True)

    def test_field_absent_in_value_is_documented_default_off(self):
        body = {"policies": [policy(None, order="201.00183")]}
        self.assertIs(self.run_t(body)[0], True)

    def test_absent_setting_in_complete_real_list_is_true(self):
        body = {"policies": [other_setting("security.two_step_verification_enrollment", {"allowEnrollment": "True"}),
                             other_setting("security.session_controls", {"webSessionDuration": "1209600s"})]}
        value, out = self.run_t(body)
        self.assertIs(value, True)
        self.assertIn("documented default", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_absent_setting_in_list_without_security_settings_is_unevaluated(self):
        body = {"policies": [other_setting("gmail.spam_override_lists", {"allowedSenders": []})]}
        self.assert_unevaluated(body)

    def test_absent_setting_with_more_pages_is_unevaluated(self):
        body = {"policies": [other_setting("security.session_controls", {"webSessionDuration": "1209600s"})],
                "nextPageToken": "synthetic-token"}
        self.assert_unevaluated(body)

    # empty / None / error / partial / unrelated
    def test_empty_inputs_are_unevaluated(self):
        for body in [{}, "{}", "", b"", "   ", {"policies": []}, {"result": {}}, []]:
            self.assert_unevaluated(body)

    def test_none_is_unevaluated(self):
        self.assert_unevaluated(None)

    def test_error_bodies_are_unevaluated(self):
        scope = {"error": {"code": 403, "message": "Request had insufficient authentication scopes.",
                           "status": "PERMISSION_DENIED"}}
        out = self.assert_unevaluated(scope)
        self.assertIn("cloud-identity.policies.readonly", out["additionalInfo"]["dataCollection"]["errors"][0])
        for body in [{"statusCode": 401, "error": "Unauthorized"}, {"status_code": 403, "error": "Forbidden"},
                     {"error": {"statusCode": 401, "message": "Unauthorized"}},
                     {"status": "Error", "message": "Integrator not configured"},
                     {"error": True, "errorType": "pagination_incomplete", "statusCode": 502}]:
            self.assert_unevaluated(body)

    def test_partial_reads_are_unevaluated(self):
        body = copy.deepcopy(flipped())
        body["nextPageToken"] = "synthetic-token"
        self.assert_unevaluated(body)
        body = copy.deepcopy(flipped())
        body["paginationTruncated"] = True
        self.assert_unevaluated(body)

    def test_unrelated_and_non_policy_records_are_unevaluated(self):
        for body in [{"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}, {"policies": [{"id": 1}]},
                     {"policies": copy.deepcopy(flipped())["policies"] + ["not a policy"]},
                     {"kind": "admin#reports#activities", "items": []}]:
            self.assert_unevaluated(body)

    def test_unreadable_value_or_org_unit_is_unevaluated(self):
        bad_value = copy.deepcopy(flipped())
        bad_value["policies"][1]["setting"]["value"]["allowLessSecureApps"] = "sometimes"
        self.assert_unevaluated(bad_value)
        no_ou = copy.deepcopy(flipped())
        del no_ou["policies"][0]["policyQuery"]["orgUnit"]
        self.assert_unevaluated(no_ou)
        no_value = copy.deepcopy(flipped())
        del no_value["policies"][0]["setting"]["value"]
        self.assert_unevaluated(no_value)

    def test_conditional_or_unordered_override_is_unevaluated(self):
        licensed = ou_query(ROOT) + " && entity.licenses.exists(license, license in ['/product/P/sku/1'])"
        body = {"policies": [policy("False", order="201.00183", query=licensed),
                             policy("True", order="201.00022", ptype="SYSTEM")]}
        self.assert_unevaluated(body)
        body = {"policies": [policy("False", order=None), policy("True", order="201.00022", ptype="SYSTEM")]}
        self.assert_unevaluated(body)

    def test_unreadable_peer_on_same_target_makes_allow_uncertain(self):
        bad = policy("False", order="201.00183")
        bad["setting"]["value"]["allowLessSecureApps"] = "unknown"
        body = {"policies": [bad, policy("True", order="201.00022", ptype="SYSTEM")]}
        self.assert_unevaluated(body)

    def test_policy_without_org_unit_blocks_a_false_verdict(self):
        stray = policy("False", order="999")
        del stray["policyQuery"]["orgUnit"]
        body = {"policies": [stray, policy("True", ou="orgUnits/0000child0001", order="203")]}
        out = self.assert_unevaluated(body)
        self.assertIn("no org unit", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_measured_allow_stands_beside_unreadable_other_target(self):
        bad = policy("False", ou="orgUnits/0000child0009", order="205")
        bad["setting"]["value"]["allowLessSecureApps"] = "unknown"
        body = {"policies": [bad, policy("True", ou="orgUnits/0000child0001", order="203")]}
        self.assertIs(self.run_t(body)[0], False)

    def test_transformation_error_is_unevaluated(self):
        original = self.t.evaluate
        try:
            self.t.evaluate = lambda policies: (_ for _ in ()).throw(RuntimeError("boom"))
            out = self.assert_unevaluated(flipped())
            self.assertEqual(out["additionalInfo"]["transformation"]["status"], "error")
        finally:
            self.t.evaluate = original

    def test_never_a_non_boolean_verdict(self):
        for body in [REAL, flipped(), {}, None, {"hello": "world"}]:
            value = self.run_t(copy.deepcopy(body))[0]
            self.assertIn(value, [True, False, None])


if __name__ == "__main__":
    unittest.main()


def test_no_call_the_token_service_sandbox_refuses():
    # Token-Service's code validator rejects any call named compile, eval, exec, getattr and the like
    # (src/utils/codeexecutor.py dangerous_calls). re.compile tripped it in production on 3 Oct 2026.
    import ast
    from pathlib import Path
    src = Path(__file__).with_name("islegacyauthblocked.py").read_text()
    denied = {"__import__", "eval", "exec", "compile", "open", "file", "input", "raw_input", "execfile", "reload",
              "__builtins__", "getattr", "setattr", "delattr", "hasattr", "globals", "locals", "vars", "dir"}
    hits = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in denied:
                hits.append((name, node.lineno))
    assert hits == []
