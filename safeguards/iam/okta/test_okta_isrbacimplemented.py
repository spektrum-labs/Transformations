"""isRBACImplemented for Okta reads the admin role holders (GET /api/v1/iam/assignees/users) and each one's roles
(GET /api/v1/users/{id}/roles), merged by the isRBACImplemented workflow. Synthetic ids and labels."""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.resolve().parents[2]
KEY = "isRBACImplemented"


def load():
    spec = importlib.util.spec_from_file_location("okta_isrbacimplemented", HERE / "isRBACImplemented.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_rbac", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / "isRBACImplemented.py").read_text(), "<transformation>")["transform"]


def role(kind, status="ACTIVE"):
    return {"id": "ra-" + kind.lower(), "label": kind.title(), "type": kind, "status": status, "assignmentType": "USER"}


def admin(n):
    return {"id": "00uADMIN" + str(n), "orn": "orn:okta:directory:example:users:00uADMIN" + str(n)}


REAL = {"result": {
    "adminAssignees": {"value": [admin(1), admin(2), admin(3)], "_links": {}},
    "adminRoles": [[role("SUPER_ADMIN")], [role("HELP_DESK_ADMIN")], [role("READ_ONLY_ADMIN"), role("CUSTOM")]],
    "paginationStats": {"adminAssignees": {"pages": 1, "paginationTruncated": False}},
    "iterateStats": {"adminRoles": {"itemsTotal": 3, "itemsProcessed": 3, "itemErrors": 0, "iterateTruncated": False}},
}}


def super_only():
    data = copy.deepcopy(REAL)
    data["result"]["adminRoles"] = [[role("SUPER_ADMIN")], [role("SUPER_ADMIN")], [role("SUPER_ADMIN"), role("HELP_DESK_ADMIN", "INACTIVE")]]
    return data


class RbacTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = [load(), sandboxed()]

    def check(self, body, expected):
        for transform in self.runs:
            full = transform(copy.deepcopy(body))
            self.assertIs(full["transformedResponse"][KEY], expected, body)
            status = full["additionalInfo"]["dataCollection"]["status"]
            self.assertEqual(status, "error" if expected is None else "success")
            if expected is None:
                self.assertTrue(full["additionalInfo"]["dataCollection"]["errors"])
        return full

    def test_real_shape_delegated_roles_pass_with_counts(self):
        full = self.check(REAL, True)
        out = full["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual((out["adminCount"], out["delegatedAdminCount"], out["fullAdminCount"]), (3, 2, 1))
        reasons = " ".join(full["additionalInfo"]["evaluation"]["passReasons"])
        self.assertNotIn("00uADMIN", reasons)  # counts only, never an admin

    def test_flipped_every_admin_super_admin_only_fails(self):
        full = self.check(super_only(), False)
        self.assertEqual(full["additionalInfo"]["transformation"]["inputSummary"]["fullAdminCount"], 3)
        self.assertTrue(full["additionalInfo"]["evaluation"]["recommendations"])

    def test_one_delegated_admin_passes_even_when_other_reads_failed(self):
        data = copy.deepcopy(REAL)
        data["result"]["adminRoles"][0] = {"error": True, "statusCode": 429, "item": admin(1), "errorType": "RATE_LIMIT"}
        data["result"]["iterateStats"]["adminRoles"]["itemErrors"] = 1
        self.check(data, True)

    def test_org_admin_is_a_full_control_role(self):
        data = copy.deepcopy(REAL)
        data["result"]["adminRoles"] = [[role("ORG_ADMIN")], [role("SUPER_ADMIN"), role("ORG_ADMIN")], [role("ORG_ADMIN")]]
        self.check(data, False)
        data["result"]["adminRoles"][2] = [role("HELP_DESK_ADMIN")]
        self.check(data, True)

    def test_super_admin_plus_narrow_role_on_every_admin_fails(self):
        data = copy.deepcopy(REAL)
        data["result"]["adminRoles"] = [[role("SUPER_ADMIN"), role("READ_ONLY_ADMIN")] for _ in range(3)]
        full = self.check(data, False)
        self.assertEqual(full["additionalInfo"]["transformation"]["inputSummary"]["fullAdminCount"], 3)
        data["result"]["paginationStats"]["adminAssignees"]["paginationTruncated"] = True
        self.check(data, None)

    def test_super_admin_only_with_a_failed_or_cut_read_is_not_evaluated(self):
        data = super_only()
        data["result"]["adminRoles"][2] = {"error": True, "statusCode": 403}
        self.check(data, None)
        data = super_only()
        data["result"]["paginationStats"]["adminAssignees"]["paginationTruncated"] = True
        self.check(data, None)
        data = super_only()
        data["result"]["iterateStats"]["adminRoles"]["iterateTruncated"] = True
        self.check(data, None)
        data = super_only()
        data["result"]["adminRoles"] = data["result"]["adminRoles"][:2]
        self.check(data, None)
        data = super_only()
        data["result"]["adminAssignees"]["_links"] = {"next": {"href": None, "truncated": True}}
        self.check(data, None)
        data = super_only()
        data["result"]["adminRoles"][1] = []
        self.check(data, None)

    def test_empty_none_and_unrelated_bodies_are_not_evaluated(self):
        for body in [{}, None, [], "null", {"result": {}}, {"adminAssignees": {"value": []}, "adminRoles": []},
                     {"adminAssignees": {"value": [admin(1)]}}, [{"factorType": "push", "status": "ACTIVE"}]]:
            self.check(body, None)

    def test_error_objects_are_not_evaluated(self):
        for body in [{"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"},
                     {"adminAssignees": {"errorCode": "E0000006"}, "adminRoles": []},
                     {"adminAssignees": {"vendorErrorAsResponse": True, "statusCode": 403}, "adminRoles": []},
                     b"\xff not json"]:
            self.check(body, None)

    def test_role_without_type_is_unread(self):
        data = super_only()
        data["result"]["adminRoles"][0] = [{"id": "ra-x", "status": "ACTIVE"}]
        self.check(data, None)


if __name__ == "__main__":
    unittest.main()
