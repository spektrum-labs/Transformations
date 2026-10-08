"""Unit tests for the vCenter administrator transform.

Fixtures are synthetic: made-up principals in example.test and vsphere.local, shaped like the vSphere Automation API 9.0
permission list and like the "spektrum.vcenter.v1" snapshot the Spektrum Connector pushes.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


KEY = "areHypervisorAdminsDedicated"
transform = load("arehypervisoradminsdedicated")


def value(result):
    return result["transformedResponse"][KEY]


def rest_item(name, role="-1", domain="example.test", kind="USER", obj_type="Folder", propagating=True):
    return {"permission": "p-" + name,
            "info": {"object": {"type": obj_type, "id": "group-d1"},
                     "principal": {"type": kind, "name": name, "domain": domain},
                     "role": {"role": role}, "propagating": propagating}}


def rest(*items, marker=None):
    body = {"items": list(items)}
    if marker:
        body["marker"] = marker
    return body


def snap(*permissions, directory=None, roles=None, sso=None, complete=True):
    return {"schema": "spektrum.vcenter.v1", "permissionsComplete": complete,
            "permissions": list(permissions), "roles": roles or [], "ssoAdministrators": sso or [],
            "directory": directory or {}}


def perm(name, role_id="-1", domain="example.test", kind="USER", obj_type="Folder", propagating=True, role_name=None):
    return {"principal": {"type": kind, "name": name, "domain": domain},
            "role": {"id": role_id, "name": role_name}, "object": {"type": obj_type, "id": "group-d1"},
            "propagating": propagating}


def test_rest_true_when_all_admins_follow_the_naming_convention():
    r = transform(rest(rest_item("adm-alice"), rest_item("bob-adm"), rest_item("carol", role="-2")))
    assert value(r) is True
    assert r["transformedResponse"]["adminPrincipals"] == 2
    assert any("naming convention only" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_broad_group_with_admin_role_fails():
    r = transform(rest(rest_item("adm-alice"), rest_item("Domain Users", kind="GROUP")))
    assert value(r) is False
    assert r["transformedResponse"]["nonDedicatedAdminPrincipals"] == 1
    assert "Domain Users" in r["additionalInfo"]["evaluation"]["failReasons"][0]


def test_named_user_without_convention_or_record_is_not_evaluated():
    r = transform(rest(rest_item("adm-alice"), rest_item("dave")))
    assert value(r) is None
    assert r["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "dave" in r["additionalInfo"]["evaluation"]["failReasons"][0]


def test_group_is_never_dedicated_by_its_name():
    r = transform(rest(rest_item("adm-alice"), rest_item("vCenter-Admin", kind="GROUP")))
    assert value(r) is None
    assert "vCenter-Admin" in r["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("name", ["maria.da.silva", "a.smith", "smith.a", "joao.da.costa", "jadministrator"])
def test_personal_names_are_not_dedicated_evidence(name):
    assert value(transform(rest(rest_item(name)))) is None


def test_custom_role_without_a_catalogue_entry_is_not_evaluated_but_a_measured_fail_wins():
    assert value(transform(rest(rest_item("adm-alice"), rest_item("Domain Users", role="1001", kind="GROUP")))) is None
    assert value(transform(rest(rest_item("adm-alice", role="-1"), rest_item("Domain Users", role="-1", kind="GROUP")))) is False
    body = snap(perm("adm-alice"), perm("Domain Users", role_id="1001", kind="GROUP"),
                roles=[{"id": "1001", "name": "Clone of Administrator", "adminCapable": True}])
    assert value(transform(body)) is False


def test_directory_record_without_mailbox_is_dedicated_evidence():
    body = snap(perm("dave"), directory={"dave@example.test": {"found": True, "enabled": True, "hasMailbox": False}})
    assert value(transform(body)) is True


def test_directory_record_with_mailbox_fails_even_with_a_convention_name():
    body = snap(perm("adm-erin"), directory={"adm-erin@example.test": {"found": True, "enabled": True, "hasMailbox": True}})
    r = transform(body)
    assert value(r) is False
    assert "mailbox" in r["additionalInfo"]["evaluation"]["failReasons"][0]


def test_role_with_modify_permissions_privilege_counts_as_admin():
    roles = [{"id": "100", "name": "Custom", "privileges": ["System.View", "Authorization.ModifyPermissions"]},
             {"id": "101", "name": "Viewer", "privileges": ["System.View"]}]
    body = snap(perm("Domain Computers", role_id="100", kind="GROUP"), perm("frank", role_id="101"), roles=roles)
    r = transform(body)
    assert value(r) is False
    assert r["transformedResponse"]["adminPrincipals"] == 1


def test_non_admin_assignments_and_leaf_objects_are_ignored():
    leaf = perm("zed", obj_type="VirtualMachine", propagating=False)
    body = snap(perm("adm-alice"), perm("gina", role_id="-2"), leaf)
    r = transform(body)
    assert value(r) is True
    assert r["transformedResponse"]["adminPrincipals"] == 1


def test_builtin_administrator_is_a_finding_and_solution_users_are_skipped():
    body = snap(perm("Administrator", domain="vsphere.local"), perm("vpxd-extension-1234", domain="vsphere.local"),
                perm("adm-alice"))
    r = transform(body)
    assert value(r) is True
    assert r["transformedResponse"]["adminPrincipals"] == 1
    assert r["additionalInfo"]["transformation"]["inputSummary"]["solutionUsersSkipped"] == 1
    assert any("break-glass" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_only_the_builtin_administrator_is_not_evaluated():
    assert value(transform(snap(perm("Administrator", domain="vsphere.local")))) is None


def test_sso_administrators_count():
    body = snap(perm("adm-alice"), sso=[{"name": "Users", "domain": "vsphere.local", "type": "GROUP"}])
    assert value(transform(body)) is False


def test_partial_lists_are_not_evaluated():
    assert value(transform(rest(rest_item("adm-alice"), marker="next-page"))) is None
    assert value(transform(snap(perm("adm-alice"), complete=False))) is None


def test_no_administrator_assignment_is_not_evaluated():
    assert value(transform(rest(rest_item("gina", role="-2")))) is None
    assert value(transform(rest())) is None


@pytest.mark.parametrize("body", [{}, None, "{}", "", [], {"hello": "world"}, {"error_type": "UNAUTHENTICATED"},
                                  {"error": {"statusCode": 401}}, {"statusCode": 403, "error": "Forbidden"}])
def test_never_answers_from_no_evidence(body):
    assert value(transform(body)) is None


def test_accepts_json_string_bytes_list_and_wrapper():
    body = rest(rest_item("adm-alice"))
    assert value(transform(json.dumps(body))) is True
    assert value(transform(json.dumps(body).encode())) is True
    assert value(transform(body["items"])) is True
    assert value(transform({"response": body})) is True
