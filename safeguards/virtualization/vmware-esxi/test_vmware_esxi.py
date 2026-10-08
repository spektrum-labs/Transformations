"""Unit tests for the standalone ESXi administrator transform.

Fixtures are synthetic: made-up host names (example.test) and principals, shaped like the "spektrum.esxi.v1" snapshot
the Spektrum Connector pushes.
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


def perm(name, role_id="-1", domain="", kind="USER", obj_type="Folder", propagating=True, admin=None):
    role = {"id": role_id, "name": None}
    if admin is not None:
        role["adminCapable"] = admin
    return {"principal": {"type": kind, "name": name, "domain": domain}, "role": role,
            "object": {"type": obj_type, "id": "ha-folder-root"}, "propagating": propagating}


def host(*permissions, name="esx01.example.test", lockdown="normal", complete=True, roles=None):
    return {"hostName": name, "version": "8.0.3", "managedByVcenter": False, "lockdownMode": lockdown,
            "permissionsComplete": complete, "permissions": list(permissions), "roles": roles or [],
            "localAccounts": [{"name": "root", "hasShell": True}]}


def snap(*hosts, complete=True, directory=None):
    return {"schema": "spektrum.esxi.v1", "hostsComplete": complete, "hosts": list(hosts), "directory": directory or {}}


def test_true_when_all_admins_are_dedicated_on_every_host():
    body = snap(host(perm("root"), perm("adm-alice")), host(perm("root"), perm("bob-adm"), name="esx02.example.test"))
    r = transform(body)
    assert value(r) is True
    assert r["transformedResponse"]["hostsJudged"] == 2 and r["transformedResponse"]["hostsFailed"] == 0
    assert any("root holds Administrator" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_root_only_with_lockdown_disabled_is_a_shared_root_login_fail():
    r = transform(snap(host(perm("root"), lockdown="disabled")))
    assert value(r) is False
    assert "shared root login" in r["additionalInfo"]["evaluation"]["failReasons"][0]
    assert r["transformedResponse"]["hostsFailed"] == 1


@pytest.mark.parametrize("mode", ["normal", "strict", "unknown"])
def test_root_only_with_lockdown_is_not_a_fail_but_has_nothing_to_judge(mode):
    r = transform(snap(host(perm("root"), lockdown=mode)))
    assert value(r) is None


def test_system_accounts_are_not_judged():
    r = transform(snap(host(perm("root"), perm("dcui"), perm("adm-alice"))))
    assert value(r) is True


def test_broad_group_fails_and_one_failing_host_makes_the_verdict_false():
    r = transform(snap(host(perm("adm-alice")), host(perm("Domain Users", kind="GROUP"), name="esx02.example.test")))
    assert value(r) is False
    assert "esx02.example.test" in r["additionalInfo"]["evaluation"]["failReasons"][0]
    assert r["transformedResponse"]["hostsFailed"] == 1


def test_mailbox_directory_record_fails_even_with_a_convention_name():
    body = snap(host(perm("adm-erin", domain="example.test")),
                directory={"adm-erin@example.test": {"found": True, "enabled": True, "hasMailbox": True}})
    assert value(transform(body)) is False


def test_directory_record_without_mailbox_is_dedicated_evidence():
    body = snap(host(perm("dave", domain="example.test")),
                directory={"dave@example.test": {"found": True, "enabled": True, "hasMailbox": False}})
    assert value(transform(body)) is True


def test_group_is_never_dedicated_by_name_and_typeless_principal_is_not_a_user():
    assert value(transform(snap(host(perm("vc-admin", kind="GROUP"))))) is None
    assert value(transform(snap(host(perm("vc-admin", kind=""))))) is None


@pytest.mark.parametrize("name", ["maria.da.silva", "a.smith", "jadministrator", "dave"])
def test_personal_names_are_not_dedicated_evidence(name):
    assert value(transform(snap(host(perm(name))))) is None


def test_non_admin_roles_and_leaf_objects_are_ignored():
    body = snap(host(perm("root"), perm("adm-alice"), perm("gina", role_id="-2"),
                     perm("zed", obj_type="VirtualMachine", propagating=False)))
    assert value(transform(body)) is True


def test_custom_role_flagged_admin_capable_counts_and_unresolved_custom_role_is_not_evaluated():
    flagged = snap(host(perm("adm-alice"), perm("Domain Users", role_id="1001", kind="GROUP", admin=True)))
    assert value(transform(flagged)) is False
    unresolved = snap(host(perm("adm-alice"), perm("gina", role_id="1001")))
    assert value(transform(unresolved)) is None
    assert value(transform(snap(host(perm("adm-alice"), perm("gina", role_id="1001", admin=False))))) is True


def test_incomplete_reads_are_not_evaluated_but_a_measured_fail_wins():
    assert value(transform(snap(host(perm("adm-alice")), complete=False))) is None
    assert value(transform(snap(host(perm("adm-alice"), complete=False)))) is None
    body = snap(host(perm("Domain Users", kind="GROUP")), complete=False)
    assert value(transform(body)) is False


def test_no_hosts_or_no_admin_assignment_is_not_evaluated():
    assert value(transform(snap())) is None
    assert value(transform(snap(host(perm("gina", role_id="-2"))))) is None


@pytest.mark.parametrize("body", [{}, None, "{}", "", [], {"hello": "world"}, {"error": {"statusCode": 401}},
                                  {"statusCode": 403, "error": "Forbidden"}, {"hosts": "x"}])
def test_never_answers_from_no_evidence(body):
    r = transform(body)
    assert value(r) is None
    assert r["additionalInfo"]["dataCollection"]["status"] == "error"


def test_accepts_json_string_bytes_and_wrapper():
    body = snap(host(perm("adm-alice")))
    assert value(transform(json.dumps(body))) is True
    assert value(transform(json.dumps(body).encode())) is True
    assert value(transform({"response": body})) is True
