"""Veeam Backup & Replication areBackupConsoleAdminsDedicated: fixtures from the VBR 13 REST API 1.3
"Get All Users and Groups" model (type, roles, isServiceAccount, pagination). Names are synthetic."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "veeam_vbr_arebackupconsoleadminsdedicated"


def load_plain():
    spec = importlib.util.spec_from_file_location(MODULE_NAME, FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    """The same file through the Token-Service RestrictedPython namespace (tools/restricted_sandbox.py)."""
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]



def run(payload, loader=load_plain):
    return loader()(payload)


def value(payload, loader=load_plain):
    return run(payload, loader)["transformedResponse"][KEY]


def ts_wrap(body):
    """How Token-Service hands an Integration-Service response to a transform."""
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"data": []},
]


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated_when_wrapped(body):
    assert value(ts_wrap(body)) is None

BACKUP_ADMIN = {"id": "r1", "name": "Veeam Backup Administrator", "description": "Built-in role with full privileges"}
SECURITY_ADMIN = {"id": "r2", "name": "Veeam Security Administrator", "description": "Built-in role"}
RESTORE_OP = {"id": "r3", "name": "Veeam Restore Operator", "description": "Built-in role"}


def entry(name, etype="InternalUser", roles=None, service=False):
    return {"id": name, "name": name, "type": etype, "roles": [BACKUP_ADMIN] if roles is None else roles,
            "isServiceAccount": service}


def coll(items, total=None):
    n = len(items) if total is None else total
    return {"data": items, "pagination": {"total": n, "count": len(items), "skip": 0, "limit": 1000}}


PASSING = coll([
    entry("BUILTIN\\Administrators", "InternalGroup"),
    entry("VBR01\\veeamadmin"),
    entry("CORP\\adm-jdoe", roles=[SECURITY_ADMIN]),
    entry("CORP\\svc-automation", service=True),
    entry("a-jroe@example.com", "ExternalUser"),
    entry("CORP\\jdoe", roles=[RESTORE_OP]),
])

FAILING = coll([
    entry("BUILTIN\\Administrators", "InternalGroup"),
    entry("CORP\\jdoe"),
])

FAILING_GROUP = coll([entry("CORP\\Domain Users", "InternalGroup")])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 5


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_unmarked_domain_admin_not_evaluated(loader):
    assert run(FAILING, loader)["transformedResponse"][KEY] is None


def test_general_group_fails():
    assert value(FAILING_GROUP) is False


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is None


def test_partial_page_not_evaluated():
    assert value(coll([entry("VBR01\\veeamadmin")], total=3)) is None


def test_missing_total_not_evaluated():
    assert value({"data": [entry("VBR01\\veeamadmin")], "pagination": {}}) is None


def test_vbr_error_envelope_not_evaluated():
    out = run({"errorCode": "AccessDenied", "message": "Access is denied", "resourceId": None})
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_no_admin_not_evaluated():
    assert value(coll([entry("CORP\\jdoe", roles=[RESTORE_OP])])) is None


def test_missing_roles_not_evaluated():
    item = entry("CORP\\adm-jdoe")
    del item["roles"]
    assert value(coll([item])) is None


def test_unknown_type_unmarked_not_evaluated():
    assert value(coll([entry("jdoe", "NewType")])) is None


def test_unmarked_identity_reads_not_evaluated():
    out = run(FAILING)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "no admin marker" in out["additionalInfo"]["evaluation"]["failReasons"][0]


# The naming rule is the same block in all five IAM-004 transforms; these rows are the same in every test file.

def load_module():
    spec = importlib.util.spec_from_file_location(MODULE_NAME + "_rule", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MARKER_ROWS = [
    ("adm-jdoe@example.com", True), ("jdoe-adm@example.com", True), ("a-jdoe@example.com", True),
    ("jdoe_a@example.com", True), ("adminjdoe@example.com", True), ("admin01@example.com", True),
    ("t0.jdoe@example.com", True), ("pam-jdoe@example.com", True), ("root_backup@example.com", True),
    ("veeamadmin@example.com", True), ("jdoe@admin.example.com", True), ("jdoe@t0.corp.example", True),
    ("ADM\\jdoe", True), ("CORP-ADM\\jdoe", True),
    # personal names, not markers
    ("pam.smith@example.com", False), ("pam@example.com", False), ("joe.root@example.com", False),
    ("administration@example.com", False), ("badmin@example.com", False), ("padmin@example.com", False),
    ("jdoeadmin@example.com", False), ("doe.a@example.com", False), ("admiral.jones@example.com", False),
    # the organisation's own domain is never a marker; a domain label matches only as a whole word
    ("jdoe@privatebank.com", False), ("jdoe@adminsoft.com", False), ("jdoe@cityadm.gov", False),
    ("jdoe@admin.ch", False), ("jdoe@admin.co.uk", False), ("jdoe@admin.gv.at", False), ("PRIVATECO\\jdoe", False), ("CORPADM\\jdoe", False),
]


@pytest.mark.parametrize("name,marked", MARKER_ROWS)
def test_shared_admin_marker(name, marked):
    assert load_module().has_admin_marker(name, False) is marked


@pytest.mark.parametrize("group,cls", [
    ("PRIVATECO\\Domain Users", "everyday-group"), ("CITYADM\\Staff", "everyday-group"),
    ("CORP\\Backup-Admins", "group"), ("BUILTIN\\Administrators", "group"), ("ADM\\Backup Operators", "group"),
])
def test_shared_group_marker(group, cls):
    assert load_module().classify([group], "group", "directory") == cls


#: Everyday addresses that the earlier rule read as admin accounts. Each, holding admin, reads Not evaluated.
UNMARKED_NAMES = ["pam.smith@example.com", "pam@example.com", "joe.root@example.com", "jdoe@privatebank.com",
                  "jdoe@adminsoft.com", "jdoe@cityadm.gov", "jdoe@admin.ch"]


@pytest.mark.parametrize("name", UNMARKED_NAMES)
def test_everyday_names_read_not_evaluated(name):
    assert value(coll([entry("CORP\\adm-jdoe"), entry(name, "ExternalUser")])) is None


def test_privateco_domain_users_group_fails():
    assert value(coll([entry("CORP\\adm-jdoe"), entry("PRIVATECO\\Domain Users", "InternalGroup")])) is False


def test_dot_local_windows_account_is_local():
    assert value(coll([entry(".\\backupuser")])) is True


def test_host_local_account_is_judged_by_name():
    """The response carries no host name, so VBR01\\veeamop cannot be told from a domain account (Limits)."""
    assert value(coll([entry("VBR01\\veeamop")])) is None
    assert value(coll([entry("VBR01\\veeamadmin")])) is True
