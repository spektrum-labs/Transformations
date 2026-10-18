"""Microsoft Entra ID isMFAConfiguredForSecurityAdmins: the role ids match Microsoft's built-in role template ids.

Conditional Access Administrator is b1be1c3e-b65d-4f19-8427-f6fa0d97feb9 and Privileged Authentication
Administrator is 7be44c8a-adaf-4e2a-84d6-ab2649e08a13 (Microsoft Entra built-in roles reference). Earlier
versions held f28a1f50-... (SharePoint Administrator) and 7698a772-... (Cloud Device Administrator) under those
names, so a policy scoped to SharePoint or Cloud Device admins counted as MFA for security admins, and a policy
scoped to the real roles did not. Synthetic policies only; role ids are Microsoft's public template ids. Each
case runs as plain Python and in the Token-Service sandbox replica.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entrasecadminroleids"

try:
    import RestrictedPython  # noqa: F401
    _spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_sandbox)
    load_code = _sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]
KEY = "isMFAConfiguredForSecurityAdmins"
CA_ADMIN = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
PRIV_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
SHAREPOINT_ADMIN = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
CLOUD_DEVICE_ADMIN = "7698a772-787b-4ac8-901f-60d6b08affd2"


def load(mode):
    path = HERE / "ismfaconfiguredforsecurityadmins.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def body(include_users=None, include_roles=None, exclude_roles=None):
    return {"value": [{"displayName": "MFA for admins", "state": "enabled",
                       "grantControls": {"builtInControls": ["mfa"]},
                       "conditions": {"applications": {"includeApplications": ["All"]},
                                      "users": {"includeUsers": include_users or [],
                                                "includeRoles": include_roles or [],
                                                "excludeRoles": exclude_roles or []}}}]}


GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
PRIV_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"
AUTH_ADMIN = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
SIX = [GLOBAL_ADMIN, SECURITY_ADMIN, CA_ADMIN, PRIV_ROLE_ADMIN, AUTH_ADMIN, PRIV_AUTH_ADMIN]


@pytest.mark.parametrize("mode", MODES)
def test_the_six_real_role_ids_pass(mode):
    out = load(mode)(body(include_roles=SIX))
    assert out["transformedResponse"][KEY] is True
    assert len(out["transformedResponse"]["coveredRoles"]) == 6


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("role,name", [(CA_ADMIN, "Conditional Access Administrator"),
                                       (PRIV_AUTH_ADMIN, "Privileged Authentication Administrator")])
def test_real_role_ids_are_counted_and_one_role_is_not_enough(mode, role, name):
    out = load(mode)(body(include_roles=[role]))
    assert out["transformedResponse"]["coveredRoles"] == [name]
    assert out["transformedResponse"][KEY] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("old", [SHAREPOINT_ADMIN, CLOUD_DEVICE_ADMIN])
def test_old_ids_do_not_stand_in_for_the_real_roles(mode, old):
    roles = [r for r in SIX if r not in (CA_ADMIN, PRIV_AUTH_ADMIN)] + [old]
    out = load(mode)(body(include_roles=roles))
    assert out["transformedResponse"][KEY] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "Conditional Access Administrator" in reason
    assert "Privileged Authentication Administrator" in reason


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("role", [SHAREPOINT_ADMIN, CLOUD_DEVICE_ADMIN])
def test_non_security_roles_do_not_count(mode, role):
    out = load(mode)(body(include_roles=[role]))
    assert out["transformedResponse"][KEY] is False
    assert out["transformedResponse"]["coveredRoles"] == []


@pytest.mark.parametrize("mode", MODES)
def test_all_users_minus_excluded_real_roles_fails(mode):
    out = load(mode)(body(include_users=["All"], exclude_roles=[CA_ADMIN, PRIV_AUTH_ADMIN]))
    assert out["transformedResponse"][KEY] is False
    covered = out["transformedResponse"]["coveredRoles"]
    assert "Conditional Access Administrator" not in covered
    assert "Privileged Authentication Administrator" not in covered
    assert len(covered) == 4


@pytest.mark.parametrize("mode", MODES)
def test_excluding_old_ids_no_longer_drops_security_roles(mode):
    out = load(mode)(body(include_users=["All"], exclude_roles=[SHAREPOINT_ADMIN, CLOUD_DEVICE_ADMIN]))
    assert len(out["transformedResponse"]["coveredRoles"]) == 6
    assert out["transformedResponse"][KEY] is True
