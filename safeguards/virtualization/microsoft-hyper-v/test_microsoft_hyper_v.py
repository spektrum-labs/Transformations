"""Unit tests for the Hyper-V administrator transform.

Fixtures are synthetic: made-up hosts, accounts in example.test, shaped like the "spektrum.hyperv.v1" snapshot the
Spektrum Connector pushes.
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


def value(r):
    return r["transformedResponse"][KEY]


def member(name, domain="EXAMPLE", kind="user", source="hyperv-administrators", **kw):
    m = {"name": name, "domain": domain, "type": kind, "source": source, "enabled": True, "isBuiltInAdministrator": False}
    m.update(kw)
    return m


def host(*members, name="HV01", complete=True, role=True, scvmm=None):
    return {"hostName": name, "osVersion": "10.0.20348", "hyperVRoleInstalled": role,
            "administrators": {"complete": complete, "members": list(members)},
            "scvmm": scvmm or {"present": False, "complete": True, "roles": []}}


def snap(*hosts, complete=True, directory=None):
    return {"schema": "spektrum.hyperv.v1", "collectedAt": "2026-10-08T12:00:00Z", "hostsComplete": complete,
            "hosts": list(hosts), "directory": directory or {}}


def test_true_when_every_admin_is_dedicated_by_affix_or_directory():
    d = {"dave@EXAMPLE": {"found": True, "enabled": True, "hasMailbox": False}}
    r = transform(snap(host(member("adm-alice"), member("dave"), member("Administrator", domain="HV01", isBuiltInAdministrator=True)),
                       directory=d))
    assert value(r) is True
    assert r["transformedResponse"]["hostsJudged"] == 1
    assert any("break-glass" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_broad_group_fails_and_names_the_host():
    r = transform(snap(host(member("adm-alice"), member("Domain Users", kind="group"))))
    assert value(r) is False
    assert "HV01" in r["additionalInfo"]["evaluation"]["failReasons"][0]
    assert r["transformedResponse"]["hostsFailed"] == 1


def test_mailbox_account_fails_even_with_admin_affix():
    d = {"adm-erin@EXAMPLE": {"found": True, "enabled": True, "hasMailbox": True}}
    assert value(transform(snap(host(member("adm-erin")), directory=d))) is False


def test_group_never_dedicated_by_name():
    r = transform(snap(host(member("adm-alice"), member("HV-Admins", kind="group"))))
    assert value(r) is None
    assert "HV-Admins" in r["additionalInfo"]["evaluation"]["failReasons"][0]


def test_domain_admins_group_is_a_finding_judged_by_the_ad_check():
    r = transform(snap(host(member("adm-alice"), member("Domain Admins", kind="group", source="local-administrators"))))
    assert value(r) is True
    assert any("Active Directory check" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_system_service_and_disabled_principals_are_not_judged():
    r = transform(snap(host(member("adm-alice"), member("SYSTEM", domain="NT AUTHORITY"),
                            member("SpektrumConnector", domain="NT SERVICE"), member("old", enabled=False))))
    assert value(r) is True


def test_personal_names_are_not_dedicated_evidence():
    for name in ["maria.da.silva", "a.smith", "jadministrator", "da-silva", "a-lee", "jose-a", "maria_a"]:
        assert value(transform(snap(host(member(name))))) is None


def test_authenticated_users_in_nt_authority_is_a_broad_group_not_a_system_identity():
    for name in ["Authenticated Users", "INTERACTIVE", "NETWORK", "Everyone"]:
        r = transform(snap(host(member("adm-alice"), member(name, domain="NT AUTHORITY", kind="group"))))
        assert value(r) is False, name


def test_scvmm_profiles_match_case_insensitively_both_spellings_and_unknown_is_not_evaluated():
    def with_profile(profile, who="Everyone"):
        roles = [{"name": "R", "profile": profile, "members": [{"name": who, "domain": "", "type": "group"}]}]
        return transform(snap(host(member("adm-alice"), scvmm={"present": True, "complete": True, "roles": roles})))
    for p in ["administrator", "DelegatedAdmin", "DelegatedAdministrator", "FabricAdministrator"]:
        assert value(with_profile(p)) is False, p
    for p in ["ReadOnlyAdmin", "TenantAdmin", "SelfServiceUser"]:
        assert value(with_profile(p)) is True, p
    assert value(with_profile("Mystery")) is None
    assert value(with_profile("Unknown")) is None


def test_malformed_host_entry_is_not_evaluated():
    body = snap(host(member("adm-alice")))
    body["hosts"].append("garbage")
    assert value(transform(body)) is None


def test_scvmm_admin_roles_count_and_read_only_roles_do_not():
    roles = [{"name": "Fabric admins", "profile": "Administrator", "members": [{"name": "Everyone", "domain": "", "type": "group"}]},
             {"name": "Viewers", "profile": "ReadOnlyAdministrator", "members": [{"name": "bob", "domain": "EXAMPLE", "type": "user"}]}]
    r = transform(snap(host(member("adm-alice"), scvmm={"present": True, "complete": True, "roles": roles})))
    assert value(r) is False
    ro = [roles[1]]
    assert value(transform(snap(host(member("adm-alice"), scvmm={"present": True, "complete": True, "roles": ro})))) is True
    assert value(transform(snap(host(member("adm-alice"), scvmm={"present": True, "complete": False, "roles": ro})))) is None


def test_any_host_failing_fails_and_any_unreadable_host_blocks_a_true():
    good = host(member("adm-alice"), name="HV01")
    bad = host(member("Everyone", kind="group"), name="HV02")
    assert value(transform(snap(good, bad))) is False
    assert value(transform(snap(good, host(member("adm-bob"), name="HV03", complete=False)))) is None
    assert value(transform(snap(good, host(member("adm-bob"), name="HV03", role=False)))) is None
    assert value(transform(snap(bad, host(member("x"), name="HV03", complete=False)))) is False


def test_incomplete_or_empty_host_list_is_not_evaluated():
    assert value(transform(snap(host(member("adm-alice")), complete=False))) is None
    assert value(transform(snap())) is None
    assert value(transform(snap(host(member("SYSTEM", domain="NT AUTHORITY"))))) is None


def test_unrecognised_types_and_computer_accounts_are_not_judged_as_dedicated():
    assert value(transform(snap(host(member("adm-alice"), member("weird", kind="alien"))))) is None
    assert value(transform(snap(host(member("adm-alice"), member("SRV9$", kind="computer"))))) is None


@pytest.mark.parametrize("body", [{}, None, "{}", "", [], {"hello": "world"}, {"error_type": "UNAUTHENTICATED"},
                                  {"error": {"statusCode": 401}}, {"statusCode": 403, "error": "Forbidden"}])
def test_never_answers_from_no_evidence(body):
    r = transform(body)
    assert value(r) is None
    assert r["additionalInfo"]["dataCollection"]["status"] == "error"


def test_accepts_json_string_bytes_and_wrapper():
    body = snap(host(member("adm-alice")))
    assert value(transform(json.dumps(body))) is True
    assert value(transform(json.dumps(body).encode())) is True
    assert value(transform({"response": body})) is True


def test_entries_that_are_not_member_records_are_never_silently_dropped():
    body = snap(host("EX\\Domain Users", member("adm-alice")))
    assert value(transform(body)) is None
    roles = [{"name": "R", "profile": "Administrator", "members": ["Everyone"]}]
    body = snap(host(member("adm-alice"), scvmm={"present": True, "complete": True, "roles": roles}))
    assert value(transform(body)) is None


def test_a_local_account_does_not_inherit_a_domain_users_directory_record():
    d = {"alice@corp": {"found": True, "enabled": True, "hasMailbox": False}}
    assert value(transform(snap(host(member("alice", domain="HV01")), directory=d))) is None
    assert value(transform(snap(host(member("alice", domain="corp")), directory=d))) is True


def test_malformed_scvmm_containers_are_not_read_as_no_admins():
    for sc in [{"present": True, "complete": True, "roles": None},
               {"present": True, "complete": True, "roles": [{"name": "R", "profile": "Administrator", "members": None}]}]:
        assert value(transform(snap(host(member("adm-alice"), scvmm=sc)))) is None


def test_a_host_listing_no_administrators_at_all_is_not_credible():
    assert value(transform(snap(host()))) is None


def test_malformed_scvmm_value_is_not_read_as_no_scvmm():
    for sc in ["error", ["x"], {"present": "true", "complete": True, "roles": []}, {"present": 1, "complete": True, "roles": []}, None]:
        h = host(member("adm-alice"))
        h["scvmm"] = sc
        assert value(transform(snap(h))) is None, sc
