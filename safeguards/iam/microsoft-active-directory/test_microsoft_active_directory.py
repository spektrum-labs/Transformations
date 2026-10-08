"""Unit tests for the Active Directory transforms (Domain Admins separation, workstation logon denial).

Fixtures are synthetic: made-up account names, example.test DNs and a made-up domain SID. They have the shape of the
"spektrum.ad.v1" snapshot the Spektrum Connector pushes.
"""
import copy
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


SEPARATE = "areDomainAdminAccountsSeparate"
DENIED = "isDomainAdminWorkstationLogonDenied"
separate = load("aredomainadminaccountsseparate")
denied = load("isdomainadminworkstationlogondenied")

SID = "S-1-5-21-1111111111-2222222222-3333333333"
DOMAIN_DN = "DC=example,DC=test"


def value(result, key):
    return result["transformedResponse"][key]


def member(sam, **overrides):
    record = {"sam": sam, "sid": SID + "-1100", "type": "user", "enabled": True, "hasMailbox": False,
              "exchangeAttributesReadable": True, "mailAttribute": None, "isBuiltInAdministrator": False}
    record.update(overrides)
    return record


def admins(*members, complete=True):
    return {"schema": "spektrum.ad.v1", "domainAdmins": {"membersComplete": complete, "members": list(members)}}


# --- areDomainAdminAccountsSeparate -------------------------------------------------------------------------

def test_separate_true_when_no_member_has_a_mailbox():
    r = separate(admins(member("adm-alice"), member("adm-bob")))
    assert value(r, SEPARATE) is True
    assert r["transformedResponse"]["judgedMembers"] == 2
    assert r["additionalInfo"]["dataCollection"]["status"] == "success"


def test_separate_false_names_the_mailbox_accounts_and_the_count():
    r = separate(admins(member("adm-alice"), member("carol", hasMailbox=True), member("dave", hasMailbox=True)))
    assert value(r, SEPARATE) is False
    assert r["transformedResponse"]["membersWithMailbox"] == 2
    reason = r["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "carol" in reason and "dave" in reason and "2 of 3" in reason


def test_mail_attribute_alone_is_a_finding_not_a_fail():
    r = separate(admins(member("adm-alice", mailAttribute="alice@example.test")))
    assert value(r, SEPARATE) is True
    assert r["transformedResponse"]["membersWithMailOnly"] == 1
    assert any("finding, not a fail" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_disabled_members_and_computers_are_not_judged():
    r = separate(admins(member("adm-alice"), member("old", enabled=False, hasMailbox=True),
                        member("SRV01$", type="computer")))
    assert value(r, SEPARATE) is True
    assert r["transformedResponse"]["judgedMembers"] == 1
    assert any("Computer account" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_unreadable_mailbox_state_is_not_evaluated():
    r = separate(admins(member("adm-alice"), member("adm-bob", exchangeAttributesReadable=False)))
    assert value(r, SEPARATE) is None
    assert r["additionalInfo"]["dataCollection"]["status"] == "error"


def test_measured_fail_wins_over_unreadable_member():
    r = separate(admins(member("carol", hasMailbox=True), member("adm-bob", exchangeAttributesReadable=False)))
    assert value(r, SEPARATE) is False


def test_incomplete_or_empty_member_list_is_not_evaluated():
    assert value(separate(admins(member("adm-alice"), complete=False)), SEPARATE) is None
    assert value(separate(admins()), SEPARATE) is None
    assert value(separate(admins(member("old", enabled=False))), SEPARATE) is None


def test_unexpanded_group_member_is_not_judged_so_no_true():
    r = separate(admins(member("adm-x"), {"sam": "Ops Admins", "type": "group", "enabled": True}))
    assert value(r, SEPARATE) is None
    assert value(separate(admins(member("carol", hasMailbox=True), {"sam": "Ops Admins", "type": "group"})), SEPARATE) is False


def test_members_with_missing_type_or_enabled_are_never_dropped_into_a_true():
    no_type = {"sam": "jdoe", "enabled": True, "hasMailbox": True, "exchangeAttributesReadable": True}
    no_enabled = {"sam": "jdoe2", "type": "user", "hasMailbox": True, "exchangeAttributesReadable": True}
    assert value(separate(admins(member("adm-x"), no_type, no_enabled)), SEPARATE) is False
    quiet = {"sam": "mystery", "enabled": True, "hasMailbox": False, "exchangeAttributesReadable": True}
    assert value(separate(admins(member("adm-x"), quiet)), SEPARATE) is None
    assert value(separate(admins(quiet)), SEPARATE) is None


@pytest.mark.parametrize("body", [{}, None, "{}", "", [], {"hello": "world"},
                                  {"error": {"statusCode": 401}}, {"statusCode": 403, "error": "Forbidden"}])
def test_separate_never_answers_from_no_evidence(body):
    assert value(separate(body), SEPARATE) is None


def test_separate_accepts_json_string_bytes_and_wrapper():
    body = admins(member("adm-alice"))
    assert value(separate(json.dumps(body)), SEPARATE) is True
    assert value(separate(json.dumps(body).encode()), SEPARATE) is True
    assert value(separate({"data": body}), SEPARATE) is True


# --- isDomainAdminWorkstationLogonDenied --------------------------------------------------------------------

def gpo(name="Workstation tier-0 deny", local=True, remote=True, links=None, **overrides):
    record = {"displayName": name, "enabled": True, "appliesTo": "authenticated", "wmiFiltered": False,
              "denyInteractive": [SID + "-512"] if local else [],
              "denyRemoteInteractive": [SID + "-512"] if remote else [],
              "links": links if links is not None else [{"scopeDn": "OU=Workstations," + DOMAIN_DN, "enabled": True, "enforced": False}]}
    record.update(overrides)
    return record


def ou(dn, count, blocked=None):
    return {"dn": dn, "enabledWorkstations": count, "inheritanceBlockedAt": blocked or []}


def rights(gpos, ous, readable=True, complete=True):
    return {"schema": "spektrum.ad.v1", "domainSid": SID,
            "logonRights": {"gposComplete": complete, "allDefiningGposIncluded": True, "ouInheritanceReadable": readable, "gpos": gpos, "workstationOus": ous}}


WS = "OU=Workstations," + DOMAIN_DN
LAPTOPS = "OU=Laptops," + WS


def test_denied_true_when_every_workstation_is_covered_by_inheritance():
    r = denied(rights([gpo()], [ou(WS, 10), ou(LAPTOPS, 5)]))
    assert value(r, DENIED) is True
    assert r["transformedResponse"]["coveragePercentage"] == 100
    assert r["transformedResponse"]["workstationsCovered"] == 15


def test_denied_false_with_denominator_when_an_ou_is_uncovered():
    r = denied(rights([gpo()], [ou(WS, 10), ou("OU=Kiosks," + DOMAIN_DN, 5)]))
    assert value(r, DENIED) is False
    assert r["transformedResponse"]["workstationsTotal"] == 15
    assert r["transformedResponse"]["workstationsCovered"] == 10
    assert "Kiosks" in r["additionalInfo"]["evaluation"]["failReasons"][0]


def test_blocked_inheritance_uncovers_unless_the_link_is_enforced():
    blocked = ou(LAPTOPS, 5, blocked=[LAPTOPS])
    assert value(denied(rights([gpo()], [ou(WS, 10), blocked])), DENIED) is False
    enforced = gpo(links=[{"scopeDn": WS, "enabled": True, "enforced": True}])
    assert value(denied(rights([enforced], [ou(WS, 10), blocked])), DENIED) is True


def test_a_block_on_the_linked_ou_itself_does_not_remove_its_own_link():
    r = denied(rights([gpo()], [ou(WS, 10, blocked=[WS])]))
    assert value(r, DENIED) is True


def test_gpo_denying_only_one_right_is_a_measured_gap():
    r = denied(rights([gpo(remote=False)], [ou(WS, 10)]))
    assert value(r, DENIED) is False
    assert any("not both" in f for f in r["additionalInfo"]["evaluation"]["additionalFindings"])


def test_no_denying_gpo_at_all_is_false():
    assert value(denied(rights([], [ou(WS, 10)])), DENIED) is False


def test_disabled_gpo_and_disabled_link_do_not_cover():
    assert value(denied(rights([gpo(enabled=False)], [ou(WS, 10)])), DENIED) is False
    off = gpo(links=[{"scopeDn": WS, "enabled": False, "enforced": False}])
    assert value(denied(rights([off], [ou(WS, 10)])), DENIED) is False


def test_domain_controllers_ou_link_does_not_cover_workstations():
    dc = gpo(links=[{"scopeDn": "OU=Domain Controllers," + DOMAIN_DN, "enabled": True, "enforced": False}])
    assert value(denied(rights([dc], [ou(WS, 10)])), DENIED) is False


def test_filtered_gpo_cannot_be_resolved_so_not_evaluated():
    f = gpo(appliesTo="filtered")
    r = denied(rights([f], [ou(WS, 10)]))
    assert value(r, DENIED) is None
    assert r["additionalInfo"]["dataCollection"]["status"] == "error"


def test_filtered_gpo_linked_where_the_clean_gpo_is_not_is_not_evaluated():
    kiosks = "OU=Kiosks," + DOMAIN_DN
    clean = gpo()
    f = gpo(name="Filtered", appliesTo="filtered", links=[{"scopeDn": kiosks, "enabled": True, "enforced": False}])
    r = denied(rights([clean, f], [ou(WS, 10), ou(kiosks, 5)]))
    assert value(r, DENIED) is None


def baseline(name="Workstation baseline", links=None, order=1):
    # Defines both deny rights WITHOUT Domain Admins (e.g. "Deny log on locally: Guests").
    return {"displayName": name, "enabled": True, "appliesTo": "authenticated", "wmiFiltered": False,
            "denyInteractive": [SID + "-501"], "denyRemoteInteractive": [SID + "-501"],
            "links": links if links is not None else [{"scopeDn": WS, "enabled": True, "enforced": False, "linkOrder": order}]}


def test_a_right_defined_with_an_empty_list_still_wins_and_clears_the_deny():
    root = gpo(links=[{"scopeDn": DOMAIN_DN, "enabled": True, "enforced": False, "linkOrder": 1}])
    empty = baseline()
    empty["denyInteractive"] = []
    empty["denyRemoteInteractive"] = []
    empty["definesDenyInteractive"] = True
    empty["definesDenyRemoteInteractive"] = True
    assert value(denied(rights([root, empty], [ou(WS, 10)])), DENIED) is False


def test_snapshot_without_the_all_defining_gpos_marker_is_not_evaluated():
    body = rights([gpo()], [ou(WS, 10)])
    del body["logonRights"]["allDefiningGposIncluded"]
    assert value(denied(body), DENIED) is None


def test_baseline_gpo_nearer_the_ou_overrides_a_deny_linked_at_the_domain_root():
    root = gpo(links=[{"scopeDn": DOMAIN_DN, "enabled": True, "enforced": False, "linkOrder": 1}])
    r = denied(rights([root, baseline()], [ou(WS, 10)]))
    assert value(r, DENIED) is False
    assert r["transformedResponse"]["workstationsCovered"] == 0


def test_enforced_root_deny_beats_a_nearer_baseline():
    root = gpo(links=[{"scopeDn": DOMAIN_DN, "enabled": True, "enforced": True, "linkOrder": 1}])
    assert value(denied(rights([root, baseline()], [ou(WS, 10)])), DENIED) is True


def test_tied_links_use_link_order_and_missing_order_is_not_evaluated():
    tier0 = gpo(links=[{"scopeDn": WS, "enabled": True, "enforced": False, "linkOrder": 1}])
    assert value(denied(rights([tier0, baseline(order=2)], [ou(WS, 10)])), DENIED) is True
    assert value(denied(rights([tier0, baseline(order=0)], [ou(WS, 10)])), DENIED) is False
    no_order = baseline(links=[{"scopeDn": WS, "enabled": True, "enforced": False}])
    assert value(denied(rights([gpo(), no_order], [ou(WS, 10)])), DENIED) is None


def test_group_flagged_as_containing_domain_admins_counts():
    g = gpo()
    g["denyInteractive"] = [{"sid": SID + "-9999", "containsDomainAdmins": True}]
    g["denyRemoteInteractive"] = [{"sid": SID + "-9999", "containsDomainAdmins": True}]
    assert value(denied(rights([g], [ou(WS, 10)])), DENIED) is True


def test_other_domains_domain_admins_sid_does_not_count():
    g = gpo()
    g["denyInteractive"] = ["S-1-5-21-9-9-9-512"]
    g["denyRemoteInteractive"] = ["S-1-5-21-9-9-9-512"]
    assert value(denied(rights([g], [ou(WS, 10)])), DENIED) is False


def test_unreadable_picture_or_incomplete_gpos_not_evaluated():
    assert value(denied(rights([gpo()], [ou(WS, 10)], readable=False)), DENIED) is None
    assert value(denied(rights([gpo()], [])), DENIED) is None
    assert value(denied(rights([gpo()], [ou(WS, 0)])), DENIED) is None
    assert value(denied(rights([gpo()], [ou(WS, 10)], complete=False)), DENIED) is None
    body = rights([gpo()], [ou(WS, 10)])
    del body["domainSid"]
    assert value(denied(body), DENIED) is None


@pytest.mark.parametrize("body", [{}, None, "{}", "", [], {"hello": "world"},
                                  {"error": {"statusCode": 401}}, {"statusCode": 403, "error": "Forbidden"}])
def test_denied_never_answers_from_no_evidence(body):
    assert value(denied(body), DENIED) is None


def test_denied_accepts_json_string_and_wrapper():
    body = rights([gpo()], [ou(WS, 10)])
    assert value(denied(json.dumps(body)), DENIED) is True
    assert value(denied({"response": copy.deepcopy(body)}), DENIED) is True
