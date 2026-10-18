"""Vanta security tests as proof (level 3): twelve test-mapped checks and two vulnerability counts.

Vanta is a proof source, not a safeguard tool. These files read what Vanta reports and never fetch. The contract
these tests pin:

Twelve test-mapped checks (one criterion each, mapped by Vanta's stable test ids):
- True only when at least one mapped test counts and every mapped test that counts is OK;
- False when any mapped test is NEEDS_ATTENTION, even when the read was cut short;
- None (Not evaluated, dataCollection.status "error") when every mapped test is absent, any is DEACTIVATED, all are
  NOT_APPLICABLE, one is IN_PROGRESS, INVALID or unknown, an entry is unreadable, the read is not proven complete,
  or the body is an error, empty or unrecognised;
- NOT_APPLICABLE tests are left out of the answer; a DEACTIVATED mapped test makes the check None (named in the
  reason), unless another mapped test needs attention, which is still False (a failure already seen settles it).

Two vulnerability counts (openCriticalVulnerabilitiesCount, overdueVulnerabilityRemediationCount):
- a count of 0 is reported only when the vulnerability read succeeded, was not truncated, and the Vanta test
  vulnerability-scanner-linked-to-vanta has status exactly OK in the tests read that rides with it;
- scanner test missing, or NEEDS_ATTENTION (or any other status): None, never 0;
- any entry with a null severity: open critical is None;
- every remediate-by date null: overdue is None;
- a read that was cut short, errored or is missing: None, never a count;
- a non-zero count is a real finding and is reported (unless the read was cut short or an entry is unreadable).

Every payload is synthetic.
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent

SENTINEL = "planted-vendor-text-9c21"

#: file -> (criterion key, one mapped id, one id with a mapped prefix or None)
TEST_CHECKS = {
    "isstrongauthrequired": ("isStrongAuthRequired", "mfa-on-accounts-okta", "mfa-on-accounts-newprovider"),
    "confirmpasswordpolicyenforced": ("confirmPasswordPolicyEnforced", "password-policy-config-okta",
                                      "password-policy-config-newprovider"),
    "isdataatrestencrypted": ("isDataAtRestEncrypted", "customer-data-encrypted-at-rest-config", None),
    "isbackupencrypted": ("isBackupEncrypted", "aws-ebs-snapshot-encryption", None),
    "isbackupenabled": ("isBackupEnabled", "daily-database-backups-config", None),
    "isdataintransitencrypted": ("isDataInTransitEncrypted", "ssl-good-ciphers", None),
    "isauditloggingenabled": ("isAuditLoggingEnabled", "infra-activity-tracked-config", None),
    "isnetworksecurityloggingenabled": ("isNetworkSecurityLoggingEnabled", "flow-logs-on-config", None),
    "islogretentionconfigured": ("isLogRetentionConfigured", "logs-retained-for-twelve-months-config", None),
    "isalertingconfigured": ("isAlertingConfigured", "aws-guardduty-enabled", None),
    "isnetworkaccessrestricted": ("isNetworkAccessRestricted", "aws-ec2instances-ports-restricted", None),
    "ispublicnetworkaccessdisabled": ("isPublicNetworkAccessDisabled", "aws-s3-public-access-blocked", None),
}
UNRELATED_ID = "some-unrelated-vanta-test"
SCANNER = "vulnerability-scanner-linked-to-vanta"


def load(name):
    spec = importlib.util.spec_from_file_location("vanta_test_check_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_entry(test_id, status="OK"):
    return {"id": test_id, "name": "synthetic " + test_id, "status": status}


def make_tests_body(entries, truncated=False):
    return {"vantaTests": {"tests": entries},
            "paginationStats": {"vantaTests": {"paginationTruncated": truncated}}}


def run(name, data):
    out = load(name).transform(data)
    value = list(out["transformedResponse"].values())[0]
    return value, out


def not_evaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_one_file_per_criterion_and_the_key_matches():
    for name, (key, _, _) in TEST_CHECKS.items():
        out = load(name).transform(make_tests_body([make_entry(UNRELATED_ID)]))
        assert key in out["transformedResponse"]
        assert out["additionalInfo"]["metadata"]["proofLevel"] == 3
        assert out["additionalInfo"]["metadata"]["proofSource"] == "third_party_claim"


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_mapped_test_ok_is_true(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, out = run(name, make_tests_body([make_entry(mapped), make_entry(UNRELATED_ID, "NEEDS_ATTENTION")]))
    assert value is True
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_mapped_test_needing_attention_is_false(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, out = run(name, make_tests_body([make_entry(mapped, "NEEDS_ATTENTION")]))
    assert value is False
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_a_failure_already_seen_counts_in_a_cut_short_read(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, _ = run(name, make_tests_body([make_entry(mapped, "NEEDS_ATTENTION")], truncated=True))
    assert value is False


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_all_mapped_tests_absent_is_none(name):
    value, out = run(name, make_tests_body([make_entry(UNRELATED_ID), make_entry("another-unrelated", "NEEDS_ATTENTION")]))
    assert value is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_empty_test_list_is_none(name):
    value, out = run(name, make_tests_body([]))
    assert value is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
@pytest.mark.parametrize("status", ["DEACTIVATED", "NOT_APPLICABLE"])
def test_deactivated_or_not_applicable_only_is_none(name, status):
    _, mapped, _ = TEST_CHECKS[name]
    value, _ = run(name, make_tests_body([make_entry(mapped, status)]))
    assert value is None


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
@pytest.mark.parametrize("status", ["IN_PROGRESS", "INVALID", "SOMETHING_NEW"])
def test_an_unclear_mapped_test_is_none_never_false(name, status):
    _, mapped, _ = TEST_CHECKS[name]
    value, out = run(name, make_tests_body([make_entry(mapped, status)]))
    assert value is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_a_pass_in_a_read_that_is_not_proven_complete_is_none(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, _ = run(name, make_tests_body([make_entry(mapped)], truncated=True))
    assert value is None
    body = make_tests_body([make_entry(mapped)])
    del body["paginationStats"]
    value, _ = run(name, body)
    assert value is None


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_a_deactivated_mapped_test_is_none_and_names_the_test(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, out = run(name, make_tests_body([make_entry(mapped, "DEACTIVATED"), make_entry(UNRELATED_ID, "OK")]))
    assert value is None and not_evaluated(out)
    assert mapped in json.dumps(out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("name", ["isstrongauthrequired", "confirmpasswordpolicyenforced"])
def test_a_deactivated_prefix_mapped_test_beside_an_ok_one_is_none(name):
    _, mapped, prefixed = TEST_CHECKS[name]
    value, out = run(name, make_tests_body([make_entry(mapped, "OK"), make_entry(prefixed, "DEACTIVATED")]))
    assert value is None and not_evaluated(out)
    assert prefixed in json.dumps(out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_a_failing_mapped_test_beside_a_deactivated_one_is_still_false(name):
    _, mapped, prefixed = TEST_CHECKS[name]
    entries = [make_entry(mapped, "NEEDS_ATTENTION")]
    if prefixed is not None:
        entries.append(make_entry(prefixed, "DEACTIVATED"))
    value, _ = run(name, make_tests_body(entries))
    assert value is False
    if prefixed is not None:
        entries = [make_entry(mapped, "DEACTIVATED"), make_entry(prefixed, "NEEDS_ATTENTION")]
        value, _ = run(name, make_tests_body(entries))
        assert value is False


def test_two_id_check_deactivated_ok_and_all_ok():
    ebs, rds = "aws-ebs-snapshot-encryption", "aws-rds-snapshot-encryption"
    out = load("isbackupencrypted").transform(make_tests_body([make_entry(ebs, "DEACTIVATED"), make_entry(rds, "DEACTIVATED")]))
    errors = json.dumps(out["additionalInfo"]["dataCollection"]["errors"])
    assert ebs in errors and rds in errors
    assert run("isbackupencrypted", make_tests_body([make_entry(ebs, "OK"), make_entry(rds, "DEACTIVATED")]))[0] is None
    assert run("isbackupencrypted", make_tests_body([make_entry(ebs, "OK"), make_entry(rds, "OK")]))[0] is True
    assert run("isbackupencrypted", make_tests_body([make_entry(ebs, "OK"), make_entry(rds, "NOT_APPLICABLE")]))[0] is True


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_an_unreadable_entry_is_none(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, _ = run(name, make_tests_body([make_entry(mapped), "not an object"]))
    assert value is None


@pytest.mark.parametrize("data", [
    None, "", "not json", {}, [], {"vantaTests": None}, {"vantaTests": {"tests": "x"}},
    {"error": SENTINEL}, {"status": 403, "message": SENTINEL}, {"vantaTests": {"error": SENTINEL}},
])
@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_error_empty_and_unrecognised_bodies_are_not_evaluated(name, data):
    value, out = run(name, data)
    assert value is None
    assert not_evaluated(out)
    assert SENTINEL not in json.dumps(out)


@pytest.mark.parametrize("name", sorted(TEST_CHECKS))
def test_the_same_answer_from_a_json_string(name):
    _, mapped, _ = TEST_CHECKS[name]
    value, _ = run(name, json.dumps(make_tests_body([make_entry(mapped)])))
    assert value is True


def test_the_strong_auth_prefix_maps_a_new_identity_provider_test():
    for name in ("isstrongauthrequired", "confirmpasswordpolicyenforced"):
        _, _, prefixed = TEST_CHECKS[name]
        value, _ = run(name, make_tests_body([make_entry(prefixed, "NEEDS_ATTENTION")]))
        assert value is False
        value, _ = run(name, make_tests_body([make_entry(prefixed)]))
        assert value is True


def test_strong_auth_no_longer_maps_by_words():
    value, _ = run("isstrongauthrequired", make_tests_body([{"id": "something-else", "name": "MFA is enabled on cloud accounts",
                                                      "status": "OK"}]))
    assert value is None


# ---------------------------------------------------------------- vulnerability counts

OPEN = "opencriticalvulnerabilitiescount"
OVERDUE = "overduevulnerabilityremediationcount"


def future():
    return (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z")


def past():
    return (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z")


def vuln(severity="LOW", due=None, vid="v1"):
    return {"id": vid, "severity": severity, "remediateByDate": due, "firstDetectedDate": past()}


def vuln_body(vulns, scanner="OK", truncated=False, tests_truncated=False):
    """The getVantaVulnerabilities workflow output: the vulnerabilities and the tests, with a scanner test status.
    scanner None leaves the scanner test out; "absent-block" leaves the whole tests read out."""
    body = {"vantaVulnerabilities": {"vulnerabilities": vulns},
            "paginationStats": {"vantaVulnerabilities": {"paginationTruncated": truncated},
                                "vantaTests": {"paginationTruncated": tests_truncated}}}
    if scanner != "absent-block":
        entries = [make_entry(UNRELATED_ID, "NEEDS_ATTENTION")]
        if scanner is not None:
            entries.append(make_entry(SCANNER, scanner))
        body["vantaTests"] = {"tests": entries}
    return body


def test_vulnerability_files_say_third_party_level_3():
    for name in (OPEN, OVERDUE):
        _, out = run(name, vuln_body([vuln()]))
        assert out["additionalInfo"]["metadata"]["proofLevel"] == 3
        assert out["additionalInfo"]["metadata"]["proofSource"] == "third_party_claim"


# open critical ----------------------------------------------------------------

def test_open_critical_counts_critical_entries():
    value, out = run(OPEN, vuln_body([vuln("CRITICAL", vid="a"), vuln("critical", vid="b"), vuln("HIGH", vid="c")]))
    assert value == 2
    assert not not_evaluated(out)


def test_open_critical_zero_passes_with_scanner_ok():
    value, out = run(OPEN, vuln_body([vuln("HIGH"), vuln("LOW", vid="b")], scanner="OK"))
    assert value == 0 and not not_evaluated(out)


def test_open_critical_empty_list_with_scanner_ok_is_zero():
    value, out = run(OPEN, vuln_body([], scanner="OK"))
    assert value == 0 and not not_evaluated(out)


@pytest.mark.parametrize("vulns", [[], [vuln("HIGH")]])
def test_open_critical_zero_with_scanner_missing_is_none(vulns):
    value, out = run(OPEN, vuln_body(vulns, scanner=None))
    assert value is None and not_evaluated(out)


@pytest.mark.parametrize("vulns", [[], [vuln("HIGH")]])
def test_open_critical_zero_with_whole_tests_read_missing_is_none(vulns):
    value, out = run(OPEN, vuln_body(vulns, scanner="absent-block"))
    assert value is None and not_evaluated(out)


@pytest.mark.parametrize("status", ["NEEDS_ATTENTION", "IN_PROGRESS", "DEACTIVATED", "INVALID", "NOT_APPLICABLE", "ok", ""])
@pytest.mark.parametrize("vulns", [[], [vuln("HIGH")]])
def test_open_critical_zero_with_scanner_not_exactly_ok_is_none(vulns, status):
    value, out = run(OPEN, vuln_body(vulns, scanner=status))
    assert value is None and not_evaluated(out)


def test_open_critical_nonzero_is_reported_even_without_the_scanner_test():
    value, _ = run(OPEN, vuln_body([vuln("CRITICAL")], scanner=None))
    assert value == 1


def test_open_critical_null_severity_is_none():
    value, out = run(OPEN, vuln_body([vuln("HIGH"), vuln(None, vid="b")]))
    assert value is None and not_evaluated(out)


def test_open_critical_null_severity_hides_no_critical_either():
    value, _ = run(OPEN, vuln_body([vuln("CRITICAL"), vuln(None, vid="b")]))
    assert value is None


def test_open_critical_unknown_severity_is_none():
    value, _ = run(OPEN, vuln_body([vuln("SEVERE")]))
    assert value is None


def test_open_critical_truncated_read_is_none_never_a_count():
    value, out = run(OPEN, vuln_body([vuln("CRITICAL")], truncated=True))
    assert value is None and not_evaluated(out)
    value, _ = run(OPEN, vuln_body([vuln("LOW")], truncated=True))
    assert value is None


def test_open_critical_read_that_does_not_say_is_none():
    body = vuln_body([vuln("LOW")])
    del body["paginationStats"]
    value, _ = run(OPEN, body)
    assert value is None


def test_open_critical_unreadable_entry_is_none():
    value, _ = run(OPEN, vuln_body([vuln("LOW"), "not an object"]))
    assert value is None


# overdue ----------------------------------------------------------------------

def test_overdue_counts_past_dates():
    value, out = run(OVERDUE, vuln_body([vuln(due=past(), vid="a"), vuln(due=future(), vid="b")]))
    assert value == 1 and not not_evaluated(out)


def test_overdue_zero_passes_when_all_dated_in_the_future_and_scanner_ok():
    value, out = run(OVERDUE, vuln_body([vuln(due=future(), vid="a"), vuln(due=future(), vid="b")]))
    assert value == 0 and not not_evaluated(out)


def test_overdue_empty_list_with_scanner_ok_is_zero():
    value, out = run(OVERDUE, vuln_body([], scanner="OK"))
    assert value == 0 and not not_evaluated(out)


@pytest.mark.parametrize("scanner", [None, "absent-block", "NEEDS_ATTENTION", "IN_PROGRESS", "ok"])
@pytest.mark.parametrize("vulns", [[], [vuln(due=future())]])
def test_overdue_zero_without_scanner_ok_is_none(vulns, scanner):
    value, out = run(OVERDUE, vuln_body(vulns, scanner=scanner))
    assert value is None and not_evaluated(out)


def test_overdue_nonzero_is_reported_even_without_the_scanner_test():
    value, _ = run(OVERDUE, vuln_body([vuln(due=past())], scanner=None))
    assert value == 1


def test_overdue_every_date_null_is_none():
    value, out = run(OVERDUE, vuln_body([vuln(due=None, vid="a"), vuln(due=None, vid="b")]))
    assert value is None and not_evaluated(out)


def test_overdue_a_null_date_beside_future_dates_is_none():
    value, _ = run(OVERDUE, vuln_body([vuln(due=None, vid="a"), vuln(due=future(), vid="b")]))
    assert value is None


def test_overdue_unparseable_date_is_none():
    value, _ = run(OVERDUE, vuln_body([vuln(due="soon")]))
    assert value is None


def test_overdue_truncated_read_is_none_never_a_count():
    value, _ = run(OVERDUE, vuln_body([vuln(due=past())], truncated=True))
    assert value is None
    value, _ = run(OVERDUE, vuln_body([vuln(due=future())], truncated=True))
    assert value is None


def test_overdue_unreadable_entry_is_none():
    value, _ = run(OVERDUE, vuln_body([vuln(due=future()), 7]))
    assert value is None


# both -------------------------------------------------------------------------

@pytest.mark.parametrize("name", [OPEN, OVERDUE])
@pytest.mark.parametrize("data", [
    None, "", "not json", {}, [], {"vantaVulnerabilities": None}, {"vantaVulnerabilities": {"vulnerabilities": "x"}},
    {"error": SENTINEL}, {"status": 500, "message": SENTINEL}, {"errors": [SENTINEL]},
    {"vantaVulnerabilities": {"error": SENTINEL}},
])
def test_vulnerability_error_empty_and_missing_reads_are_none(name, data):
    value, out = run(name, data)
    assert value is None
    assert not_evaluated(out)
    assert SENTINEL not in json.dumps(out)


@pytest.mark.parametrize("name", [OPEN, OVERDUE])
def test_vulnerability_read_missing_but_tests_present_is_none(name):
    value, _ = run(name, make_tests_body([make_entry(SCANNER)]))
    assert value is None


@pytest.mark.parametrize("name", [OPEN, OVERDUE])
def test_vulnerability_files_work_from_a_json_string(name):
    value, _ = run(name, json.dumps(vuln_body([vuln("LOW", due=future())])))
    assert value == 0


@pytest.mark.parametrize("name", [OPEN, OVERDUE])
def test_vulnerability_summary_carries_no_free_text(name):
    body = vuln_body([vuln("CRITICAL", due=past())])
    body["vantaVulnerabilities"]["vulnerabilities"][0]["description"] = SENTINEL
    _, out = run(name, body)
    assert SENTINEL not in json.dumps(out)
