"""AWS Security Hub findings checks: a partial read never proves an absence.

The rule, for every check that reads the Security Hub GetFindings list:

  * When a next-page token is present (NextToken, or nextToken in lower camel case, on the page or on any
    wrapper around it), or when a finding cannot be read (its Compliance entry is not an object), any result
    that rests on the ABSENCE of a failure is None (Not evaluated): a True, a "none found" False and a total count.
  * A negative PROVEN by a finding already seen may stay False, but its count is None, and the number seen is
    reported as a lower bound in a separate field. It is never a total.
  * unencryptedStorageResourceCount needs a status for all three storage controls before it can say True.
  * A finding that cannot be read never raises: the check answers from the findings it could read.

Each case runs twice: as plain Python and compiled in the production RestrictedPython sandbox
(tools/restricted_sandbox.py) when RestrictedPython is installed. All payloads are synthetic.
"""
import functools
import importlib.util
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


@functools.lru_cache(maxsize=None)
def plain(name):
    spec = importlib.util.spec_from_file_location("awssh_partial_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


@functools.lru_cache(maxsize=None)
def sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, str(ROOT / "tools"))
    import restricted_sandbox
    return restricted_sandbox.load((HERE / (name + ".py")).read_text())["transform"]


LOADERS = [plain, sandboxed]
LOADER_IDS = ["plain", "sandbox"]


def finding(control, status, severity="MEDIUM"):
    return {"Compliance": {"Status": status, "SecurityControlId": control},
            "Severity": {"Label": severity}, "RecordState": "ACTIVE"}


# name -> (criterion key, controls the check reads)
CONTROL_CHECKS = {
    "areadminaccountsseparate": ("areAdminAccountsSeparate", ["IAM.1", "IAM.4"]),
    "aredlppoliciesconfigured": ("areDLPPoliciesConfigured", ["Macie.1", "Macie.2"]),
    "isguarddutyenabled": ("isGuardDutyEnabled", ["GuardDuty.1"]),
    "isiamloggingenabled": ("isIAMLoggingEnabled", ["CloudTrail.1"]),
    "ismfaenforcedforusers": ("isMFAEnforcedForUsers", ["IAM.5"]),
    "unencryptedstorageresourcecount": ("unencryptedStorageResourceCount", ["EC2.7", "RDS.3", "EFS.1"]),
}
SCORE = "compliancepercentage"
CRITICAL = "criticalopenfindingscount"
ALL_FINDINGS_CHECKS = sorted(CONTROL_CHECKS) + [SCORE, CRITICAL]
KEYS = {name: spec[0] for name, spec in CONTROL_CHECKS.items()}
KEYS[SCORE] = "compliancePercentage"
KEYS[CRITICAL] = "criticalOpenFindingsCount"


def passing_findings(name):
    """Findings that would make this check read True (or a real score) on a complete page."""
    if name == SCORE:
        return [finding("IAM.1", "PASSED"), finding("IAM.4", "PASSED")]
    if name == CRITICAL:
        return [finding("S3.3", "PASSED", "CRITICAL"), finding("S3.2", "FAILED", "HIGH")]
    return [finding(control, "PASSED") for control in CONTROL_CHECKS[name][1]]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def not_evaluated(out, name):
    inner = out["transformedResponse"]
    assert inner[KEYS[name]] is None, name + " = " + repr(inner[KEYS[name]])
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    # a reason, not a crash: the check did not raise
    assert out["additionalInfo"]["transformation"]["status"] == "success"


def answered(out, name):
    inner = out["transformedResponse"]
    assert collection(out)["status"] == "success"
    return inner[KEYS[name]]


# --- a clean page still answers --------------------------------------------------------------

@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
def test_a_complete_page_still_answers(loader, name):
    out = loader(name)({"Findings": passing_findings(name)})
    if name == CRITICAL:
        assert answered(out, name) is True
    elif name == SCORE:
        assert answered(out, name) == 100
    else:
        assert answered(out, name) is True


# --- the next-page token, in every spelling and position --------------------------------------

TOKEN_SHAPES = [
    ("NextToken on the page", lambda f: {"Findings": f, "NextToken": "abc"}),
    ("nextToken on the page", lambda f: {"Findings": f, "nextToken": "abc"}),
    ("NextToken on the wrapper", lambda f: {"api_response": {"Findings": f}, "NextToken": "abc"}),
    ("nextToken on the wrapper", lambda f: {"response": {"Findings": f}, "nextToken": "abc"}),
    ("nextToken on an inner wrapper", lambda f: {"api_response": {"result": {"Findings": f}, "nextToken": "abc"}}),
    ("nextToken in a data envelope", lambda f: {"data": {"Findings": f, "nextToken": "abc"}, "validation": {"status": "skipped"}}),
]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("label,shape", TOKEN_SHAPES, ids=[s[0] for s in TOKEN_SHAPES])
def test_a_pass_from_a_partial_page_is_not_a_pass(loader, name, label, shape):
    not_evaluated(loader(name)(shape(passing_findings(name))), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("token", [None, ""])
@pytest.mark.parametrize("key", ["NextToken", "nextToken"])
def test_an_empty_token_is_not_a_next_page(loader, name, key, token):
    out = loader(name)({"Findings": passing_findings(name), key: token})
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
@pytest.mark.parametrize("key", ["NextToken", "nextToken"])
def test_a_failing_control_seen_on_a_partial_page_stays_false(loader, name, key):
    control = CONTROL_CHECKS[name][1][0]
    out = loader(name)({"Findings": [finding(control, "FAILED")], key: "abc"})
    assert out["transformedResponse"][KEYS[name]] is False
    assert collection(out)["status"] == "success"


# --- counts of a partial read are a lower bound, never a total ---------------------------------

CRITICAL_FINDINGS = [finding("IAM.4", "FAILED", "CRITICAL"), finding("S3.1", "FAILED", "CRITICAL"),
                     finding("S3.2", "FAILED", "HIGH"), finding("S3.3", "PASSED", "CRITICAL")]
UNENCRYPTED_FINDINGS = [finding("EC2.7", "FAILED"), finding("RDS.3", "FAILED"), finding("EFS.1", "PASSED"),
                        finding("S3.1", "FAILED")]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("key", ["NextToken", "nextToken"])
def test_critical_count_of_a_partial_page_is_a_lower_bound(loader, key):
    inner = loader(CRITICAL)({"Findings": CRITICAL_FINDINGS, key: "abc"})["transformedResponse"]
    assert inner["criticalOpenFindingsCount"] is False
    assert inner["openCriticalFindings"] is None
    assert inner["openCriticalFindingsAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("key", ["NextToken", "nextToken"])
def test_unencrypted_count_of_a_partial_page_is_a_lower_bound(loader, key):
    inner = loader("unencryptedstorageresourcecount")({"Findings": UNENCRYPTED_FINDINGS, key: "abc"})["transformedResponse"]
    assert inner["unencryptedStorageResourceCount"] is False
    assert inner["unencryptedResources"] is None
    assert inner["unencryptedResourcesAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_counts_of_a_complete_page_are_totals_with_no_lower_bound_field(loader):
    crit = loader(CRITICAL)({"Findings": CRITICAL_FINDINGS})["transformedResponse"]
    assert crit["openCriticalFindings"] == 2 and "openCriticalFindingsAtLeast" not in crit
    unenc = loader("unencryptedstorageresourcecount")({"Findings": UNENCRYPTED_FINDINGS})["transformedResponse"]
    assert unenc["unencryptedResources"] == 2 and "unencryptedResourcesAtLeast" not in unenc


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_a_lower_bound_reason_says_so(loader):
    out = loader(CRITICAL)({"Findings": CRITICAL_FINDINGS, "NextToken": "abc"})
    reasons = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
    assert "At least 2" in reasons


# --- unencryptedStorageResourceCount needs all three controls to say True ---------------------

@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("read", [["EC2.7"], ["RDS.3"], ["EFS.1"], ["EC2.7", "RDS.3"], ["RDS.3", "EFS.1"]])
def test_fewer_than_all_three_storage_controls_is_not_a_pass(loader, read):
    out = loader("unencryptedstorageresourcecount")({"Findings": [finding(c, "PASSED") for c in read]})
    not_evaluated(out, "unencryptedstorageresourcecount")
    assert out["transformedResponse"]["unencryptedResources"] is None
    unread = [c for c in ["EC2.7", "RDS.3", "EFS.1"] if c not in read]
    assert all(c in " ".join(collection(out)["errors"]) for c in unread)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_all_three_storage_controls_passing_is_true(loader):
    out = loader("unencryptedstorageresourcecount")({"Findings": [finding(c, "PASSED") for c in ["EC2.7", "RDS.3", "EFS.1"]]})
    assert out["transformedResponse"]["unencryptedStorageResourceCount"] is True
    assert out["transformedResponse"]["unencryptedResources"] == 0


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_a_failure_seen_with_fewer_than_three_controls_read_stays_false(loader):
    out = loader("unencryptedstorageresourcecount")({"Findings": [finding("EC2.7", "FAILED")]})
    inner = out["transformedResponse"]
    assert inner["unencryptedStorageResourceCount"] is False and inner["unencryptedResources"] == 1


# --- a finding that cannot be read never raises -----------------------------------------------

UNREADABLE = ["oops", ["IAM.1"], 7, True, [{"Status": "FAILED"}]]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("bad", UNREADABLE, ids=[repr(b) for b in UNREADABLE])
def test_an_unreadable_finding_beside_passes_is_not_a_pass(loader, name, bad):
    findings = passing_findings(name) + [{"Compliance": bad, "Severity": {"Label": "CRITICAL"}}]
    not_evaluated(loader(name)({"Findings": findings}), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("bad", UNREADABLE, ids=[repr(b) for b in UNREADABLE])
def test_only_unreadable_findings_is_not_evaluated(loader, name, bad):
    not_evaluated(loader(name)({"Findings": [{"Compliance": bad}, {"Compliance": bad}]}), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_an_unreadable_finding_beside_a_failure_stays_false(loader, name):
    control = CONTROL_CHECKS[name][1][0]
    out = loader(name)({"Findings": [{"Compliance": "oops"}, finding(control, "FAILED")]})
    assert out["transformedResponse"][KEYS[name]] is False
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_counts_beside_an_unreadable_finding_are_lower_bounds(loader):
    crit = loader(CRITICAL)({"Findings": CRITICAL_FINDINGS + [{"Compliance": "oops"}]})["transformedResponse"]
    assert crit["criticalOpenFindingsCount"] is False
    assert crit["openCriticalFindings"] is None and crit["openCriticalFindingsAtLeast"] == 2
    unenc = loader("unencryptedstorageresourcecount")({"Findings": UNENCRYPTED_FINDINGS + [{"Compliance": ["x"]}]})["transformedResponse"]
    assert unenc["unencryptedResources"] is None and unenc["unencryptedResourcesAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("severity", ["CRITICAL", ["CRITICAL"], None, 3])
def test_a_failing_finding_with_an_unreadable_severity_is_not_a_clean_zero(loader, severity):
    findings = [finding("S3.3", "PASSED", "CRITICAL"), {"Compliance": {"Status": "FAILED", "SecurityControlId": "S3.9"},
                                                         "Severity": severity}]
    out = loader(CRITICAL)({"Findings": findings})
    inner = out["transformedResponse"]
    assert inner["criticalOpenFindingsCount"] is not True
    assert out["additionalInfo"]["transformation"]["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_a_finding_with_no_compliance_entry_is_just_not_counted(loader):
    # No Compliance at all is a finding that is not a control finding; it is not an unreadable one.
    out = loader(CRITICAL)({"Findings": passing_findings(CRITICAL) + [{"Severity": {"Label": "LOW"}}]})
    assert out["transformedResponse"]["criticalOpenFindingsCount"] is True


# --- a list entry that is not an object cannot be read either ---------------------------------

NOT_OBJECTS = ["garbled", 7, None, ["IAM.1"], True]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("bad", NOT_OBJECTS, ids=[repr(b) for b in NOT_OBJECTS])
def test_a_list_entry_that_is_not_an_object_beside_passes_is_not_a_pass(loader, name, bad):
    out = loader(name)({"Findings": passing_findings(name) + [bad]})
    not_evaluated(out, name)
    out = loader(name)({"Findings": [bad] + passing_findings(name)})
    not_evaluated(out, name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("bad", NOT_OBJECTS, ids=[repr(b) for b in NOT_OBJECTS])
def test_only_entries_that_are_not_objects_is_not_evaluated(loader, name, bad):
    not_evaluated(loader(name)({"Findings": [bad, bad]}), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_an_entry_that_is_not_an_object_beside_a_failure_stays_false(loader, name):
    control = CONTROL_CHECKS[name][1][0]
    out = loader(name)({"Findings": ["garbled", finding(control, "FAILED")]})
    assert out["transformedResponse"][KEYS[name]] is False
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_counts_beside_an_entry_that_is_not_an_object_are_lower_bounds(loader):
    crit = loader(CRITICAL)({"Findings": CRITICAL_FINDINGS + ["garbled"]})["transformedResponse"]
    assert crit["criticalOpenFindingsCount"] is False
    assert crit["openCriticalFindings"] is None and crit["openCriticalFindingsAtLeast"] == 2
    unenc = loader("unencryptedstorageresourcecount")({"Findings": UNENCRYPTED_FINDINGS + [None]})["transformedResponse"]
    assert unenc["unencryptedResources"] is None and unenc["unencryptedResourcesAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_an_empty_object_is_not_an_unreadable_finding(loader):
    # {} is an object with no Compliance entry: a finding about nothing we read, not an unreadable one.
    out = loader(CRITICAL)({"Findings": passing_findings(CRITICAL) + [{}]})
    assert out["transformedResponse"]["criticalOpenFindingsCount"] is True


# --- checks that read several controls need a status for every one ----------------------------

MULTI = {"areadminaccountsseparate": ["IAM.1", "IAM.4"], "aredlppoliciesconfigured": ["Macie.1", "Macie.2"]}


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(MULTI))
def test_one_control_passing_and_the_other_unread_is_not_a_pass(loader, name):
    for read in MULTI[name]:
        out = loader(name)({"Findings": [finding(read, "PASSED")]})
        not_evaluated(out, name)
        unread = [c for c in MULTI[name] if c != read][0]
        assert unread in " ".join(collection(out)["errors"])


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(MULTI))
def test_every_control_passing_is_true_and_a_failure_beside_an_unread_control_is_false(loader, name):
    out = loader(name)({"Findings": [finding(c, "PASSED") for c in MULTI[name]]})
    assert out["transformedResponse"][KEYS[name]] is True
    out = loader(name)({"Findings": [finding(MULTI[name][1], "FAILED")]})
    assert out["transformedResponse"][KEYS[name]] is False


# --- confirmedLicensePurchased ----------------------------------------------------------------

LICENCE = "confirmedlicensepurchased"
LICENCE_KEY = "confirmedLicensePurchased"


def licence_not_evaluated(out):
    assert out["transformedResponse"][LICENCE_KEY] is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("key", ["NextToken", "nextToken"])
def test_licence_findings_count_with_a_next_page_token_is_a_lower_bound(loader, key):
    findings = [finding("IAM.4", "PASSED"), finding("IAM.5", "PASSED")]
    for body in ({"Findings": findings, key: "abc"}, {"api_response": {"Findings": findings}, key: "abc"},
                 {"api_response": {"result": {"Findings": findings}, key: "abc"}}):
        inner = loader(LICENCE)(body)["transformedResponse"]
        assert inner[LICENCE_KEY] is True
        assert inner["findingsCount"] is None
        assert inner["findingsCountAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_licence_findings_count_without_a_token_is_a_total(loader):
    inner = loader(LICENCE)({"Findings": [finding("IAM.4", "PASSED")], "NextToken": None})["transformedResponse"]
    assert inner["findingsCount"] == 1 and "findingsCountAtLeast" not in inner


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("wrapper", ["api_response", "response", "result", "apiResponse", "Output"])
def test_licence_reads_every_wrapper_key(loader, wrapper):
    assert loader(LICENCE)({wrapper: {"subscription": "enterprise"}})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({wrapper: {"licenses": []}})["transformedResponse"][LICENCE_KEY] is False
    licence_not_evaluated(loader(LICENCE)({wrapper: {"error": "denied"}}))


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_licence_reads_nested_wrappers_and_an_error_inside_them(loader):
    assert loader(LICENCE)({"api_response": {"result": {"Findings": []}}})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({"Output": {"response": {"sku": "SH-1"}}})["transformedResponse"][LICENCE_KEY] is True
    licence_not_evaluated(loader(LICENCE)({"api_response": {"result": {"statusCode": 500}}}))
    licence_not_evaluated(loader(LICENCE)({"api_response": {"nothing": "here"}}))


EMPTY_FIELDS = [{"subscription": None}, {"subscription": ""}, {"subscription": "  "}, {"subscription": {}},
                {"sku": None}, {"sku": ""}, {"license": None}, {"license": []},
                {"active": None}, {"enabled": None},
                {"subscription": None, "licenses": []}, {"sku": "", "license": None}]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("body", EMPTY_FIELDS, ids=[repr(b) for b in EMPTY_FIELDS])
def test_licence_field_that_is_null_or_empty_is_not_evaluated(loader, body):
    licence_not_evaluated(loader(LICENCE)(body))
    licence_not_evaluated(loader(LICENCE)({"api_response": body}))


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_licence_empty_field_does_not_hide_a_real_licence_or_a_real_no(loader):
    assert loader(LICENCE)({"subscription": None, "sku": "SH-1"})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({"subscription": None, "licenses": [{"id": 1}]})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({"subscription": None, "Findings": []})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({"licenses": []})["transformedResponse"][LICENCE_KEY] is False
    assert loader(LICENCE)({"active": False})["transformedResponse"][LICENCE_KEY] is False
    assert loader(LICENCE)({"enabled": False, "subscription": None})["transformedResponse"][LICENCE_KEY] is False


# --- a token on the page that sits five wrappers down is still read ---------------------------

def nest(inner, levels, key="api_response"):
    for _ in range(levels):
        inner = {key: inner}
    return inner


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("levels", [0, 1, 2, 3, 4, 5])
@pytest.mark.parametrize("token_key", ["NextToken", "nextToken"])
def test_a_token_on_the_page_at_any_wrapper_depth_is_read(loader, name, levels, token_key):
    page = {"Findings": passing_findings(name), token_key: "abc"}
    not_evaluated(loader(name)(nest(page, levels)), name)
    not_evaluated(loader(name)(nest(page, levels, "Output")), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", ALL_FINDINGS_CHECKS)
@pytest.mark.parametrize("levels", [4, 5])
def test_a_complete_page_at_depth_four_and_five_still_answers(loader, name, levels):
    page = {"Findings": passing_findings(name)}
    out = loader(name)(nest(page, levels))
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_a_lower_bound_count_survives_a_token_five_wrappers_down(loader):
    page = {"Findings": CRITICAL_FINDINGS, "NextToken": "abc"}
    inner = loader(CRITICAL)(nest(page, 5))["transformedResponse"]
    assert inner["criticalOpenFindingsCount"] is False
    assert inner["openCriticalFindings"] is None and inner["openCriticalFindingsAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("levels", [0, 1, 2, 3, 4, 5])
def test_licence_token_on_the_page_at_any_wrapper_depth_is_read(loader, levels):
    page = {"Findings": [finding("IAM.4", "PASSED"), finding("IAM.5", "PASSED")], "nextToken": "abc"}
    inner = loader(LICENCE)(nest(page, levels))["transformedResponse"]
    assert inner[LICENCE_KEY] is True
    assert inner["findingsCount"] is None and inner["findingsCountAtLeast"] == 2


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("levels", [4, 5])
def test_licence_complete_page_at_depth_four_and_five_keeps_its_total(loader, levels):
    page = {"Findings": [finding("IAM.4", "PASSED")]}
    inner = loader(LICENCE)(nest(page, levels))["transformedResponse"]
    assert inner["findingsCount"] == 1 and "findingsCountAtLeast" not in inner


# --- the active / enabled flag says something only when it is a clear true or false -----------

CLEAR_FLAGS = [(True, True), (False, False), ("true", True), ("false", False), (" True ", True), ("FALSE", False)]
UNCLEAR_FLAGS = ["", "  ", [], {}, "no", "yes", "disabled", "enabled", "active", "inactive", 0, 1, 2.5, ["true"], {"a": 1}, "0", "1"]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("field", ["active", "enabled"])
@pytest.mark.parametrize("flag,expected", CLEAR_FLAGS, ids=[repr(c[0]) for c in CLEAR_FLAGS])
def test_licence_flag_that_is_clear_gives_its_verdict(loader, field, flag, expected):
    out = loader(LICENCE)({field: flag})
    assert out["transformedResponse"][LICENCE_KEY] is expected
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("field", ["active", "enabled"])
@pytest.mark.parametrize("flag", UNCLEAR_FLAGS, ids=[repr(f) for f in UNCLEAR_FLAGS])
def test_licence_flag_that_is_not_a_clear_true_or_false_is_not_evaluated(loader, field, flag):
    licence_not_evaluated(loader(LICENCE)({field: flag}))
    licence_not_evaluated(loader(LICENCE)({"api_response": {field: flag}}))


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_licence_unclear_flag_does_not_hide_a_real_licence(loader):
    assert loader(LICENCE)({"active": "disabled", "sku": "SH-1"})["transformedResponse"][LICENCE_KEY] is True
    assert loader(LICENCE)({"enabled": "no", "licenses": [{"id": 1}]})["transformedResponse"][LICENCE_KEY] is True
