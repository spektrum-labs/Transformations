"""AWS Security Hub findings checks: an error or empty read is Not evaluated, never False and never a
measured 0.

Every check below reads the Security Hub GetFindings response ({"Findings": [...], "NextToken": ...}),
except confirmedLicensePurchased, which reads a subscription / licence / findings shape. A body that
proves nothing -- an error envelope (this integration's, an HTTP one, an AWS one), an empty or
non-JSON body, an unrecognised shape, a findings list that carries no status for the controls the
check reads, a findings list with more pages left unread and nothing failing, or a transform that
raises -- must answer None for the criterion (and for any count or percentage reported beside it) AND
set additionalInfo.dataCollection.status "error" with a non-empty errors list, which is the only channel
the evaluator reads to show "Not evaluated". The reason text is fixed: the vendor's own error text is
never copied into the result.

A readable answer that proves a negative keeps its verdict: a failing control is still False, zero
passing controls out of a nonzero total is still 0%, a critical failing finding is still counted.

Each case runs twice: imported as plain Python, and compiled and run in the production RestrictedPython
sandbox (tools/restricted_sandbox.py) when RestrictedPython is installed. All payloads are synthetic.
"""
import functools
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SENTINEL = "SENTINEL-planted-vendor-text.example"


@functools.lru_cache(maxsize=None)
def plain(name):
    spec = importlib.util.spec_from_file_location("awssh_err_" + name, HERE / (name + ".py"))
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


class PoisonedBody(dict):
    """A non-empty object whose every read raises: it drives the transform down its except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def finding(control, status, severity="MEDIUM"):
    return {"Compliance": {"Status": status, "SecurityControlId": control},
            "Severity": {"Label": severity}, "RecordState": "ACTIVE"}


# name -> (criterion keys that must read None when nothing is proven, controls the check reads)
CONTROL_CHECKS = {
    "areadminaccountsseparate": (["areAdminAccountsSeparate"], ["IAM.1", "IAM.4"]),
    "aredlppoliciesconfigured": (["areDLPPoliciesConfigured"], ["Macie.1", "Macie.2"]),
    "isguarddutyenabled": (["isGuardDutyEnabled"], ["GuardDuty.1"]),
    "isiamloggingenabled": (["isIAMLoggingEnabled"], ["CloudTrail.1"]),
    "ismfaenforcedforusers": (["isMFAEnforcedForUsers"], ["IAM.5"]),
    "unencryptedstorageresourcecount": (["unencryptedStorageResourceCount", "unencryptedResources"],
                                        ["EC2.7", "RDS.3", "EFS.1"]),
}
OTHER_CHECKS = {
    "confirmedlicensepurchased": ["confirmedLicensePurchased"],
    "compliancepercentage": ["compliancePercentage", "CIScompliancePercentage"],
    "criticalopenfindingscount": ["criticalOpenFindingsCount", "openCriticalFindings"],
}
NONE_KEYS = {name: spec[0] for name, spec in CONTROL_CHECKS.items()}
NONE_KEYS.update(OTHER_CHECKS)
FINDINGS_CHECKS = [name for name in NONE_KEYS if name != "confirmedlicensepurchased"]

# Bodies that prove nothing, for every transform in this file.
COMMON_BAD = [
    ("error flag", {"error": True, "message": "upstream timeout"}),
    ("error string", {"error": "x"}),
    ("errors list", {"errors": [{"code": "x"}]}),
    ("403 with message", {"statusCode": 403, "message": "Forbidden"}),
    ("403 as text", {"statusCode": "403", "message": "Forbidden"}),
    ("500 snake case", {"status_code": 500}),
    ("401 with error", {"statusCode": 401, "error": "Unauthorized"}),
    ("nested error", {"error": {"statusCode": 401, "message": "Unauthorized"}}),
    ("auth error", {"error": {"type": "authentication_error", "message": "invalid credentials"}}),
    ("aws json error", {"__type": "AccessDeniedException", "message": "x"}),
    ("aws query error", {"Error": {"Code": "AccessDenied", "Message": "x"}}),
    ("aws error response", {"ErrorResponse": {"Error": {"Code": "AccessDenied"}}}),
    ("coral error", {"Output": {"__type": "com.amazon.coral.service#UnknownOperationException"}, "Version": "1.0"}),
    ("error beside findings", {"error": True, "Findings": [finding("IAM.4", "PASSED")]}),
    ("wrapped error", {"response": {"__type": "AccessDeniedException", "message": "x"}}),
    ("enveloped error", {"data": {"error": True, "message": "x"}, "validation": {"status": "skipped"}}),
    ("error as json text", json.dumps({"error": True, "message": "x"})),
    ("empty object", {}),
    ("empty list", []),
    ("list of empty object", [{}]),
    ("none", None),
    ("empty text", ""),
    ("blank text", "   "),
    ("empty object text", "{}"),
    ("null text", "null"),
    ("non-json text", "Forbidden"),
    ("html text", "<html><body>Bad Gateway</body></html>"),
    ("unrelated json", {"hello": "world"}),
    ("unrelated nested", {"foo": {"bar": [1, 2, 3]}}),
    ("wrapped empty", {"response": {}}),
    ("number", 7),
    ("poisoned", PoisonedBody),
]

# Bodies that prove nothing for the checks that read a GetFindings list.
FINDINGS_BAD = [
    ("empty findings", {"Findings": []}),
    ("empty findings with a next page", {"Findings": [], "NextToken": "abc"}),
    ("wrapped empty findings", {"api_response": {"Findings": []}}),
    ("findings not a list", {"Findings": "x"}),
    ("findings null", {"Findings": None}),
    ("findings of empty objects", {"Findings": [{}]}),
    ("findings of non-objects", {"Findings": [1, "x", None]}),
    ("finding without a status", {"Findings": [{"Compliance": {"SecurityControlId": "IAM.4"}}]}),
    ("finding with an unreadable status", {"Findings": [finding("IAM.4", "NOT_AVAILABLE")]}),
]


def body_of(spec):
    return spec() if callable(spec) else json.loads(json.dumps(spec))


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def assert_not_evaluated(out, keys):
    inner = out["transformedResponse"]
    for key in keys:
        assert key in inner, "criterion " + key + " missing from the output"
        assert inner[key] is None, key + " = " + repr(inner[key]) + ", expected None"
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(NONE_KEYS))
@pytest.mark.parametrize("label,body", COMMON_BAD, ids=[c[0] for c in COMMON_BAD])
def test_error_or_empty_body_is_not_evaluated(loader, name, label, body):
    assert_not_evaluated(loader(name)(body_of(body)), NONE_KEYS[name])


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", FINDINGS_CHECKS)
@pytest.mark.parametrize("label,body", FINDINGS_BAD, ids=[c[0] for c in FINDINGS_BAD])
def test_unreadable_findings_are_not_evaluated(loader, name, label, body):
    assert_not_evaluated(loader(name)(body_of(body)), NONE_KEYS[name])


SENTINEL_BODIES = [
    {"error": True, "message": SENTINEL},
    {"error": SENTINEL},
    {"errors": [{"code": SENTINEL, "message": SENTINEL}]},
    {"statusCode": 500, "message": SENTINEL},
    {"__type": SENTINEL, "message": SENTINEL},
    {"Error": {"Code": SENTINEL, "Message": SENTINEL}},
    {"ErrorResponse": {"Error": {"Code": SENTINEL, "Message": SENTINEL}}},
    {"data": {"error": True, "message": SENTINEL}, "validation": {"status": "skipped"}},
    {"response": {"__type": SENTINEL, "message": SENTINEL}},
    SENTINEL,
    json.dumps({"error": True, "message": SENTINEL}),
    {"hello": SENTINEL},
]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(NONE_KEYS))
@pytest.mark.parametrize("body", SENTINEL_BODIES, ids=[str(i) for i in range(len(SENTINEL_BODIES))])
def test_vendor_error_text_is_never_echoed(loader, name, body):
    out = loader(name)(body_of(body))
    assert_not_evaluated(out, NONE_KEYS[name])
    assert SENTINEL not in json.dumps(out, default=str)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(NONE_KEYS))
def test_exception_text_is_only_under_transformation_errors(loader, name):
    out = loader(name)(PoisonedBody())
    assert_not_evaluated(out, NONE_KEYS[name])
    info = out["additionalInfo"]
    assert "poisoned read" not in json.dumps(info["dataCollection"])
    assert "poisoned read" not in json.dumps(info["evaluation"])
    assert "poisoned read" in json.dumps(info["transformation"]["errors"])


# --- the other checks in this folder: the same rule, no vendor text -----------------------------
#
# These five already answered Not evaluated for an error or empty body. They are held to the same
# battery so the folder has one contract: the value that means "not evaluated" (None, or True for
# the inverted isPublicStorageBucketExposed, where True is the fail-closed reading), a dataCollection
# error, and fixed reason text.

UNCHANGED = {
    "ispublicstoragebucketexposed": ("isPublicStorageBucketExposed", True),
    "isrootuseraccesskeyrestricted": ("isRootUserAccessKeyRestricted", None),
    "isrootusermfaenabled": ("isRootUserMFAEnabled", None),
    "issessiontimeoutconfigured": ("isSessionTimeoutConfigured", None),
    "isssoenabled": ("isSSOEnabled", None),
}

LEG_SENTINEL_BODIES = [
    {"samlProviders": {"error": True, "message": SENTINEL},
     "ssoInstances": {"__type": SENTINEL, "message": SENTINEL}},
    {"samlProviders": {"ErrorResponse": {"Error": {"Code": SENTINEL}}},
     "ssoInstances": {"error": True, "errorMessage": SENTINEL}},
    {"Instances": [{"Status": "ACTIVE"}], "__type": SENTINEL, "message": SENTINEL},
    {"Instances": [{"Status": "ACTIVE"}], "error": True, "message": SENTINEL},
]


def assert_other_not_evaluated(out, name):
    key, empty = UNCHANGED[name]
    assert out["transformedResponse"][key] is empty
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(UNCHANGED))
@pytest.mark.parametrize("label,body", COMMON_BAD + FINDINGS_BAD, ids=[c[0] for c in COMMON_BAD + FINDINGS_BAD])
def test_other_checks_error_or_empty_body_is_not_evaluated(loader, name, label, body):
    assert_other_not_evaluated(loader(name)(body_of(body)), name)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(UNCHANGED))
@pytest.mark.parametrize("body", SENTINEL_BODIES + LEG_SENTINEL_BODIES,
                         ids=[str(i) for i in range(len(SENTINEL_BODIES + LEG_SENTINEL_BODIES))])
def test_other_checks_never_echo_vendor_error_text(loader, name, body):
    out = loader(name)(body_of(body))
    assert_other_not_evaluated(out, name)
    assert SENTINEL not in json.dumps(out, default=str)


# --- the control checks: a real answer keeps its verdict --------------------------------------

def verdict(out, key):
    return out["transformedResponse"][key], collection(out)["status"]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_a_failing_control_is_still_false(loader, name):
    key = NONE_KEYS[name][0]
    controls = CONTROL_CHECKS[name][1]
    for control in controls:
        body = {"Findings": [finding(control, "FAILED")]}
        out = loader(name)(body)
        assert verdict(out, key) == (False, "success")
        assert out["additionalInfo"]["evaluation"]["failReasons"]
        # a failing control stays False beside a passing one, and when more pages exist
        both = {"Findings": [finding(controls[0], "PASSED"), finding(control, "FAILED")]}
        assert verdict(loader(name)(both), key) == (False, "success")
        paged = {"Findings": [finding(control, "FAILED")], "NextToken": "abc"}
        assert verdict(loader(name)(paged), key) == (False, "success")


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_a_passing_control_is_still_true(loader, name):
    key = NONE_KEYS[name][0]
    controls = CONTROL_CHECKS[name][1]
    for control in controls:
        for token in (None, ""):
            body = {"Findings": [finding(control, "PASSED")]}
            if token is not None:
                body["NextToken"] = token
            out = loader(name)(body)
            if len(controls) > 1:
                # one of several controls read: no failure seen is not a pass
                assert_not_evaluated(out, NONE_KEYS[name])
                continue
            assert verdict(out, key) == (True, "success")
            assert out["additionalInfo"]["evaluation"]["passReasons"]
    every = {"Findings": [finding(control, "PASSED") for control in controls]}
    assert verdict(loader(name)(every), key) == (True, "success")
    # the same findings in the other shapes the integration hands over
    assert verdict(loader(name)({"response": every}), key) == (True, "success")
    assert verdict(loader(name)(json.dumps(every)), key) == (True, "success")
    assert verdict(loader(name)({"data": every, "validation": {"status": "skipped"}}), key) == (True, "success")
    assert verdict(loader(name)(every["Findings"]), key) == (True, "success")


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_a_pass_from_a_partial_read_is_not_a_pass(loader, name):
    """More pages (NextToken) and nothing failing on the page read: a later page may hold the failure."""
    key = NONE_KEYS[name][0]
    passing = [finding(control, "PASSED") for control in CONTROL_CHECKS[name][1]]
    body = {"Findings": passing, "NextToken": "abc"}
    assert_not_evaluated(loader(name)(body), NONE_KEYS[name])
    assert_not_evaluated(loader(name)({"api_response": body}), NONE_KEYS[name])
    assert verdict(loader(name)({"Findings": passing, "NextToken": None}), key) == (True, "success")


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("name", sorted(CONTROL_CHECKS))
def test_findings_for_other_controls_prove_nothing_about_this_one(loader, name):
    body = {"Findings": [finding("Unrelated.1", "PASSED"), finding("Unrelated.2", "FAILED")]}
    assert_not_evaluated(loader(name)(body), NONE_KEYS[name])


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_multi_control_checks_need_every_control(loader):
    admin = loader("areadminaccountsseparate")
    dlp = loader("aredlppoliciesconfigured")
    # one control with a status and the other unread is not a pass
    assert_not_evaluated(admin({"Findings": [finding("IAM.1", "PASSED")]}), NONE_KEYS["areadminaccountsseparate"])
    assert_not_evaluated(admin({"Findings": [finding("IAM.4", "PASSED")]}), NONE_KEYS["areadminaccountsseparate"])
    assert_not_evaluated(dlp({"Findings": [finding("Macie.2", "PASSED")]}), NONE_KEYS["aredlppoliciesconfigured"])
    assert_not_evaluated(dlp({"Findings": [finding("Macie.1", "PASSED")]}), NONE_KEYS["aredlppoliciesconfigured"])
    # every control read and passing is True
    both = {"Findings": [finding("IAM.1", "PASSED"), finding("IAM.4", "PASSED")]}
    assert verdict(admin(both), "areAdminAccountsSeparate") == (True, "success")
    # a failing control keeps the verdict False, whether or not the other one was read
    mixed = {"Findings": [finding("IAM.1", "PASSED"), finding("IAM.4", "FAILED")]}
    assert verdict(admin(mixed), "areAdminAccountsSeparate") == (False, "success")
    alone = {"Findings": [finding("IAM.4", "FAILED")]}
    assert verdict(admin(alone), "areAdminAccountsSeparate") == (False, "success")


# --- unencryptedStorageResourceCount and criticalOpenFindingsCount ---------------------------

@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_unencrypted_storage_counts_failing_findings(loader):
    t = loader("unencryptedstorageresourcecount")
    body = {"Findings": [finding("EC2.7", "FAILED"), finding("RDS.3", "FAILED"), finding("EFS.1", "PASSED"),
                         finding("S3.1", "FAILED")]}
    inner = t(body)["transformedResponse"]
    assert inner["unencryptedStorageResourceCount"] is False and inner["unencryptedResources"] == 2
    paged = t(dict(body, NextToken="abc"))["transformedResponse"]
    # a failure already seen keeps the verdict False, but the count of a partial read is a lower bound, never a total
    assert paged["unencryptedStorageResourceCount"] is False
    assert paged["unencryptedResources"] is None and paged["unencryptedResourcesAtLeast"] == 2
    clean = t({"Findings": [finding("EC2.7", "PASSED"), finding("RDS.3", "PASSED"), finding("EFS.1", "PASSED")]})
    assert clean["transformedResponse"]["unencryptedStorageResourceCount"] is True
    assert clean["transformedResponse"]["unencryptedResources"] == 0
    assert collection(clean)["status"] == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_critical_open_findings_counts_critical_failing_findings(loader):
    t = loader("criticalopenfindingscount")
    body = {"Findings": [finding("IAM.4", "FAILED", "CRITICAL"), finding("S3.1", "FAILED", "CRITICAL"),
                         finding("S3.2", "FAILED", "HIGH"), finding("S3.3", "PASSED", "CRITICAL")]}
    inner = t(body)["transformedResponse"]
    assert inner["criticalOpenFindingsCount"] is False and inner["openCriticalFindings"] == 2
    paged = t(dict(body, NextToken="abc"))["transformedResponse"]
    assert paged["criticalOpenFindingsCount"] is False
    assert paged["openCriticalFindings"] is None and paged["openCriticalFindingsAtLeast"] == 2
    clean = t({"Findings": [finding("S3.2", "FAILED", "HIGH"), finding("S3.3", "PASSED", "CRITICAL")]})
    assert clean["transformedResponse"]["criticalOpenFindingsCount"] is True
    assert clean["transformedResponse"]["openCriticalFindings"] == 0
    assert collection(clean)["status"] == "success"
    # more pages and nothing critical on the page read: the zero is not proven
    assert_not_evaluated(t({"Findings": [finding("S3.3", "PASSED", "CRITICAL")], "NextToken": "abc"}),
                         NONE_KEYS["criticalopenfindingscount"])


# --- compliancePercentage ---------------------------------------------------------------------

@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_compliance_percentage_keeps_a_real_zero(loader):
    t = loader("compliancepercentage")
    body = {"Findings": [finding("IAM.1", "FAILED"), finding("IAM.4", "FAILED"), finding("S3.1", "FAILED")]}
    out = t(body)
    inner = out["transformedResponse"]
    assert inner["compliancePercentage"] == 0 and inner["CIScompliancePercentage"] == 0
    assert inner["passingControls"] == 0 and inner["totalControls"] == 3
    assert collection(out)["status"] == "success"
    # more pages and a failing control on the page read: the percentage is still not a measurement
    assert_not_evaluated(t(dict(body, NextToken="abc")), NONE_KEYS["compliancepercentage"])


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_compliance_percentage_is_control_level(loader):
    t = loader("compliancepercentage")
    # two findings for one control: the control fails if any of them fails
    body = {"Findings": [finding("IAM.1", "PASSED"), finding("IAM.1", "FAILED"), finding("IAM.4", "PASSED"),
                         finding("S3.1", "WARNING")]}
    inner = t(body)["transformedResponse"]
    assert inner["compliancePercentage"] == 50 and inner["passingControls"] == 1 and inner["totalControls"] == 2
    full = t({"Findings": [finding("IAM.1", "PASSED"), finding("IAM.4", "PASSED")], "NextToken": ""})
    assert full["transformedResponse"]["compliancePercentage"] == 100
    assert full["transformedResponse"]["CIScompliancePercentage"] == 100
    assert collection(full)["status"] == "success"


# --- confirmedLicensePurchased ----------------------------------------------------------------

LICENSE_CASES = [
    ("subscription", {"subscription": "enterprise"}, True),
    ("sku", {"sku": "SH-1"}, True),
    ("license", {"license": {"id": 1}}, True),
    ("licenses", {"licenses": [{"id": 1}]}, True),
    ("active", {"active": True}, True),
    ("enabled", {"enabled": True}, True),
    ("findings list", {"Findings": [finding("IAM.4", "PASSED")]}, True),
    ("empty findings list (the query ran)", {"Findings": []}, True),
    ("wrapped result", {"result": {"subscription": "x"}}, True),
    ("wrapped response", {"response": {"Findings": [finding("IAM.4", "FAILED")]}}, True),
    ("no licences", {"licenses": []}, False),
    ("inactive", {"active": False}, False),
    ("disabled", {"enabled": False}, False),
]


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
@pytest.mark.parametrize("label,body,expected", LICENSE_CASES, ids=[c[0] for c in LICENSE_CASES])
def test_license_readable_answers_keep_their_verdict(loader, label, body, expected):
    out = loader("confirmedlicensepurchased")(body)
    assert verdict(out, "confirmedLicensePurchased") == (expected, "success")
    assert "additionalInfo" in out


@pytest.mark.parametrize("loader", LOADERS, ids=LOADER_IDS)
def test_license_findings_count_is_reported(loader):
    out = loader("confirmedlicensepurchased")({"Findings": [finding("IAM.4", "PASSED"), finding("IAM.5", "PASSED")]})
    assert out["transformedResponse"]["findingsCount"] == 2
    assert out["transformedResponse"]["status"] == "enabled"
