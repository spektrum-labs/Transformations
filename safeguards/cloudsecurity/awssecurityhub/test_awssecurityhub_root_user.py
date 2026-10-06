"""AWS root user lockdown (IAM-004): isRootUserAccessKeyRestricted and isRootUserMFAEnabled,
from the IAM credential report, the IAM account summary and Security Hub control IAM.4.

Fixtures in fixtures/ are built from the vendor's documented response shape with every name,
id and account replaced (example.com, 111111111111). Each case runs twice: imported as plain
Python, and compiled and run in the production RestrictedPython sandbox (tools/restricted_sandbox.py)
when RestrictedPython is installed."""
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

NO_EVIDENCE = [{}, None, "{}", "", {"error": {"type": "authentication_error"}},
               {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
               {"error": True, "message": "upstream timeout"}, {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}]

#: The fixtures' credential reports carry GeneratedTime 2026-10-06T14:00:00Z. Fixture runs pin
#: the evaluation clock one hour later so the 24-hour report-age limit does not drift with the
#: wall clock. REAL_CLOCK leaves the transform's own datetime.utcnow() in place.
CLOCK = datetime(2026, 10, 6, 15, 0, 0)
REAL_CLOCK = object()


def plain(name, now=CLOCK):
    spec = importlib.util.spec_from_file_location("awsroot_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if now is not REAL_CLOCK:
        module.evaluation_now = lambda: now
    return module.transform


def sandboxed(name, now=CLOCK):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, str(ROOT / "tools"))
    import restricted_sandbox
    namespace = restricted_sandbox.load((HERE / (name + ".py")).read_text())
    if now is not REAL_CLOCK:
        namespace["evaluation_now"] = lambda: now
    return namespace["transform"]


LOADERS = [plain, sandboxed]


def fixture(name):
    return json.loads((HERE / "fixtures" / name).read_text())


def verdict(out, key):
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


CASES = [
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'credential_report_root_locked_down.json', True),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'credential_report_root_active_key.json', False),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'credential_report_in_progress.json', None),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'account_summary_root_mfa_no_keys.json', True),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'account_summary_root_no_mfa_with_keys.json', False),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'securityhub_iam4_passed.json', True),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'securityhub_iam4_failed.json', False),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'securityhub_no_iam4.json', None),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'securityhub_iam4_archived_passed_only.json', None),
    ('isrootuseraccesskeyrestricted', 'isRootUserAccessKeyRestricted', 'securityhub_iam4_archived_failed_active_passed.json', True),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'credential_report_root_locked_down.json', True),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'credential_report_root_never_signed_in.json', True),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'credential_report_root_no_mfa.json', False),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'credential_report_root_signed_in_recently.json', False),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'credential_report_in_progress.json', None),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'account_summary_root_mfa_no_keys.json', None),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'account_summary_root_no_mfa_with_keys.json', False),
    ('isrootusermfaenabled', 'isRootUserMFAEnabled', 'securityhub_iam4_passed.json', None),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key,fixture_name,expected", CASES)
def test_fixture(loader, module, key, fixture_name, expected):
    value, status = verdict(loader(module)(fixture(fixture_name)), key)
    assert value is expected
    assert status == ("error" if expected is None else "success")


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", sorted(set((c[0], c[1]) for c in CASES)))
@pytest.mark.parametrize("body", NO_EVIDENCE, ids=[str(i) for i in range(len(NO_EVIDENCE))])
def test_no_evidence_is_not_evaluated(loader, module, key, body):
    value, status = verdict(loader(module)(body), key)
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key,fixture_name,expected", [c for c in CASES if c[3] is not None][:2])
def test_json_string_input_matches_dict(loader, module, key, fixture_name, expected):
    body = (HERE / "fixtures" / fixture_name).read_text()
    assert verdict(loader(module)(body), key)[0] is expected


# --- IAM.4 findings: RecordState, Workflow.Status and paging ---------------------------------

def iam4(status, record_state="ACTIVE", workflow="NEW"):
    return {"Compliance": {"Status": status, "SecurityControlId": "IAM.4"},
            "RecordState": record_state, "Workflow": {"Status": workflow}}


IAM4_CASES = [
    ("suppressed FAILED alone", {"Findings": [iam4("FAILED", workflow="SUPPRESSED")]}, None),
    ("suppressed FAILED beside active PASSED", {"Findings": [iam4("FAILED", workflow="SUPPRESSED"), iam4("PASSED")]}, True),
    ("archived and suppressed only", {"Findings": [iam4("PASSED", "ARCHIVED"), iam4("PASSED", workflow="SUPPRESSED")]}, None),
    ("active FAILED beside archived PASSED", {"Findings": [iam4("PASSED", "ARCHIVED"), iam4("FAILED")]}, False),
    ("PASSED with more pages", {"Findings": [iam4("PASSED")], "NextToken": "abc"}, None),
    ("FAILED with more pages", {"Findings": [iam4("FAILED")], "NextToken": "abc"}, False),
    ("PASSED with empty NextToken", {"Findings": [iam4("PASSED")], "NextToken": ""}, True),
    ("PASSED with null NextToken", {"Findings": [iam4("PASSED")], "NextToken": None}, True),
    ("no IAM.4 with more pages", {"Findings": [], "NextToken": "abc"}, None),
    ("wrapped, PASSED with more pages", {"api_response": {"Findings": [iam4("PASSED")], "NextToken": "abc"}}, None),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("label,body,expected", IAM4_CASES, ids=[c[0] for c in IAM4_CASES])
def test_iam4_record_state_workflow_and_paging(loader, label, body, expected):
    value, status = verdict(loader("isrootuseraccesskeyrestricted")(body), "isRootUserAccessKeyRestricted")
    assert value is expected
    assert status == ("error" if expected is None else "success")


# --- credential report age (GeneratedTime against the evaluation clock) -----------------------

REPORT_MODULES = [("isrootuseraccesskeyrestricted", "isRootUserAccessKeyRestricted"),
                  ("isrootusermfaenabled", "isRootUserMFAEnabled")]
GENERATED = datetime(2026, 10, 6, 14, 0, 0)


def with_generated_time(value, name="credential_report_root_locked_down.json"):
    body = fixture(name)
    result = body["GetCredentialReportResponse"]["GetCredentialReportResult"]
    if value is None:
        result.pop("GeneratedTime", None)
    else:
        result["GeneratedTime"] = value
    return body


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", REPORT_MODULES)
@pytest.mark.parametrize("now,expected", [
    (GENERATED + timedelta(hours=24), True),
    (GENERATED + timedelta(hours=24, seconds=1), None),
    (GENERATED + timedelta(days=120), None),
    (GENERATED - timedelta(minutes=30), True),
    (GENERATED - timedelta(hours=2), None),
], ids=["24h-old", "just-over-24h", "120-days-old", "30min-skew", "2h-in-future"])
def test_report_age_limit(loader, module, key, now, expected):
    value, status = verdict(loader(module, now)(fixture("credential_report_root_locked_down.json")), key)
    assert value is expected
    assert status == ("error" if expected is None else "success")


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", REPORT_MODULES)
@pytest.mark.parametrize("generated", [None, "", "yesterday", "2026-13-40T00:00:00Z", 1759759200],
                         ids=["missing", "empty", "word", "bad-date", "epoch-int"])
def test_report_without_usable_generated_time_is_not_evaluated(loader, module, key, generated):
    value, status = verdict(loader(module)(with_generated_time(generated)), key)
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", REPORT_MODULES)
def test_stale_report_hides_nothing_even_when_it_would_fail(loader, module, key):
    """A 30-day-old report is not evaluated whatever it says: a stale True and a stale False are
    both unproven."""
    stale = loader(module, GENERATED + timedelta(days=30))
    for name in ("credential_report_root_active_key.json", "credential_report_root_no_mfa.json"):
        value, status = verdict(stale(fixture(name)), key)
        assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", REPORT_MODULES)
def test_fresh_report_on_the_real_clock(loader, module, key):
    """The production clock (datetime.utcnow()) accepts a report generated an hour ago."""
    fresh = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    value, status = verdict(loader(module, REAL_CLOCK)(with_generated_time(fresh)), key)
    assert value is True and status == "success"
