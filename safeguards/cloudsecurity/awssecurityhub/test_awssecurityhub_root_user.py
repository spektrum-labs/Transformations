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

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

NO_EVIDENCE = [{}, None, "{}", "", {"error": {"type": "authentication_error"}},
               {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
               {"error": True, "message": "upstream timeout"}, {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}]


def plain(name):
    spec = importlib.util.spec_from_file_location("awsroot_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, str(ROOT / "tools"))
    import restricted_sandbox
    return restricted_sandbox.load((HERE / (name + ".py")).read_text())["transform"]


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
