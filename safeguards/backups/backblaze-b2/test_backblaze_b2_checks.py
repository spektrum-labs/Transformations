"""Backblaze B2 checks read from the native API v4: b2_list_buckets and b2_list_keys.

Bodies follow Backblaze's public API reference (backblaze.com/apidocs/b2-list-buckets and
b2-list-keys); every id, name and value is synthetic. Each check is run both as plain Python and in the
RestrictedPython sandbox the evaluator uses. Each key has a pass body, a fail body, and bodies that prove
nothing, which must come back None with dataCollection "error" (not evaluated), never a verdict.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_backblaze_b2", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    SANDBOX = sandbox.load
except ImportError:
    SANDBOX = None


def load_plain(code, filename):
    ns = {"__name__": "backblaze_b2_" + filename}
    exec(compile(code, filename, "exec"), ns)
    return ns


LOADERS = [pytest.param(load_plain, id="plain")]
if SANDBOX is not None:
    LOADERS.append(pytest.param(SANDBOX, id="sandbox"))


@pytest.fixture(params=LOADERS)
def run(request):
    loader = request.param

    def go(key, body):
        out = loader((HERE / (key.lower() + ".py")).read_text(), key)["transform"](body)
        return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]
    return go


def wrap(inner):
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


OWN_A = "4a48fe8875c6214145260818"
OWN_B = "5b59af9986d7325256371929"
OTHER_ACCOUNT_BUCKET = "9f00aa11bb22cc33dd44ee55"


def bucket(name, bucket_id, kind="allPrivate", encryption="SSE-B2", lock=None, replicate_to=None,
           replication_readable=True):
    """A b2_list_buckets entry. encryption=False hides it (no readBucketEncryption); lock is None (off),
    False (unreadable), "bare" (on, no default retention) or (mode, days)."""
    entry = {"accountId": "a1b2c3d4e5f6", "bucketId": bucket_id, "bucketName": name, "bucketType": kind,
             "bucketInfo": {}, "corsRules": [], "lifecycleRules": [], "options": ["s3"], "revision": 3}
    if encryption is False:
        entry["defaultServerSideEncryption"] = {"isClientAuthorizedToRead": False, "value": None}
    else:
        entry["defaultServerSideEncryption"] = {"isClientAuthorizedToRead": True, "value": {
            "algorithm": "AES256" if encryption else None, "mode": encryption}}
    if lock is False:
        entry["fileLockConfiguration"] = {"isClientAuthorizedToRead": False, "value": None}
    elif lock is None:
        entry["fileLockConfiguration"] = {"isClientAuthorizedToRead": True, "value": {
            "defaultRetention": {"mode": None, "period": None}, "isFileLockEnabled": False}}
    elif lock == "bare":
        entry["fileLockConfiguration"] = {"isClientAuthorizedToRead": True, "value": {
            "defaultRetention": {"mode": None, "period": None}, "isFileLockEnabled": True}}
    else:
        entry["fileLockConfiguration"] = {"isClientAuthorizedToRead": True, "value": {
            "defaultRetention": {"mode": lock[0], "period": {"duration": lock[1], "unit": "days"}},
            "isFileLockEnabled": True}}
    if not replication_readable:
        entry["replicationConfiguration"] = {"isClientAuthorizedToRead": False, "value": None}
    else:
        rules = [{"destinationBucketId": dest, "fileNamePrefix": "", "includeExistingFiles": True,
                  "isEnabled": True, "priority": 1, "replicationRuleName": "rule-" + str(i)}
                 for i, dest in enumerate(replicate_to or [])]
        entry["replicationConfiguration"] = {"isClientAuthorizedToRead": True, "value": {
            "asReplicationSource": {"replicationRules": rules, "sourceApplicationKeyId": "0051key0000000001"}
            if rules else None, "asReplicationDestination": None}}
    return entry


def buckets(*entries):
    return wrap({"buckets": list(entries)})


def key(name, expires=1893456000000, capabilities=("listBuckets", "listKeys"), bucket_ids=None):
    return {"accountId": "a1b2c3d4e5f6", "applicationKeyId": "0051" + name.replace("-", "")[:12].ljust(12, "0"),
            "keyName": name, "capabilities": list(capabilities), "expirationTimestamp": expires,
            "bucketIds": bucket_ids, "namePrefix": None, "options": ["s3"]}


def keys(*entries, more=None):
    return wrap({"keys": list(entries), "nextApplicationKeyId": more})


SPEKTRUM_KEY = key("spektrum-readonly", capabilities=(
    "listBuckets", "listKeys", "readBucketEncryption", "readBucketReplications", "readBucketRetentions"))

BUCKET_KEYS = ["isArchivedDataAccessRestricted", "isBackupEncrypted", "isExternalTargetEncryptionAES256",
               "isBackupImmutable", "isDataLockComplianceModeEnabled", "isDeletionRetentionPeriodEnforced",
               "objectLockCoveragePercentage", "isGeoRedundant", "isCrossAccountBackupEnabled"]
KEY_KEYS = ["nonExpiringApplicationKeysCount", "governanceBypassKeysCount", "unscopedDeleteCapableKeysCount"]

NO_EVIDENCE = {
    "none": None,
    "empty_dict": {},
    "empty_list": [],
    "empty_string": "",
    "html": "<html><body>Sign in</body></html>",
    "unrelated": {"foo": "bar"},
    "not_available": {"status": "Not Available"},
    "b2_401": wrap({"status": 401, "code": "unauthorized", "message": "not authorized"}),
    "b2_expired": {"status": 401, "code": "expired_auth_token", "message": "Authorization token has expired"},
    "envelope_error": {"error": True, "statusCode": 403, "message": "Forbidden"},
    "wrapped_null": wrap(None),
}


@pytest.mark.parametrize("criteria_key", BUCKET_KEYS + KEY_KEYS)
@pytest.mark.parametrize("case", sorted(NO_EVIDENCE))
def test_no_evidence_is_not_evaluated(run, criteria_key, case):
    assert run(criteria_key, copy.deepcopy(NO_EVIDENCE[case])) == (None, "error")


@pytest.mark.parametrize("criteria_key", BUCKET_KEYS)
def test_empty_bucket_list_is_not_evaluated(run, criteria_key):
    assert run(criteria_key, buckets()) == (None, "error")


@pytest.mark.parametrize("criteria_key", KEY_KEYS)
def test_empty_or_partial_key_list_is_not_evaluated(run, criteria_key):
    assert run(criteria_key, keys()) == (None, "error")
    assert run(criteria_key, keys(SPEKTRUM_KEY, more="0051nextpage00001")) == (None, "error")


def test_a_json_string_body_is_read(run):
    import json
    body = {"data": {"apiResponse": json.dumps({"buckets": [bucket("backups", OWN_A)]})},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}
    assert run("isArchivedDataAccessRestricted", body) == (True, "success")


# ---- isArchivedDataAccessRestricted -------------------------------------------------------

def test_private_buckets_pass_and_a_public_one_fails(run):
    k = "isArchivedDataAccessRestricted"
    assert run(k, buckets(bucket("backups", OWN_A), bucket("snaps", OWN_B, kind="snapshot"))) == (True, "success")
    assert run(k, buckets(bucket("backups", OWN_A), bucket("site", OWN_B, kind="allPublic"))) == (False, "success")
    assert run(k, buckets(bucket("backups", OWN_A), bucket("odd", OWN_B, kind="futureType"))) == (None, "error")


def test_a_restricted_bucket_counts_as_private(run):
    # bucketTypes ["all"] lists "restricted" buckets; they are private, not an unknown type.
    k = "isArchivedDataAccessRestricted"
    assert run(k, buckets(bucket("backups", OWN_A), bucket("vault", OWN_B, kind="restricted"))) == (True, "success")
    assert run(k, buckets(bucket("vault", OWN_A, kind="restricted"), bucket("site", OWN_B, kind="allPublic"))) == (
        False, "success")


# ---- encryption ---------------------------------------------------------------------------

def test_encryption_reads_the_effective_default(run):
    for k in ("isBackupEncrypted", "isExternalTargetEncryptionAES256"):
        assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B))) == (True, "success")
        assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, encryption=None))) == (False, "success")
        assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, encryption=False))) == (None, "error")
        # a definite failure is not hidden by an unreadable sibling
        assert run(k, buckets(bucket("a", OWN_A, encryption=None), bucket("b", OWN_B, encryption=False))) == (
            False, "success")


def test_aes256_needs_the_algorithm(run):
    body = buckets(bucket("a", OWN_A))
    body["data"]["apiResponse"]["buckets"][0]["defaultServerSideEncryption"]["value"]["algorithm"] = "AES128"
    assert run("isExternalTargetEncryptionAES256", body) == (False, "success")
    assert run("isBackupEncrypted", body) == (True, "success")


# ---- Object Lock --------------------------------------------------------------------------

def test_immutable_needs_a_locked_bucket_with_default_retention(run):
    k = "isBackupImmutable"
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, lock=("governance", 30)))) == (True, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, lock="bare"))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, lock=False))) == (None, "error")
    assert run(k, buckets(bucket("a", OWN_A, lock=("compliance", 7)), bucket("b", OWN_B, lock=False))) == (
        True, "success")


def test_compliance_mode_is_not_governance_mode(run):
    k = "isDataLockComplianceModeEnabled"
    assert run(k, buckets(bucket("a", OWN_A, lock=("compliance", 30)))) == (True, "success")
    assert run(k, buckets(bucket("a", OWN_A, lock=("governance", 30)))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A, lock=("compliance", 0)))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A, lock=("governance", 30)), bucket("b", OWN_B, lock=False))) == (
        None, "error")


def test_retention_period_is_enforced_on_every_lock_bucket(run):
    k = "isDeletionRetentionPeriodEnforced"
    assert run(k, buckets(bucket("a", OWN_A, lock=("governance", 30)), bucket("b", OWN_B))) == (True, "success")
    assert run(k, buckets(bucket("a", OWN_A, lock=("governance", 30)), bucket("b", OWN_B, lock="bare"))) == (
        False, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A, lock=("governance", 30)), bucket("b", OWN_B, lock=False))) == (
        None, "error")


def test_retention_in_years_counts(run):
    assert run("isBackupImmutable", buckets(bucket("a", OWN_A, lock=("compliance", 1)))) == (True, "success")
    body = buckets(bucket("a", OWN_A, lock=("compliance", 1)))
    body["data"]["apiResponse"]["buckets"][0]["fileLockConfiguration"]["value"]["defaultRetention"]["period"] = {
        "duration": 1, "unit": "years"}
    assert run("isDeletionRetentionPeriodEnforced", body) == (True, "success")


def test_object_lock_coverage_is_a_floor_over_private_buckets(run):
    k = "objectLockCoveragePercentage"
    assert run(k, buckets(bucket("a", OWN_A, lock="bare"), bucket("b", OWN_B, lock=("compliance", 7)))) == (
        100, "success")
    three = buckets(bucket("a", OWN_A, lock="bare"), bucket("b", OWN_B), bucket("c", "6c60", lock=None),
                    bucket("site", "7d71", kind="allPublic"))
    assert run(k, three) == (33, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B))) == (0, "success")
    assert run(k, buckets(bucket("site", OWN_A, kind="allPublic", lock="bare"))) == (None, "error")
    assert run(k, buckets(bucket("a", OWN_A, lock="bare"), bucket("b", OWN_B, lock=False))) == (None, "error")


def test_object_lock_coverage_counts_restricted_buckets(run):
    k = "objectLockCoveragePercentage"
    assert run(k, buckets(bucket("a", OWN_A, lock="bare"), bucket("vault", OWN_B, kind="restricted"))) == (
        50, "success")


def test_replication_to_a_restricted_sibling_is_inside_the_account(run):
    # With every bucket type listed, a same-account "restricted" destination is one of our own buckets.
    k = "isCrossAccountBackupEnabled"
    assert run(k, buckets(bucket("a", OWN_A, replicate_to=[OWN_B]), bucket("vault", OWN_B, kind="restricted"))) == (
        False, "success")


# ---- replication --------------------------------------------------------------------------

def test_cross_account_needs_a_destination_outside_the_account(run):
    k = "isCrossAccountBackupEnabled"
    assert run(k, buckets(bucket("a", OWN_A, replicate_to=[OTHER_ACCOUNT_BUCKET]), bucket("b", OWN_B))) == (
        True, "success")
    assert run(k, buckets(bucket("a", OWN_A, replicate_to=[OWN_B]), bucket("b", OWN_B))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B, replication_readable=False))) == (None, "error")


def test_a_disabled_rule_is_no_replication(run):
    body = buckets(bucket("a", OWN_A, replicate_to=[OTHER_ACCOUNT_BUCKET]))
    body["data"]["apiResponse"]["buckets"][0]["replicationConfiguration"]["value"]["asReplicationSource"][
        "replicationRules"][0]["isEnabled"] = False
    assert run("isCrossAccountBackupEnabled", body) == (False, "success")


def test_replication_settings_missing_from_the_body_are_not_read_as_off(run):
    body = buckets(bucket("a", OWN_A))
    del body["data"]["apiResponse"]["buckets"][0]["replicationConfiguration"]
    assert run("isCrossAccountBackupEnabled", body) == (None, "error")
    assert run("isGeoRedundant", body) == (None, "error")


def test_geo_redundancy_is_false_without_outbound_replication_and_never_asserted(run):
    k = "isGeoRedundant"
    assert run(k, buckets(bucket("a", OWN_A), bucket("b", OWN_B))) == (False, "success")
    assert run(k, buckets(bucket("a", OWN_A, replicate_to=[OWN_B]), bucket("b", OWN_B))) == (False, "success")
    # another account may or may not be another region; the source cannot see it
    assert run(k, buckets(bucket("a", OWN_A, replicate_to=[OTHER_ACCOUNT_BUCKET]))) == (None, "error")
    assert run(k, buckets(bucket("a", OWN_A, replication_readable=False))) == (None, "error")


def test_unwrapped_replication_shape_is_read(run):
    body = buckets(bucket("a", OWN_A))
    body["data"]["apiResponse"]["buckets"][0]["replicationConfiguration"] = {"asReplicationSource": {
        "replicationRules": [{"destinationBucketId": OTHER_ACCOUNT_BUCKET, "isEnabled": True, "priority": 1,
                              "fileNamePrefix": "", "includeExistingFiles": False, "replicationRuleName": "r"}],
        "sourceApplicationKeyId": "0051key0000000001"}}
    assert run("isCrossAccountBackupEnabled", body) == (True, "success")


# ---- application keys ---------------------------------------------------------------------

def test_non_expiring_keys_are_counted(run):
    k = "nonExpiringApplicationKeysCount"
    assert run(k, keys(SPEKTRUM_KEY, key("backup-job"))) == (0, "success")
    assert run(k, keys(SPEKTRUM_KEY, key("old-sync", expires=None), key("legacy", expires=None))) == (2, "success")


def test_governance_bypass_keys_are_counted(run):
    k = "governanceBypassKeysCount"
    assert run(k, keys(SPEKTRUM_KEY, key("backup-job", capabilities=("writeFiles", "readFiles")))) == (0, "success")
    assert run(k, keys(SPEKTRUM_KEY, key("admin", capabilities=("deleteFiles", "bypassGovernance")))) == (
        1, "success")
    broken = key("odd")
    broken["capabilities"] = None
    assert run(k, keys(SPEKTRUM_KEY, broken)) == (None, "error")


def test_unscoped_delete_capable_keys_are_counted(run):
    k = "unscopedDeleteCapableKeysCount"
    scoped = key("job", capabilities=("writeFiles", "deleteFiles"), bucket_ids=[OWN_A])
    assert run(k, keys(SPEKTRUM_KEY, scoped)) == (0, "success")
    everywhere = key("cleanup", capabilities=("listFiles", "deleteFiles"))
    minter = key("ops", capabilities=("writeKeys",))
    assert run(k, keys(SPEKTRUM_KEY, scoped, everywhere, minter)) == (2, "success")
    legacy = key("legacy", capabilities=("deleteBuckets",))
    del legacy["bucketIds"]
    legacy["bucketId"] = OWN_B
    assert run(k, keys(SPEKTRUM_KEY, legacy)) == (0, "success")
    broken = key("odd")
    broken["capabilities"] = "deleteFiles"
    assert run(k, keys(SPEKTRUM_KEY, broken)) == (None, "error")


def test_a_poisoned_body_is_not_evaluated(run):
    class Poisoned(dict):
        def __init__(self):
            super().__init__(buckets=True)

        def boom(self, *args, **kwargs):
            raise RuntimeError("poisoned read")

        get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    for criteria_key in BUCKET_KEYS + KEY_KEYS:
        value, status = run(criteria_key, Poisoned())
        assert value is None and status == "error"


def test_reasons_carry_no_vendor_message_text(run):
    body = wrap({"status": 401, "code": "unauthorized", "message": "SECRET-LOOKING-TEXT"})
    for criteria_key in BUCKET_KEYS + KEY_KEYS:
        out = load_plain((HERE / (criteria_key.lower() + ".py")).read_text(), criteria_key)["transform"](body)
        errors = out["additionalInfo"]["dataCollection"]["errors"]
        assert errors and "SECRET-LOOKING-TEXT" not in " ".join(errors)
        assert "status 401, unauthorized" in errors[0]
