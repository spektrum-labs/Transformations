"""Azure Backup: isBackupEncrypted, confirmedLicensePurchased, isBackupImmutable.

Every case runs twice, once as plain Python and once in the RestrictedPython namespace
production uses (tools/restricted_sandbox.py), and every body is fed in the shapes the
transforms meet:

  * drilled   -- what production Token-Service passes a legacy transform: its envelope drill
                 (response / result / apiResponse / Output / data) reduces a Resource Graph
                 objectArray body to the bare row list and a `table` body to {columns, rows}
  * envelope  -- the undrilled Resource Graph body, as a stored response or replay holds it
  * wrapped   -- the envelope inside an Integration-Service style {"response": ...} wrapper
  * text      -- the envelope as a JSON string
  * stringified -- the envelope with every leaf a string, as Token-Service stores it

All fixtures are synthetic.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TAG = "azure_backup_vault_checks"

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # without RestrictedPython the "sandbox" leg runs as plain exec (CI installs
    # requirements-test.txt, which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

FILES = {
    "isBackupEncrypted": "is_backup_encrypted.py",
    "confirmedLicensePurchased": "confirmedlicensepurchased.py",
    "isBackupImmutable": "is_backup_immutable.py",
}


def transform_for(key, mode):
    path = HERE / FILES[key]
    if mode == "sandbox":
        return load_code(path.read_text(), str(path))["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


SUB = "00000000-0000-0000-0000-000000000000"


def vault_id(name, kind="Microsoft.RecoveryServices/vaults"):
    return "/subscriptions/" + SUB + "/resourceGroups/rg-test/providers/" + kind + "/" + name


def list_vault(name):
    """A listVaults row (projection: name, location, id, subscriptionId, resourceGroup, subscriptionName)."""
    return {"name": name, "location": "eastus", "id": vault_id(name), "subscriptionId": SUB,
            "resourceGroup": "rg-test", "subscriptionName": "sub-test"}


def lock_vault(name, immutability="absent", kind="microsoft.recoveryservices/vaults", properties=True):
    """A getBackupVaultLockConfiguration row; immutability: absent | None | a state string."""
    security = {"softDeleteSettings": {"softDeleteState": "Enabled", "softDeleteRetentionPeriodInDays": 14}}
    if immutability != "absent":
        security["immutabilitySettings"] = None if immutability is None else {"state": immutability}
    row = {"name": name, "type": kind, "subscriptionId": SUB, "resourceGroup": "rg-test", "location": "eastus",
           "softDeleteState": "", "isSoftDeleteEnabled": True, "hasRetentionPeriod": True, "isImmutable": True}
    if properties:
        row["properties"] = {"provisioningState": "Succeeded", "securitySettings": security}
    return row


def policy(name, vault="vault-a", items=3):
    return {"name": name, "vaultName": vault, "resourceGroup": "rg-test", "subscriptionId": SUB,
            "type": "microsoft.recoveryservices/vaults/backuppolicies", "scheduleType": "Daily",
            "hasSchedule": True, "properties": {"protectedItemsCount": items, "backupManagementType": "AzureIaasVM"}}


def object_array(rows, truncated=False):
    return {"totalRecords": len(rows), "count": len(rows), "data": rows, "facets": [],
            "resultTruncated": "true" if truncated else "false"}


def table(objects, truncated=False):
    return {"totalRecords": len(objects), "count": len(objects),
            "data": {"columns": [{"name": "result", "type": "object"}], "rows": [[o] for o in objects]},
            "facets": [], "resultTruncated": "true" if truncated else "false"}


def stringify(value):
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return "" if value is None else str(value)


def drill(body):
    """Token-Service's legacy envelope drill (codeexecutor._parse_api_response_for_transformer)."""
    current = body
    for key in ("response", "result", "apiResponse", "Output", "data"):
        if isinstance(current, dict) and key in current:
            current = current[key]
    return current


SHAPES = {
    "drilled": drill,
    "envelope": lambda body: body,
    "wrapped": lambda body: {"response": body},
    "text": json.dumps,
    "stringified": stringify,
    "stringified_drilled": lambda body: drill(stringify(body)),
}
MODES = ["python", "sandbox"]


def verdict(key, mode, payload):
    out = transform_for(key, mode)(payload)
    value = out["transformedResponse"][key]
    collection = out["additionalInfo"]["dataCollection"]
    if value is None:
        # Not evaluated must be visible to Token-Service: dataCollection.status "error" with a reason
        assert collection["status"] == "error" and collection["errors"], out
    else:
        assert collection["status"] == "success", out
    return value, out


# ---------------------------------------------------------------- isBackupEncrypted

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_encrypted_true_for_vaults_in_every_input_shape(mode, shape):
    body = object_array([list_vault("vault-a"), list_vault("vault-b")])
    value, out = verdict("isBackupEncrypted", mode, SHAPES[shape](body))
    assert value is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["vaultCount"] == 2
    assert "vault-a" in out["additionalInfo"]["evaluation"]["passReasons"][0]


@pytest.mark.parametrize("mode", MODES)
def test_encrypted_reports_customer_managed_keys(mode):
    row = list_vault("vault-cmk")
    row["properties"] = {"encryption": {"keyVaultProperties": {"keyUri": "https://kv-test.vault.azure.net/keys/k1"}}}
    value, out = verdict("isBackupEncrypted", mode, drill(object_array([row, list_vault("vault-pmk")])))
    assert value is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["customerManagedKeyVaults"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_encrypted_null_when_list_truncated(mode):
    value, _ = verdict("isBackupEncrypted", mode, object_array([list_vault("vault-a")], truncated=True))
    assert value is None


# ---------------------------------------------------------------- confirmedLicensePurchased

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_license_true_for_policies_in_every_input_shape(mode, shape):
    body = table([policy("pol-daily"), policy("pol-hourly", items=0)])
    value, out = verdict("confirmedLicensePurchased", mode, SHAPES[shape](body))
    assert value is True
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["policyCount"] == 2 and summary["protectedItemsCount"] == 3


@pytest.mark.parametrize("mode", MODES)
def test_license_reads_object_array_and_truncated_lists(mode):
    assert verdict("confirmedLicensePurchased", mode, object_array([policy("pol-a")]))[0] is True
    # more rows can only add policies, so a truncated list that holds one still confirms
    assert verdict("confirmedLicensePurchased", mode, table([policy("pol-a")], truncated=True))[0] is True


@pytest.mark.parametrize("mode", MODES)
def test_license_null_for_malformed_table(mode):
    bad = {"columns": [{"name": "a"}, {"name": "b"}], "rows": [[policy("pol-a")]]}
    assert verdict("confirmedLicensePurchased", mode, bad)[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_license_null_when_rows_are_not_policies(mode):
    assert verdict("confirmedLicensePurchased", mode, table([list_vault("vault-a")]))[0] is None


# ---------------------------------------------------------------- isBackupImmutable

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("state,expected", [("Locked", True), ("Unlocked", True), ("Disabled", False)])
def test_immutable_reads_vault_state_in_every_input_shape(mode, shape, state, expected):
    body = object_array([lock_vault("vault-a", state), lock_vault("vault-b", "Locked")])
    value, out = verdict("isBackupImmutable", mode, SHAPES[shape](body))
    assert value is expected
    if expected is False:
        assert "vault-a" in out["additionalInfo"]["evaluation"]["failReasons"][0]
        assert "vault-b" not in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("immutability", ["absent", None])
def test_immutable_false_when_setting_absent_from_readable_properties(mode, immutability):
    # soft delete on and the query's soft-delete isImmutable column true: still not immutability
    value, out = verdict("isBackupImmutable", mode, drill(object_array([lock_vault("vault-a", immutability)])))
    assert value is False
    assert out["additionalInfo"]["transformation"]["inputSummary"]["mutableVaults"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_immutable_backup_vault_type_is_read(mode):
    row = lock_vault("bv-a", "Locked", kind="microsoft.dataprotection/backupvaults")
    assert verdict("isBackupImmutable", mode, drill(object_array([row])))[0] is True


@pytest.mark.parametrize("mode", MODES)
def test_immutable_null_when_a_vault_is_unreadable_and_none_is_off(mode):
    rows = [lock_vault("vault-a", "Locked"), lock_vault("vault-b", properties=False)]
    assert verdict("isBackupImmutable", mode, drill(object_array(rows)))[0] is None
    rows = [lock_vault("vault-a", "Locked"), lock_vault("vault-b", "SomethingNew")]
    assert verdict("isBackupImmutable", mode, drill(object_array(rows)))[0] is None


@pytest.mark.parametrize("mode", MODES)
def test_immutable_off_vault_is_a_finding_even_beside_an_unreadable_one(mode):
    rows = [lock_vault("vault-a", "Disabled"), lock_vault("vault-b", properties=False)]
    value, out = verdict("isBackupImmutable", mode, drill(object_array(rows)))
    assert value is False
    assert out["additionalInfo"]["transformation"]["inputSummary"]["unreadableVaults"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_immutable_null_when_all_on_but_list_truncated(mode):
    assert verdict("isBackupImmutable", mode, object_array([lock_vault("vault-a", "Locked")], truncated=True))[0] is None


# ---------------------------------------------------------------- no evidence: never a verdict

NO_EVIDENCE = {
    "none": None,
    "empty_dict": {},
    "empty_text": "",
    "empty_object_text": "{}",
    "empty_list_drilled": [],
    "empty_object_array": {"totalRecords": 0, "count": 0, "data": [], "resultTruncated": "false"},
    "empty_object_array_stringified": {"totalRecords": "0", "count": "0", "data": [], "resultTruncated": "false"},
    "empty_table": {"columns": [{"name": "result", "type": "object"}], "rows": []},
    "azure_error": {"error": {"code": "AuthorizationFailed", "message": "The client does not have authorization"}},
    "azure_error_wrapped": {"response": {"error": {"code": "InvalidAuthenticationToken", "message": "expired"}}},
    "is_error_envelope": {"error": True, "message": "Request failed with status 403"},
    "status_403": {"statusCode": 403, "error": "Forbidden"},
    "status_401_text": {"status_code": "401", "message": "Unauthorized"},
    "error_row": [{"error": {"code": "BadRequest", "message": "query failed"}}],
    "unrelated_json": {"hello": "world"},
    "unrelated_nested": {"foo": {"bar": [1, 2, 3]}},
    "unrelated_rows": [{"enabled": True, "status": "active"}],
    "data_null": {"data": None},
    "non_json_text": "upstream timeout",
    "number": 7,
    "bytes": b"{}",
}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", sorted(FILES))
@pytest.mark.parametrize("case", sorted(NO_EVIDENCE))
def test_no_evidence_is_not_evaluated(mode, key, case):
    value, out = verdict(key, mode, NO_EVIDENCE[case])
    assert value is None, (case, out)
