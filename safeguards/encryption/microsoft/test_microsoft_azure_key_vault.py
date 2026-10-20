"""Microsoft Azure Key Vault (Encryption): the 13 measured criteria in this directory.

Fixture shapes follow Microsoft's published responses, with placeholder ids and names:
  vault          https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2023-07-01
  connections    https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/private-endpoint-connections/list-by-resource?view=rest-keyvault-keyvault-2023-07-01
  pricing        https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/get?view=rest-defenderforcloud-2024-01-01
  diagnostics    https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview
  policy states  https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/list-query-results-for-resource?view=rest-policyinsights-2019-10-01
  keys           https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-7.4
  certificates   https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-7.4
  ARM errors     https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/common-deployment-errors

isAzureADAuthEnabled, isDataInTransitEncrypted and isDataAtRestEncrypted are platform constants
and are deliberately not driven here.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

SUB = "00000000-0000-0000-0000-000000000000"
TENANT = "11111111-1111-1111-1111-111111111111"
VAULT_ID = ("/subscriptions/" + SUB + "/resourceGroups/sample-group/providers/"
            "Microsoft.KeyVault/vaults/sample-vault")
SUBNET_ID = ("/subscriptions/" + SUB + "/resourceGroups/sample-group/providers/"
             "Microsoft.Network/virtualNetworks/sample-vnet/subnets/sample-subnet")

KEYS = [
    "certificatesHaveValidityPeriod",
    "isAzurePolicyCompliant",
    "isDefenderForKeyVaultEnabled",
    "isDiagnosticLoggingEnabled",
    "isFirewallEnabled",
    "isManagedIdentityUsed",
    "isPrivateLinkEnabled",
    "isPublicNetworkAccessDisabled",
    "isPurgeProtectionEnabled",
    "isRbacAuthorizationEnabled",
    "isSoftDeleteEnabled",
    "isVNetIntegrationEnabled",
    "keysHaveExpirationDate",
]
MEASURED = [k for k in KEYS if k != "isManagedIdentityUsed"]


def load(name):
    spec = importlib.util.spec_from_file_location("akv_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {k: load(k) for k in KEYS}


def run(key, payload):
    """(criterion value, dataCollection status). Reads the flat legacy dict as well as the envelope."""
    out = MODULES[key].transform(payload)
    inner = out.get("transformedResponse", out)
    info = out.get("additionalInfo")
    collection = info.get("dataCollection") if isinstance(info, dict) else None
    status = collection.get("status") if isinstance(collection, dict) else None
    return inner.get(key), status


def vault(**overrides):
    """A Vaults - Get body for a vault that meets every vault-property criterion."""
    body = {
        "id": VAULT_ID,
        "name": "sample-vault",
        "type": "Microsoft.KeyVault/vaults",
        "location": "westus",
        "tags": {},
        "systemData": {"createdBy": "user@example.com", "createdByType": "User",
                       "createdAt": "2026-01-01T00:00:00Z"},
        "properties": {
            "sku": {"family": "A", "name": "standard"},
            "tenantId": TENANT,
            "accessPolicies": [],
            "enabledForDeployment": False,
            "enabledForDiskEncryption": False,
            "enabledForTemplateDeployment": False,
            "enableSoftDelete": True,
            "softDeleteRetentionInDays": 90,
            "enableRbacAuthorization": True,
            "enablePurgeProtection": True,
            "vaultUri": "https://sample-vault.vault.azure.net",
            "provisioningState": "Succeeded",
            "publicNetworkAccess": "Disabled",
            "networkAcls": {
                "bypass": "AzureServices",
                "defaultAction": "Deny",
                "ipRules": [],
                "virtualNetworkRules": [{"id": SUBNET_ID, "ignoreMissingVnetServiceEndpoint": False}],
            },
        },
    }
    body["properties"].update(overrides)
    return body


def acls(**overrides):
    base = vault()["properties"]["networkAcls"]
    base.update(overrides)
    return base


def connection(status):
    return {
        "id": VAULT_ID + "/privateEndpointConnections/sample-pec",
        "name": "sample-pec",
        "type": "Microsoft.KeyVault/vaults/privateEndpointConnections",
        "etag": "",
        "properties": {
            "privateEndpoint": {"id": "/subscriptions/" + SUB + "/resourceGroups/sample-group/providers/"
                                      "Microsoft.Network/privateEndpoints/sample-pe"},
            "privateLinkServiceConnectionState": {"status": status, "description": "", "actionsRequired": "None"},
            "provisioningState": "Succeeded",
        },
    }


def pricing(tier):
    return {
        "id": "/subscriptions/" + SUB + "/providers/Microsoft.Security/pricings/KeyVaults",
        "name": "KeyVaults",
        "type": "Microsoft.Security/pricings",
        "properties": {"pricingTier": tier, "subPlan": "PerKeyVault", "freeTrialRemainingTime": "PT0S"},
    }


def diagnostic(enabled=True, destination=True):
    props = {
        "metrics": [{"category": "AllMetrics", "enabled": False}],
        "logs": [{"category": "AuditEvent", "categoryGroup": None, "enabled": enabled}],
        "logAnalyticsDestinationType": None,
    }
    if destination:
        props["workspaceId"] = ("/subscriptions/" + SUB + "/resourceGroups/sample-group/providers/"
                                "Microsoft.OperationalInsights/workspaces/sample-workspace")
    return {"value": [{"id": VAULT_ID + "/providers/microsoft.insights/diagnosticSettings/sample-setting",
                       "name": "sample-setting", "type": "Microsoft.Insights/diagnosticSettings",
                       "properties": props}]}


def policy_states(non_compliant):
    rows = [{"timestamp": "2026-01-01T00:00:00Z", "resourceId": VAULT_ID,
             "policyAssignmentId": "/subscriptions/" + SUB + "/providers/Microsoft.Authorization/"
                                   "policyAssignments/sample-assignment",
             "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/"
                                   "22222222-2222-2222-2222-222222222222",
             "isCompliant": False, "complianceState": "NonCompliant"} for i in range(non_compliant)]
    return {"@odata.context": "https://management.azure.com/providers/Microsoft.PolicyInsights/"
                              "policyStates/$metadata#latest",
            "@odata.count": len(rows), "value": rows}


def key_item(n, exp=True):
    attributes = {"enabled": True, "created": 1767225600, "updated": 1767225600, "recoveryLevel": "Recoverable+Purgeable"}
    if exp:
        attributes["exp"] = 1798761600
    return {"kid": "https://sample-vault.vault.azure.net/keys/sample-key-" + str(n), "attributes": attributes}


def cert_item(n, days=365):
    nbf = 1767225600
    attributes = {"enabled": True, "nbf": nbf, "exp": nbf + days * 86400,
                  "created": nbf, "updated": nbf, "recoveryLevel": "Recoverable+Purgeable"}
    return {"id": "https://sample-vault.vault.azure.net/certificates/sample-cert-" + str(n),
            "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAA", "attributes": attributes, "subject": "CN=example.com"}


def listing(items, next_link=None):
    return {"value": items, "nextLink": next_link}


PASS = {
    "certificatesHaveValidityPeriod": listing([cert_item(1), cert_item(2, days=397)]),
    "isAzurePolicyCompliant": policy_states(0),
    "isDefenderForKeyVaultEnabled": pricing("Standard"),
    "isDiagnosticLoggingEnabled": diagnostic(),
    "isFirewallEnabled": vault(),
    "isPrivateLinkEnabled": {"value": [connection("Pending"), connection("Approved")]},
    "isPublicNetworkAccessDisabled": vault(),
    "isPurgeProtectionEnabled": vault(),
    "isRbacAuthorizationEnabled": vault(),
    "isSoftDeleteEnabled": vault(),
    "isVNetIntegrationEnabled": vault(),
    "keysHaveExpirationDate": listing([key_item(1), key_item(2)]),
}

FAIL = {
    "certificatesHaveValidityPeriod": listing([cert_item(1), cert_item(2, days=825)]),
    "isAzurePolicyCompliant": policy_states(2),
    "isDefenderForKeyVaultEnabled": pricing("Free"),
    "isDiagnosticLoggingEnabled": diagnostic(enabled=False),
    "isFirewallEnabled": vault(networkAcls=acls(defaultAction="Allow")),
    "isPrivateLinkEnabled": {"value": [connection("Pending"), connection("Rejected")]},
    "isPublicNetworkAccessDisabled": vault(publicNetworkAccess="Enabled",
                                           networkAcls=acls(ipRules=[{"value": "203.0.113.0/24"}])),
    "isPurgeProtectionEnabled": vault(enablePurgeProtection=None),
    "isRbacAuthorizationEnabled": vault(enableRbacAuthorization=False),
    "isSoftDeleteEnabled": vault(enableSoftDelete=False),
    "isVNetIntegrationEnabled": vault(networkAcls=acls(virtualNetworkRules=[])),
    "keysHaveExpirationDate": listing([key_item(1), key_item(2, exp=False)]),
}

ERRORS = {
    "arm_authorization_failed": {"error": {"code": "AuthorizationFailed",
                                           "message": "The client does not have authorization to perform action."}},
    "in_response": {"response": {"error": {"code": "AuthorizationFailed", "message": "no authorization"}}},
    "in_result": {"result": {"error": {"code": "ResourceNotFound", "message": "resource not found"}}},
    "in_api_response": {"apiResponse": {"error": {"code": "InvalidAuthenticationToken", "message": "token expired"}}},
    "data_plane_forbidden": {"error": {"code": "Forbidden", "message": "Caller is not authorized.",
                                       "innererror": {"code": "ForbiddenByRbac"}}},
    "status_401": {"statusCode": 401, "error": "Unauthorized"},
    "status_403_nested": {"response": {"statusCode": 403, "message": "Forbidden"}},
    "as_json_string": json.dumps({"error": {"code": "AuthorizationFailed", "message": "no authorization"}}),
}

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "empty_json_string": "{}",
    "unrelated": {"hello": "world"},
    "unrelated_nested": {"foo": {"bar": [1, 2, 3]}},
}


class Poisoned(dict):
    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom


@pytest.mark.parametrize("key", MEASURED)
def test_pass_sample_is_true(key):
    assert run(key, copy.deepcopy(PASS[key])) == (True, "success")


@pytest.mark.parametrize("key", MEASURED)
def test_fail_sample_is_false(key):
    assert run(key, copy.deepcopy(FAIL[key])) == (False, "success")


@pytest.mark.parametrize("key", MEASURED)
def test_pass_sample_survives_wrappers_and_encodings(key):
    body = PASS[key]
    assert run(key, {"response": copy.deepcopy(body)})[0] is True
    assert run(key, {"result": {"apiResponse": copy.deepcopy(body)}})[0] is True
    assert run(key, json.dumps(body))[0] is True
    assert run(key, json.dumps(body).encode("utf-8"))[0] is True


@pytest.mark.parametrize("case", sorted(ERRORS))
@pytest.mark.parametrize("key", KEYS)
def test_error_envelope_is_not_evaluated(key, case):
    assert run(key, copy.deepcopy(ERRORS[case])) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_error_envelope_carries_the_vendor_error(key):
    out = MODULES[key].transform(copy.deepcopy(ERRORS["arm_authorization_failed"]))
    assert "AuthorizationFailed" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("case", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("key", KEYS)
def test_no_evidence_is_not_evaluated(key, case):
    assert run(key, copy.deepcopy(NO_EVIDENCE[case])) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_own_exception_is_reported_on_the_data_collection_channel(key):
    assert run(key, Poisoned(x=1)) == (None, "error")


@pytest.mark.parametrize("body", [
    vault(),
    vault(enableRbacAuthorization=True, accessPolicies=[]),
    vault(enableRbacAuthorization=False, accessPolicies=[{
        "tenantId": TENANT, "objectId": "33333333-3333-3333-3333-333333333333",
        "permissions": {"keys": ["get"], "secrets": ["get"], "certificates": []}}]),
    vault(enableRbacAuthorization=False, accessPolicies=[]),
], ids=["rbac_vault", "rbac_no_policies", "access_policy_vault", "access_policy_empty"])
def test_managed_identity_is_never_answered_from_a_vault_body(body):
    value, status = run("isManagedIdentityUsed", body)
    assert value is not True
    assert (value, status) == (None, "error")
    out = MODULES["isManagedIdentityUsed"].transform(body)
    assert "role-assignment" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("key,make", [
    ("keysHaveExpirationDate", key_item),
    ("certificatesHaveValidityPeriod", cert_item),
])
def test_a_partial_listing_cannot_pass(key, make):
    next_link = "https://sample-vault.vault.azure.net/" + key + "?api-version=7.4&$skiptoken=page2"
    assert run(key, listing([make(1)], next_link)) == (None, "error")


def test_a_partial_listing_can_still_fail():
    next_link = "https://sample-vault.vault.azure.net/keys?api-version=7.4&$skiptoken=page2"
    assert run("keysHaveExpirationDate", listing([key_item(1, exp=False)], next_link)) == (False, "success")


@pytest.mark.parametrize("key", ["keysHaveExpirationDate", "certificatesHaveValidityPeriod"])
def test_a_listed_empty_vault_is_compliant(key):
    assert run(key, listing([])) == (True, "success")


def test_private_link_reads_connections_embedded_in_the_vault_body():
    body = vault(privateEndpointConnections=[connection("Approved")])
    assert run("isPrivateLinkEnabled", body) == (True, "success")
    assert run("isPrivateLinkEnabled", vault()) == (False, "success")


def test_public_network_access_is_disabled_by_deny_with_no_ip_rules():
    body = vault(publicNetworkAccess="Enabled")
    assert run("isPublicNetworkAccessDisabled", body) == (True, "success")


def test_soft_delete_defaults_on_only_for_a_real_vault_body():
    body = vault()
    del body["properties"]["enableSoftDelete"]
    assert run("isSoftDeleteEnabled", body) == (True, "success")


def test_every_changed_transform_reports_schema_version_2_0():
    for key in KEYS:
        for payload in (PASS.get(key, vault()), {}):
            out = MODULES[key].transform(copy.deepcopy(payload))
            assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0", key
            assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation",
                                                  "evaluation", "metadata"}, key
