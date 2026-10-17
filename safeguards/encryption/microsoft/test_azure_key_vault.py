"""Azure Key Vault (Encryption): the 16 checks under safeguards/encryption/microsoft/.

Each criterion is replayed three ways, natively and in the production sandbox
(tools/restricted_sandbox.py): a body that should pass, one that should fail, and the
no-evidence routes -- an empty object, an Azure error envelope and a poisoned body whose every
read raises. Every assertion is on the pair (value, dataCollection.status): None under
"success" still grades as a measured fail, so the value alone proves nothing.

Body provenance. "vendor example" bodies are Microsoft's published 200-response examples for
the exact api-version the definition calls, from Azure/azure-rest-api-specs (the source of the
"Sample response" on each learn.microsoft.com REST page), trimmed to the fields read and with
the example's contact address removed. "doc-derived" bodies are those examples with one
documented field changed, and prove only that we handle a shape the documentation describes.
No body here came from a customer tenant.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

VAULT = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sample-resource-group/providers/Microsoft.KeyVault/vaults/sample-vault"

# vendor example: KeyVault/stable/2023-07-01/examples/getVault.json (Vaults - Get)
GET_VAULT = {
    "id": VAULT,
    "name": "sample-vault",
    "type": "Microsoft.KeyVault/vaults",
    "location": "westus",
    "tags": {},
    "properties": {
        "sku": {"family": "A", "name": "standard"},
        "tenantId": "00000000-0000-0000-0000-000000000000",
        "accessPolicies": [{"tenantId": "00000000-0000-0000-0000-000000000000",
                            "objectId": "00000000-0000-0000-0000-000000000000",
                            "permissions": {"keys": ["get", "list"], "secrets": ["get"], "certificates": ["get"]}}],
        "enabledForDeployment": True,
        "enabledForDiskEncryption": True,
        "enabledForTemplateDeployment": True,
        "hsmPoolResourceId": "00000000-0000-0000-0000-000000000000",
        "vaultUri": "https://sample-vault.vault.azure.net",
        "provisioningState": "Succeeded",
        "publicNetworkAccess": "Enabled",
    },
}

# vendor example: KeyVault/stable/2023-07-01/examples/listPrivateEndpointConnection.json
PRIVATE_ENDPOINTS = {
    "value": [
        {"id": VAULT + "/privateEndpointConnections/sample-pec", "name": "sample-pec",
         "type": "Microsoft.KeyVault/vaults/privateEndpointConnections", "etag": "",
         "properties": {"provisioningState": "Succeeded",
                        "privateEndpoint": {"id": "/subscriptions/00000000-0000-0000-1234-000000000000/resourceGroups/sample-group/providers/Microsoft.Network/privateEndpoints/sample-pe"},
                        "privateLinkServiceConnectionState": {"status": "Approved", "actionsRequired": "None"}}},
    ],
    "nextLink": None,
}

# vendor example: data-plane/Legacy/stable/7.4/examples/GetKeys-example.json (exp absent, nextLink set)
GET_KEYS = {
    "value": [{"kid": "https://myvault.vault.azure.net/keys/sdktestkey",
               "attributes": {"enabled": True, "created": 1493937656, "updated": 1493937656,
                              "recoveryLevel": "Recoverable+Purgeable"}}],
    "nextLink": "https://myvault.vault.azure.net:443/keys?api-version=7.2&$skiptoken=eyJOZXh0TWFya2VyIjoiMiE5NiJ9&maxresults=1",
}

# vendor example: data-plane/Legacy/stable/7.4/examples/GetCertificates-example.json (~8,700-day validity)
GET_CERTIFICATES = {
    "value": [
        {"id": "https://myvault.vault.azure.net/certificates/listCert01", "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo",
         "attributes": {"enabled": True, "nbf": 1430344421, "exp": 2208988799, "created": 1482188987,
                        "updated": 1482188987}},
        {"id": "https://myvault.vault.azure.net/certificates/listCert02", "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo",
         "attributes": {"enabled": True, "nbf": 1430344421, "exp": 2208988799, "created": 1482188988,
                        "updated": 1482188988}},
    ],
    "nextLink": None,
}

# vendor example: Security/stable/2024-01-01/examples/Pricings/GetPricingByNameVirtualMachines_example.json,
# the same Pricings - Get operation; the spec publishes no KeyVaults-plan example, so name/id are doc-derived.
DEFENDER_PRICING = {
    "name": "KeyVaults",
    "type": "Microsoft.Security/pricings",
    "id": "/subscriptions/20ff7fc3-e762-44dd-bd96-b71116dcdc23/providers/Microsoft.Security/pricings/KeyVaults",
    "properties": {"enablementTime": "2023-03-01T12:42:42.1921106Z", "freeTrialRemainingTime": "PT0S",
                   "pricingTier": "Standard"},
}

# vendor example: Insights/preview/2021-05-01-preview/examples/listDiagnosticSettings.json
DIAGNOSTIC_SETTINGS = {
    "value": [{
        "name": "mysetting",
        "type": "Microsoft.Insights/diagnosticSettings",
        "properties": {
            "eventHubAuthorizationRuleId": "/subscriptions/b67f7fec-69fc-4974-9099-a26bd6ffeda3/resourceGroups/andy1101/providers/Microsoft.EventHub/namespaces/andy1101/authorizationrules/RootManageSharedAccessKey",
            "logs": [{"categoryGroup": "allLogs", "enabled": True, "retentionPolicy": {"days": 0, "enabled": False}}],
            "metrics": [{"category": "WorkflowMetrics", "enabled": True}],
            "storageAccountId": "/subscriptions/df602c9c-7aa0-407d-a6fb-eb20c8bd1192/resourceGroups/apptest/providers/Microsoft.Storage/storageAccounts/appteststorage1",
            "workspaceId": "",
        },
    }],
}

# vendor example: PolicyInsights/stable/2019-10-01/examples/PolicyStates_QueryResourceScope.json
POLICY_STATES = {
    "@odata.nextLink": None,
    "@odata.count": 2,
    "value": [{"complianceState": "NonCompliant", "isCompliant": False, "policyAssignmentName": "test"},
              {"complianceState": "NonCompliant", "isCompliant": False, "policyAssignmentName": "test"}],
}

# vendor example: Authorization/stable/2022-04-01/examples/RoleAssignments_ListForResource.json
ROLE_ASSIGNMENTS = {
    "value": [{"name": n, "type": "Microsoft.Authorization/roleAssignments",
               "properties": {"roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/0b5fe924-9a61-425c-96af-cfe6e287ca2d",
                              "principalId": "ce2ce14e-85d7-4629-bdbc-454d0519d987", "principalType": "User"}}
              for n in ("b0f43c54-e787-4862-89b1-a653fa9cf747", "96786e4b-dede-4c2e-8736-8ab911987f08",
                        "05c5a614-a7d6-4502-b150-c2fb455033ff")],
}


def vault(**props):
    body = copy.deepcopy(GET_VAULT)
    body["properties"].update(props)
    return body


def edited(body, mutate):
    body = copy.deepcopy(body)
    mutate(body)
    return body


def set_state(status):
    def mutate(body):
        body["value"][0]["properties"]["privateLinkServiceConnectionState"]["status"] = status
    return mutate


def with_exp(body):
    body["value"][0]["attributes"]["exp"] = 1525473656
    body["nextLink"] = None


def short_certs(body):
    for cert in body["value"]:
        cert["attributes"]["exp"] = cert["attributes"]["nbf"] + 365 * 86400


def tier(value):
    def mutate(body):
        body["properties"]["pricingTier"] = value
    return mutate


def no_destination(body):
    props = body["value"][0]["properties"]
    for field in ("eventHubAuthorizationRuleId", "storageAccountId"):
        del props[field]


def compliant(body):
    body["value"] = []
    body["@odata.count"] = 0


def service_principal(body):
    body["value"][0]["properties"]["principalType"] = "ServicePrincipal"


ACLS_DENY = {"bypass": "AzureServices", "defaultAction": "Deny", "ipRules": [],
             "virtualNetworkRules": [{"id": VAULT.replace("Microsoft.KeyVault/vaults/sample-vault", "Microsoft.Network/virtualNetworks/vnet/subnets/default")}]}

# key -> (expected-pass body, expected-fail body). None in a slot means that verdict is not
# reachable for the key by design, and the body in its place must produce None + "error".
CASES = {
    "isFirewallEnabled": (vault(networkAcls=ACLS_DENY), GET_VAULT),
    "isVNetIntegrationEnabled": (vault(networkAcls=ACLS_DENY), GET_VAULT),
    "isPublicNetworkAccessDisabled": (vault(publicNetworkAccess="Disabled"), GET_VAULT),
    "isPurgeProtectionEnabled": (vault(enableSoftDelete=True, enablePurgeProtection=True), GET_VAULT),
    "isRbacAuthorizationEnabled": (vault(enableRbacAuthorization=True), vault(enableRbacAuthorization=False)),
    "isSoftDeleteEnabled": (vault(enableSoftDelete=True), vault(enableSoftDelete=False)),
    "isPrivateLinkEnabled": (PRIVATE_ENDPOINTS, edited(PRIVATE_ENDPOINTS, set_state("Rejected"))),
    "keysHaveExpirationDate": (edited(GET_KEYS, with_exp), GET_KEYS),
    "certificatesHaveValidityPeriod": (edited(GET_CERTIFICATES, short_certs), GET_CERTIFICATES),
    "isDefenderForKeyVaultEnabled": (DEFENDER_PRICING, edited(DEFENDER_PRICING, tier("Free"))),
    "isDiagnosticLoggingEnabled": (DIAGNOSTIC_SETTINGS, edited(DIAGNOSTIC_SETTINGS, no_destination)),
    "isAzurePolicyCompliant": (edited(POLICY_STATES, compliant), POLICY_STATES),
}

# Platform facts and the role-assignment read: no body can make these say yes or no.
NOT_MEASURED = {
    "isAzureADAuthEnabled": [GET_VAULT, vault(networkAcls=ACLS_DENY)],
    "isDataInTransitEncrypted": [GET_VAULT, vault(publicNetworkAccess="Disabled")],
    "isDataAtRestEncrypted": [GET_VAULT, vault(sku={"family": "A", "name": "premium"})],
    "isManagedIdentityUsed": [ROLE_ASSIGNMENTS, edited(ROLE_ASSIGNMENTS, service_principal), GET_VAULT],
}

ALL_KEYS = sorted(list(CASES) + list(NOT_MEASURED))


class PoisonedBody(dict):
    """A non-empty object whose every read raises: it reaches the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


NO_EVIDENCE = {
    "empty": lambda: {},
    "arm_error": lambda: {"error": {"code": "AuthorizationFailed",
                                    "message": "The client does not have authorization to perform action"}},
    "dataplane_forbidden": lambda: {"error": {"code": "Forbidden", "message": "Caller is not authorized"}},
    "status_403": lambda: {"statusCode": 403, "error": "Forbidden"},
    "value_missing": lambda: {"nextLink": None},
    "poisoned": PoisonedBody,
}


def native(key):
    spec = importlib.util.spec_from_file_location("akv_" + key, HERE / (key + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(key):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_akv", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (key + ".py")).read_text(), "<transformation>")["transform"]


RUNNERS = [pytest.param(native, id="native"), pytest.param(sandboxed, id="sandbox")]


def run(loader, key, body):
    out = loader(key)(copy.deepcopy(body) if not isinstance(body, PoisonedBody) else body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("key", sorted(CASES))
def test_expected_pass(loader, key):
    assert run(loader, key, CASES[key][0]) == (True, "success")


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("key", sorted(CASES))
def test_expected_fail(loader, key):
    assert run(loader, key, CASES[key][1]) == (False, "success")


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("route", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("key", ALL_KEYS)
def test_no_evidence_is_not_evaluated(loader, key, route):
    assert run(loader, key, NO_EVIDENCE[route]()) == (None, "error")


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("key", sorted(NOT_MEASURED))
def test_platform_facts_and_role_assignments_are_never_measured(loader, key):
    for body in NOT_MEASURED[key]:
        assert run(loader, key, body) == (None, "error")


def test_legacy_string_input_and_wrappers():
    transform = native("isPurgeProtectionEnabled")
    import json
    body = vault(enablePurgeProtection=True)
    assert transform(json.dumps(body))["transformedResponse"]["isPurgeProtectionEnabled"] is True
    assert transform({"response": body})["transformedResponse"]["isPurgeProtectionEnabled"] is True
    assert transform({"data": body, "validation": {"status": "valid"}})["transformedResponse"][
        "isPurgeProtectionEnabled"] is True


@pytest.mark.parametrize("key, body", [
    ("isSoftDeleteEnabled", GET_VAULT),  # the vendor's own example omits enableSoftDelete
    ("keysHaveExpirationDate", {"value": [], "nextLink": None}),
    ("certificatesHaveValidityPeriod", {"value": [], "nextLink": None}),
    ("keysHaveExpirationDate", edited(edited(GET_KEYS, with_exp), lambda b: b.update(nextLink=GET_KEYS["nextLink"]))),
    ("certificatesHaveValidityPeriod", edited(edited(GET_CERTIFICATES, short_certs),
                                              lambda b: b["value"][0]["attributes"].pop("nbf"))),
    ("isPrivateLinkEnabled", edited(edited(PRIVATE_ENDPOINTS, set_state("Pending")), lambda b: b.update(nextLink="https://next"))),
    ("isDefenderForKeyVaultEnabled", edited(DEFENDER_PRICING, lambda b: b.update(name="VirtualMachines"))),
    ("isFirewallEnabled", vault(networkAcls={"defaultAction": "Sometimes"})),
])
def test_absence_and_partial_reads_are_not_evaluated(key, body):
    assert run(native, key, body) == (None, "error")


def test_empty_vault_is_not_a_pass_for_either_population():
    for key in ("keysHaveExpirationDate", "certificatesHaveValidityPeriod"):
        out = native(key)({"value": [], "nextLink": None})
        assert out["transformedResponse"][key] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_a_definite_failure_on_a_partial_read_still_fails():
    assert run(native, "keysHaveExpirationDate", GET_KEYS) == (False, "success")
    assert GET_KEYS["nextLink"]


def test_event_hub_name_alone_is_not_a_destination():
    body = edited(DIAGNOSTIC_SETTINGS, no_destination)
    body["value"][0]["properties"]["eventHubName"] = "hub"
    assert run(native, "isDiagnosticLoggingEnabled", body) == (False, "success")
    body["value"][0]["properties"]["marketplacePartnerId"] = "/subscriptions/x/providers/Microsoft.Datadog/monitors/dd1"
    assert run(native, "isDiagnosticLoggingEnabled", body) == (True, "success")


def test_managed_identity_reports_its_evidence():
    out = native("isManagedIdentityUsed")(edited(ROLE_ASSIGNMENTS, service_principal))
    assert out["transformedResponse"]["servicePrincipalAssignmentCount"] == 1
    assert out["transformedResponse"]["roleAssignmentCount"] == 3


# --- review findings on #1066 -------------------------------------------------------------

def test_a_deny_all_firewall_is_not_public_access_disabled():
    """The vault keeps its public endpoint: bypass AzureServices still admits trusted Microsoft
    services, and service-endpoint VNet rules still arrive over it. Microsoft's own built-in
    policy tests publicNetworkAccess alone, and deny-all is what isFirewallEnabled measures."""
    body = vault(publicNetworkAccess="Enabled", networkAcls=ACLS_DENY)
    assert run(native, "isPublicNetworkAccessDisabled", body) == (False, "success")
    assert run(native, "isFirewallEnabled", body) == (True, "success")


def test_a_vault_body_with_vaultUri_and_no_tenantId_is_still_a_vault():
    body = vault(publicNetworkAccess="Disabled")
    body["properties"].pop("tenantId", None)
    assert body["properties"].get("vaultUri")
    assert run(native, "isPrivateLinkEnabled", body) == (False, "success")


#: Keys with a reachable pass body. A key whose True verdict is unreachable by design has None
#: in that slot; parametrising over those would skip, and a skipped test is not a passing test.
KEYS_WITH_A_PASS_BODY = sorted(k for k in CASES if CASES[k][0] is not None)


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("key", KEYS_WITH_A_PASS_BODY)
def test_a_bare_data_wrapper_is_unwrapped(loader, key):
    """Every one of these files unwrapped {"data": {...}} on main, and nothing has confirmed
    which shape Integration-Service sends, because they have never run live."""
    assert run(loader, key, {"data": CASES[key][0]}) == (True, "success")
