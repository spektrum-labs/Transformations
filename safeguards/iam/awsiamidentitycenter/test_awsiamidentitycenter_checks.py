"""AWS IAM Identity Center (sso-admin) checks, on bodies shaped as AWS documents them.

No customer body has been seen: no customer has connected this integration. Shapes follow the
sso-admin API reference and the botocore service model (sso-admin 2020-07-20). CORAL_UNKNOWN is a
real body, observed 2026-09-25: AWS answers HTTP 200 with it when a request reaches sso or
identitystore with Content-Type application/json instead of application/x-amz-json-1.1."""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("iamic_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


ARN = "arn:aws:sso:::instance/ssoins-1111111111111111"
CORAL_UNKNOWN = {"Output": {"__type": "com.amazon.coral.service#UnknownOperationException"}, "Version": "1.0"}
AWS_DENIED = {"__type": "AccessDeniedException", "message": "User is not authorized to perform: sso:ListInstances"}
ERR_IS = {"error": True, "statusCode": 403, "message": "Forbidden"}
EMPTYISH = [{}, None, "{}", "", ERR_IS, AWS_DENIED, CORAL_UNKNOWN, json.dumps(CORAL_UNKNOWN)]

INSTANCES = {"Instances": [{"InstanceArn": ARN, "IdentityStoreId": "d-1234567890", "Status": "ACTIVE", "Name": "org"}]}
SAML_P = "arn:aws:sso::aws:applicationProvider/custom-saml"
OAUTH_P = "arn:aws:sso::aws:applicationProvider/custom-oauth"
PROVIDERS = {"ApplicationProviders": [{"ApplicationProviderArn": SAML_P, "FederationProtocol": "SAML"},
                                      {"ApplicationProviderArn": OAUTH_P, "FederationProtocol": "OAUTH"}]}


def app(name, status="ENABLED", provider=SAML_P):
    return {"ApplicationArn": "arn:aws:sso::123456789012:application/ssoins-1111111111111111/apl-" + name,
            "ApplicationProviderArn": provider, "Name": name, "InstanceArn": ARN, "Status": status}


def merged(*parts):
    out = {}
    for p in parts:
        out.update(copy.deepcopy(p))
    return out


# ---- isSSOEnabled ----------------------------------------------------------------------

def test_sso_enabled():
    t = load("isssoenabled")
    good = merged(INSTANCES, {"Applications": [app("jira"), app("old", "DISABLED")]})
    assert t(good)["isSSOEnabled"] is True
    assert t({"apiResponse": good})["isSSOEnabled"] is True
    assert t(json.dumps(good))["isSSOEnabled"] is True
    assert t(merged(INSTANCES, {"Applications": [app("old", "DISABLED")]}))["isSSOEnabled"] is False
    assert t(merged(INSTANCES, {"Applications": []}))["isSSOEnabled"] is False
    creating = merged({"Instances": [dict(INSTANCES["Instances"][0], Status="CREATE_IN_PROGRESS")]}, {"Applications": [app("jira")]})
    assert t(creating)["isSSOEnabled"] is False
    assert t(merged({"Instances": []}, {"Applications": [app("jira")]}))["isSSOEnabled"] is False
    assert t(merged(good, {"NextToken": "abc"}))["isSSOEnabled"] is False
    assert t(INSTANCES)["isSSOEnabled"] is False                      # applications never read
    for bad in EMPTYISH:
        assert t(bad)["isSSOEnabled"] is False


# ---- authTypesAllowed -------------------------------------------------------------------

def test_auth_types():
    t = load("authtypesallowed")
    assert t(merged(PROVIDERS, {"Applications": [app("a"), app("b")]}))["authTypesAllowed"] == "SAML"
    assert t(merged(PROVIDERS, {"Applications": [app("a"), app("b", provider=OAUTH_P)]}))["authTypesAllowed"] == "OAUTH,SAML"
    assert t(merged(PROVIDERS, {"Applications": [app("b", provider=OAUTH_P), app("x", "DISABLED")]}))["authTypesAllowed"] == "OAUTH"
    unknown = merged(PROVIDERS, {"Applications": [app("a"), app("z", provider="arn:aws:sso::aws:applicationProvider/other")]})
    assert t(unknown)["authTypesAllowed"] is None
    assert t(merged(PROVIDERS, {"Applications": [app("x", "DISABLED")]}))["authTypesAllowed"] is None
    assert t(merged(PROVIDERS, {"Applications": [app("a")], "NextToken": "n"}))["authTypesAllowed"] is None
    assert t({"Applications": [app("a")]})["authTypesAllowed"] is None
    for bad in EMPTYISH:
        assert t(bad)["authTypesAllowed"] is None


# ---- isTrustedApplicationProtectionEnabled ----------------------------------------------

def test_trusted_token_issuers():
    t = load("istrustedapplicationprotectionenabled")
    tti = {"TrustedTokenIssuers": [{"TrustedTokenIssuerArn": "arn:aws:sso::123456789012:trustedTokenIssuer/ssoins-1/tti-1",
                                    "Name": "okta", "TrustedTokenIssuerType": "OIDC_JWT"}]}
    assert t(tti)["isTrustedApplicationProtectionEnabled"] is True
    assert t({"TrustedTokenIssuers": []})["isTrustedApplicationProtectionEnabled"] is False
    assert t({"TrustedTokenIssuers": [{"Name": "no arn"}]})["isTrustedApplicationProtectionEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isTrustedApplicationProtectionEnabled"] is False


# ---- permission-set provisioning ---------------------------------------------------------

PS = ["arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-%d" % i for i in range(3)]


def provisioning(account_lists, sets=None):
    return {"PermissionSets": list(PS if sets is None else sets),
            "provisionedAccounts": [{"AccountIds": a} for a in account_lists]}


def test_rbac():
    t = load("isrbacimplemented")
    assert t(provisioning([["111111111111"], [], ["222222222222", "333333333333"]]))["isRBACImplemented"] is True
    assert t(provisioning([[], [], []]))["isRBACImplemented"] is False
    assert t(provisioning([], sets=[]))["isRBACImplemented"] is False
    assert t(provisioning([["111111111111"], []]))["isRBACImplemented"] is False          # one body missing
    partial = provisioning([["111111111111"], [], []])
    partial["provisionedAccounts"][1] = AWS_DENIED
    assert t(partial)["isRBACImplemented"] is False
    paged = provisioning([["111111111111"], [], []])
    paged["provisionedAccounts"][0]["NextToken"] = "more"
    assert t(paged)["isRBACImplemented"] is False
    assert t({"PermissionSets": PS})["isRBACImplemented"] is False                       # fan-out never ran
    for bad in EMPTYISH:
        assert t(bad)["isRBACImplemented"] is False


def test_unprovisioned_count():
    t = load("unprovisionedpermissionsetscount")
    assert t(provisioning([["111111111111"], ["1"], ["2"]]))["unprovisionedPermissionSetsCount"] == 0
    assert t(provisioning([["111111111111"], [], []]))["unprovisionedPermissionSetsCount"] == 2
    assert t(provisioning([], sets=[]))["unprovisionedPermissionSetsCount"] is None        # zero population proves nothing
    assert t(provisioning([["1"], ["2"]]))["unprovisionedPermissionSetsCount"] is None
    assert t(merged(provisioning([["1"], ["2"], ["3"]]), {"NextToken": "x"}))["unprovisionedPermissionSetsCount"] is None
    bad_item = provisioning([["1"], ["2"], ["3"]])
    bad_item["provisionedAccounts"][2] = CORAL_UNKNOWN
    assert t(bad_item)["unprovisionedPermissionSetsCount"] is None
    for bad in EMPTYISH:
        assert t(bad)["unprovisionedPermissionSetsCount"] is None
