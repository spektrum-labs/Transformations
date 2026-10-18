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


def not_evaluated(out, key):
    """Nothing was measured: the criterion is None and the response says so (Token-Service grades a bare
    None as Failed unless additionalInfo.dataCollection.status is "error")."""
    assert out[key] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


def measured(out, key, value):
    """A real read that shows the answer: the value, and no not-evaluated marker."""
    assert out[key] is value
    assert "additionalInfo" not in out or out["additionalInfo"]["dataCollection"]["status"] != "error"


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
    # measured absence: both lists were read and the instance is not enabled for sign-in
    measured(t(merged(INSTANCES, {"Applications": [app("old", "DISABLED")]})), "isSSOEnabled", False)
    measured(t(merged(INSTANCES, {"Applications": []})), "isSSOEnabled", False)
    creating = merged({"Instances": [dict(INSTANCES["Instances"][0], Status="CREATE_IN_PROGRESS")]}, {"Applications": [app("jira")]})
    measured(t(creating), "isSSOEnabled", False)
    measured(t(merged({"Instances": []}, {"Applications": [app("jira")]})), "isSSOEnabled", False)
    # nothing measured: an unread page, a list that never arrived, an AWS or Integration-Service error
    not_evaluated(t(merged(good, {"NextToken": "abc"})), "isSSOEnabled")
    not_evaluated(t(INSTANCES), "isSSOEnabled")                       # applications never read
    for bad in EMPTYISH:
        not_evaluated(t(bad), "isSSOEnabled")


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
    measured(t(tti), "isTrustedApplicationProtectionEnabled", True)
    measured(t({"TrustedTokenIssuers": []}), "isTrustedApplicationProtectionEnabled", False)    # read, and none configured
    assert t(merged(tti, {"NextToken": "more"}))["isTrustedApplicationProtectionEnabled"] is True  # one issuer is enough
    not_evaluated(t({"TrustedTokenIssuers": [], "NextToken": "more"}), "isTrustedApplicationProtectionEnabled")
    not_evaluated(t({"TrustedTokenIssuers": [{"Name": "no arn"}]}), "isTrustedApplicationProtectionEnabled")  # shape not recognised
    not_evaluated(t({"TrustedTokenIssuers": "oops"}), "isTrustedApplicationProtectionEnabled")
    for bad in EMPTYISH:
        not_evaluated(t(bad), "isTrustedApplicationProtectionEnabled")


# ---- permission-set provisioning ---------------------------------------------------------

PS = ["arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-%d" % i for i in range(3)]


def provisioning(account_lists, sets=None):
    return {"PermissionSets": list(PS if sets is None else sets),
            "provisionedAccounts": [{"AccountIds": a} for a in account_lists]}


def test_rbac():
    t = load("isrbacimplemented")
    assert t(provisioning([["111111111111"], [], ["222222222222", "333333333333"]]))["isRBACImplemented"] is True
    # measured absence: every permission set's accounts were read and none is provisioned, or there are no sets
    measured(t(provisioning([[], [], []])), "isRBACImplemented", False)
    measured(t(provisioning([], sets=[])), "isRBACImplemented", False)
    # nothing measured: a missing body, an AWS error on one set, an unread page, a fan-out that never ran
    not_evaluated(t(provisioning([["111111111111"], []])), "isRBACImplemented")          # one body missing
    partial = provisioning([["111111111111"], [], []])
    partial["provisionedAccounts"][1] = AWS_DENIED
    not_evaluated(t(partial), "isRBACImplemented")
    paged = provisioning([["111111111111"], [], []])
    paged["provisionedAccounts"][0]["NextToken"] = "more"
    not_evaluated(t(paged), "isRBACImplemented")
    not_evaluated(t(merged(provisioning([["111111111111"], [], []]), {"NextToken": "more"})), "isRBACImplemented")
    not_evaluated(t({"PermissionSets": PS}), "isRBACImplemented")                        # fan-out never ran
    for bad in EMPTYISH:
        not_evaluated(t(bad), "isRBACImplemented")


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
