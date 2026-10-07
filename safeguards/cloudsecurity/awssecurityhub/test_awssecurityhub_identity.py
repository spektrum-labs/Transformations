"""AWS Security Hub identity checks: isSSOEnabled (IAM SAML providers OR IAM Identity Center) and
isSessionTimeoutConfigured (longest permission-set SessionDuration, minutes).

Shapes are the ones Integration-Service returned at Spektrum Labs on 2026-09-28 (read-only
run_with_override), with every ARN, id and name replaced: ListSAMLProviders comes back as
xmltodict-parsed XML; sso-admin bodies are awsJson1_1."""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("awssh_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def value(out, key):
    return out["transformedResponse"][key]


def collection_status(out):
    return out["additionalInfo"]["dataCollection"]["status"]


ERR_IS = {"error": True, "statusCode": 403, "message": "Forbidden"}
AWS_DENIED = {"__type": "AccessDeniedException", "message": "User is not authorized to perform: sso:ListInstances"}
CORAL_UNKNOWN = {"Output": {"__type": "com.amazon.coral.service#UnknownOperationException"}, "Version": "1.0"}
EMPTYISH = [{}, None, "{}", "", "null", ERR_IS, AWS_DENIED, CORAL_UNKNOWN, json.dumps(ERR_IS), [], {"result": {}}]


def saml(members):
    lst = None if members is None else {"member": members}
    return {"ListSAMLProvidersResponse": {"@xmlns": "https://iam.amazonaws.com/doc/2010-05-08/",
                                          "ListSAMLProvidersResult": {"SAMLProviderList": lst},
                                          "ResponseMetadata": {"RequestId": "00000000-0000-0000-0000-000000000000"}}}


def provider(n):
    return {"IsTrustedIdentityPropagationEnabled": "false", "ValidUntil": "2126-01-01T00:00:00Z",
            "Arn": "arn:aws:iam::111111111111:saml-provider/idp-" + str(n), "CreateDate": "2024-01-01T00:00:00Z"}


INSTANCE = {"CreatedDate": 1.6e9, "IdentityStoreArn": "arn:aws:identitystore::111111111111:identitystore/d-0000000000",
            "IdentityStoreId": "d-0000000000", "InstanceArn": "arn:aws:sso:::instance/ssoins-0000000000000000",
            "OwnerAccountId": "111111111111", "PrimaryRegion": "us-east-1",
            "Regions": [{"AddedDate": 1.6e9, "IsPrimaryRegion": True, "RegionName": "us-east-1", "Status": "ACTIVE"}],
            "State": {"Name": "ACTIVE"}, "Status": "ACTIVE"}


def instances(*statuses):
    return {"Instances": [dict(INSTANCE, Status=s) for s in statuses]}


# ---- isSSOEnabled ------------------------------------------------------------------------------

def sso_body(s, i):
    body = {}
    if s is not ...:
        body["samlProviders"] = s
    if i is not ...:
        body["ssoInstances"] = i
    return body


def test_sso_true_on_either_leg():
    t = load("isssoenabled")
    real = sso_body(saml([provider(1), provider(2), provider(3)]), instances("ACTIVE"))
    assert value(t(real), "isSSOEnabled") is True
    assert value(t(real), "samlProviderCount") == 3
    assert value(t({"result": real}), "isSSOEnabled") is True
    assert value(t(json.dumps({"result": real})), "isSSOEnabled") is True
    assert value(t(sso_body(saml([provider(1), provider(2)]), instances())), "isSSOEnabled") is True
    assert value(t(sso_body(saml(provider(1)), instances())), "isSSOEnabled") is True          # xmltodict single member
    assert value(t(sso_body(saml(None), instances("ACTIVE"))), "isSSOEnabled") is True
    # today (before IS parses x-amz-json) the workflow stops after the SAML leg: SAML alone can prove true
    assert value(t(sso_body(saml([provider(1)]), ...)), "isSSOEnabled") is True


def test_sso_false_only_when_both_legs_read_empty():
    t = load("isssoenabled")
    out = t(sso_body(saml(None), instances()))
    assert value(out, "isSSOEnabled") is False and collection_status(out) == "success"
    assert value(t(sso_body(saml(None), instances("CREATE_IN_PROGRESS"))), "isSSOEnabled") is False
    assert value(t(sso_body({"ListSAMLProvidersResponse": {"ListSAMLProvidersResult": {"SAMLProviderList": ""}}},
                            instances())), "isSSOEnabled") is False


def test_sso_unknown_is_null_with_collection_error():
    t = load("isssoenabled")
    cases = [sso_body(saml(None), ...), sso_body(..., instances()), sso_body(saml(None), ERR_IS),
             sso_body(ERR_IS, instances()), sso_body(saml(None), AWS_DENIED), sso_body(saml(None), CORAL_UNKNOWN),
             sso_body({"ErrorResponse": {"Error": {"Code": "AccessDenied"}}}, instances()),
             sso_body(saml(None), dict(instances(), NextToken="n")), sso_body({"x": 1}, {"y": 2})] + EMPTYISH
    for bad in cases:
        out = t(bad)
        assert value(out, "isSSOEnabled") is None, bad
        assert collection_status(out) == "error", bad


# ---- isSessionTimeoutConfigured -----------------------------------------------------------------

def ps(n, duration):
    return {"PermissionSet": {"CreatedDate": 1.6e9, "Description": "d", "Name": "Set" + str(n),
                              "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-0000000000000000/ps-" + str(n),
                              "SessionDuration": duration}}


def session_body(durations, inst=("ACTIVE",), extra=None):
    body = dict(instances(*inst))
    body["PermissionSets"] = ["arn:aws:sso:::permissionSet/ssoins-0000000000000000/ps-" + str(n) for n in range(len(durations))]
    body["permissionSetDetails"] = [ps(n, d) for n, d in enumerate(durations)]
    body.update(extra or {})
    return body


def test_session_is_the_longest_duration_in_minutes():
    t = load("issessiontimeoutconfigured")
    assert value(t(session_body(["PT1H"] * 14)), "isSessionTimeoutConfigured") == 60      # Spektrum Labs today
    out = t(session_body(["PT1H", "PT8H", "PT4H"]))
    assert value(out, "isSessionTimeoutConfigured") == 480 and collection_status(out) == "success"
    assert value(out, "longestSessionPermissionSets") == ["Set1"]
    assert value(t(session_body(["PT12H", "PT1H"])), "isSessionTimeoutConfigured") == 720    # flipped: fails <= 480
    assert value(t(session_body(["PT1H30M"])), "isSessionTimeoutConfigured") == 90
    assert value(t(session_body(["PT90M"])), "isSessionTimeoutConfigured") == 90
    assert value(t({"result": session_body(["PT2H"])}), "isSessionTimeoutConfigured") == 120
    assert value(t(json.dumps(session_body(["PT2H"]))), "isSessionTimeoutConfigured") == 120


def test_session_never_zero_null_with_collection_error():
    t = load("issessiontimeoutconfigured")
    no_details = session_body(["PT1H"]); no_details["permissionSetDetails"] = []
    short = session_body(["PT1H", "PT1H"]); short["permissionSetDetails"] = short["permissionSetDetails"][:1]
    cases = [session_body([]),                                 # instance without permission sets
             session_body(["PT1H"], inst=()),                   # no instance
             session_body(["PT1H"], inst=("CREATE_IN_PROGRESS",)),
             session_body(["PT1H"], extra={"NextToken": "n"}),  # unread page
             no_details, short,
             session_body(["1 hour"]), session_body([None]), session_body(["PT"]), session_body(["PTXH"]),
             instances("ACTIVE"),                               # workflow stopped after step 1
             dict(instances("ACTIVE"), PermissionSets=["a"])] + EMPTYISH
    for bad in cases:
        out = t(bad)
        assert value(out, "isSessionTimeoutConfigured") is None, bad
        assert collection_status(out) == "error", bad
