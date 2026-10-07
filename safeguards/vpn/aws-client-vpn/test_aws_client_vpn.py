"""Unit tests for the AWS Client VPN transforms (DescribeClientVpnEndpoints).

Fixtures are synthetic: made-up endpoint ids and ARNs, shaped like the EC2 Query API XML body
after xmltodict (what Integration-Service hands a transform) and like the SDK JSON shape.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


KEYS = {
    "isidentityproviderrequiredforremoteaccess": "isIdentityProviderRequiredForRemoteAccess",
    "isconnectionloggingenabled": "isConnectionLoggingEnabled",
    "issplittunneldisabled": "isSplitTunnelDisabled",
    "isdisconnectonsessiontimeoutenabled": "isDisconnectOnSessionTimeoutEnabled",
    "isfederatedauthenticationconfigured": "isFederatedAuthenticationConfigured",
    "isendpointanalysispolicybound": "isEndpointAnalysisPolicyBound",
    "isclientrouteenforcementenabled": "isClientRouteEnforcementEnabled",
    "isclientcertificateauthrequired": "isClientCertificateAuthRequired",
    "isvpnvserverup": "isVpnVserverUp",
}

SAML = {"type": "federated-authentication",
        "federatedAuthentication": {"samlProviderArn": "arn:aws:iam::000000000000:saml-provider/example"}}
CERT = {"type": "certificate-authentication",
        "mutualAuthentication": {"clientRootCertificateChain": "arn:aws:acm:us-east-1:000000000000:certificate/x"}}
AD = {"type": "directory-service-authentication", "activeDirectory": {"directoryId": "d-0000000000"}}


def good_endpoint(endpoint_id="cvpn-endpoint-0000000000000000a", **overrides):
    endpoint = {
        "clientVpnEndpointId": endpoint_id,
        "status": {"code": "available"},
        "splitTunnel": "false",
        "connectionLogOptions": {"enabled": "true", "cloudwatchLogGroup": "example"},
        "authenticationOptions": {"item": [CERT, SAML]},
        "disconnectOnSessionTimeout": "true",
        "sessionTimeoutHours": "8",
        "clientRouteEnforcementOptions": {"enforced": "true"},
        "clientConnectOptions": {"enabled": "true",
                                 "lambdaFunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:AWSClientVPN-x"},
    }
    endpoint.update(overrides)
    return endpoint


def xml_body(*endpoints, next_token=None):
    result = {"@xmlns": "http://ec2.amazonaws.com/doc/2016-11-15/", "requestId": "00000000-0000-0000-0000-000000000000"}
    if not endpoints:
        result["clientVpnEndpoint"] = None
    elif len(endpoints) == 1:
        result["clientVpnEndpoint"] = {"item": endpoints[0]}
    else:
        result["clientVpnEndpoint"] = {"item": list(endpoints)}
    if next_token:
        result["nextToken"] = next_token
    return {"DescribeClientVpnEndpointsResponse": result}


def sdk_body(*endpoints):
    def pascal(endpoint):
        auth = endpoint["authenticationOptions"]["item"]
        auth = auth if isinstance(auth, list) else [auth]
        return {
            "ClientVpnEndpointId": endpoint["clientVpnEndpointId"],
            "Status": {"Code": endpoint["status"]["code"]},
            "SplitTunnel": endpoint["splitTunnel"] == "true",
            "ConnectionLogOptions": {"Enabled": endpoint["connectionLogOptions"]["enabled"] == "true"},
            "AuthenticationOptions": [
                {"Type": a["type"], "FederatedAuthentication": {"SamlProviderArn": a["federatedAuthentication"]["samlProviderArn"]}}
                if "federatedAuthentication" in a else {"Type": a["type"]} for a in auth],
            "DisconnectOnSessionTimeout": endpoint["disconnectOnSessionTimeout"] == "true",
            "SessionTimeoutHours": int(endpoint["sessionTimeoutHours"]),
            "ClientRouteEnforcementOptions": {"Enforced": endpoint["clientRouteEnforcementOptions"]["enforced"] == "true"},
            "ClientConnectOptions": {"Enabled": endpoint["clientConnectOptions"]["enabled"] == "true",
                                     "LambdaFunctionArn": endpoint["clientConnectOptions"].get("lambdaFunctionArn")},
        }
    return {"ClientVpnEndpoints": [pascal(e) for e in endpoints]}


def verdict(module, body):
    out = load(module)(body)
    return out["transformedResponse"][KEYS[module]], out


@pytest.mark.parametrize("module", sorted(KEYS))
def test_good_endpoint_passes_xml_and_sdk_and_string(module):
    assert verdict(module, xml_body(good_endpoint()))[0] is True
    assert verdict(module, sdk_body(good_endpoint()))[0] is True
    assert verdict(module, json.dumps(xml_body(good_endpoint())))[0] is True
    assert verdict(module, {"response": xml_body(good_endpoint())})[0] is True


@pytest.mark.parametrize("module", sorted(KEYS))
@pytest.mark.parametrize("body", [
    {}, None, "", "{}", {"hello": "world"},
    {"Response": {"Errors": {"Error": {"Code": "UnauthorizedOperation", "Message": "not authorized"}}}},
    {"statusCode": 403, "error": "Forbidden"},
    {"DescribeClientVpnEndpointsResponse": {"requestId": "x"}},
])
def test_no_evidence_is_not_evaluated(module, body):
    value, out = verdict(module, body)
    assert value is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("module", sorted(KEYS))
def test_no_active_endpoint_is_not_evaluated(module):
    assert verdict(module, xml_body())[0] is None
    assert verdict(module, {"ClientVpnEndpoints": []})[0] is None
    deleted = good_endpoint(status={"code": "deleted"})
    assert verdict(module, xml_body(deleted))[0] is None


@pytest.mark.parametrize("module", sorted(KEYS))
def test_partial_page_is_not_evaluated(module):
    value, out = verdict(module, xml_body(good_endpoint(), next_token="abc"))
    assert value is None
    assert "nextToken" in out["additionalInfo"]["evaluation"]["failReasons"][0]


FAILS = {
    "isidentityproviderrequiredforremoteaccess": {"authenticationOptions": {"item": CERT}},
    "isconnectionloggingenabled": {"connectionLogOptions": {"enabled": "false"}},
    "issplittunneldisabled": {"splitTunnel": "true"},
    "isdisconnectonsessiontimeoutenabled": {"disconnectOnSessionTimeout": "false"},
    "isfederatedauthenticationconfigured": {"authenticationOptions": {"item": [CERT, AD]}},
    "isendpointanalysispolicybound": {"clientConnectOptions": {"enabled": "false"}},
    "isclientrouteenforcementenabled": {"clientRouteEnforcementOptions": {"enforced": "false"}},
    "isclientcertificateauthrequired": {"authenticationOptions": {"item": SAML}},
    "isvpnvserverup": {"status": {"code": "pending-associate"}},
}


@pytest.mark.parametrize("module", sorted(KEYS))
def test_one_bad_endpoint_fails_the_whole_estate(module):
    bad = good_endpoint("cvpn-endpoint-0000000000000000b", **FAILS[module])
    value, out = verdict(module, xml_body(good_endpoint(), bad))
    assert value is False
    assert "cvpn-endpoint-0000000000000000b" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert verdict(module, sdk_body(good_endpoint(), bad))[0] is False


UNREPORTED = {
    "isidentityproviderrequiredforremoteaccess": ["authenticationOptions"],
    "isfederatedauthenticationconfigured": ["authenticationOptions"],
    "isclientcertificateauthrequired": ["authenticationOptions"],
    "isconnectionloggingenabled": ["connectionLogOptions"],
    "issplittunneldisabled": ["splitTunnel"],
    "isdisconnectonsessiontimeoutenabled": ["disconnectOnSessionTimeout"],
    "isclientrouteenforcementenabled": ["clientRouteEnforcementOptions"],
    "isendpointanalysispolicybound": ["clientConnectOptions"],
    "isvpnvserverup": ["status"],
}


@pytest.mark.parametrize("module", sorted(KEYS))
def test_a_setting_that_is_not_reported_is_not_evaluated_never_false(module):
    endpoint = good_endpoint("cvpn-endpoint-0000000000000000c")
    for field in UNREPORTED[module]:
        endpoint.pop(field)
    if module == "isvpnvserverup":
        endpoint["status"] = {}
    value, out = verdict(module, xml_body(good_endpoint(), endpoint))
    assert value is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "cvpn-endpoint-0000000000000000c" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("module", sorted(KEYS))
def test_a_reported_failure_still_wins_over_an_unreported_endpoint(module):
    unreported = good_endpoint("cvpn-endpoint-0000000000000000c")
    for field in UNREPORTED[module]:
        unreported.pop(field)
    bad = good_endpoint("cvpn-endpoint-0000000000000000b", **FAILS[module])
    assert verdict(module, xml_body(unreported, bad))[0] is False


@pytest.mark.parametrize("module", ["isidentityproviderrequiredforremoteaccess", "isfederatedauthenticationconfigured",
                                    "isclientcertificateauthrequired"])
@pytest.mark.parametrize("options", [{"item": {"type": "something-new"}}, {"item": {"type": ""}}, {"item": []}, None])
def test_an_unrecognised_or_empty_auth_option_is_not_evaluated(module, options):
    assert verdict(module, xml_body(good_endpoint(authenticationOptions=options)))[0] is None


def test_idp_directory_sign_in_is_not_evaluated():
    value, out = verdict("isidentityproviderrequiredforremoteaccess", xml_body(
        good_endpoint("cvpn-endpoint-1", authenticationOptions={"item": SAML}),
        good_endpoint("cvpn-endpoint-2", authenticationOptions={"item": [CERT, AD]}),
    ))
    assert value is None
    body = out["transformedResponse"]
    assert body["federatedEndpoints"] == 1 and body["directoryEndpoints"] == 1
    assert "directory sign-in" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_idp_federated_everywhere_passes_and_never_claims_mfa():
    value, out = verdict("isidentityproviderrequiredforremoteaccess", xml_body(
        good_endpoint("cvpn-endpoint-1", authenticationOptions={"item": SAML}),
        good_endpoint("cvpn-endpoint-2", authenticationOptions={"item": [CERT, SAML]}),
    ))
    assert value is True
    assert out["transformedResponse"]["federatedEndpoints"] == 2
    reason = out["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "SAML federation" in reason and "MFA" not in reason
    assert "isMFARequiredForRemoteAccess" not in out["transformedResponse"]


def test_idp_certificate_only_fails_and_counts():
    value, out = verdict("isidentityproviderrequiredforremoteaccess", xml_body(
        good_endpoint("cvpn-endpoint-1"),
        good_endpoint("cvpn-endpoint-2", authenticationOptions={"item": [CERT]}),
        good_endpoint("cvpn-endpoint-3", authenticationOptions={"item": [AD]}),
    ))
    assert value is False
    assert out["transformedResponse"]["certificateOnlyEndpoints"] == 1


def test_federated_counts_distinct_saml_providers():
    _, out = verdict("isfederatedauthenticationconfigured", xml_body(good_endpoint("a"), good_endpoint("b")))
    assert out["transformedResponse"]["samlProviders"] == 1


def test_federated_option_without_a_provider_arn_is_not_evaluated():
    value, _ = verdict("isfederatedauthenticationconfigured",
                       xml_body(good_endpoint(authenticationOptions={"item": {"type": "federated-authentication"}})))
    assert value is None


def test_connect_handler_enabled_without_a_function_is_not_evaluated():
    value, _ = verdict("isendpointanalysispolicybound",
                       xml_body(good_endpoint(clientConnectOptions={"enabled": "true"})))
    assert value is None


def test_connect_handler_reported_off_fails():
    value, _ = verdict("isendpointanalysispolicybound",
                       xml_body(good_endpoint(clientConnectOptions={"enabled": "false"})))
    assert value is False


@pytest.mark.parametrize("module", ["isidentityproviderrequiredforremoteaccess", "isfederatedauthenticationconfigured"])
def test_federated_option_without_saml_provider_arn_is_a_mismatch_not_evidence(module):
    value, out = verdict(module, xml_body(
        good_endpoint("a"),
        good_endpoint("b", authenticationOptions={"item": [CERT, {"type": "federated-authentication"}]})))
    assert value is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("module", sorted(KEYS))
def test_vendor_error_text_never_reaches_the_reasons(module):
    body = {"Response": {"Errors": {"Error": {"Code": "UnauthorizedOperation",
                                              "Message": "<script>x</script> arn:aws:iam::000000000000:role/r"}}}}
    value, out = verdict(module, body)
    reasons = json.dumps(out["additionalInfo"])
    assert value is None and "script" not in reasons and "UnauthorizedOperation" not in reasons
    value, out = verdict(module, {"error": "free text from somewhere <b>"})
    assert value is None and "free text" not in json.dumps(out["additionalInfo"])


@pytest.mark.parametrize("module", sorted(KEYS))
def test_fail_reasons_read_cleanly(module):
    bad = good_endpoint("cvpn-endpoint-0000000000000000b", **FAILS[module])
    reason = verdict(module, xml_body(bad))[1]["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "::" not in reason and " on on " not in reason
