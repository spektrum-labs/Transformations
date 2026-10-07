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
    "ismfarequiredforremoteaccess": "isMFARequiredForRemoteAccess",
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
    "ismfarequiredforremoteaccess": {"authenticationOptions": {"item": CERT}},
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


@pytest.mark.parametrize("module", sorted(KEYS))
def test_missing_setting_is_not_a_pass(module):
    endpoint = good_endpoint()
    for field in ["splitTunnel", "connectionLogOptions", "disconnectOnSessionTimeout",
                  "clientRouteEnforcementOptions", "authenticationOptions", "status", "clientConnectOptions"]:
        endpoint.pop(field, None)
    endpoint["status"] = {"code": "pending-associate"}
    assert verdict(module, xml_body(endpoint))[0] is False


def test_mfa_counts_directory_and_federated_and_reports_numbers():
    value, out = verdict("ismfarequiredforremoteaccess", xml_body(
        good_endpoint("cvpn-endpoint-1", authenticationOptions={"item": SAML}),
        good_endpoint("cvpn-endpoint-2", authenticationOptions={"item": [CERT, AD]}),
    ))
    assert value is True
    body = out["transformedResponse"]
    assert body["federatedEndpoints"] == 1 and body["directoryEndpoints"] == 1
    assert body["certificateOnlyEndpoints"] == 0
    assert "proves the MFA" in out["additionalInfo"]["evaluation"]["passReasons"][0]


def test_mfa_certificate_only_fails_and_counts():
    value, out = verdict("ismfarequiredforremoteaccess", xml_body(
        good_endpoint("cvpn-endpoint-1"),
        good_endpoint("cvpn-endpoint-2", authenticationOptions={"item": [CERT]}),
    ))
    assert value is False
    assert out["transformedResponse"]["certificateOnlyEndpoints"] == 1


def test_mfa_unknown_auth_type_fails():
    value, _ = verdict("ismfarequiredforremoteaccess",
                       xml_body(good_endpoint(authenticationOptions={"item": {"type": "something-new"}})))
    assert value is False


def test_session_timeout_reports_longest():
    _, out = verdict("isdisconnectonsessiontimeoutenabled", xml_body(
        good_endpoint("a", sessionTimeoutHours="8"), good_endpoint("b", sessionTimeoutHours="24")))
    assert out["transformedResponse"]["maxSessionTimeoutHours"] == 24


def test_federated_counts_distinct_saml_providers():
    _, out = verdict("isfederatedauthenticationconfigured", xml_body(good_endpoint("a"), good_endpoint("b")))
    assert out["transformedResponse"]["samlProviders"] == 1


def test_connect_handler_needs_a_function():
    value, _ = verdict("isendpointanalysispolicybound",
                       xml_body(good_endpoint(clientConnectOptions={"enabled": "true"})))
    assert value is False
