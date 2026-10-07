# ismfarequiredforremoteaccess.py - AWS Client VPN (Amazon EC2 Client VPN endpoints)
#
# Method: describeClientVpnEndpoints (Integration-Service), one read-only call:
#   GET https://ec2.{region}.amazonaws.com/?Action=DescribeClientVpnEndpoints&Version=2016-11-15
#   IAM action: ec2:DescribeClientVpnEndpoints. No write, no other permission.
# Docs: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeClientVpnEndpoints.html
#       https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ClientVpnEndpoint.html
#
# Input shapes accepted (both proven by the unit tests):
#   * the EC2 Query API XML body as Integration-Service parses it (xmltodict):
#     DescribeClientVpnEndpointsResponse.clientVpnEndpoint.item (one dict or a list), lowerCamel
#     field names, booleans as the strings "true" / "false";
#   * the JSON shape the AWS SDKs return: ClientVpnEndpoints[] with PascalCase field names.
# Endpoints whose status is "deleting" or "deleted" are not judged. A body with a nextToken is a
# partial page and is not judged (None, not evaluated).


def transform(input):
    """
    isMFARequiredForRemoteAccess (AWS side) - True only when there is at least one active Client VPN
    endpoint and EVERY active endpoint requires an identity-provider sign-in: one of its
    AuthenticationOptions is "federated-authentication" (SAML 2.0 through an IAM SAML provider) or
    "directory-service-authentication" (Active Directory). An endpoint whose only option is
    "certificate-authentication" (mutual TLS, no user sign-in) fails it: a device certificate alone
    opens the tunnel, and no identity provider can demand a second factor on that path.

    What AWS can prove: an identity provider is in the path of every Client VPN connection.
    What AWS cannot prove: that the identity provider demands MFA. That is the identity provider's
    own check (for Okta, its isMFARequiredForRemoteAccess reads the authentication policy of the
    AWS Client VPN app). Each tool speaks only for what it protects; neither line alone is the
    whole control. Directory authentication counts as "IdP in the path" here, but AWS cannot show
    whether that directory enforces MFA (a RADIUS second factor) either.

    Returns None (not evaluated) for an error body, a body with no endpoint list, a partial page,
    or no active endpoint. Also returns clientVpnEndpoints, federatedEndpoints,
    directoryEndpoints and certificateOnlyEndpoints, as numbers.
    """
    import json
    from datetime import datetime, timezone

    key = "isMFARequiredForRemoteAccess"

    def as_text(value):
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value).strip()

    def as_dict(value):
        if isinstance(value, dict):
            return value
        return {}

    def as_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and "item" in value:
            return as_list(value.get("item"))
        if isinstance(value, dict):
            return [value]
        return []

    def field(record, camel, pascal):
        record = as_dict(record)
        if camel in record:
            return record.get(camel)
        return record.get(pascal)

    def as_bool(value):
        text = as_text(value).lower()
        if text == "true":
            return True
        if text == "false":
            return False
        return None

    def respond(value, extra, passes, fails, summary, errors):
        body = {key: None if errors else value}
        for name in extra:
            body[name] = extra[name]
        return {
            "transformedResponse": body,
            "additionalInfo": {
                "dataCollection": {"status": "error" if errors else "success", "errors": errors},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "success", "errors": [], "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Amazon Web Services (AWS)",
                             "product": "AWS Client VPN",
                             "category": "Virtual Private Networks (VPNs)"},
            },
        }

    def not_evaluated(reason, extra=None, summary=None):
        return respond(None, extra or {}, [], [reason], summary or {}, [reason])

    def endpoint_label(endpoint):
        label = as_text(field(endpoint, "clientVpnEndpointId", "ClientVpnEndpointId"))
        return label or "an endpoint with no id"

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data) if data.strip() else None
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data \
                    and "DescribeClientVpnEndpointsResponse" not in data and "ClientVpnEndpoints" not in data:
                data = data[wrapper]
        if not isinstance(data, dict):
            return not_evaluated("Response is not an EC2 DescribeClientVpnEndpoints result")

        aws_error = as_dict(as_dict(as_dict(data.get("Response")).get("Errors")).get("Error"))
        if not aws_error:
            aws_error = as_dict(data.get("Error"))
        if aws_error or data.get("error") or data.get("errors") or data.get("errorMessage"):
            code = as_text(aws_error.get("Code")) or as_text(data.get("error"))[:120] or "error"
            return not_evaluated("AWS returned an error instead of the endpoint list: " + code[:200])

        if "DescribeClientVpnEndpointsResponse" in data:
            result = as_dict(data.get("DescribeClientVpnEndpointsResponse"))
            if "clientVpnEndpoint" not in result and "clientVpnEndpointSet" not in result:
                return not_evaluated("The DescribeClientVpnEndpoints result carries no endpoint list")
            raw = result.get("clientVpnEndpoint", result.get("clientVpnEndpointSet"))
            next_token = as_text(result.get("nextToken"))
        elif isinstance(data.get("ClientVpnEndpoints"), list):
            raw = data.get("ClientVpnEndpoints")
            next_token = as_text(data.get("NextToken"))
        else:
            return not_evaluated("Response carries no Client VPN endpoint list, so the query cannot be shown to have run")
        if next_token:
            return not_evaluated("The endpoint list is one page of several (nextToken present), so not every endpoint was read")

        endpoints = []
        for endpoint in as_list(raw):
            if not isinstance(endpoint, dict):
                continue
            state = as_text(field(field(endpoint, "status", "Status"), "code", "Code")).lower()
            if state in ["deleting", "deleted"]:
                continue
            endpoints.append(endpoint)
        summary = {"endpointsRead": len(as_list(raw)), "endpointsJudged": len(endpoints)}
        if not endpoints:
            return not_evaluated("No active AWS Client VPN endpoint in this Region: AWS Client VPN does not "
                                 "provide remote access here, so it has no answer", {"clientVpnEndpoints": 0}, summary)

        federated = 0
        directory = 0
        cert_only = []
        unknown = []
        for endpoint in endpoints:
            types = []
            for option in as_list(field(endpoint, "authenticationOptions", "AuthenticationOptions")):
                types.append(as_text(field(option, "type", "Type")).lower())
            if "federated-authentication" in types:
                federated = federated + 1
            elif "directory-service-authentication" in types:
                directory = directory + 1
            elif types and all([t == "certificate-authentication" for t in types]):
                cert_only.append(endpoint_label(endpoint))
            else:
                unknown.append(endpoint_label(endpoint))
        extra = {"clientVpnEndpoints": len(endpoints), "federatedEndpoints": federated,
                 "directoryEndpoints": directory, "certificateOnlyEndpoints": len(cert_only)}
        if cert_only:
            return respond(False, extra, [], [
                "Certificate-only authentication (no identity-provider sign-in, so no MFA is possible) on: "
                + ", ".join(cert_only[:20])], summary, [])
        if unknown:
            return respond(False, extra, [], [
                "No recognised identity-provider authentication option on: " + ", ".join(unknown[:20])],
                summary, [])
        return respond(True, extra, [
            "Every active Client VPN endpoint (" + str(len(endpoints)) + ") requires an identity-provider "
            "sign-in: " + str(federated) + " SAML federated, " + str(directory) + " directory. AWS shows the "
            "identity provider is in the path; the identity provider's own check proves the MFA."],
            [], summary, [])
    except Exception as e:
        return not_evaluated("Could not evaluate the Client VPN endpoint list: the response has an unexpected shape")
