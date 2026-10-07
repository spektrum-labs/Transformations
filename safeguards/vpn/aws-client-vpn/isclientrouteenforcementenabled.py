# isclientrouteenforcementenabled.py - AWS Client VPN (Amazon EC2 Client VPN endpoints)
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
    isClientRouteEnforcementEnabled - True only when there is at least one active Client VPN
    endpoint and every active endpoint reports ClientRouteEnforcementOptions.Enforced = true (the
    AWS client keeps the device's routes matching the routes the endpoint pushes, so a user cannot
    route around the tunnel). False when any active endpoint reports it off. Not evaluated (None)
    when none is off but one or more do not report it.
    """
    import json
    from datetime import datetime, timezone

    key = "isClientRouteEnforcementEnabled"

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

    def decide(verdicts, extra_name, fail_text, pass_text, summary, more=None):
        failed = [v[0] for v in verdicts if v[1] == "fail"]
        unknown = [v[0] for v in verdicts if v[1] == "unknown"]
        extra = {"clientVpnEndpoints": len(verdicts), extra_name: len(failed)}
        for name in (more or {}):
            extra[name] = more[name]
        if failed:
            return respond(False, extra, [], [fail_text + ": " + ", ".join(failed[:20])], summary, [])
        if unknown:
            return not_evaluated("Not reported, so not judged, on: " + ", ".join(unknown[:20]), extra, summary)
        return respond(True, extra, [pass_text + " (" + str(len(verdicts)) + ")"], [], summary, [])

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
            return not_evaluated("AWS returned an error instead of the endpoint list")

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

        verdicts = []
        for endpoint in endpoints:
            value = as_bool(field(field(endpoint, "clientRouteEnforcementOptions", "ClientRouteEnforcementOptions"), "enforced", "Enforced"))
            if value is None:
                verdicts.append([endpoint_label(endpoint), "unknown"])
            elif value is True:
                verdicts.append([endpoint_label(endpoint), "pass"])
            else:
                verdicts.append([endpoint_label(endpoint), "fail"])
        return decide(verdicts, "endpointsWithoutRouteEnforcement", "Client route enforcement is off on", "Client route enforcement is on for every active Client VPN endpoint", summary)
    except Exception as e:
        return not_evaluated("Could not evaluate the Client VPN endpoint list: the response has an unexpected shape")
