# istrustedapplicationprotectionenabled.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: listTrustedTokenIssuers -> X-Amz-Target: SWBExternalService.ListTrustedTokenIssuers
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListTrustedTokenIssuers.html
#         TrustedTokenIssuers[] {TrustedTokenIssuerArn, Name, TrustedTokenIssuerType: OIDC_JWT}.

import json


def transform(input):
    """
    isTrustedApplicationProtectionEnabled = true when the instance has at least one trusted token issuer, so
    applications exchange a scoped, attributable identity token instead of shared credentials. False on an
    empty list, an unread page or any error body.
    """
    key = "isTrustedApplicationProtectionEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def unwrap(value, marker):
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def aws_error(d):
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        if d.get("__type"):
            return "AWS error " + str(d.get("__type")) + ": " + str(d.get("message") or d.get("Message") or "")
        out = d.get("Output")
        if isinstance(out, dict) and out.get("__type"):
            return "AWS error " + str(out.get("__type")) + " (request not dispatched; Content-Type must be application/x-amz-json-1.1)"
        return None

    try:
        data = unwrap(parse_input(input), "TrustedTokenIssuers")
        problem = aws_error(data)
        if problem:
            return {key: False, "reason": problem}
        issuers = data.get("TrustedTokenIssuers")
        if not isinstance(issuers, list):
            return {key: False, "reason": "Response has no TrustedTokenIssuers list"}
        named = [i for i in issuers if isinstance(i, dict) and i.get("TrustedTokenIssuerArn")]
        if len(named) == 0:
            return {key: False, "reason": "No trusted token issuer is configured"}
        return {key: True, "reason": str(len(named)) + " trusted token issuer(s)",
                "issuers": [str(i.get("Name")) + " (" + str(i.get("TrustedTokenIssuerType")) + ")" for i in named][:25]}
    except Exception as e:
        return {key: False, "error": str(e)}
