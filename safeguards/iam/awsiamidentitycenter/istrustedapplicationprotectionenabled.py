# istrustedapplicationprotectionenabled.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: listTrustedTokenIssuers -> X-Amz-Target: SWBExternalService.ListTrustedTokenIssuers
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListTrustedTokenIssuers.html
#         TrustedTokenIssuers[] {TrustedTokenIssuerArn, Name, TrustedTokenIssuerType: OIDC_JWT}.

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isTrustedApplicationProtectionEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def transform_unmarked(input):
    """
    isTrustedApplicationProtectionEnabled = true when the instance has at least one trusted token issuer, so
    applications exchange a scoped, attributable identity token instead of shared credentials. False only from
    a read that shows none: the list arrived, was read completely, and is empty. None, reported as not evaluated,
    when nothing was measured: an AWS or Integration-Service error body (for example AccessDenied), no list, an
    unread page (NextToken left) with nothing on it, entries without an ARN, or an exception.
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
            return {key: None, "reason": problem}
        issuers = data.get("TrustedTokenIssuers")
        if not isinstance(issuers, list):
            return {key: None, "reason": "Response has no TrustedTokenIssuers list"}
        named = [i for i in issuers if isinstance(i, dict) and i.get("TrustedTokenIssuerArn")]
        if len(named) == 0 and (data.get("NextToken") or len(issuers) > 0):
            return {key: None, "reason": "No trusted token issuer could be read (an unread page, or entries without an ARN)"}
        if len(named) == 0:
            return {key: False, "reason": "No trusted token issuer is configured"}
        return {key: True, "reason": str(len(named)) + " trusted token issuer(s)",
                "issuers": [str(i.get("Name")) + " (" + str(i.get("TrustedTokenIssuerType")) + ")" for i in named][:25]}
    except Exception as e:
        return {key: None, "error": str(e)}


def transform(input):
    """transform_unmarked(), with a None criterion reported as not evaluated.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". This file's responses do not set that status, so it is set here, carrying the
    file's own reason for the None.
    """
    out = transform_unmarked(input)
    if not isinstance(out, dict):
        return out
    inner = out.get("transformedResponse", out)
    if not isinstance(inner, dict) or not criteria_unmeasured(inner):
        return out
    info = out.get("additionalInfo")
    info = info if isinstance(info, dict) else {}
    collection = info.get("dataCollection")
    if isinstance(collection, dict) and str(collection.get("status") or "").lower() == "error":
        return out
    evaluation = info.get("evaluation")
    reasons = evaluation.get("failReasons") if isinstance(evaluation, dict) else None
    why = [str(r) for r in reasons if r] if isinstance(reasons, list) else []
    for k in ("reason", "error", "unevaluated"):
        if out.get(k) and str(out.get(k)) not in why:
            why = why + [str(out.get(k))]
    errors = collection.get("errors") if isinstance(collection, dict) else None
    why = why + [str(e) for e in errors if e] if isinstance(errors, list) else why
    marked = dict(collection if isinstance(collection, dict) else {}, status="error",
                  errors=why or ["The response could not answer this check, so it was not evaluated."])
    return dict(out, additionalInfo=dict(info, dataCollection=marked))
