# authtypesallowed.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: getApplicationProtocols (workflow) = listApplications + listApplicationProviders, merged.
#   X-Amz-Target: SWBExternalService.ListApplications / SWBExternalService.ListApplicationProviders
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListApplications.html
#         https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListApplicationProviders.html
#         Applications[].ApplicationProviderArn -> ApplicationProviders[].FederationProtocol (SAML | OAUTH).

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('authTypesAllowed',)


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
    authTypesAllowed = the federation protocol of the instance's ENABLED applications, read from each
    application's provider: "SAML" when every enabled application federates with SAML, "OAUTH" when every one
    uses OAuth, and the sorted comma-joined set when they differ. None when nothing can be read, no application
    is enabled, or any enabled application's provider is not in the provider list.
    """
    key = "authTypesAllowed"

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
        data = unwrap(parse_input(input), "Applications")
        problem = aws_error(data)
        if problem:
            return {key: None, "reason": problem}
        apps = data.get("Applications")
        providers = data.get("ApplicationProviders")
        if not isinstance(apps, list) or not isinstance(providers, list):
            return {key: None, "reason": "Response lacks Applications or ApplicationProviders"}
        if data.get("NextToken"):
            return {key: None, "reason": "A page was left unread (NextToken present)"}
        protocol_by_arn = {}
        for p in providers:
            if isinstance(p, dict) and p.get("ApplicationProviderArn") and p.get("FederationProtocol"):
                protocol_by_arn[p.get("ApplicationProviderArn")] = str(p.get("FederationProtocol")).upper()
        enabled = [a for a in apps if isinstance(a, dict) and a.get("Status") == "ENABLED"]
        if len(enabled) == 0:
            return {key: None, "reason": "No ENABLED application"}
        seen = []
        for a in enabled:
            proto = protocol_by_arn.get(a.get("ApplicationProviderArn"))
            if proto is None:
                return {key: None, "reason": "Provider of application " + str(a.get("Name")) + " is not in the provider list"}
            if proto not in seen:
                seen.append(proto)
        value = ",".join(sorted(seen))
        return {key: value, "reason": str(len(enabled)) + " ENABLED application(s) federate with " + value}
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
