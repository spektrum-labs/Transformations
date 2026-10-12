# isssoenabled.py - Delinea Platform (identity-federation API)
#
# Method: getSAMLProviders -> GET {serverUrl}/identity-federation/api/saml-providers
# Docs:   https://docs.delinea.com/online-help/platform-api/identity-federation.htm
#         (identity-federation.externalapi.json): {records: [{id, entityId, enabled, loginUrl, ...}], count, totalCount}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isSSOEnabled',)


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
    isSSOEnabled = true when the Platform tenant has at least one ENABLED SAML identity provider, so users sign in
    through an external IdP. False only when the complete providers list was read and none is enabled. None (not
    evaluated) on an error body, no records list, a partial read (totalCount above the records read) with none
    enabled, a totalCount that is not a non-negative whole number, an empty list without an explicit totalCount
    of 0, or an exception.
    """
    key = "isSSOEnabled"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("HTML or XML body; expected JSON from the Delinea API")
            return json.loads(text)
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

    def vendor_error(d):
        """A reason when the body is an Integration-Service or Delinea error, else None."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        if d.get("success") is False:
            return "Delinea reported success=false: " + str(d.get("message") or d.get("Message") or "")[:200]
        if d.get("errorCode"):
            return "Delinea error " + str(d.get("errorCode")) + ": " + str(d.get("message") or "")[:200]
        status = d.get("status")
        if isinstance(status, int) and status >= 400:
            return "Delinea HTTP " + str(status) + ": " + str(d.get("title") or d.get("detail") or "")[:200]
        return None

    try:
        data = unwrap(parse_input(input), "records")
        problem = vendor_error(data)
        if problem:
            return {key: None, "reason": problem}
        records = data.get("records")
        if not isinstance(records, list):
            return {key: None, "reason": "Response has no records list"}
        enabled = [r for r in records if isinstance(r, dict) and r.get("enabled") is True]
        if len(enabled) > 0:
            return {key: True, "reason": str(len(enabled)) + " enabled SAML identity provider(s)",
                    "providers": [str(r.get("entityId") or r.get("id")) for r in enabled][:25]}
        total = data.get("totalCount")
        if total is not None and (isinstance(total, bool) or not isinstance(total, int) or total < 0):
            return {key: None, "reason": "totalCount is not a count, so whether all SAML providers were read is unknown"}
        if isinstance(total, int) and total > len(records):
            return {key: None, "reason": "Only " + str(len(records)) + " of " + str(total) + " SAML providers were read"}
        if len(records) == 0 and total != 0:
            return {key: None, "reason": "No SAML providers were returned and no completed count of 0 was given"}
        return {key: False, "reason": "No enabled SAML identity provider", "providers": len(records)}
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
