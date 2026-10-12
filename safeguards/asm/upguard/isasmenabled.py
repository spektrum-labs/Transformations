# isasmenabled.py - UpGuard (Attack Surface Management, c2104db1)
#
# Method: getActiveDomains -> GET https://cyber-risk.upguard.com/api/public/domains?active=true
#         (page_token / next_page_token, all pages)
# Docs:   https://cyber-risk.upguard.com/api/docs (spec /api/swagger.json)
#           GET /domains "Returns a list of domains for your account."; Domain.active "The status of
#           the domain"; Domain.scanned_at "The time the domain was scanned. If the domain is inactive
#           or hasn't been scanned yet this field will be absent". Permission: BreachRisk

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isASMEnabled',)


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
    True when at least one domain is active and has been scanned: UpGuard is monitoring the
    organisation's external surface. False on an empty list or when no active domain has been scanned.
    None (not evaluated) when the body has no domains list, holds no object record, or cannot be read.
    """
    key = "isASMEnabled"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value, marker):
        for depth in range(4):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), dict):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    try:
        data = unwrap(parse(input), "domains")
        if not isinstance(data, dict) or not isinstance(data.get("domains"), list):
            return {key: None, "reason": "Response has no domains list (the /domains call did not run)"}
        if data["domains"] and not any(isinstance(d, dict) for d in data["domains"]):
            return {key: None, "reason": "Domain list holds no object record"}
        scanned = [d for d in data["domains"] if isinstance(d, dict) and d.get("active") is True and d.get("scanned_at")]
        if scanned:
            return {key: True, "reason": "Active domains are being scanned", "scannedDomains": len(scanned), "domainCount": len(data["domains"])}
        return {key: False, "reason": "No active domain has been scanned", "domainCount": len(data["domains"])}
    except Exception:
        return {key: None, "error": "The response could not be read, so it was not evaluated."}


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
