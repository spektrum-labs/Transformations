# openorphanaccountscount.py - Delinea Secret Server (REST API v1, Discovery)
#
# Method: getDiscoveryStatus -> GET {secretServerUrl}/api/v1/discovery/status?includeExtendedMetrics=true
# Docs:   Secret Server REST API reference 12.1.2, DiscoveryStatusModel: {isDiscoveryEnabled, discoverySourceCount,
#         discoveryFetchEndDateTime, itemMetrics: [{itemType, itemTypeDisplayName, managedCount, notManagedCount}]}.
#         Item types documented for filter.itemType: account, computer, key, service-account.
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('openOrphanAccountsCount',)


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
    openOrphanAccountsCount = discovered accounts (item types account and service-account) that Discovery found on
    managed systems but that are not managed in the vault (notManagedCount). None when Discovery is off, has no
    source, has never completed a fetch, reports no account metrics, or on any error body: a zero from a scan
    that never ran proves nothing. Ruling needed: "account" includes non-administrator local accounts.
    """
    key = "openOrphanAccountsCount"

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
        data = unwrap(parse_input(input), "isDiscoveryEnabled")
        problem = vendor_error(data)
        if problem:
            return {key: None, "reason": problem}
        if data.get("isDiscoveryEnabled") is not True:
            return {key: None, "reason": "Discovery is not enabled"}
        sources = data.get("discoverySourceCount")
        if isinstance(sources, bool) or not isinstance(sources, int) or sources < 1:
            return {key: None, "reason": "Discovery has no source"}
        if not data.get("discoveryFetchEndDateTime"):
            return {key: None, "reason": "Discovery has never completed a fetch"}
        metrics = data.get("itemMetrics")
        if not isinstance(metrics, list):
            return {key: None, "reason": "Response has no itemMetrics (includeExtendedMetrics not honoured)"}
        count = 0
        matched = []
        for m in metrics:
            if not isinstance(m, dict):
                continue
            kind = str(m.get("itemType") or "").strip().lower().replace("_", "-").replace(" ", "-")
            if kind not in ["account", "service-account", "serviceaccount"]:
                continue
            n = m.get("notManagedCount")
            if isinstance(n, bool) or not isinstance(n, int):
                return {key: None, "reason": "notManagedCount for " + kind + " is not a number"}
            count = count + n
            matched.append(kind)
        if len(matched) == 0:
            return {key: None, "reason": "No account item metrics in the Discovery status",
                    "itemTypes": [str(m.get("itemType")) for m in metrics if isinstance(m, dict)][:25]}
        return {key: count, "reason": str(count) + " discovered account(s) not managed in the vault", "itemTypes": matched}
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
