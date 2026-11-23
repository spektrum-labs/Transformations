# isseparationofdutiesenabled.py - Delinea Secret Server (REST API, secret policies)
#
# Method: getSecretPolicies (workflow) = searchSecretPolicies (GET {secretServerUrl}/api/v1/secret-policy/search?take=100),
#         then iterate records into getSecretPolicy (GET {secretServerUrl}/api/v2/secret-policy/{secretPolicyId}),
#         output key policyDetails (one body per policy, same order).
# Docs:   Secret Server REST API reference 12.1.2, SecretPolicyDetailModelV2: {active, affectedSecretCount,
#         affectedInheritingSecretsCount, securityItems: {requireApprovalForAccess: {value, policyApplyType:
#         NotSet|Default|Enforced}, approvalGroups: {value: [..]}, approvalWorkflow: {value}}}
# Auth:   Delinea Platform OAuth2 client credentials (POST {serverUrl}/identity/api/oauth2/token/xpmplatform, scope
#         xpmheadless); the same bearer token is accepted by the tenant's Secret Server (docs.delinea.com
#         /online-help/platform-api/secret-server-apis-from-platform.htm).

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isSeparationOfDutiesEnabled',)


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
    isSeparationOfDutiesEnabled = true when at least one active secret policy requires approval for access
    (requireApprovalForAccess true, applied as Default or Enforced), names approvers (approval groups or an
    approval workflow), and is applied to at least one secret. False only when every policy was read and none
    qualifies. None (not evaluated) when policies were left unread (next page, or total above the policies read),
    when any policy detail could not be read or the detail count does not match, on an error body, a response
    lacking records or policyDetails, a total that is not a non-negative whole number, an empty list without an
    explicit total of 0, or an exception. Coverage across all secrets is reported by count, not judged.
    """
    key = "isSeparationOfDutiesEnabled"

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
        details = data.get("policyDetails")
        if not isinstance(records, list) or not isinstance(details, list):
            return {key: None, "reason": "Response lacks records or policyDetails"}
        if data.get("hasNext") is True:
            return {key: None, "reason": "More secret policies exist than were read"}
        total = data.get("total")
        if total is not None and (isinstance(total, bool) or not isinstance(total, int) or total < 0):
            return {key: None, "reason": "total is not a count, so whether all secret policies were read is unknown"}
        if isinstance(total, int) and total > len(records):
            return {key: None, "reason": "Only " + str(len(records)) + " of " + str(total) + " secret policies were read"}
        if len(records) == 0:
            if total == 0:
                return {key: False, "reason": "No active secret policy"}
            return {key: None, "reason": "No secret policies were returned and no completed count of 0 was given"}
        if len(details) != len(records):
            return {key: None, "reason": "Read " + str(len(details)) + " policy details for " + str(len(records)) + " policies"}
        qualifying = []
        for d in details:
            d = unwrap(d, "securityItems")
            issue = vendor_error(d)
            if issue:
                return {key: None, "reason": "A secret policy could not be read: " + issue}
            if d.get("active") is not True:
                continue
            sec = d.get("securityItems")
            if not isinstance(sec, dict):
                continue
            req = sec.get("requireApprovalForAccess")
            if not isinstance(req, dict) or req.get("value") is not True or req.get("policyApplyType") not in ["Default", "Enforced"]:
                continue
            groups = sec.get("approvalGroups")
            flow = sec.get("approvalWorkflow")
            has_groups = isinstance(groups, dict) and isinstance(groups.get("value"), list) and len(groups.get("value")) > 0
            has_flow = isinstance(flow, dict) and isinstance(flow.get("value"), int) and not isinstance(flow.get("value"), bool)
            if not (has_groups or has_flow):
                continue
            applied = 0
            for f in ["affectedSecretCount", "affectedInheritingSecretsCount"]:
                v = d.get(f)
                if isinstance(v, int) and not isinstance(v, bool):
                    applied = applied + v
            if applied > 0:
                qualifying.append(str(d.get("secretPolicyName")) + " (" + str(applied) + " secrets)")
        if len(qualifying) == 0:
            return {key: False, "reason": "No active secret policy requires approval from named approvers on any secret"}
        return {key: True, "reason": str(len(qualifying)) + " secret polic(ies) require approval for access", "policies": qualifying[:25]}
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
