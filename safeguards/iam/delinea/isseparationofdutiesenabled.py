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


def transform(input):
    """
    isSeparationOfDutiesEnabled = true when at least one active secret policy requires approval for access
    (requireApprovalForAccess true, applied as Default or Enforced), names approvers (approval groups or an
    approval workflow), and is applied to at least one secret. False otherwise, when policies were left unread,
    when any policy detail could not be read, or on any error body. Coverage across all secrets is reported
    by count, not judged.
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
            return {key: False, "reason": problem}
        records = data.get("records")
        details = data.get("policyDetails")
        if not isinstance(records, list) or not isinstance(details, list):
            return {key: False, "reason": "Response lacks records or policyDetails"}
        if data.get("hasNext") is True:
            return {key: False, "reason": "More secret policies exist than were read"}
        if len(records) == 0:
            return {key: False, "reason": "No active secret policy"}
        if len(details) != len(records):
            return {key: False, "reason": "Read " + str(len(details)) + " policy details for " + str(len(records)) + " policies"}
        qualifying = []
        for d in details:
            d = unwrap(d, "securityItems")
            issue = vendor_error(d)
            if issue:
                return {key: False, "reason": "A secret policy could not be read: " + issue}
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
        return {key: False, "error": str(e)}
