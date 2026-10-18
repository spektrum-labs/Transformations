# isrbacimplemented.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: getPermissionSetProvisioning (workflow) = listPermissionSets, then iterate PermissionSets into
#   listAccountsForProvisionedPermissionSet (output key provisionedAccounts, one body per permission set, same order).
#   X-Amz-Target: SWBExternalService.ListPermissionSets / .ListAccountsForProvisionedPermissionSet
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListPermissionSets.html
#         https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountsForProvisionedPermissionSet.html
#         PermissionSets: [arn]; AccountIds: ["123456789012"]; NextToken absent on the last page.

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isRBACImplemented',)


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
    isRBACImplemented = true when access is granted through permission sets: at least one permission set is
    provisioned to at least one AWS account. False only from a complete read that shows it is not: no permission
    set exists, or every permission set's accounts were read and none is provisioned. None, reported as not
    evaluated, when nothing was measured: an AWS or Integration-Service error body (for example AccessDenied),
    a missing list, an unread page (NextToken left), a permission set whose accounts were not read, or an exception.
    """
    key = "isRBACImplemented"
    UNMEASURED = None

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
        data = unwrap(parse_input(input), "PermissionSets")
        problem = aws_error(data)
        if problem:
            return {key: UNMEASURED, "reason": problem}
        sets = data.get("PermissionSets")
        bodies = data.get("provisionedAccounts")
        if not isinstance(sets, list) or not isinstance(bodies, list):
            return {key: UNMEASURED, "reason": "Response lacks PermissionSets or provisionedAccounts"}
        if data.get("NextToken"):
            return {key: UNMEASURED, "reason": "A permission-set page was left unread (NextToken present)"}
        if len(sets) == 0:
            return {key: False, "reason": "The instance has no permission sets"}
        if len(bodies) != len(sets):
            return {key: UNMEASURED, "reason": "Read " + str(len(bodies)) + " provisioning bodies for " + str(len(sets)) + " permission sets"}
        counts = []
        for i in range(len(sets)):
            b = unwrap(bodies[i], "AccountIds")
            issue = aws_error(b)
            if issue:
                return {key: UNMEASURED, "reason": "Permission set " + str(sets[i]) + ": " + issue}
            if not isinstance(b.get("AccountIds"), list) or b.get("NextToken"):
                return {key: UNMEASURED, "reason": "Permission set " + str(sets[i]) + ": AccountIds missing or not fully read"}
            counts.append(len(b.get("AccountIds")))
        used = [sets[i] for i in range(len(sets)) if counts[i] > 0]
        if len(used) == 0:
            return {key: False, "reason": "No permission set is provisioned to any AWS account", "permissionSets": len(sets)}
        return {key: True, "reason": str(len(used)) + " of " + str(len(sets)) + " permission sets are provisioned to AWS accounts"}
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
