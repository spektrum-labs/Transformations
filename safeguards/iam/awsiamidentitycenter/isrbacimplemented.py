# isrbacimplemented.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: getPermissionSetProvisioning (workflow) = listPermissionSets, then iterate PermissionSets into
#   listAccountsForProvisionedPermissionSet (output key provisionedAccounts, one body per permission set, same order).
#   X-Amz-Target: SWBExternalService.ListPermissionSets / .ListAccountsForProvisionedPermissionSet
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListPermissionSets.html
#         https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountsForProvisionedPermissionSet.html
#         PermissionSets: [arn]; AccountIds: ["123456789012"]; NextToken absent on the last page.

import json


def transform(input):
    """
    isRBACImplemented = true when access is granted through permission sets: at least one permission set is
    provisioned to at least one AWS account. False when none is provisioned, when any permission set's accounts
    could not be read, or on any error body.
    """
    key = "isRBACImplemented"
    FAIL = False

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
            return {key: FAIL, "reason": problem}
        sets = data.get("PermissionSets")
        bodies = data.get("provisionedAccounts")
        if not isinstance(sets, list) or not isinstance(bodies, list):
            return {key: FAIL, "reason": "Response lacks PermissionSets or provisionedAccounts"}
        if data.get("NextToken"):
            return {key: FAIL, "reason": "A permission-set page was left unread (NextToken present)"}
        if len(sets) == 0:
            return {key: FAIL, "reason": "The instance has no permission sets"}
        if len(bodies) != len(sets):
            return {key: FAIL, "reason": "Read " + str(len(bodies)) + " provisioning bodies for " + str(len(sets)) + " permission sets"}
        counts = []
        for i in range(len(sets)):
            b = unwrap(bodies[i], "AccountIds")
            issue = aws_error(b)
            if issue:
                return {key: FAIL, "reason": "Permission set " + str(sets[i]) + ": " + issue}
            if not isinstance(b.get("AccountIds"), list) or b.get("NextToken"):
                return {key: FAIL, "reason": "Permission set " + str(sets[i]) + ": AccountIds missing or not fully read"}
            counts.append(len(b.get("AccountIds")))
        used = [sets[i] for i in range(len(sets)) if counts[i] > 0]
        if len(used) == 0:
            return {key: False, "reason": "No permission set is provisioned to any AWS account", "permissionSets": len(sets)}
        return {key: True, "reason": str(len(used)) + " of " + str(len(sets)) + " permission sets are provisioned to AWS accounts"}
    except Exception as e:
        return {key: False, "error": str(e)}
