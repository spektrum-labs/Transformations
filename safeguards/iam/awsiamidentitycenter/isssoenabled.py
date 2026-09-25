# isssoenabled.py - AWS IAM Identity Center (sso-admin API, awsJson1_1)
#
# Method: getSSOApplications (workflow) = listInstances + listApplications, merged.
#   POST https://sso.{region}.amazonaws.com/  X-Amz-Target: SWBExternalService.ListInstances / .ListApplications
# Docs:   https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListInstances.html
#         https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListApplications.html
#         Instances[].Status ACTIVE; Applications[].Status ENABLED | DISABLED; NextToken is absent on the last page.

import json


def transform(input):
    """
    isSSOEnabled = true when the Identity Center instance in the connected Region is ACTIVE and at least one
    application is ENABLED for federated sign-in. False on no instance, no enabled application, an unread
    page (NextToken left) or any error body.
    """
    key = "isSSOEnabled"

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
        data = unwrap(parse_input(input), "Instances")
        problem = aws_error(data)
        if problem:
            return {key: False, "reason": problem}
        instances = data.get("Instances")
        apps = data.get("Applications")
        if not isinstance(instances, list) or not isinstance(apps, list):
            return {key: False, "reason": "Response lacks Instances or Applications"}
        if data.get("NextToken"):
            return {key: False, "reason": "A page was left unread (NextToken present)"}
        active = [i for i in instances if isinstance(i, dict) and i.get("Status") == "ACTIVE"]
        if len(active) == 0:
            return {key: False, "reason": "No ACTIVE IAM Identity Center instance in this Region", "instances": len(instances)}
        enabled = [a for a in apps if isinstance(a, dict) and a.get("Status") == "ENABLED"]
        if len(enabled) == 0:
            return {key: False, "reason": "The instance has no ENABLED application", "applications": len(apps)}
        return {key: True, "reason": "ACTIVE instance with " + str(len(enabled)) + " ENABLED application(s)",
                "applications": [str(a.get("Name")) for a in enabled][:25]}
    except Exception as e:
        return {key: False, "error": str(e)}
