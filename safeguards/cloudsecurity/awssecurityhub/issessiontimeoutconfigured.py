"""
Transformation: isSessionTimeoutConfigured (a NUMBER: minutes)
Vendor: AWS Security Hub  |  Category: Cloud Security

Workflow getSSOPermissionSetSessions (sso-admin, awsJson1_1):
  listSSOInstances          ListInstances                  -> Instances[]
  listSSOPermissionSets     ListPermissionSets(InstanceArn) -> PermissionSets[] (ARNs)
  describeSSOPermissionSet  DescribePermissionSet, once per ARN -> permissionSetDetails[]
  https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DescribePermissionSet.html
  SessionDuration is ISO-8601 ("PT1H", "PT8H", "PT1H30M"); AWS allows 1 to 12 hours, default 1 hour.

The value is the LONGEST session duration, in minutes, across every permission set of the instance: the
longest a user's AWS access portal session can last before re-authentication. The requirement compares
it with lessThanOrEqual. There is no measured 0: no instance, no permission sets, a page left unread, a
missing or unparseable duration, or fewer details than permission sets is null with dataCollection
status "error".
"""

import json
from datetime import datetime

CRITERIA_KEY = "isSessionTimeoutConfigured"
TRANSFORM_ID = "issessiontimeoutconfigured"


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def find_body(data):
    for depth in range(5):
        if not isinstance(data, dict):
            return None
        if "permissionSetDetails" in data or "PermissionSets" in data or "Instances" in data:
            return data
        nxt = None
        for key in ("data", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def duration_minutes(text):
    """ISO-8601 duration with hours/minutes/seconds only (PT8H, PT1H30M, PT90M) -> minutes, else None."""
    if not isinstance(text, str) or not text.upper().startswith("PT") or len(text) < 4:
        return None
    rest = text.upper()[2:]
    total = 0.0
    number = ""
    units = {"H": 60.0, "M": 1.0, "S": 1.0 / 60.0}
    for ch in rest:
        if ch.isdigit() or ch == ".":
            number = number + ch
        elif ch in units and number:
            total = total + float(number) * units[ch]
            number = ""
        else:
            return None
    if number:
        return None
    return total


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (errors or []) else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (errors or []) else "success", "errors": errors or [],
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORM_ID, "vendor": "AWS Security Hub", "category": "Cloud Security"},
        },
    }


def unknown(reason, summary=None):
    return build_response({CRITERIA_KEY: None}, errors=[reason], summary=summary)


def transform(input):
    try:
        body = find_body(parse(input))
        if body is None:
            return unknown("No IAM Identity Center data was returned")
        if body.get("error") is True or body.get("__type"):
            return unknown("AWS or Integration-Service error: " + str(body.get("__type") or body.get("message") or "")[:200])
        instances = body.get("Instances")
        if not isinstance(instances, list) or not [i for i in instances if isinstance(i, dict) and i.get("Status") == "ACTIVE"]:
            return unknown("No ACTIVE IAM Identity Center instance: there is no permission-set session to measure")
        arns = body.get("PermissionSets")
        if not isinstance(arns, list) or body.get("NextToken"):
            return unknown("Permission sets were not read completely")
        if len(arns) == 0:
            return unknown("The IAM Identity Center instance has no permission sets: there is no session to measure")
        details = body.get("permissionSetDetails")
        if not isinstance(details, list) or len(details) != len(arns):
            return unknown("Read " + str(len(details) if isinstance(details, list) else 0) + " permission-set details for "
                           + str(len(arns)) + " permission sets")
        longest = None
        longest_names = []
        for d in details:
            ps = d.get("PermissionSet") if isinstance(d, dict) else None
            minutes = duration_minutes(ps.get("SessionDuration")) if isinstance(ps, dict) else None
            if minutes is None:
                return unknown("A permission set has no readable SessionDuration")
            name = str(ps.get("Name") or ps.get("PermissionSetArn") or "")
            if longest is None or minutes > longest:
                longest = minutes
                longest_names = [name]
            elif minutes == longest:
                longest_names.append(name)
        value = int(longest) if longest == int(longest) else round(longest, 2)
        summary = {"permissionSetCount": len(details), "maxSessionDurationMinutes": value}
        result = {CRITERIA_KEY: value, "maxSessionDurationMinutes": value, "permissionSetCount": len(details),
                  "longestSessionPermissionSets": longest_names[:25]}
        return build_response(result, pass_reasons=["Measured longest permission-set session: " + str(value) + " minutes ("
                                                    + ", ".join(longest_names[:5]) + ")"], summary=summary)
    except Exception as error:
        return build_response({CRITERIA_KEY: None}, errors=[str(error)])
