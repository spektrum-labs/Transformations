"""Transformation: unencryptedStorageResourceCount (data at rest on the Azure subscription)
Vendor: Microsoft Defender for Cloud
Category: Cloud Security
Method: getAssessments

  GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments
      ?api-version=2020-01-01   (paged by nextLink, pinned to management.azure.com)
  https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list

Counts Unhealthy resources on the Defender for Cloud recommendations "Transparent Data Encryption on SQL
databases should be enabled", "Virtual machines should encrypt temp disks, caches, and data flows between
Compute and Storage resources" and "Disk encryption should be applied on virtual machines", matched on
the display name. None (Unevaluated), never 0, when none of them was evaluated or the list was only
partly read.
"""

import json
from datetime import datetime, timezone

VENDOR = "Microsoft Defender for Cloud"
CATEGORY = "Cloud Security"
WRAPPER_KEYS = ["apiResponse", "api_response", "response", "result", "Output"]
REQUIRED_ROLES = "Reader and Security Reader on the subscription"
PERMISSION_CODES = ["authorizationfailed", "forbidden", "insufficientpermissions", "linkedauthorizationfailed"]


def decode(value):
    """A body as an object: dicts and lists as they are, JSON text or bytes parsed, else None."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def unwrap(value):
    """Strip the Integration-Service envelopes (data/validation, apiResponse, response, result)."""
    value = decode(value)
    for step in range(4):
        if not isinstance(value, dict):
            return value
        if "data" in value and "validation" in value and isinstance(value.get("data"), (dict, list)):
            value = value["data"]
            continue
        moved = False
        for key in WRAPPER_KEYS:
            inner = value.get(key)
            if isinstance(inner, (dict, list)):
                value = inner
                moved = True
                break
        if not moved:
            return value
    return value


def arm_error(body):
    """The reason an ARM read failed, or None. Never treats an error body as evidence."""
    if not isinstance(body, dict):
        return None
    marker = body.get("vendorErrorAsResponse")
    if isinstance(marker, dict):
        inner = decode(marker.get("body"))
        status = marker.get("status")
        code = ""
        if isinstance(inner, dict) and isinstance(inner.get("error"), dict):
            code = str(inner["error"].get("code") or "")
        return {"status": status, "code": code}
    err = body.get("error")
    if isinstance(err, dict):
        return {"status": err.get("statusCode") or body.get("statusCode"), "code": str(err.get("code") or "")}
    if isinstance(err, str) and err:
        return {"status": body.get("statusCode") or body.get("status_code"), "code": err}
    for field in ("statusCode", "status_code"):
        status = body.get(field)
        if isinstance(status, int) and status >= 400:
            return {"status": status, "code": ""}
    return None


def is_permission_error(problem):
    if not isinstance(problem, dict):
        return False
    if problem.get("status") in (401, 403):
        return True
    return str(problem.get("code") or "").lower() in PERMISSION_CODES


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, additional_findings=None, key=None):
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": key or "",
                "vendor": VENDOR,
                "category": CATEGORY,
            },
        },
    }


def not_evaluated(keys, reason, problem=None, recommendation=None):
    """Nothing was measured: every key None (Unevaluated), never True, never 0."""
    result = {}
    for k in keys:
        result[k] = None
    text = "Not evaluated: " + reason
    recs = []
    if recommendation:
        recs.append(recommendation)
    out = create_response(result, fail_reasons=[text], api_errors=[text], recommendations=recs, key=keys[0])
    if is_permission_error(problem):
        out["additionalInfo"]["dataCollection"]["errorCode"] = "permission_not_granted"
        out["additionalInfo"]["dataCollection"]["requiredPermission"] = REQUIRED_ROLES
        out["additionalInfo"]["evaluation"]["recommendations"] = [
            "Assign the built-in Reader and Security Reader roles on the subscription to the Spektrum app "
            "registration (Azure portal > Subscriptions > Access control (IAM) > Add role assignment)."]
    return out


def error_reason(problem, endpoint):
    status = problem.get("status") if isinstance(problem, dict) else None
    code = problem.get("code") if isinstance(problem, dict) else ""
    text = "Azure refused " + endpoint
    if status:
        text = text + " (HTTP " + str(status)[:10] + ")"
    if code:
        text = text + " with " + str(code)[:80]
    return text + "; nothing was measured."


def arm_list(body, endpoint):
    """(items, None) for a complete ARM list body, else (None, (reason, problem)).

    A body with an unread nextLink, or one Integration-Service marked paginationTruncated, is a partial
    read: a partial list can hide the unhealthy item, so it is never evidence."""
    body = unwrap(body)
    if isinstance(body, list):
        return None, ("the " + endpoint + " response is a bare list, not an ARM collection", None)
    if not isinstance(body, dict):
        return None, ("no " + endpoint + " response was returned", None)
    problem = arm_error(body)
    if problem is not None:
        return None, (error_reason(problem, endpoint), problem)
    items = body.get("value")
    if not isinstance(items, list):
        return None, ("the " + endpoint + " response carries no value collection", None)
    if body.get("paginationTruncated") is True or (isinstance(body.get("nextLink"), str) and body.get("nextLink")):
        return None, ("the " + endpoint + " list was only partly read (unread next page)", None)
    return items, None


def norm(text):
    return " ".join(str(text or "").lower().split())


def props_of(item):
    props = item.get("properties") if isinstance(item, dict) else None
    return props if isinstance(props, dict) else {}


def assessment_display_name(item):
    props = props_of(item)
    name = props.get("displayName")
    if not name and isinstance(props.get("metadata"), dict):
        name = props["metadata"].get("displayName")
    return str(name or "")


def assessment_status(item):
    status = props_of(item).get("status")
    if not isinstance(status, dict):
        return ""
    code = norm(status.get("code"))
    if code == "healthy":
        return "Healthy"
    if code == "unhealthy":
        return "Unhealthy"
    if code == "notapplicable":
        return "NotApplicable"
    return ""


def assessment_resource(item):
    details = props_of(item).get("resourceDetails")
    if isinstance(details, dict) and details.get("id"):
        return str(details.get("id"))
    return str(item.get("id") or "") if isinstance(item, dict) else ""


def tally(items, matcher):
    """Healthy / Unhealthy / NotApplicable assessments whose display name the matcher accepts."""
    out = {"healthy": [], "unhealthy": [], "notApplicable": [], "names": []}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = assessment_display_name(item)
        if not name or not matcher(norm(name)):
            continue
        status = assessment_status(item)
        if name not in out["names"]:
            out["names"].append(name)
        if status == "Healthy":
            out["healthy"].append(item)
        elif status == "Unhealthy":
            out["unhealthy"].append(item)
        elif status == "NotApplicable":
            out["notApplicable"].append(item)
    return out


def describe(items, limit):
    lines = []
    for item in items[:limit]:
        lines.append(assessment_display_name(item) + " -> " + assessment_resource(item))
    return lines

KEY = "unencryptedStorageResourceCount"
ENDPOINT = "GET assessments"


def matches(name):
    if "transparent data encryption" in name and "sql" in name:
        return True
    if "virtual machines should encrypt temp disks" in name:
        return True
    return "disk encryption should be applied on virtual machines" in name


def measure(input):
    items, failure = arm_list(input, ENDPOINT)
    if items is None:
        return not_evaluated([KEY], failure[0], failure[1])
    found = tally(items, matches)
    healthy = len(found["healthy"])
    unhealthy = len(found["unhealthy"])
    summary = {"assessments": len(items), "matched": found["names"], "healthy": healthy, "unhealthy": unhealthy,
               "notApplicable": len(found["notApplicable"])}
    if healthy + unhealthy == 0:
        return not_evaluated([KEY], "Defender for Cloud returned no evaluated encryption-at-rest recommendation "
                                    "(SQL TDE or VM disk encryption) for the subscription")
    result = {KEY: unhealthy, "resourcesEvaluated": healthy + unhealthy}
    if unhealthy:
        return create_response(result, fail_reasons=["Resources without encryption at rest: "
                                                     + "; ".join(describe(found["unhealthy"], 5))],
                               recommendations=["Enable Transparent Data Encryption on every SQL database and "
                                                "encryption at host or Azure Disk Encryption on every VM."],
                               input_summary=summary, key=KEY)
    return create_response(result, pass_reasons=["Every evaluated SQL database and VM disk is encrypted ("
                                                  + str(healthy) + " Healthy)."], input_summary=summary, key=KEY)


def transform(input):
    try:
        return measure(input)
    except Exception:
        return not_evaluated([KEY], "the assessments response could not be processed")
