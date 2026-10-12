"""
Transformation: unencryptedStorageResourceCount
Vendor: AWS Security Hub  |  Category: Cloud Security

Counts the FAILED findings for the storage-encryption controls EC2.7 (EBS default encryption), RDS.3
(RDS encryption at rest) and EFS.1 (EFS encryption) in the Security Hub GetFindings list. The criterion
is True when that count is 0, False when it is above 0.

Not evaluated (criterion and count None, dataCollection status "error"), never False and never a
measured 0: an error body (this integration's, an HTTP one or an AWS one), an empty, non-JSON or
unrecognised body, a findings list with no PASSED or FAILED status for any of the three controls (they
were not evaluated, so zero failures is not a result), a findings list with more pages (NextToken) left
unread and no failing control on the pages read, and an exception. A FAILED finding keeps the verdict
False whether or not more pages exist, but with more pages unread, or a finding that cannot be read, the count of
unencrypted resources is None and unencryptedResourcesAtLeast reports the number seen (a lower bound, never a total).
A pass needs a PASSED or FAILED status for all three controls: with fewer read, no failure seen is not a pass.

The next-page token is read as NextToken or nextToken, on the findings page or on any wrapper around it. A list entry
that is not an object, or a finding whose Compliance entry is not an object, cannot be read: it is skipped without
raising, and a result that rests on the absence of a failure is then None.
"""

import json
from datetime import datetime

VENDOR = "AWS Security Hub"
CATEGORY = "Cloud Security"
WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output"]
ERROR_PROBLEM = "The Security Hub call returned an error, so there is nothing to measure."
SHAPE_PROBLEM = "The response carries no Security Hub findings list, so there is nothing to measure."
RAISED_PROBLEM = "The Security Hub response could not be processed, so no verdict can be given."
PAGED_PROBLEM = ("The findings list has more pages (NextToken) that were not read, and nothing on the pages read "
                 "shows a failure, so a pass cannot be shown.")


def parse_body(value):
    """JSON text to an object. Text that is not JSON is None (nothing readable), never an exception."""
    try:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
    except ValueError:
        return None
    return value


def is_error_body(data):
    """True for an error envelope: this integration's, an HTTP one or an AWS one."""
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors") or data.get("__type") or data.get("ErrorResponse"):
        return True
    if isinstance(data.get("Error"), dict) and data.get("Error"):
        return True
    for key in ["statusCode", "status_code", "httpStatus", "status"]:
        code = data.get(key)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return True
    return False


def read_findings(input_data):
    """(findings, next_token, problem): the Security Hub GetFindings list, or why there is none."""
    data = parse_body(input_data)
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = parse_body(data["data"])
    token = None
    for depth in range(5):
        if is_error_body(data):
            return None, None, ERROR_PROBLEM
        token = token or page_token(data)
        if not isinstance(data, dict) or "Findings" in data:
            break
        nxt = None
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), (dict, list)):
                nxt = data[key]
                break
        if nxt is None:
            break
        data = nxt
    # The loop reads levels 0-4; the page it ends on (level 5 when five wrappers were opened) has its token read here.
    token = token or page_token(data)
    if is_error_body(data):
        return None, None, ERROR_PROBLEM
    if isinstance(data, dict) and isinstance(data.get("Findings"), list):
        return data["Findings"], token, None
    if isinstance(data, list) and data:
        return data, token, None
    return None, None, SHAPE_PROBLEM


def build_response(result, pass_reasons=None, fail_reasons=None, api_errors=None, transformation_errors=None):
    api_errors = api_errors or []
    transformation_errors = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if transformation_errors else "success",
                               "errors": transformation_errors, "inputSummary": {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORM_ID, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_evaluated(reason, result, transformation_errors=None):
    """No verdict: the criterion is None and dataCollection is an error, so the evaluator shows Not
    evaluated. The reason is fixed text; the vendor's own error text is never copied into it."""
    return build_response(result, fail_reasons=["Not evaluated: " + reason], api_errors=[reason],
                          transformation_errors=transformation_errors)


def page_token(data):
    """The next-page token of a findings page: NextToken, or nextToken in lower camel case. None when there is none."""
    if isinstance(data, dict):
        return data.get("NextToken") or data.get("nextToken")
    return None


def compliance_of(finding):
    """The Compliance object of a finding: {} when the finding has none, None when it is not an object (unreadable)."""
    comp = finding.get("Compliance")
    if comp is None:
        return {}
    return comp if isinstance(comp, dict) else None


def unreadable_findings(findings):
    """How many list entries cannot be read: an entry that is not an object, or a finding whose Compliance entry is not an object."""
    count = 0
    for f in findings:
        if not isinstance(f, dict) or compliance_of(f) is None:
            count = count + 1
    return count


UNREADABLE_PROBLEM = ("A finding in the list has a Compliance entry that could not be read, and nothing on the "
                      "findings that were read shows a failure, so a pass cannot be shown.")


def control_status_map(findings, control_ids):
    statuses = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        comp = compliance_of(f)
        if comp is None:
            continue
        cid = comp.get("SecurityControlId")
        if cid not in control_ids:
            continue
        status = str(comp.get("Status") or "").upper()
        if status in ("PASSED", "FAILED"):
            prev = statuses.get(cid)
            statuses[cid] = "FAILED" if (status == "FAILED" or prev == "FAILED") else "PASSED"
    return statuses


CRITERIA_KEY = "unencryptedStorageResourceCount"
CONTROL_IDS = ["EC2.7", "RDS.3", "EFS.1"]
TRANSFORM_ID = "unencryptedstorageresourcecount"


def transform(input):
    result_none = {CRITERIA_KEY: None, "unencryptedResources": None}
    try:
        findings, next_token, problem = read_findings(input)
        if problem is not None:
            return not_evaluated(problem, result_none)
        statuses = control_status_map(findings, CONTROL_IDS)
        unencrypted = 0
        unreadable = 0
        for f in findings:
            if not isinstance(f, dict):
                unreadable = unreadable + 1
                continue
            comp = compliance_of(f)
            if comp is None:
                unreadable = unreadable + 1
                continue
            if comp.get("SecurityControlId") in CONTROL_IDS and str(comp.get("Status") or "").upper() == "FAILED":
                unencrypted = unencrypted + 1
        if unencrypted > 0:
            if next_token or unreadable:
                return build_response({CRITERIA_KEY: False, "unencryptedResources": None,
                                       "unencryptedResourcesAtLeast": unencrypted},
                                      fail_reasons=["At least " + str(unencrypted) + " unencrypted storage resource findings (more findings could not be read, so the total is not known)"])
            return build_response({CRITERIA_KEY: False, "unencryptedResources": unencrypted},
                                  fail_reasons=[str(unencrypted) + " unencrypted storage resource findings"])
        if not statuses:
            return not_evaluated("The Security Hub findings carry no status for " + ", ".join(CONTROL_IDS)
                                 + ": the storage-encryption controls were not evaluated in what was returned, "
                                 "so zero unencrypted storage resources is not evidence that none exist.",
                                 result_none)
        unread = [cid for cid in CONTROL_IDS if cid not in statuses]
        if unread:
            return not_evaluated("The Security Hub findings carry no status for " + ", ".join(unread)
                                 + ": not every storage-encryption control was evaluated in what was returned, "
                                 "so zero unencrypted storage resources is not evidence that none exist.",
                                 result_none)
        if next_token:
            return not_evaluated(PAGED_PROBLEM, result_none)
        if unreadable:
            return not_evaluated(UNREADABLE_PROBLEM, result_none)
        return build_response({CRITERIA_KEY: True, "unencryptedResources": 0},
                              pass_reasons=["No unencrypted storage resources"])
    except Exception as error:
        return not_evaluated(RAISED_PROBLEM, result_none, transformation_errors=[str(error)[:200]])
