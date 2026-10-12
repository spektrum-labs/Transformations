"""
Transformation: criticalOpenFindingsCount
Vendor: AWS Security Hub  |  Category: Cloud Security

Counts the findings that are both CRITICAL severity and a FAILED compliance status in the Security
Hub GetFindings list. The criterion is True when that count is 0, False when it is above 0.

Not evaluated (criterion and count None, dataCollection status "error"), never False and never a
measured 0: an error body (this integration's, an HTTP one or an AWS one), an empty, non-JSON or
unrecognised body, a findings list that carries no PASSED or FAILED compliance status (nothing was
evaluated, so zero critical findings is not a result), a findings list with more pages (NextToken)
left unread and no critical failing finding on the pages read, and an exception. A critical failing
finding keeps the verdict False whether or not more pages exist.
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
    for depth in range(5):
        if is_error_body(data):
            return None, None, ERROR_PROBLEM
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
    if is_error_body(data):
        return None, None, ERROR_PROBLEM
    if isinstance(data, dict) and isinstance(data.get("Findings"), list):
        return data["Findings"], data.get("NextToken"), None
    if isinstance(data, list) and data:
        return data, None, None
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


def control_status_map(findings, control_ids):
    statuses = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        comp = f.get("Compliance") or {}
        cid = comp.get("SecurityControlId")
        if cid not in control_ids:
            continue
        status = str(comp.get("Status") or "").upper()
        if status in ("PASSED", "FAILED"):
            prev = statuses.get(cid)
            statuses[cid] = "FAILED" if (status == "FAILED" or prev == "FAILED") else "PASSED"
    return statuses


CRITERIA_KEY = "criticalOpenFindingsCount"
TRANSFORM_ID = "criticalopenfindingscount"
NO_STATUS_PROBLEM = ("The Security Hub findings carry no PASSED or FAILED compliance status, so zero open "
                     "critical findings is not evidence that none exist.")


def transform(input):
    result_none = {CRITERIA_KEY: None, "openCriticalFindings": None}
    try:
        findings, next_token, problem = read_findings(input)
        if problem is not None:
            return not_evaluated(problem, result_none)
        critical = 0
        evaluated = 0
        for f in findings:
            if not isinstance(f, dict):
                continue
            comp = f.get("Compliance") or {}
            severity = str((f.get("Severity") or {}).get("Label") or "").upper()
            status = str(comp.get("Status") or "").upper()
            if status in ("PASSED", "FAILED"):
                evaluated = evaluated + 1
            if severity == "CRITICAL" and status == "FAILED":
                critical = critical + 1
        if critical > 0:
            return build_response({CRITERIA_KEY: False, "openCriticalFindings": critical},
                                  fail_reasons=[str(critical) + " open critical findings"])
        if evaluated == 0:
            return not_evaluated(NO_STATUS_PROBLEM, result_none)
        if next_token:
            return not_evaluated(PAGED_PROBLEM, result_none)
        return build_response({CRITERIA_KEY: True, "openCriticalFindings": 0},
                              pass_reasons=["No open critical findings"])
    except Exception as error:
        return not_evaluated(RAISED_PROBLEM, result_none, transformation_errors=[str(error)[:200]])
