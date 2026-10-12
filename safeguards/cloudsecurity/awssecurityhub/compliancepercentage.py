"""
Transformation: compliancePercentage
Vendor: AWS Security Hub  |  Category: Cloud Security

Control-level compliance score (matches AWS Security Hub's own methodology): findings are
deduplicated by SecurityControlId, a control passes unless any finding for it is FAILED, and the
score is passing_controls / total_controls. Sets both compliancePercentage and
CIScompliancePercentage from the findings provided (the method determines the standard).

There is no measured 0%. Not evaluated (both keys None, dataCollection status "error"): an error
body (this integration's, an HTTP one or an AWS one), an empty, non-JSON or unrecognised body, a
findings list that carries no PASSED or FAILED control status (0 of 0 is not a score), a findings
list with more pages (NextToken) left unread (the controls on later pages are not in the score),
and an exception. A readable list with controls and none passing is a real 0.

The next-page token is read as NextToken or nextToken, on the findings page or on any wrapper around it. A list entry
that is not an object, or a finding whose Compliance entry is not an object, cannot be read; it is skipped without
raising and the score is None.
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


TRANSFORM_ID = "compliancepercentage"
PAGED_SCORE_PROBLEM = ("The findings list has more pages (NextToken) that were not read, so the controls on "
                       "the later pages are missing from the score.")
UNREADABLE_SCORE_PROBLEM = ("A finding in the list has a Compliance entry that could not be read, so the controls it belongs to "
                            "may be missing from the score.")
NO_CONTROLS_PROBLEM = ("The Security Hub findings carry no PASSED or FAILED control status, so there is no "
                       "control to score.")


def transform(input):
    result_none = {"compliancePercentage": None, "CIScompliancePercentage": None}
    try:
        findings, next_token, problem = read_findings(input)
        if problem is not None:
            return not_evaluated(problem, result_none)
        control_failed = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            comp = compliance_of(f)
            if comp is None:
                continue
            cid = comp.get("SecurityControlId")
            status = str(comp.get("Status") or "").upper()
            if not cid or status not in ("PASSED", "FAILED"):
                continue
            if cid not in control_failed:
                control_failed[cid] = False
            if status == "FAILED":
                control_failed[cid] = True
        total = len(control_failed)
        if total == 0:
            return not_evaluated(NO_CONTROLS_PROBLEM, result_none)
        if next_token:
            return not_evaluated(PAGED_SCORE_PROBLEM, result_none)
        if unreadable_findings(findings):
            return not_evaluated(UNREADABLE_SCORE_PROBLEM, result_none)
        passing = 0
        for cid in control_failed:
            if not control_failed[cid]:
                passing = passing + 1
        percentage = int(round(100 * passing / total))
        result = {
            "compliancePercentage": percentage,
            "CIScompliancePercentage": percentage,
            "passingControls": passing,
            "totalControls": total,
        }
        return build_response(result,
                              pass_reasons=[str(percentage) + "% of controls passing (" + str(passing) + "/" + str(total) + ")"])
    except Exception as error:
        return not_evaluated(RAISED_PROBLEM, result_none, transformation_errors=[str(error)[:200]])
