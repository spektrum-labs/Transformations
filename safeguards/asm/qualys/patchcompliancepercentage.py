"""
Transformation: patchCompliancePercentage
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Patch compliance as percentage of fixed vs total detections.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "patchCompliancePercentage", "vendor": "Qualys", "category": "Attack Surface Management"}
        }
    }


NOT_SCANNED = "Confirm Qualys has scanned the hosts in scope."
# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None, findings=None,
                 recommendations=(NOT_OURS_TO_ASK,)):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings, recommendations=list(recommendations))
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


# --- Qualys detection reply: byte-identical in every transform that reads it (a test compares the copies) ---
OPEN_STATUSES = {'new', 'active', 'reopened'}


def detection_response(data):
    """HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE, or None when the body is not a detection reply."""
    output = data.get('HOST_LIST_VM_DETECTION_OUTPUT') if isinstance(data, dict) else None
    response = output.get('RESPONSE') if isinstance(output, dict) else None
    return response if isinstance(response, dict) else None


def status_token(value):
    """One status spelling: Qualys writes Re-Opened, REOPENED and Fixed, FIXED for the same state."""
    return str(value).strip().lower().replace('-', '').replace('_', '').replace(' ', '')


def echoed_statuses(data):
    """The detection statuses Qualys says it applied, or None when the reply carries no request echo.

    Qualys returns only New, Active and Re-Opened detections unless status= names others. With
    echo_request=1 it repeats the parameters it applied under HOST_LIST_VM_DETECTION_OUTPUT.REQUEST.
    That echo is the only proof of the filter: a definition can name Fixed and never send it
    (inputParameters on a GET without parametersIn "query" travel as an ignored body). An echo with
    no status parameter means Qualys applied its default.
    """
    output = data.get('HOST_LIST_VM_DETECTION_OUTPUT') if isinstance(data, dict) else None
    request = output.get('REQUEST') if isinstance(output, dict) else None
    param_list = request.get('PARAM_LIST') if isinstance(request, dict) else None
    params = param_list.get('PARAM') if isinstance(param_list, dict) else None
    if isinstance(params, dict):
        params = [params]
    if not isinstance(params, list):
        return None
    for param in params:
        if isinstance(param, dict) and str(param.get('KEY', '')).strip().lower() == 'status':
            return {status_token(v) for v in str(param.get('VALUE', '')).split(',') if v.strip()}
    return set(OPEN_STATUSES)


EMPTY = (None, '', [])  # xmltodict writes an empty element as None


def detection_hosts(response):
    """Host records in a detection RESPONSE; none when Qualys omits HOST_LIST, which means nothing assessed.

    A HOST_LIST that is present but empty, or holds anything but host records, raises: that is our read
    failing, not "nothing scanned", and grading the readable hosts would grade an unstated subset.
    """
    host_list = response.get('HOST_LIST')
    if host_list is None:
        return []
    hosts = host_list.get('HOST') if isinstance(host_list, dict) else None
    if isinstance(hosts, dict):
        hosts = [hosts]
    if not isinstance(hosts, list) or not hosts or any(not isinstance(host, dict) for host in hosts):
        raise ValueError("unreadable host list")
    return hosts


def detection_rows(host):
    """A host's detection records; none when DETECTION_LIST or DETECTION is empty.

    Any other shape, or any row that is not a record, raises: grading the readable rows would grade an
    unstated subset, so every reader treats an unreadable row the same way, as not measured.
    """
    if not isinstance(host, dict):
        raise ValueError("unreadable host record")
    detection_list = host.get('DETECTION_LIST')
    if detection_list in EMPTY:
        return []
    if not isinstance(detection_list, dict):
        raise ValueError("unreadable detection list")
    rows = detection_list.get('DETECTION')
    if rows in EMPTY:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("unreadable detection row")
    return rows


def truncated(response):
    """True when Qualys stopped the host list at its record limit (WARNING code 1980)."""
    warning = response.get('WARNING')
    warnings = warning if isinstance(warning, list) else [warning]
    return any(isinstance(w, dict) and str(w.get('CODE', '')).strip() == '1980' for w in warnings)
# --- end Qualys detection reply ----------------------------------------------------------------------------


def evaluate(data):
    """Fixed detections as a share of every detection, graded only when the reply proves its filter."""
    try:
        if truncated(detection_response(data)):
            return {"patchCompliancePercentage": None, "errorCode": "partial_read",
                    "notMeasured": "Spektrum's Qualys read stopped at a page limit, so patch compliance is not graded."}
        hosts = detection_hosts(detection_response(data))
        total = 0
        fixed = 0
        for host in hosts:
            detections = detection_rows(host)
            total += len(detections)
            fixed += sum(1 for d in detections if status_token(d.get('STATUS', '')) == 'fixed')
        statuses = echoed_statuses(data)
        if statuses is None and total == 0:
            statuses = set(OPEN_STATUSES)  # no echo: Qualys applied its default, and no open detection is a measured 100
        if statuses is None or not OPEN_STATUSES <= statuses or (total > 0 and 'fixed' not in statuses):
            # The share needs open and fixed detections both, and only the echo proves both were asked for.
            return {"patchCompliancePercentage": None, "totalDetections": total, "fixedDetections": fixed,
                    "errorCode": "not_measured",
                    "notMeasured": "Spektrum's Qualys read does not yet include both open and fixed detections, "
                                   "so patch compliance could not be measured."}
        compliance = int((fixed / total) * 100) if total > 0 else 100
        return {"patchCompliancePercentage": str(compliance), "totalDetections": total, "fixedDetections": fixed}
    except Exception:
        return {"patchCompliancePercentage": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "patchCompliancePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so patch compliance could not be measured.",
                                "not_measured", validation=validation)
        response = detection_response(data)
        if response is None:
            return not_measured(criteriaKey, "The Qualys response could not be read, so patch compliance could not be measured.",
                                "not_measured", validation=validation)
        if not detection_hosts(response):  # raises on an unreadable list, which the except below reports
            return not_measured(criteriaKey, "Qualys returned no assessed hosts, so patch compliance could not be measured.",
                                "no_data", validation=validation, recommendations=(NOT_SCANNED,))
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], eval_result["errorCode"], validation=validation,
                                findings=[f"{k}: {v}" for k, v in eval_result.items()
                                          if k not in (criteriaKey, "notMeasured", "errorCode")])
        if "error" in eval_result or eval_result.get(criteriaKey) is None:
            return not_measured(criteriaKey, "The Qualys detection list could not be read, so patch compliance could not be measured.",
                                "not_measured", validation=validation, transformation_errors=[eval_result.get("error", "no value")])
        result_value = eval_result[criteriaKey]
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        summary = ["patchCompliancePercentage: " + str(result_value)] + [f"{k}: {v}" for k, v in extra_fields.items()]
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=summary,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so patch compliance could not be measured.",
                            "not_measured", validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
