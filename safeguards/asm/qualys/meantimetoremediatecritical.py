"""
Transformation: meanTimeToRemediateCritical
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Average days to remediate critical vulnerabilities.
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


# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "meanTimeToRemediateCritical", "vendor": "Qualys", "category": "Attack Surface Management"}
        }
    }


def fixed_requested(data):
    """True when Qualys echoes a status filter that includes Fixed.

    Qualys returns only New, Active and Re-Opened detections unless the request names Fixed. With
    echo_request=1 it repeats the parameters it applied in HOST_LIST_VM_DETECTION_OUTPUT.REQUEST.
    That echo is the only proof Fixed was asked for: a definition can name Fixed and still never
    send it (inputParameters on a GET without parametersIn "query" travel as an ignored body).
    """
    try:
        params = data['HOST_LIST_VM_DETECTION_OUTPUT']['REQUEST']['PARAM_LIST']['PARAM']
    except Exception:
        return False
    if isinstance(params, dict):
        params = [params]
    if not isinstance(params, list):
        return False
    for param in params:
        if isinstance(param, dict) and str(param.get('KEY', '')).strip().lower() == 'status':
            return any(v.strip().lower() == 'fixed' for v in str(param.get('VALUE', '')).split(','))
    return False


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None, findings=None,
                 recommendations=(NOT_OURS_TO_ASK,)):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings,
        recommendations=list(recommendations))
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


def evaluate(data):
    """Core evaluation logic."""
    try:
        hosts = data.get('HOST_LIST_VM_DETECTION_OUTPUT', {}).get('RESPONSE', {}).get('HOST_LIST', {}).get('HOST', [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        deltas = []
        any_fixed = False
        for host in hosts:
            detections = host.get('DETECTION_LIST', {}).get('DETECTION', [])
            if isinstance(detections, dict):
                detections = [detections]
            for d in detections:
                is_fixed = isinstance(d, dict) and str(d.get('STATUS', '')).lower() == 'fixed'
                any_fixed = any_fixed or is_fixed
                if is_fixed and int(d.get('SEVERITY', 0)) >= 4:
                    found = d.get('FIRST_FOUND_DATETIME', '')
                    fixed_dt = d.get('LAST_FIXED_DATETIME', '')
                    if found and fixed_dt:
                        t_found = datetime.fromisoformat(found.replace('Z', '+00:00'))
                        t_fixed = datetime.fromisoformat(fixed_dt.replace('Z', '+00:00'))
                        if t_fixed >= t_found:  # a fix dated before the finding is not a remediation time
                            deltas.append((t_fixed - t_found).days)
        if not deltas:
            # No remediated critical detection to average is not a 0-day remediation time.
            if not any_fixed and not fixed_requested(data):  # a Fixed row of any severity proves Fixed was asked for
                return {"meanTimeToRemediateCritical": None, "sampleSize": 0, "errorCode": "not_measured",
                        "notMeasured": "Spektrum's Qualys read does not yet include fixed detections, so mean "
                                       "time to remediate could not be measured."}
            return {"meanTimeToRemediateCritical": None, "sampleSize": 0, "errorCode": "no_data",
                    "notMeasured": "Qualys reports no remediated critical detections, so there is no "
                                   "remediation time to average."}
        mttr = int(sum(deltas) / len(deltas))
        return {"meanTimeToRemediateCritical": str(mttr), "averageDays": mttr, "sampleSize": len(deltas)}
    except Exception:
        return {"meanTimeToRemediateCritical": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "meanTimeToRemediateCritical"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so mean time to remediate could not be measured.",
                                "not_measured", validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], eval_result["errorCode"], validation=validation,
                                findings=[f"{k}: {v}" for k, v in eval_result.items()
                                          if k not in (criteriaKey, "notMeasured", "errorCode")],
                                recommendations=() if eval_result["errorCode"] == "no_data" else (NOT_OURS_TO_ASK,))
        if "error" in eval_result or eval_result.get(criteriaKey) is None:
            return not_measured(criteriaKey, "The Qualys response could not be read, so mean time to remediate could not be measured.",
                                "not_measured", validation=validation, transformation_errors=[eval_result.get("error", "no value")])
        result_value = eval_result[criteriaKey]
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        summary = ["meanTimeToRemediateCritical: " + str(result_value)] + [f"{k}: {v}" for k, v in extra_fields.items()]
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=summary,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so mean time to remediate could not be measured.",
                            "not_measured", validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
