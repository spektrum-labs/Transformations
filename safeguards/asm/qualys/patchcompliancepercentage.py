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


def host_list(data):
    """The assessed hosts, or None when the reply carries no host list.

    No HOST_LIST means nothing was assessed, which is not 100% compliant and not a measured
    zero (ENG-1353). Hosts present with no open detections is a real measurement.
    """
    if not isinstance(data, dict):
        return None
    output = data.get('HOST_LIST_VM_DETECTION_OUTPUT')
    response = output.get('RESPONSE') if isinstance(output, dict) else None
    hl = response.get('HOST_LIST') if isinstance(response, dict) else None
    hosts = hl.get('HOST') if isinstance(hl, dict) else None
    if isinstance(hosts, dict):
        hosts = [hosts]
    if not isinstance(hosts, list):
        return None
    hosts = [h for h in hosts if isinstance(h, dict)]
    return hosts or None


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


# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."
NOT_SCANNED = "Confirm Qualys has scanned the hosts in scope."


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None,
                 recommendation=NOT_OURS_TO_ASK):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        recommendations=[recommendation])
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


def evaluate(data):
    """Core evaluation logic."""
    try:
        hosts = host_list(data) or []
        total = 0
        fixed = 0
        for host in hosts:
            detections = host.get('DETECTION_LIST', {}).get('DETECTION', [])
            if isinstance(detections, dict):
                detections = [detections]
            total += len(detections)
            fixed += sum(1 for d in detections if isinstance(d, dict) and str(d.get('STATUS', '')).lower() == 'fixed')
        if total > 0 and fixed == 0 and not fixed_requested(data):
            # Open detections only, and nothing shows Fixed was asked for: "none fixed" is unproven.
            return {"patchCompliancePercentage": None, "totalDetections": total, "fixedDetections": 0,
                    "notMeasured": "Spektrum's Qualys read does not yet include fixed detections, so patch "
                                   "compliance could not be measured."}
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
        if host_list(data) is None:
            return not_measured(criteriaKey, "Qualys returned no assessed hosts, so patch compliance could not be measured.",
                                "no_data", validation=validation, recommendation=NOT_SCANNED)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], "not_measured", validation=validation)
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
