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


RECOMMENDATION = "Confirm the Qualys detection list request includes Fixed detections."


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


def not_measured(criteria_key, reason, validation=None, transformation_errors=None, findings=None):
    """criteria_key None plus a dataCollection error, so the evaluator records Not evaluated."""
    return create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings,
        recommendations=[RECOMMENDATION])


def evaluate(data):
    """Core evaluation logic."""
    try:
        hosts = data.get('HOST_LIST_VM_DETECTION_OUTPUT', {}).get('RESPONSE', {}).get('HOST_LIST', {}).get('HOST', [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        deltas = []
        for host in hosts:
            detections = host.get('DETECTION_LIST', {}).get('DETECTION', [])
            if isinstance(detections, dict):
                detections = [detections]
            for d in detections:
                if int(d.get('SEVERITY', 0)) >= 4 and d.get('STATUS') == 'Fixed':
                    found = d.get('FIRST_FOUND_DATETIME', '')
                    fixed_dt = d.get('LAST_FIXED_DATETIME', '')
                    if found and fixed_dt:
                        t_found = datetime.fromisoformat(found.replace('Z', '+00:00'))
                        t_fixed = datetime.fromisoformat(fixed_dt.replace('Z', '+00:00'))
                        deltas.append((t_fixed - t_found).days)
        if not deltas:
            # No remediated critical detection to average is not a 0-day remediation time.
            return {"meanTimeToRemediateCritical": None, "sampleSize": 0,
                    "notMeasured": "The Qualys detection list holds no remediated critical detections, "
                                   "so mean time to remediate could not be measured."}
        mttr = int(sum(deltas) / len(deltas))
        return {"meanTimeToRemediateCritical": str(mttr), "averageDays": mttr, "sampleSize": len(deltas)}
    except Exception as e:
        return {"meanTimeToRemediateCritical": None, "error": str(e)}


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
                                validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], validation=validation,
                                findings=[f"{k}: {v}" for k, v in eval_result.items() if k not in (criteriaKey, "notMeasured")])
        if "error" in eval_result or eval_result.get(criteriaKey) is None:
            return not_measured(criteriaKey, "The Qualys response could not be read, so mean time to remediate could not be measured.",
                                validation=validation, transformation_errors=[eval_result.get("error", "no value")])
        result_value = eval_result[criteriaKey]
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        summary = ["meanTimeToRemediateCritical: " + str(result_value)] + [f"{k}: {v}" for k, v in extra_fields.items()]
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=summary,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return not_measured(criteriaKey, "The Qualys response could not be read, so mean time to remediate could not be measured.",
                            validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=[str(e)])
