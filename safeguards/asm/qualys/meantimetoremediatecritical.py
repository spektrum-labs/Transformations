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
        mttr = int(sum(deltas) / len(deltas)) if deltas else 0
        return {"meanTimeToRemediateCritical": str(mttr), "averageDays": mttr, "sampleSize": len(deltas)}
    except Exception as e:
        return {"meanTimeToRemediateCritical": "0", "error": str(e)}


def transform(input):
    criteriaKey = "meanTimeToRemediateCritical"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Qualys configuration for {criteriaKey}")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
