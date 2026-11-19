"""
Transformation: externalAssetInventoryCount
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Count of hosts in the Qualys host list; not measured when Qualys truncates the list.
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


RECOMMENDATION = "Confirm the Qualys account can list hosts and that the host list request returned all of them."


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "externalAssetInventoryCount", "vendor": "Qualys", "category": "Attack Surface Management"}
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
    """Hosts in the Qualys host list (HOST_LIST_OUTPUT), the reply getHostList returns."""
    try:
        output = data.get('HOST_LIST_OUTPUT') if isinstance(data, dict) else None
        response = output.get('RESPONSE') if isinstance(output, dict) else None
        if not isinstance(response, dict):
            return {"externalAssetInventoryCount": None,
                    "notMeasured": "Qualys returned no host list, so the asset inventory could not be counted."}
        host_list = response.get('HOST_LIST')
        hosts = host_list.get('HOST', []) if isinstance(host_list, dict) else []
        if isinstance(hosts, dict):
            hosts = [hosts]
        count = len([h for h in hosts if isinstance(h, dict)]) if isinstance(hosts, list) else 0
        warning = response.get('WARNING')
        if isinstance(warning, dict) and str(warning.get('CODE', '')).strip() == '1980':
            # A truncated read is a lower bound, and a transform is never told the bar it is graded against.
            return {"externalAssetInventoryCount": None, "sampleCount": count,
                    "notMeasured": "Qualys stopped the host list at " + str(count) + " records (warning 1980), "
                                   "so the asset inventory count is a lower bound and is not graded."}
        if count == 0:
            # An empty host list is nothing assessed, not a measured zero (as ENG-1353 for its siblings).
            return {"externalAssetInventoryCount": None,
                    "notMeasured": "Qualys lists no hosts, so the asset inventory count could not be graded."}
        return {"externalAssetInventoryCount": count}
    except Exception:
        return {"externalAssetInventoryCount": None, "error": "unreadable value in the Qualys reply"}


def transform(input):
    criteriaKey = "externalAssetInventoryCount"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so the asset inventory count could not be measured.",
                                validation=validation)
        eval_result = evaluate(data)
        if eval_result.get("notMeasured"):
            return not_measured(criteriaKey, eval_result["notMeasured"], validation=validation,
                                findings=[f"{k}: {v}" for k, v in eval_result.items() if k not in (criteriaKey, "notMeasured")])
        if "error" in eval_result or eval_result.get(criteriaKey) is None:
            return not_measured(criteriaKey, "The Qualys response could not be read, so the asset inventory count could not be measured.",
                                validation=validation, transformation_errors=[eval_result.get("error", "no value")])
        result_value = eval_result[criteriaKey]
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey}
        summary = ["externalAssetInventoryCount: " + str(result_value)] + [f"{k}: {v}" for k, v in extra_fields.items()]
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            additional_findings=summary,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so the asset inventory count could not be measured.",
                            validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
