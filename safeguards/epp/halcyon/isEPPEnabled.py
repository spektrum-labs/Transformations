"""
Transformation: isEPPEnabled
Vendor: Halcyon  |  Category: epp
Evaluates: Checks whether the Halcyon EPP agent is enabled and actively protecting endpoints.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Halcyon", "category": "epp"}
        }
    }


def extract_bool_flag(data, primary_keys, fallback_status_values):
    """
    Attempts to read a boolean flag from a dict.
    Tries primary_keys first (exact bool/int), then looks for a 'status' string
    matched against fallback_status_values.
    Returns (found: bool, value: bool).
    """
    for key in primary_keys:
        if key in data:
            raw = data[key]
            if isinstance(raw, bool):
                return True, raw
            if isinstance(raw, int):
                return True, raw != 0
            if isinstance(raw, str):
                return True, raw.lower() in fallback_status_values
    status_val = data.get("status", "")
    if isinstance(status_val, str) and status_val != "":
        return True, status_val.lower() in fallback_status_values
    return False, False


def evaluate(data):
    """
    Determines whether the Halcyon EPP agent is enabled.
    The workflow merges getEPPEnabledStatus, getEPPDeploymentStatus, and
    getEPPConfigurationStatus, so the input may contain keys from all three.
    Passes when the EPP enabled flag is explicitly true.
    """
    try:
        positive_strings = ["enabled", "true", "active", "on", "yes", "1"]

        inner = data
        if isinstance(data.get("data"), dict):
            inner = data["data"]

        primary_keys = [
            "isEPPEnabled",
            "eppEnabled",
            "epp_enabled",
            "enabled",
            "result",
            "passed",
            "pass",
            "value",
        ]

        found, flag_value = extract_bool_flag(inner, primary_keys, positive_strings)

        if not found:
            found, flag_value = extract_bool_flag(data, primary_keys, positive_strings)

        if not found:
            return {
                "isEPPEnabled": False,
                "error": "Could not determine EPP enabled status from API response",
            }

        # Collect supplementary fields present in the merged workflow response
        additional = {}
        for sup_key in ["isEPPDeployed", "isEPPConfigured", "deploymentStatus", "configurationStatus"]:
            if sup_key in inner:
                additional[sup_key] = inner[sup_key]
            elif sup_key in data:
                additional[sup_key] = data[sup_key]

        result = {"isEPPEnabled": flag_value}
        for k in additional:
            result[k] = additional[k]
        return result
    except Exception as e:
        return {"isEPPEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"],
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(
                "Halcyon EPP agent is enabled and actively protecting endpoints."
            )
            for k, v in extra_fields.items():
                additional_findings.append(k + ": " + str(v))
        else:
            fail_reasons.append("Halcyon EPP agent is not enabled.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable the Halcyon EPP agent across all managed endpoints via the Halcyon console "
                "to ensure active endpoint protection is in place."
            )
            for k, v in extra_fields.items():
                additional_findings.append(k + ": " + str(v))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value},
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
