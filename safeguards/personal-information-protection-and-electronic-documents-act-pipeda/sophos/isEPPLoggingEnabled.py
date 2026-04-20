"""
Transformation: isEPPLoggingEnabled
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether endpoint event logging is enabled across the Sophos-protected estate by checking endpoint health and assigned product settings.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isEPPLoggingEnabled": False, "error": "No endpoint records found in response"}

        total = len(items)
        epp_codes = ["endpointProtection", "interceptX", "interceptXForServer", "coreAgent"]
        logging_active_count = 0
        no_logging_count = 0

        for item in items:
            assigned_products = item.get("assignedProducts", [])
            codes = [p.get("code", "") for p in assigned_products]
            has_epp = False
            for code in epp_codes:
                if code in codes:
                    has_epp = True
                    break

            if not has_epp:
                continue

            health = item.get("health", {})
            overall = health.get("overall", "")
            last_seen = item.get("lastSeenAt", "")
            has_recent_activity = bool(last_seen)

            is_logging = has_epp and has_recent_activity and overall.lower() not in ["bad"]
            if is_logging:
                logging_active_count = logging_active_count + 1
            else:
                no_logging_count = no_logging_count + 1

        epp_total = logging_active_count + no_logging_count
        logging_enabled = logging_active_count > 0 and no_logging_count == 0
        logging_ratio = (logging_active_count * 100) / epp_total if epp_total > 0 else 0.0

        return {
            "isEPPLoggingEnabled": logging_enabled,
            "totalEndpoints": total,
            "loggingActiveCount": logging_active_count,
            "loggingInactiveCount": no_logging_count,
            "loggingCoveragePercentage": round(logging_ratio, 2)
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
            pass_reasons.append("EPP logging is active across all Sophos-managed endpoints")
            pass_reasons.append("Logging-active endpoints: " + str(extra_fields.get("loggingActiveCount", 0)) + " of " + str(extra_fields.get("totalEndpoints", 0)))
        else:
            fail_reasons.append("EPP logging is not fully enabled across all endpoints")
            fail_reasons.append("Endpoints without active logging: " + str(extra_fields.get("loggingInactiveCount", 0)))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure all endpoints have Sophos Intercept X or Endpoint Protection installed and are actively reporting to Sophos Central")
            recommendations.append("Check that no endpoints have stale last-seen timestamps indicating connectivity issues")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
