"""
Transformation: isEPPConfigured
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether endpoint protection is correctly configured across devices -- checks that endpoints have Sophos protection software assigned and no critical configuration errors are present.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isEPPConfigured": False, "error": "No endpoint records found in response"}

        total = len(items)
        epp_codes = ["endpointProtection", "interceptX", "interceptXForServer", "coreAgent"]
        configured_count = 0
        misconfigured_count = 0
        tampered_count = 0

        for item in items:
            assigned_products = item.get("assignedProducts", [])
            codes = [p.get("code", "") for p in assigned_products]
            has_epp = False
            for code in epp_codes:
                if code in codes:
                    has_epp = True
                    break

            health = item.get("health", {})
            service_health = health.get("services", {})
            overall_health = health.get("overall", "")
            tampered = service_health.get("tamperProtectionEnabled", True)

            if has_epp and overall_health.lower() not in ["bad", "error"]:
                configured_count = configured_count + 1
            elif has_epp:
                misconfigured_count = misconfigured_count + 1
            if not tampered:
                tampered_count = tampered_count + 1

        configuration_ratio = (configured_count * 100) / total if total > 0 else 0.0
        is_configured = configured_count > 0 and misconfigured_count == 0

        return {
            "isEPPConfigured": is_configured,
            "totalEndpoints": total,
            "configuredCount": configured_count,
            "misconfiguredCount": misconfigured_count,
            "tamperedCount": tampered_count,
            "configuredPercentage": round(configuration_ratio, 2)
        }
    except Exception as e:
        return {"isEPPConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfigured"
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
            pass_reasons.append("Endpoint Protection is correctly configured across all Sophos-managed devices")
            pass_reasons.append("Configured endpoints: " + str(extra_fields.get("configuredCount", 0)) + " of " + str(extra_fields.get("totalEndpoints", 0)))
        else:
            fail_reasons.append("Endpoint Protection configuration issues detected")
            fail_reasons.append("Misconfigured endpoints: " + str(extra_fields.get("misconfiguredCount", 0)))
            if extra_fields.get("tamperedCount", 0) > 0:
                fail_reasons.append("Endpoints with tamper protection disabled: " + str(extra_fields.get("tamperedCount", 0)))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Remediate all endpoints showing bad health or configuration errors in Sophos Central")
            recommendations.append("Enable tamper protection on all endpoints")
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
