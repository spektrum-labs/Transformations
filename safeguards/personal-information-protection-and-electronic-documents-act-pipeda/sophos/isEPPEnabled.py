"""
Transformation: isEPPEnabled
Vendor: Sophos  |  Category: personal-information-protection-and-electronic-documents-act-pipeda
Evaluates: Whether EPP solutions are deployed on endpoints by checking that at least one endpoint has an Endpoint Protection product assigned.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Sophos", "category": "personal-information-protection-and-electronic-documents-act-pipeda"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])

        endpoint_items = [item for item in items if "assignedProducts" in item or "hostname" in item]

        if not endpoint_items and items:
            endpoint_items = [item for item in items if "type" in item and item.get("type") in ["computer", "server", "laptop", "mobile"]]

        if not endpoint_items:
            return {"isEPPEnabled": False, "error": "No endpoint records found in response"}

        total = len(endpoint_items)
        protected_count = 0
        epp_codes = ["endpointProtection", "interceptX", "interceptXForServer", "coreAgent"]

        for item in endpoint_items:
            assigned_products = item.get("assignedProducts", [])
            codes = [p.get("code", "") for p in assigned_products]
            found = False
            for code in epp_codes:
                if code in codes:
                    found = True
                    break
            if found:
                protected_count = protected_count + 1

        coverage = (protected_count * 100) / total if total > 0 else 0
        is_enabled = protected_count > 0

        return {
            "isEPPEnabled": is_enabled,
            "totalEndpoints": total,
            "protectedEndpoints": protected_count,
            "coveragePercentage": coverage
        }
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Endpoint Protection is deployed on Sophos-managed endpoints")
            pass_reasons.append("Protected endpoints: " + str(extra_fields.get("protectedEndpoints", 0)) + " of " + str(extra_fields.get("totalEndpoints", 0)))
            pass_reasons.append("Coverage: " + str(round(extra_fields.get("coveragePercentage", 0), 2)) + "%")
        else:
            fail_reasons.append("No endpoints have Endpoint Protection products assigned")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Deploy Sophos Endpoint Protection or Intercept X to all managed endpoints")
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
