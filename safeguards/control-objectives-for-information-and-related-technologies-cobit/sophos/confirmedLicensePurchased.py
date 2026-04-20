"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether a valid Sophos Central license is active by verifying a successful
authenticated whoami response with non-empty 'id' and 'idType' fields.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        tenant_id = data.get("id", "")
        id_type = data.get("idType", "")
        data_region = data.get("dataRegion", "")

        has_id = tenant_id != "" and tenant_id is not None
        has_id_type = id_type != "" and id_type is not None

        is_licensed = has_id and has_id_type

        return {
            "confirmedLicensePurchased": is_licensed,
            "tenantId": tenant_id if has_id else "",
            "idType": id_type if has_id_type else "",
            "dataRegion": data_region
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteria_key = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteria_key: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteria_key and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Valid Sophos Central license confirmed via authenticated whoami response")
            pass_reasons.append("Tenant ID present: " + str(extra_fields.get("tenantId", "")))
            pass_reasons.append("ID type: " + str(extra_fields.get("idType", "")))
        else:
            fail_reasons.append("Could not confirm a valid Sophos Central license")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("Tenant ID or idType missing from whoami response")
            recommendations.append("Verify Sophos Central API credentials and ensure the tenant is properly licensed")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value})
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
