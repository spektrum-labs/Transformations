"""
Transformation: isEPPEnabled
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Check that Sophos endpoint protection is actively deployed. Confirms EPP agents
are running (health.services.status == 'good') and endpointProtection product is assigned.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isEPPEnabled": False, "error": "No endpoints found", "totalEndpoints": 0, "protectedEndpoints": 0}
        total = len(items)
        protected = 0
        for item in items:
            assigned = item.get("assignedProducts", [])
            has_epp = False
            for prod in assigned:
                if prod.get("code") == "endpointProtection":
                    has_epp = True
                    break
            health = item.get("health", {})
            services = health.get("services", {})
            services_status = services.get("status", "")
            if has_epp and services_status == "good":
                protected = protected + 1
        is_enabled = protected > 0
        return {"isEPPEnabled": is_enabled, "totalEndpoints": total, "protectedEndpoints": protected}
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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("Endpoint protection is actively deployed and running on at least one endpoint")
            pass_reasons.append("protectedEndpoints: " + str(extra_fields.get("protectedEndpoints", 0)))
            pass_reasons.append("totalEndpoints: " + str(extra_fields.get("totalEndpoints", 0)))
        else:
            fail_reasons.append("Endpoint protection is not actively deployed or no endpoints report healthy EPP services")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Sophos endpoint protection agents are installed and the health.services.status is 'good' on all endpoints")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), "protectedEndpoints": extra_fields.get("protectedEndpoints", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
