"""
Transformation: isEPPConfigured
Vendor: Sophos  |  Category: epp
Evaluates: EPP configuration health by inspecting the 'endpoint.protection' sub-object of the
           Sophos account health check response. Passes when notFullyProtected counts for
           both 'computer' and 'server' are zero (all devices are fully protected).
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Sophos", "category": "epp"}
        }
    }


def get_not_fully_protected(protection_obj, device_type):
    if not isinstance(protection_obj, dict):
        return 0
    type_data = protection_obj.get(device_type, {})
    if not isinstance(type_data, dict):
        return 0
    return int(type_data.get("notFullyProtected", 0))


def evaluate(data):
    try:
        endpoint_health = data.get("endpoint", {})
        if not isinstance(endpoint_health, dict):
            endpoint_health = {}
        protection = endpoint_health.get("protection", {})
        if not isinstance(protection, dict):
            protection = {}
        computers_not_protected = get_not_fully_protected(protection, "computer")
        servers_not_protected = get_not_fully_protected(protection, "server")
        total_not_protected = computers_not_protected + servers_not_protected
        has_health_data = "endpoint" in data and isinstance(data.get("endpoint"), dict)
        configured = has_health_data and total_not_protected == 0
        return {
            "isEPPConfigured": configured,
            "computersNotFullyProtected": computers_not_protected,
            "serversNotFullyProtected": servers_not_protected,
            "totalNotFullyProtected": total_not_protected,
            "hasHealthCheckData": has_health_data
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
        additional_findings = []
        if result_value:
            pass_reasons.append("All endpoints are fully protected — no notFullyProtected computers or servers reported in account health check")
        else:
            if not extra_fields.get("hasHealthCheckData", False):
                fail_reasons.append("Account health check endpoint data is unavailable; EPP configuration status cannot be determined")
                recommendations.append("Ensure the Sophos Central API credentials have access to the account health check endpoint")
            else:
                total = extra_fields.get("totalNotFullyProtected", 0)
                fail_reasons.append(str(total) + " endpoint(s) are not fully protected according to the Sophos account health check")
                comp = extra_fields.get("computersNotFullyProtected", 0)
                srv = extra_fields.get("serversNotFullyProtected", 0)
                if comp > 0:
                    additional_findings.append(str(comp) + " computer(s) not fully protected")
                if srv > 0:
                    additional_findings.append(str(srv) + " server(s) not fully protected")
                recommendations.append("Review and remediate unprotected endpoints in Sophos Central to achieve full EPP coverage")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalNotFullyProtected": extra_fields.get("totalNotFullyProtected", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
