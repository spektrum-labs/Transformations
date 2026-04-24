"""
Transformation: isEPPLoggingEnabled
Vendor: Sophos  |  Category: epp
Evaluates: Checks that Sophos logging / event-collection services are running on at least one
           EPP-assigned endpoint by inspecting health.services.serviceDetails for service names
           that indicate Sophos logging or telemetry activity.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Sophos", "category": "epp"}
        }
    }


def has_logging_service(service_details):
    if not isinstance(service_details, list):
        return False
    logging_keywords = ["log", "event", "telemetry", "siem", "journal", "collector"]
    for svc in service_details:
        if not isinstance(svc, dict):
            continue
        name = svc.get("name", "").lower()
        status = svc.get("status", "").lower()
        for keyword in logging_keywords:
            if keyword in name:
                if status in ("running", "good", "ok", "active"):
                    return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total = len(items)
        if total == 0:
            return {"isEPPLoggingEnabled": False, "totalEndpoints": 0, "eppEndpointsChecked": 0, "loggingEnabledCount": 0}
        epp_checked = 0
        logging_enabled_count = 0
        for endpoint in items:
            assigned = endpoint.get("assignedProducts", [])
            if not isinstance(assigned, list):
                assigned = []
            has_epp = False
            for product in assigned:
                if isinstance(product, dict) and product.get("code", "") == "endpointProtection":
                    has_epp = True
                    break
            if not has_epp:
                continue
            epp_checked = epp_checked + 1
            health = endpoint.get("health", {})
            if not isinstance(health, dict):
                continue
            services = health.get("services", {})
            if not isinstance(services, dict):
                continue
            service_details = services.get("serviceDetails", [])
            if has_logging_service(service_details):
                logging_enabled_count = logging_enabled_count + 1
        enabled = logging_enabled_count > 0
        return {
            "isEPPLoggingEnabled": enabled,
            "totalEndpoints": total,
            "eppEndpointsChecked": epp_checked,
            "loggingEnabledCount": logging_enabled_count
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
            pass_reasons.append("Sophos logging/event-collection services are running on " + str(extra_fields.get("loggingEnabledCount", 0)) + " EPP-assigned endpoint(s)")
        else:
            epp_checked = extra_fields.get("eppEndpointsChecked", 0)
            if epp_checked == 0:
                fail_reasons.append("No EPP-assigned endpoints were found to evaluate logging status")
                recommendations.append("Assign Endpoint Protection to managed endpoints and confirm logging services are enabled")
            else:
                fail_reasons.append("No running logging or event-collection services detected on any of the " + str(epp_checked) + " EPP-assigned endpoint(s)")
                recommendations.append("Ensure Sophos logging and telemetry services are running on all managed endpoints")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
