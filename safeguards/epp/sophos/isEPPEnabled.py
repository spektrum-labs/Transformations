"""
Transformation: isEPPEnabled
Vendor: Sophos  |  Category: epp
Evaluates: Checks that Sophos Endpoint Protection is enabled across managed endpoints by verifying
           that at least one endpoint has 'endpointProtection' in assignedProducts and that its
           health.services.status is not 'bad'.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Sophos", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total = len(items)
        if total == 0:
            return {"isEPPEnabled": False, "totalEndpoints": 0, "eppAssignedCount": 0, "unhealthyCount": 0}
        epp_assigned_count = 0
        unhealthy_count = 0
        for endpoint in items:
            assigned = endpoint.get("assignedProducts", [])
            if not isinstance(assigned, list):
                assigned = []
            has_epp = False
            for product in assigned:
                if isinstance(product, dict) and product.get("code", "") == "endpointProtection":
                    has_epp = True
                    break
            if has_epp:
                epp_assigned_count = epp_assigned_count + 1
                health = endpoint.get("health", {})
                if isinstance(health, dict):
                    services = health.get("services", {})
                    if isinstance(services, dict):
                        svc_status = services.get("status", "")
                        if svc_status == "bad":
                            unhealthy_count = unhealthy_count + 1
        enabled = epp_assigned_count > 0
        return {
            "isEPPEnabled": enabled,
            "totalEndpoints": total,
            "eppAssignedCount": epp_assigned_count,
            "unhealthyCount": unhealthy_count
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
        additional_findings = []
        if result_value:
            pass_reasons.append("Sophos Endpoint Protection (endpointProtection) is assigned to " + str(extra_fields.get("eppAssignedCount", 0)) + " of " + str(extra_fields.get("totalEndpoints", 0)) + " endpoints")
            unhealthy = extra_fields.get("unhealthyCount", 0)
            if unhealthy > 0:
                additional_findings.append(str(unhealthy) + " EPP-assigned endpoint(s) have health.services.status of 'bad'")
        else:
            fail_reasons.append("No endpoints have Sophos Endpoint Protection (endpointProtection) assigned")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign the Endpoint Protection product to all managed endpoints in Sophos Central")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalEndpoints": extra_fields.get("totalEndpoints", 0), criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
