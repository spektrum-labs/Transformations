"""
Transformation: isEPPConfigured
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether endpoint protection is properly configured across the estate using the
Sophos Account Health Check API. Checks that notFullyProtected counts for both computer
and server are zero.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        endpoint_section = data.get("endpoint", {})
        protection = endpoint_section.get("protection", {})
        computer = protection.get("computer", {})
        server = protection.get("server", {})

        computer_not_protected = computer.get("notFullyProtected", None)
        server_not_protected = server.get("notFullyProtected", None)

        if computer_not_protected is None and server_not_protected is None:
            return {
                "isEPPConfigured": False,
                "error": "No account health check data found in response",
                "computerNotFullyProtected": None,
                "serverNotFullyProtected": None,
                "overallStatus": ""
            }

        computer_ok = (computer_not_protected == 0) if computer_not_protected is not None else True
        server_ok = (server_not_protected == 0) if server_not_protected is not None else True

        overall = data.get("overall", {})
        overall_status = overall.get("status", "")

        is_configured = computer_ok and server_ok

        return {
            "isEPPConfigured": is_configured,
            "computerNotFullyProtected": computer_not_protected if computer_not_protected is not None else 0,
            "serverNotFullyProtected": server_not_protected if server_not_protected is not None else 0,
            "overallStatus": overall_status
        }
    except Exception as e:
        return {"isEPPConfigured": False, "error": str(e)}


def transform(input):
    criteria_key = "isEPPConfigured"
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
            pass_reasons.append("Endpoint protection is fully configured across the estate")
            pass_reasons.append("computerNotFullyProtected: " + str(extra_fields.get("computerNotFullyProtected", 0)))
            pass_reasons.append("serverNotFullyProtected: " + str(extra_fields.get("serverNotFullyProtected", 0)))
        else:
            fail_reasons.append("Endpoint protection is not fully configured")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("computerNotFullyProtected: " + str(extra_fields.get("computerNotFullyProtected", 0)))
                fail_reasons.append("serverNotFullyProtected: " + str(extra_fields.get("serverNotFullyProtected", 0)))
            recommendations.append("Ensure all endpoints and servers have Sophos EPP fully deployed and configured")
            recommendations.append("Review Account Health Check in Sophos Central for unprotected devices")
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
