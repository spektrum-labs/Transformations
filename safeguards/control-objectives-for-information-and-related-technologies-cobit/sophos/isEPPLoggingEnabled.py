"""
Transformation: isEPPLoggingEnabled
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether logging and event forwarding are configured in Sophos endpoint policies by
inspecting threat protection policy types for SIEM integration or event data collection settings.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def policy_has_logging(policy):
    settings = policy.get("settings", {})
    if not settings:
        return False
    siem_section = settings.get("siem", {})
    if siem_section:
        enabled = siem_section.get("enabled", False)
        if enabled:
            return True
    event_forwarding = settings.get("eventForwarding", {})
    if event_forwarding:
        enabled = event_forwarding.get("enabled", False)
        if enabled:
            return True
    threat_protection = settings.get("threatProtection", {})
    if threat_protection:
        logging = threat_protection.get("logging", {})
        if logging and logging.get("enabled", False):
            return True
    event_collection = settings.get("eventDataCollection", {})
    if event_collection and event_collection.get("enabled", False):
        return True
    log_settings = settings.get("logging", {})
    if log_settings and log_settings.get("enabled", False):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "isEPPLoggingEnabled": False,
                "error": "No policy items found in response",
                "totalPolicies": 0,
                "loggingEnabledCount": 0
            }

        threat_policies = [p for p in items if "threat" in p.get("type", "").lower() or "endpoint" in p.get("type", "").lower()]
        if not threat_policies:
            threat_policies = items

        total = len(threat_policies)
        logging_count = 0
        for p in threat_policies:
            if policy_has_logging(p):
                logging_count = logging_count + 1

        is_enabled = logging_count > 0

        return {
            "isEPPLoggingEnabled": is_enabled,
            "totalPolicies": total,
            "loggingEnabledCount": logging_count
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isEPPLoggingEnabled"
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
            pass_reasons.append("EPP logging or event forwarding is configured in at least one policy")
            pass_reasons.append(str(extra_fields.get("loggingEnabledCount", 0)) + " of " + str(extra_fields.get("totalPolicies", 0)) + " policies have logging enabled")
        else:
            fail_reasons.append("No endpoint policies have logging or event forwarding configured")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable SIEM integration or event forwarding in Sophos endpoint threat protection policies")
            recommendations.append("Configure event data collection in Sophos Central policy settings")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0)})
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
