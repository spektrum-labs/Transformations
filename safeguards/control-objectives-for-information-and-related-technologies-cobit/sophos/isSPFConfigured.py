"""
Transformation: isSPFConfigured
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether SPF (Sender Policy Framework) validation is configured and enforced in
Sophos Email settings for inbound email authentication, checking for reject or quarantine
actions on non-compliant senders.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSPFConfigured", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def check_spf_in_setting(setting):
    spf = setting.get("spf", {})
    if spf:
        if spf.get("enabled", False):
            action = spf.get("action", "").lower()
            if action in ["reject", "quarantine", "block", "junk"]:
                return True, action
            return True, "enabled"
        if spf.get("configured", False):
            return True, "configured"
    inbound = setting.get("inbound", {})
    if inbound:
        spf_inbound = inbound.get("spf", {})
        if spf_inbound and spf_inbound.get("enabled", False):
            action = spf_inbound.get("action", "").lower()
            return True, action if action else "enabled"
    sender_auth = setting.get("senderAuthentication", {})
    if sender_auth:
        spf_auth = sender_auth.get("spf", {})
        if spf_auth and spf_auth.get("enabled", False):
            return True, "enabled"
    return False, "none"


def evaluate(data):
    try:
        items = data.get("items", [])

        if not items and isinstance(data, dict):
            is_configured, action = check_spf_in_setting(data)
            return {
                "isSPFConfigured": is_configured,
                "spfAction": action,
                "configuredDomainCount": 1 if is_configured else 0
            }

        configured_count = 0
        detected_action = "none"
        for setting in items:
            is_configured, action = check_spf_in_setting(setting)
            if is_configured:
                configured_count = configured_count + 1
                detected_action = action

        is_configured = configured_count > 0

        return {
            "isSPFConfigured": is_configured,
            "spfAction": detected_action,
            "totalSettings": len(items),
            "configuredDomainCount": configured_count
        }
    except Exception as e:
        return {"isSPFConfigured": False, "error": str(e)}


def transform(input):
    criteria_key = "isSPFConfigured"
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
            pass_reasons.append("SPF validation is configured and enforced in Sophos Email settings")
            pass_reasons.append("SPF action: " + str(extra_fields.get("spfAction", "")))
            pass_reasons.append("Configured domain count: " + str(extra_fields.get("configuredDomainCount", 0)))
        else:
            fail_reasons.append("SPF validation is not configured in Sophos Email settings")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable SPF validation in Sophos Email Security inbound settings")
            recommendations.append("Set the SPF failure action to 'reject' or 'quarantine' to block non-compliant senders")
            recommendations.append("Publish an SPF DNS TXT record for all sending domains")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value, "spfAction": extra_fields.get("spfAction", "")})
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
