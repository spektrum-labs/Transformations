"""
Transformation: isEmailSecurityEnabled
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Inspects secureScoreControlProfiles for active email security controls such as SafeAttachments, SafeLinks, EnableMailboxAuditing, and BlockLegacyAuthentication.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEmailSecurityEnabled", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


EMAIL_SECURITY_CONTROL_KEYWORDS = [
    "safeattachments",
    "safelinks",
    "mailboxaudit",
    "enablemailboxaudit",
    "legacyauth",
    "blocklegacyauth",
    "antimalware",
    "antispam",
    "antiphish",
    "exchangeonline"
]


def is_email_security_control(control_name):
    name_lower = control_name.lower()
    for keyword in EMAIL_SECURITY_CONTROL_KEYWORDS:
        if keyword in name_lower:
            return True
    return False


def control_is_active(control):
    implementation_status = control.get("implementationStatus", "").lower()
    control_state_updates = control.get("controlStateUpdates", [])
    if implementation_status in ["implemented", "thirdparty", "alternate"]:
        return True
    for update in control_state_updates:
        state = update.get("state", "").lower()
        if state in ["implemented", "thirdparty", "alternate"]:
            return True
    return False


def evaluate(data):
    try:
        profiles = data.get("value", [])
        if not profiles:
            nested = data.get("getSecureScoreControlProfiles", {})
            if isinstance(nested, dict):
                profiles = nested.get("value", [])
        if not isinstance(profiles, list):
            profiles = []
        total_profiles = len(profiles)
        email_controls = [p for p in profiles if is_email_security_control(p.get("controlName", ""))]
        active_email_controls = [p for p in email_controls if control_is_active(p)]
        active_names = [p.get("controlName", "") for p in active_email_controls]
        email_control_names = [p.get("controlName", "") for p in email_controls]
        is_enabled = len(active_email_controls) > 0
        return {
            "isEmailSecurityEnabled": is_enabled,
            "totalControlProfiles": total_profiles,
            "emailSecurityControlsFound": len(email_controls),
            "activeEmailSecurityControls": len(active_email_controls),
            "activeControlNames": ", ".join(active_names) if active_names else "None",
            "allEmailControlNames": ", ".join(email_control_names) if email_control_names else "None"
        }
    except Exception as e:
        return {"isEmailSecurityEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailSecurityEnabled"
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
            pass_reasons.append("Active email security controls detected in Secure Score Control Profiles")
            pass_reasons.append("Active controls: " + eval_result.get("activeControlNames", "None"))
        else:
            fail_reasons.append("No active email security controls found in Secure Score Control Profiles")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable SafeAttachments, SafeLinks, and mailbox auditing in Microsoft 365 Defender and Exchange Online Protection settings")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"totalControlProfiles": eval_result.get("totalControlProfiles", 0), "activeEmailSecurityControls": eval_result.get("activeEmailSecurityControls", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
