"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Which authentication factor types are permitted by reading push_enabled,
sms_enabled, voice_enabled, and mobile_otp_enabled from /admin/v1/settings, and
passes if at least one strong factor (push or mobile OTP) is enabled.
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "authTypesAllowed",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        push_enabled = data.get("push_enabled", False)
        sms_enabled = data.get("sms_enabled", False)
        voice_enabled = data.get("voice_enabled", False)
        mobile_otp_enabled = data.get("mobile_otp_enabled", False)

        enabled_types = []
        if push_enabled:
            enabled_types.append("push")
        if sms_enabled:
            enabled_types.append("sms")
        if voice_enabled:
            enabled_types.append("voice")
        if mobile_otp_enabled:
            enabled_types.append("mobile_otp")

        strong_factor_enabled = True if (push_enabled or mobile_otp_enabled) else False
        total_enabled = len(enabled_types)

        return {
            "authTypesAllowed": strong_factor_enabled,
            "enabledAuthTypes": enabled_types,
            "pushEnabled": True if push_enabled else False,
            "smsEnabled": True if sms_enabled else False,
            "voiceEnabled": True if voice_enabled else False,
            "mobileOtpEnabled": True if mobile_otp_enabled else False,
            "totalEnabledTypes": total_enabled
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("At least one strong authentication factor is enabled (push or mobile OTP)")
            enabled_types = extra_fields.get("enabledAuthTypes", [])
            pass_reasons.append("Enabled auth types: " + str(enabled_types))
        else:
            fail_reasons.append("No strong authentication factor is enabled (push and mobile OTP are both disabled)")
            recommendations.append("Enable Duo Push or mobile OTP to ensure strong factor authentication is available")
            enabled_types = extra_fields.get("enabledAuthTypes", [])
            if enabled_types:
                additional_findings.append("Weak factors still enabled: " + str(enabled_types))
            else:
                additional_findings.append("No authentication factors are currently enabled in settings")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
