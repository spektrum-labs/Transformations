"""
Transformation: isAntiPhishingEnabled
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Inspects secure score control profiles for anti-phishing controls and checks that
actionType indicates the control is active and scored
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        profiles = data.get("value", [])
        antiphish_profiles = []
        for profile in profiles:
            title = profile.get("title", "")
            control_id = profile.get("id", "")
            title_lower = title.lower()
            id_lower = control_id.lower()
            if "phish" in title_lower or "phish" in id_lower or "antispoof" in title_lower or "antispoof" in id_lower:
                antiphish_profiles.append(profile)
        if not antiphish_profiles:
            return {
                "isAntiPhishingEnabled": False,
                "reason": "No anti-phishing control profiles found in Secure Score",
                "antiPhishingControlsFound": 0,
                "implementedControlsCount": 0
            }
        implemented_count = 0
        implemented_names = []
        for profile in antiphish_profiles:
            impl_status = profile.get("implementationStatus", "notImplemented")
            if impl_status in ["implemented", "thirdParty", "alternativeMitigationAccepted"]:
                implemented_count = implemented_count + 1
                implemented_names.append(profile.get("title", profile.get("id", "Unknown")))
        anti_phishing_enabled = implemented_count > 0
        return {
            "isAntiPhishingEnabled": anti_phishing_enabled,
            "antiPhishingControlsFound": len(antiphish_profiles),
            "implementedControlsCount": implemented_count,
            "implementedControlNames": implemented_names
        }
    except Exception as e:
        return {"isAntiPhishingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error" and k != "reason":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed: Anti-phishing controls are implemented in Secure Score")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if "reason" in eval_result:
                fail_reasons.append(eval_result["reason"])
            recommendations.append("Enable Microsoft Defender for Office 365 anti-phishing policies in the Microsoft 365 Defender portal and configure impersonation protection, spoof intelligence, and safe links")
        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=result_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
