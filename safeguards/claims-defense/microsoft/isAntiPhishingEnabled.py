"""
Transformation: isAntiPhishingEnabled
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Checks secure score control profiles for anti-phishing controls to confirm email filters
           are configured to block phishing and spam.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


ANTI_PHISHING_KEYWORDS = [
    "antiphish",
    "anti-phish",
    "phish",
    "antispam",
    "anti-spam",
    "spam",
    "impersonation",
    "spoofing",
    "defender"
]


def is_anti_phishing_profile(control_id, title):
    combined = (control_id + " " + title).lower()
    for kw in ANTI_PHISHING_KEYWORDS:
        if kw in combined:
            return True
    return False


def evaluate(data):
    try:
        profiles = data.get("value", [])
        if not isinstance(profiles, list):
            profiles = []
        total_profiles = len(profiles)
        anti_phishing_controls = []
        passed_controls = []
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            control_id = profile.get("id", "")
            title = profile.get("title", profile.get("controlName", ""))
            if is_anti_phishing_profile(control_id, title):
                implementation_status = profile.get("implementationStatus", "")
                control_entry = {"id": control_id, "title": title, "implementationStatus": implementation_status}
                anti_phishing_controls.append(control_entry)
                if implementation_status and implementation_status.lower() in ["implemented", "thirdparty", "alternate"]:
                    passed_controls.append(control_id)
        anti_phishing_enabled = len(anti_phishing_controls) > 0
        return {
            "isAntiPhishingEnabled": anti_phishing_enabled,
            "totalSecureScoreProfiles": total_profiles,
            "antiPhishingControlCount": len(anti_phishing_controls),
            "implementedControlCount": len(passed_controls),
            "implementedControlIds": passed_controls
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Anti-phishing secure score control profiles are present in the tenant.")
            pass_reasons.append("Anti-phishing controls found: " + str(extra_fields.get("antiPhishingControlCount", 0)))
            if extra_fields.get("implementedControlCount", 0) > 0:
                pass_reasons.append("Implemented controls: " + str(extra_fields.get("implementedControlIds", [])))
        else:
            fail_reasons.append("No anti-phishing or anti-spam secure score control profiles found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure anti-phishing policies in Microsoft Defender for Office 365 and ensure they appear in the Secure Score control profiles.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalSecureScoreProfiles": extra_fields.get("totalSecureScoreProfiles", 0), "antiPhishingControlCount": extra_fields.get("antiPhishingControlCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
