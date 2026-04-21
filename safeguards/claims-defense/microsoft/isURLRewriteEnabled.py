"""
Transformation: isURLRewriteEnabled
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Checks secure score control profiles for Safe Links / URL rewrite controls to confirm
           URLs are scanned and rewritten before delivery.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isURLRewriteEnabled", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


URL_REWRITE_KEYWORDS = [
    "safelink",
    "safe link",
    "safe-link",
    "urlrewrite",
    "url rewrite",
    "url-rewrite",
    "atp",
    "turnonsafelinks",
    "enablesafelinks"
]


def is_url_rewrite_profile(control_id, title):
    combined = (control_id + " " + title).lower()
    for kw in URL_REWRITE_KEYWORDS:
        if kw in combined:
            return True
    return False


def evaluate(data):
    try:
        profiles = data.get("value", [])
        if not isinstance(profiles, list):
            profiles = []
        total_profiles = len(profiles)
        url_rewrite_controls = []
        implemented_controls = []
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            control_id = profile.get("id", "")
            title = profile.get("title", profile.get("controlName", ""))
            if is_url_rewrite_profile(control_id, title):
                implementation_status = profile.get("implementationStatus", "")
                url_rewrite_controls.append({"id": control_id, "title": title, "implementationStatus": implementation_status})
                if implementation_status and implementation_status.lower() in ["implemented", "thirdparty", "alternate"]:
                    implemented_controls.append(control_id)
        url_rewrite_enabled = len(url_rewrite_controls) > 0
        return {
            "isURLRewriteEnabled": url_rewrite_enabled,
            "totalSecureScoreProfiles": total_profiles,
            "urlRewriteControlCount": len(url_rewrite_controls),
            "implementedControlCount": len(implemented_controls),
            "implementedControlIds": implemented_controls
        }
    except Exception as e:
        return {"isURLRewriteEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isURLRewriteEnabled"
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
            pass_reasons.append("Safe Links / URL rewrite secure score control profiles are present in the tenant.")
            pass_reasons.append("URL rewrite controls found: " + str(extra_fields.get("urlRewriteControlCount", 0)))
            if extra_fields.get("implementedControlCount", 0) > 0:
                pass_reasons.append("Implemented controls: " + str(extra_fields.get("implementedControlIds", [])))
        else:
            fail_reasons.append("No Safe Links or URL rewrite secure score control profiles found.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Safe Links in Microsoft Defender for Office 365 to scan and rewrite URLs in emails before delivery.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalSecureScoreProfiles": extra_fields.get("totalSecureScoreProfiles", 0), "urlRewriteControlCount": extra_fields.get("urlRewriteControlCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
