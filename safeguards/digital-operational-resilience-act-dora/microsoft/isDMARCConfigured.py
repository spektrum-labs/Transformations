"""
Transformation: isDMARCConfigured
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Checks secure score control profiles for an active DMARC policy control.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


DMARC_KEYWORDS = ["dmarc", "setdmarc", "dmarcpolicy"]


def is_dmarc_profile(profile_id, title):
    pid = profile_id.lower()
    ptitle = title.lower()
    for kw in DMARC_KEYWORDS:
        if kw in pid or kw in ptitle:
            return True
    return False


def has_active_state(control_state_updates):
    active_states = ["thirdParty", "ignore", "default", "completed", "resolvedThirdParty"]
    for update in control_state_updates:
        state = update.get("state", "")
        if state in active_states:
            return True
    return False


def get_profiles(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        profiles = get_profiles(data)
        if not profiles:
            return {"isDMARCConfigured": False, "error": "No secure score control profiles found", "profilesChecked": 0}

        matching_profiles = []
        active_profiles = []

        for profile in profiles:
            profile_id = profile.get("id", "")
            title = profile.get("title", "")
            max_score = profile.get("maxScore", 0)
            state_updates = profile.get("controlStateUpdates", [])
            if is_dmarc_profile(profile_id, title):
                matching_profiles.append(title if title else profile_id)
                if has_active_state(state_updates) or max_score > 0:
                    active_profiles.append(title if title else profile_id)

        is_configured = len(active_profiles) > 0
        return {
            "isDMARCConfigured": is_configured,
            "dmarcProfilesFound": len(matching_profiles),
            "activeDMARCProfiles": ", ".join(active_profiles),
            "profilesChecked": len(profiles)
        }
    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDMARCConfigured"
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
            pass_reasons.append("DMARC policy control is active in Microsoft Secure Score profiles")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("No active DMARC control profile found in Secure Score profiles")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure a DMARC policy (quarantine or reject) for all email domains and acknowledge the control in Microsoft Secure Score")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
