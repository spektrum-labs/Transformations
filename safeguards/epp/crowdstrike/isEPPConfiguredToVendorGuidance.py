"""
Transformation: isEPPConfiguredToVendorGuidance
Vendor: Crowdstrike  |  Category: epp
Evaluates: Verify that enabled prevention policies have key protective settings configured per
CrowdStrike vendor guidance. Evaluates the settings array on each enabled policy to confirm
that critical prevention categories such as cloud_anti_malware, on_sensor_ml_sliders, and
behaviour-based detections are set to recommended values (detection and prevention modes
rather than disabled).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfiguredToVendorGuidance", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def safe_list(val):
    return val if isinstance(val, list) else []


def safe_dict(val):
    return val if isinstance(val, dict) else {}


# Critical setting categories per CrowdStrike vendor guidance.
# For slider-type settings, accepted non-disabled values: MODERATE, AGGRESSIVE, EXTRA_AGGRESSIVE.
# For toggle-type settings, value must be True/true/"1"/"true".
CRITICAL_SETTINGS = [
    "cloud_anti_malware",
    "on_sensor_ml_sliders",
    "adware_and_pup",
    "quarantine",
    "prevention_quarantine_on_write"
]

SLIDER_SETTINGS = [
    "cloud_anti_malware",
    "on_sensor_ml_sliders"
]

ACCEPTABLE_SLIDER_VALUES = ["MODERATE", "AGGRESSIVE", "EXTRA_AGGRESSIVE", "moderate", "aggressive", "extra_aggressive"]


def is_setting_recommended(setting_id, setting_value):
    """Return True if a given setting value meets vendor guidance."""
    if setting_id in SLIDER_SETTINGS:
        detection = None
        prevention = None
        if isinstance(setting_value, dict):
            detection = setting_value.get("detection", "DISABLED")
            prevention = setting_value.get("prevention", "DISABLED")
        elif isinstance(setting_value, str):
            detection = setting_value
            prevention = setting_value
        if detection is None and prevention is None:
            return False
        det_ok = detection in ACCEPTABLE_SLIDER_VALUES if detection else False
        prev_ok = prevention in ACCEPTABLE_SLIDER_VALUES if prevention else False
        return det_ok or prev_ok
    else:
        if isinstance(setting_value, str):
            return setting_value.lower() in ("1", "true", "yes", "enabled")
        return bool(setting_value)


def evaluate(data):
    try:
        resources = None

        # Try method-keyed merged format
        if isinstance(data, dict):
            gpp = data.get("getPreventionPolicies", None)
            if isinstance(gpp, dict):
                resources = gpp.get("resources", None)

        # Fall back to flat top-level format
        if resources is None and isinstance(data, dict):
            resources = data.get("resources", None)

        if resources is None:
            return {
                "isEPPConfiguredToVendorGuidance": None,
                "error": "required fields missing from API response: resources (getPreventionPolicies)"
            }

        policies = safe_list(resources)

        if len(policies) == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalEnabledPolicies": 0,
                "compliantPolicies": 0
            }

        compliant_count = 0
        non_compliant_count = 0
        evaluated_count = 0
        findings = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            raw_enabled = policy.get("enabled", False)
            if isinstance(raw_enabled, str):
                is_enabled = raw_enabled.lower() in ("1", "true", "yes")
            else:
                is_enabled = bool(raw_enabled)

            if not is_enabled:
                continue

            evaluated_count = evaluated_count + 1
            policy_name = policy.get("name", "Unknown")

            # Prevention settings can live at different paths:
            # - policy.prevention_settings (list of category dicts with settings sub-list)
            # - policy.settings (dict keyed by setting id)
            settings_found = {}

            # Path 1: prevention_settings list
            prev_settings = safe_list(policy.get("prevention_settings", []))
            for category in prev_settings:
                if not isinstance(category, dict):
                    continue
                cat_settings = safe_list(category.get("settings", []))
                for s in cat_settings:
                    if not isinstance(s, dict):
                        continue
                    sid = s.get("id", "")
                    sval = s.get("value", None)
                    if sid:
                        settings_found[sid] = sval

            # Path 2: flat settings dict
            if len(settings_found) == 0:
                flat_settings = safe_dict(policy.get("settings", {}))
                for sk in flat_settings:
                    settings_found[sk] = flat_settings.get(sk)

            if len(settings_found) == 0:
                findings.append("Policy '" + policy_name + "': no settings data found — cannot evaluate vendor guidance compliance")
                non_compliant_count = non_compliant_count + 1
                continue

            policy_failed = []
            policy_passed = []
            policy_missing = []

            for crit in CRITICAL_SETTINGS:
                if crit not in settings_found:
                    policy_missing.append(crit)
                else:
                    if is_setting_recommended(crit, settings_found.get(crit)):
                        policy_passed.append(crit)
                    else:
                        policy_failed.append(crit)

            if len(policy_failed) > 0:
                non_compliant_count = non_compliant_count + 1
                findings.append("Policy '" + policy_name + "': non-compliant settings: " + ", ".join(policy_failed))
            elif len(policy_missing) == len(CRITICAL_SETTINGS):
                non_compliant_count = non_compliant_count + 1
                findings.append("Policy '" + policy_name + "': all critical settings absent from response")
            else:
                compliant_count = compliant_count + 1
                findings.append("Policy '" + policy_name + "': compliant (" + str(len(policy_passed)) + " critical settings verified)")

        if evaluated_count == 0:
            return {
                "isEPPConfiguredToVendorGuidance": False,
                "totalEnabledPolicies": 0,
                "compliantPolicies": 0
            }

        is_compliant = compliant_count > 0 and non_compliant_count == 0

        return {
            "isEPPConfiguredToVendorGuidance": is_compliant,
            "totalEnabledPolicies": evaluated_count,
            "compliantPolicies": compliant_count,
            "nonCompliantPolicies": non_compliant_count,
            "additionalFindings": findings
        }
    except Exception as e:
        return {"isEPPConfiguredToVendorGuidance": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfiguredToVendorGuidance"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        additional_findings = eval_result.get("additionalFindings", [])
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error" and k != "additionalFindings"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is True:
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields.get(k)))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be evaluated: insufficient data in API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the getPreventionPolicies API endpoint returns policy settings data")
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            for k in extra_fields:
                fail_reasons.append(k + ": " + str(extra_fields.get(k)))
            recommendations.append("Review enabled prevention policies and ensure cloud_anti_malware, on_sensor_ml_sliders, and behaviour-based detection settings are set to MODERATE or higher per CrowdStrike vendor guidance")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields.get(k)

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields.get(k)

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
