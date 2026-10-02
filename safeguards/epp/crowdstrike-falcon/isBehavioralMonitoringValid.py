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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


BEHAVIORAL_KEYWORDS = [
    "ioa", "behavior", "additionalusermodedata", "scriptbasedexecutionmonitoring",
    "cloudantimalware", "onsensormlslider", "adwarepup", "interpreteronly",
    "sensortamperingprotection", "nextgenav",
]


def is_behavioral_setting(setting_id):
    sid = (setting_id or "")
    if not isinstance(sid, str):
        return False
    sid = sid.lower()
    for kw in BEHAVIORAL_KEYWORDS:
        if kw in sid:
            return True
    return False


def setting_is_enabled(value):
    if isinstance(value, dict):
        if value.get("enabled") is True:
            return True
        detection = value.get("detection")
        prevention = value.get("prevention")
        if detection and str(detection).upper() != "DISABLED":
            return True
        if prevention and str(prevention).upper() != "DISABLED":
            return True
        return False
    if isinstance(value, bool):
        return value
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("resources") or data.get("data") or []
    else:
        policies = []

    total_policies = len(policies) if isinstance(policies, list) else 0
    enabled_policies = 0
    assigned_enabled_policies = 0
    policies_with_behavioral_settings_found = 0
    policies_with_behavioral_settings_enabled = 0
    inspected_setting_ids = []

    for policy in policies if isinstance(policies, list) else []:
        if not isinstance(policy, dict):
            continue
        is_enabled = policy.get("enabled") is True
        groups = policy.get("groups") or []
        has_group = isinstance(groups, list) and len(groups) > 0
        if is_enabled:
            enabled_policies = enabled_policies + 1
        if is_enabled and has_group:
            assigned_enabled_policies = assigned_enabled_policies + 1

        settings_groups = policy.get("prevention_settings") or policy.get("settings") or []
        behavioral_settings_found = []
        if isinstance(settings_groups, list):
            for grp in settings_groups:
                if isinstance(grp, dict) and isinstance(grp.get("settings"), list):
                    for s in grp["settings"]:
                        if isinstance(s, dict) and is_behavioral_setting(s.get("id") or s.get("name")):
                            behavioral_settings_found.append(s)
                elif isinstance(grp, dict) and is_behavioral_setting(grp.get("id") or grp.get("name")):
                    behavioral_settings_found.append(grp)

        if behavioral_settings_found:
            policies_with_behavioral_settings_found = policies_with_behavioral_settings_found + 1
            for s in behavioral_settings_found:
                inspected_setting_ids.append(s.get("id") or s.get("name") or "unknown")
            enabled_behavioral = [s for s in behavioral_settings_found if setting_is_enabled(s.get("value"))]
            if enabled_behavioral and is_enabled:
                policies_with_behavioral_settings_enabled = policies_with_behavioral_settings_enabled + 1

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_policies == 0:
        result_value = False
        fail_reasons.append("No prevention policies were returned by queryCombinedPreventionPolicies, so behavioral (IOA) detection settings could not be verified.")
        recommendations.append("Confirm the CrowdStrike API credentials have Prevention Policies: READ scope and that prevention policies exist in the tenant.")
    elif policies_with_behavioral_settings_found == 0:
        result_value = False
        fail_reasons.append(
            f"Inspected {total_policies} prevention policies ({enabled_policies} enabled, {assigned_enabled_policies} enabled and assigned to a host group), but no behavior-based (IOA) detection settings (e.g. UnknownDetectionRelatedExecutables, SensorTamperingProtection, CloudAntiMalware) were found in the settings payload returned for these policies."
        )
        recommendations.append("Verify the prevention policy settings payload includes IOA/behavioral detection toggles and re-check policy configuration in the Falcon console.")
    elif policies_with_behavioral_settings_enabled > 0:
        sample_ids = sorted(set(inspected_setting_ids))[:10]
        result_value = True
        pass_reasons.append(
            f"{policies_with_behavioral_settings_enabled} of {assigned_enabled_policies} enabled, host-group-assigned prevention policies have behavior-based (IOA) detection settings enabled (inspected settings include: {', '.join(sample_ids)})."
        )
    else:
        result_value = False
        fail_reasons.append(
            f"Found behavior-based (IOA) detection settings on {policies_with_behavioral_settings_found} of {total_policies} prevention policies, but none of the {assigned_enabled_policies} enabled/host-group-assigned policies have those settings turned on (enabled=true or a non-DISABLED detection/prevention level)."
        )
        recommendations.append("Enable the IOA/behavioral detection settings (e.g. set detection/prevention level above Disabled) on the prevention policy assigned to production host groups.")

    result = {
        "isBehavioralMonitoringValid": result_value,
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_policies,
        "assignedEnabledPolicies": assigned_enabled_policies,
        "policiesWithBehavioralSettingsFound": policies_with_behavioral_settings_found,
        "policiesWithBehavioralSettingsEnabled": policies_with_behavioral_settings_enabled,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "enabledPolicies": enabled_policies,
            "assignedEnabledPolicies": assigned_enabled_policies,
        },
        metadata={
            "transformationId": "isBehavioralMonitoringValid",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
