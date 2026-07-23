import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
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
    "ioa", "behavior", "interprocess", "indicatorofattack", "customioa",
    "extendeduser", "exploit", "cloudantimalware", "adwarepup", "malware"
]


def is_behavioral_setting(setting_id, setting_name):
    text = ((setting_id or "") + " " + (setting_name or "")).lower().replace(" ", "").replace("_", "")
    for kw in BEHAVIORAL_KEYWORDS:
        if kw in text:
            return True
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") or (data.get("statusCode") and data.get("statusCode") != 200):
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"Vendor API returned an error: {msg}")

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    enabled_policies_with_groups = []
    behavioral_findings = []
    total_policies = 0

    for policy in resources:
        if not isinstance(policy, dict):
            continue
        total_policies = total_policies + 1
        policy_name = policy.get("name") or policy.get("id") or "unnamed-policy"
        policy_enabled = bool(policy.get("enabled"))
        groups = policy.get("groups") or []
        has_groups = len(groups) > 0
        prevention_settings = policy.get("prevention_settings") or []
        if not isinstance(prevention_settings, list):
            prevention_settings = []

        policy_behavioral_settings = []
        for group in prevention_settings:
            if not isinstance(group, dict):
                continue
            settings = group.get("settings") or []
            if not isinstance(settings, list):
                settings = []
            for setting in settings:
                if not isinstance(setting, dict):
                    continue
                setting_id = setting.get("id")
                setting_name = setting.get("name")
                if is_behavioral_setting(setting_id, setting_name):
                    value = setting.get("value") or {}
                    setting_enabled = False
                    if isinstance(value, dict):
                        setting_enabled = bool(value.get("enabled"))
                    elif isinstance(value, bool):
                        setting_enabled = value
                    if setting_enabled:
                        policy_behavioral_settings.append(setting_name or setting_id)

        if policy_enabled and has_groups and len(policy_behavioral_settings) > 0:
            enabled_policies_with_groups.append(policy_name)
            behavioral_findings.append(
                f"Policy '{policy_name}' (enabled=True, assigned to {len(groups)} group(s)) has behavioral settings enabled: {', '.join(policy_behavioral_settings)}."
            )

    is_valid = len(enabled_policies_with_groups) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "validBehavioralPolicies": len(enabled_policies_with_groups),
    }

    if is_valid:
        pass_reasons = behavioral_findings
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_policies == 0:
            fail_reasons = ["No prevention policies were returned by getCombinedPreventionPolicies; unable to confirm behavioral/IOA detection configuration."]
        else:
            fail_reasons = [
                f"None of the {total_policies} prevention polic(y/ies) returned have an enabled=True policy assigned to a host group with a behavior-based (IOA/ML) detection setting turned on."
            ]
        recommendations = [
            "Enable the applicable prevention policy and turn on behavior-based detection settings (e.g. Cloud/On-sensor ML, Custom IOA, Adware/PUP detection) and assign the policy to the relevant host group(s)."
        ]

    result = {
        "isBehavioralMonitoringValid": is_valid,
        "totalPolicies": total_policies,
        "validBehavioralPolicies": len(enabled_policies_with_groups),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBehavioralMonitoringValid",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
        api_errors=api_errors,
    )
