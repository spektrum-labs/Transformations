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


def transform(input):
    """Dependabot alerts enablement, read from the org code security configurations.

    Reads `dependabot_alerts` on GET /orgs/{org}/code-security/configurations.

    This criterion previously read security_and_analysis.dependabot_security_updates
    on the repository list. Those are two different GitHub features: alerts tell you a
    dependency has a CVE, security updates raise the patch PR. The repository object
    carries no dependabot_alerts field at all, so the substitution reported alerts as
    disabled on orgs where they are on -- contradicted by this integration's own
    openCriticalDependabotAlertsCount, which counts those very alerts.

    Configurations with target_type "global" are GitHub's own built-in templates and
    are present in every organization with dependabot_alerts already enabled. They are
    excluded: counting them would pass every customer regardless of configuration.
    """
    data, validation = extract_input(input)

    if isinstance(data, list):
        configs = data
    elif isinstance(data, dict):
        configs = data.get("data") or data.get("configurations") or []
        if not isinstance(configs, list):
            configs = []
    else:
        configs = []

    owned = []
    for cfg in configs:
        if isinstance(cfg, dict) and str(cfg.get("target_type", "")).lower() in ("organization", "enterprise"):
            owned.append(cfg)

    enabled_names = []
    disabled_names = []
    not_set_names = []
    for cfg in owned:
        name = cfg.get("name") or "unnamed configuration"
        status = str(cfg.get("dependabot_alerts", "")).lower()
        if status == "enabled":
            enabled_names.append(name)
        elif status == "disabled":
            disabled_names.append(name)
        else:
            not_set_names.append(name)

    is_enabled = len(enabled_names) > 0 and len(disabled_names) == 0

    result = {
        "isDependabotAlertsEnabled": is_enabled,
        "totalConfigurations": len(configs),
        "ownedConfigurations": len(owned),
        "enabledConfigurations": len(enabled_names),
        "disabledConfigurations": len(disabled_names),
        "notSetConfigurations": len(not_set_names),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if len(configs) == 0:
        fail_reasons.append("No code security configurations were returned, so Dependabot alert enablement cannot be confirmed.")
        recommendations.append("Verify the organization name and that the token can read organization code security configurations.")
    elif len(owned) == 0:
        fail_reasons.append("Only GitHub's built-in global configuration templates are present; this organization has no code security configuration of its own.")
        recommendations.append("Create an organization or enterprise code security configuration with Dependabot alerts enabled and apply it to all repositories.")
    elif disabled_names:
        fail_reasons.append(f"Dependabot alerts are disabled in {len(disabled_names)} of {len(owned)} code security configurations: {', '.join(disabled_names)}")
        recommendations.append("Set Dependabot alerts to enabled in every organization and enterprise code security configuration.")
    elif is_enabled:
        pass_reasons.append(f"Dependabot alerts are enabled in all {len(enabled_names)} organization and enterprise code security configurations: {', '.join(enabled_names)}")
        if not_set_names:
            pass_reasons.append(f"{len(not_set_names)} configuration(s) leave it unset and inherit: {', '.join(not_set_names)}")
    else:
        fail_reasons.append(f"Dependabot alerts are not enabled in any of the {len(owned)} organization or enterprise code security configurations; all leave it unset.")
        recommendations.append("Set Dependabot alerts to enabled in the configuration applied to your repositories.")

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalConfigurations": len(configs),
            "ownedConfigurations": len(owned),
            "enabledConfigurations": len(enabled_names),
            "disabledConfigurations": len(disabled_names),
        },
        metadata={"transformationId": "isDependabotAlertsEnabled", "vendor": "GitHub", "category": "devsecops"},
    )
