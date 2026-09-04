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
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    org_login = None
    field_present = False
    dependabot_enabled = False

    if isinstance(data, dict):
        org_login = data.get("login")
        if "dependabot_alerts_enabled_for_new_repositories" in data:
            field_present = True
            dependabot_enabled = bool(data.get("dependabot_alerts_enabled_for_new_repositories"))

    input_summary = {
        "orgLogin": org_login,
        "fieldPresent": field_present,
        "dependabotAlertsEnabledForNewRepositories": dependabot_enabled if field_present else None,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if field_present and dependabot_enabled:
        pass_reasons.append(
            f"Org '{org_login}' has dependabot_alerts_enabled_for_new_repositories=true, meaning Dependabot alerts are enabled by default for new repositories."
        )
    elif field_present and not dependabot_enabled:
        fail_reasons.append(
            f"Org '{org_login}' reports dependabot_alerts_enabled_for_new_repositories=false, so Dependabot alerts are NOT enabled by default for new repositories."
        )
        recommendations.append(
            "Enable 'Dependabot alerts' as a default for new repositories in the organization's Code security settings (Settings > Code security and analysis)."
        )
    else:
        fail_reasons.append(
            "The org profile response did not include a 'dependabot_alerts_enabled_for_new_repositories' field, so no default-enablement setting could be confirmed."
        )
        recommendations.append(
            "Verify the organization's Code security and analysis settings and ensure the API token has admin:org scope to retrieve dependabot_alerts_enabled_for_new_repositories."
        )

    result = {
        "isDependabotAlertsEnabled": bool(field_present and dependabot_enabled),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isDependabotAlertsEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
