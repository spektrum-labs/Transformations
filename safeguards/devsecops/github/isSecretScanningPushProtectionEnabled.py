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

    if isinstance(data, list):
        repos = data
    elif isinstance(data, dict):
        repos = data.get("data") or data.get("items") or data.get("repositories") or []
        if not isinstance(repos, list):
            repos = []
    else:
        repos = []

    active_repos = [r for r in repos if isinstance(r, dict) and not r.get("archived", False) and not r.get("disabled", False)]

    enabled_repos = []
    disabled_repos = []
    unknown_repos = []

    for r in active_repos:
        sa = r.get("security_and_analysis")
        name = r.get("full_name") or r.get("name") or "unknown"
        if not isinstance(sa, dict):
            unknown_repos.append(name)
            continue
        pp = sa.get("secret_scanning_push_protection")
        if not isinstance(pp, dict):
            unknown_repos.append(name)
            continue
        status = pp.get("status")
        if status == "enabled":
            enabled_repos.append(name)
        elif status == "disabled":
            disabled_repos.append(name)
        else:
            unknown_repos.append(name)

    total_active = len(active_repos)
    total_enabled = len(enabled_repos)
    total_disabled = len(disabled_repos)
    total_unknown = len(unknown_repos)

    is_enabled = total_active > 0 and total_disabled == 0 and total_unknown == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_active == 0:
        fail_reasons.append("No active (non-archived, non-disabled) repositories were returned by listOrgRepositories, so push protection coverage cannot be confirmed.")
        recommendations.append("Verify the org has repositories and that the API token has org read access.")
    elif is_enabled:
        sample = enabled_repos[:5]
        pass_reasons.append(
            f"All {total_active} active repositories report security_and_analysis.secret_scanning_push_protection.status='enabled' (e.g. {sample})."
        )
    else:
        if total_disabled > 0:
            sample = disabled_repos[:5]
            fail_reasons.append(
                f"{total_disabled} of {total_active} active repositories report secret_scanning_push_protection.status='disabled' (e.g. {sample})."
            )
            recommendations.append(
                "Enable secret scanning push protection on all repositories, or enforce it enterprise-wide via the organization security configuration."
            )
        if total_unknown > 0:
            sample = unknown_repos[:5]
            fail_reasons.append(
                f"{total_unknown} of {total_active} active repositories do not expose a readable secret_scanning_push_protection.status field (e.g. {sample})."
            )
            recommendations.append(
                "Confirm GitHub Advanced Security is enabled for these repositories so the secret_scanning_push_protection status can be evaluated."
            )

    result = {
        "isSecretScanningPushProtectionEnabled": is_enabled,
        "totalActiveRepositories": total_active,
        "pushProtectionEnabledCount": total_enabled,
        "pushProtectionDisabledCount": total_disabled,
        "pushProtectionUnknownCount": total_unknown,
    }

    input_summary = {
        "totalRepositoriesInResponse": len(repos),
        "activeRepositories": total_active,
        "enabledCount": total_enabled,
        "disabledCount": total_disabled,
        "unknownCount": total_unknown,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSecretScanningPushProtectionEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
