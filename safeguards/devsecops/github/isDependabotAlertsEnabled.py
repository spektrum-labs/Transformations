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
        repos = data.get("data") or data.get("repos") or data.get("items") or []
        if not isinstance(repos, list):
            repos = []
    else:
        repos = []

    active_repos = [r for r in repos if isinstance(r, dict) and not r.get("archived") and not r.get("disabled")]

    total = len(active_repos)
    enabled_count = 0
    disabled_repo_names = []
    for r in active_repos:
        sa = r.get("security_and_analysis") or {}
        dsu = sa.get("dependabot_security_updates") or {}
        status = dsu.get("status")
        if status == "enabled":
            enabled_count = enabled_count + 1
        else:
            name = r.get("full_name") or r.get("name") or "unknown"
            disabled_repo_names.append(name)

    is_enabled = bool(total > 0 and enabled_count == total)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No active (non-archived, non-disabled) repositories were found in the organization repo list to evaluate dependabot_security_updates.status.")
        recommendations.append("Verify org repository listing access and re-run once repositories are visible.")
    elif is_enabled:
        pass_reasons.append(
            f"All {total} active repositories report security_and_analysis.dependabot_security_updates.status='enabled' ({enabled_count}/{total})."
        )
    else:
        sample = ", ".join(disabled_repo_names[:5])
        fail_reasons.append(
            f"Only {enabled_count}/{total} active repositories have security_and_analysis.dependabot_security_updates.status='enabled'. Repos without it enabled include: {sample}."
        )
        recommendations.append(
            "Enable Dependabot security updates (and alerts) by default for all repositories via org-level security settings, or enable it individually on the listed repositories."
        )

    result = {
        "isDependabotAlertsEnabled": is_enabled,
        "totalActiveRepos": total,
        "reposWithDependabotEnabled": enabled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalActiveRepos": total, "reposWithDependabotEnabled": enabled_count},
        metadata={
            "transformationId": "isDependabotAlertsEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
