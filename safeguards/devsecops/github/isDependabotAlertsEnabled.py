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
        repos = data.get("data") or data.get("repositories") or []
        if not isinstance(repos, list):
            repos = []
    else:
        repos = []

    total = len(repos)
    enabled_count = 0
    disabled_repos = []
    unknown_count = 0

    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = repo.get("full_name") or repo.get("name") or "unknown"
        sec = repo.get("security_and_analysis") or {}
        if not isinstance(sec, dict):
            sec = {}
        dep = sec.get("dependabot_security_updates") or {}
        if not isinstance(dep, dict):
            dep = {}
        status = dep.get("status")
        if status == "enabled":
            enabled_count = enabled_count + 1
        elif status == "disabled":
            disabled_repos.append(name)
        else:
            unknown_count = unknown_count + 1

    is_enabled = (total > 0) and (enabled_count == total) and (unknown_count == 0)

    result = {
        "isDependabotAlertsEnabled": is_enabled,
        "totalRepos": total,
        "enabledRepos": enabled_count,
        "disabledRepos": len(disabled_repos),
        "unknownStatusRepos": unknown_count,
    }

    if total == 0:
        pass_reasons = []
        fail_reasons = ["No repositories were returned by listOrgRepositories, so Dependabot alert enablement cannot be confirmed."]
        recommendations = ["Verify org name and token scope; re-run once repositories are visible."]
    elif is_enabled:
        pass_reasons = [
            f"All {total} organization repositories report security_and_analysis.dependabot_security_updates.status='enabled' (enabled_count={enabled_count}/{total})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        sample = ", ".join(disabled_repos[:5]) if disabled_repos else "none named"
        fail_reasons = [
            f"Only {enabled_count} of {total} repositories have Dependabot security updates (and therefore Dependabot alerts) enabled; {len(disabled_repos)} explicitly disabled ({sample}), {unknown_count} with unknown/missing status."
        ]
        recommendations = [
            "Enable Dependabot alerts (and security updates) by default for new repositories at the organization level, and enable it on the repositories currently reporting 'disabled' or unknown status."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRepos": total, "enabledRepos": enabled_count, "disabledRepos": len(disabled_repos), "unknownStatusRepos": unknown_count},
        metadata={"transformationId": "isDependabotAlertsEnabled", "vendor": "GitHub", "category": "devsecops"},
    )
