
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
        repos = data.get("data") or data.get("apiResponse") or []
        if not isinstance(repos, list):
            repos = []
    else:
        repos = []

    total_repos = len(repos)
    non_archived_non_disabled = [r for r in repos if isinstance(r, dict) and not r.get("archived") and not r.get("disabled")]

    evaluated = []
    enabled_count = 0
    disabled_count = 0
    missing_count = 0

    for repo in non_archived_non_disabled:
        sa = repo.get("security_and_analysis")
        name = repo.get("full_name") or repo.get("name") or "unknown"
        if isinstance(sa, dict):
            adv = sa.get("advanced_security") or {}
            status = adv.get("status") if isinstance(adv, dict) else None
            if status == "enabled":
                enabled_count = enabled_count + 1
                evaluated.append(name)
            elif status == "disabled":
                disabled_count = disabled_count + 1
            else:
                missing_count = missing_count + 1
        else:
            missing_count = missing_count + 1

    applicable_total = enabled_count + disabled_count

    if applicable_total == 0:
        is_enabled = False
        fail_reasons = [
            "No repository in the fetched list of %d repos exposed a readable security_and_analysis.advanced_security.status field, so GHAS enablement could not be confirmed." % total_repos
        ]
        pass_reasons = []
        recommendations = [
            "Verify the API token has admin/org-level access sufficient to read security_and_analysis on repositories, and enable GitHub Advanced Security at the organization level for new repositories."
        ]
    elif disabled_count == 0:
        is_enabled = True
        pass_reasons = [
            "All %d repositories with a readable security_and_analysis field report advanced_security.status='enabled' (checked out of %d total non-archived, non-disabled repos)." % (enabled_count, len(non_archived_non_disabled))
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enabled = False
        fail_reasons = [
            "%d of %d repositories with readable security_and_analysis have advanced_security.status not equal to 'enabled' (enabled=%d, disabled=%d, unreadable=%d)." % (disabled_count, applicable_total, enabled_count, disabled_count, missing_count)
        ]
        pass_reasons = []
        recommendations = [
            "Enable GitHub Advanced Security organization-wide (and specifically on the flagged repositories) so new repositories inherit code scanning, CodeQL, and secret scanning by default."
        ]

    result = {
        "isAdvancedSecurityEnabled": is_enabled,
        "totalRepositories": total_repos,
        "applicableRepositories": applicable_total,
        "advancedSecurityEnabledCount": enabled_count,
        "advancedSecurityDisabledCount": disabled_count,
        "unreadableSecurityAnalysisCount": missing_count,
    }

    input_summary = {
        "totalRepositories": total_repos,
        "nonArchivedNonDisabledRepos": len(non_archived_non_disabled),
        "applicableRepositories": applicable_total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAdvancedSecurityEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
