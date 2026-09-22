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

    private_repos = []
    for r in repos:
        if not isinstance(r, dict):
            continue
        if r.get("archived"):
            continue
        if r.get("private"):
            private_repos.append(r)

    total_private = len(private_repos)
    enabled_count = 0
    disabled_repos = []
    unknown_repos = []

    for r in private_repos:
        sec = r.get("security_and_analysis") or {}
        ghas = sec.get("advanced_security") or {}
        status = ghas.get("status")
        if status == "enabled":
            enabled_count = enabled_count + 1
        elif status == "disabled":
            disabled_repos.append(r.get("full_name") or r.get("name") or "unknown")
        else:
            unknown_repos.append(r.get("full_name") or r.get("name") or "unknown")

    if total_private == 0:
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            "No non-archived private repositories were found in the organization's repository list, so GitHub Advanced Security enablement cannot be confirmed."
        ]
        recommendations = [
            "Verify that the organization has private repositories, and enable GitHub Advanced Security for them."
        ]
    else:
        is_enabled = (enabled_count == total_private)
        if is_enabled:
            pass_reasons = [
                f"All {total_private} non-archived private repositories report security_and_analysis.advanced_security.status='enabled' (checked via listOrgRepositories)."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"{enabled_count} of {total_private} non-archived private repositories have advanced_security.status='enabled'. "
                f"Repositories without GHAS enabled: {', '.join(disabled_repos[:10]) if disabled_repos else 'see unknown status list'}."
            ]
            if unknown_repos:
                fail_reasons.append(
                    f"{len(unknown_repos)} private repositories did not report an advanced_security status field: {', '.join(unknown_repos[:10])}."
                )
            recommendations = [
                "Enable GitHub Advanced Security organization-wide (or via a policy/enterprise setting) so all new private repositories inherit code scanning, CodeQL, and expanded secret scanning by default."
            ]

    result = {
        "isAdvancedSecurityEnabled": is_enabled,
        "totalPrivateRepositories": total_private,
        "advancedSecurityEnabledCount": enabled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalReposSeen": len(repos),
            "totalPrivateRepositories": total_private,
            "advancedSecurityEnabledCount": enabled_count,
            "disabledRepos": disabled_repos[:20],
            "unknownStatusRepos": unknown_repos[:20],
        },
        metadata={
            "transformationId": "isAdvancedSecurityEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
