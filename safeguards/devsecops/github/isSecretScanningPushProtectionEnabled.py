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


def transform(input):
    """Secret scanning push protection on every active repository, read per repository.

    Reads security_and_analysis.secret_scanning_push_protection on GET /orgs/{org}/repos.

    Three outcomes:
      * True: every active repository reports push protection enabled.
      * False: at least one repository was READ and has push protection off.
      * None (Not evaluated, with a data collection error): the answer could not be read.
        That is an error or unrecognised body, an empty list, no active repository, or no
        repository that reports the field. GitHub returns security_and_analysis only to an
        owner, a security manager or a repository admin, so a missing block is a token that
        cannot see it, not a repository with the feature off. A refused or empty read is not
        a failed control; a repository that was read and is off still fails the check.
    """
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    repos = None
    if isinstance(data, list):
        repos = data
    elif isinstance(data, dict):
        for key in ("data", "repositories"):
            if isinstance(data.get(key), list):
                repos = data.get(key)
                break

    api_errors = []
    if repos is None:
        repos = []
        api_errors.append("The repository list response was not a list of repositories, so push protection cannot be read.")
    elif not repos:
        api_errors.append("The repository list response was empty, so push protection cannot be read.")

    active_repos = [
        r for r in repos
        if isinstance(r, dict) and not r.get("archived") and not r.get("disabled")
    ]

    total_active = len(active_repos)
    enabled_repos = []
    disabled_repos = []
    missing_field_repos = []

    for r in active_repos:
        sec = r.get("security_and_analysis")
        name = r.get("full_name") or r.get("name") or "unknown"
        if not isinstance(sec, dict):
            missing_field_repos.append(name)
            continue
        pp = sec.get("secret_scanning_push_protection")
        if not isinstance(pp, dict):
            missing_field_repos.append(name)
            continue
        status = pp.get("status")
        if status == "enabled":
            enabled_repos.append(name)
        else:
            disabled_repos.append(name)

    evaluated_count = len(enabled_repos) + len(disabled_repos)

    if repos and total_active == 0:
        api_errors.append("No active (non-archived, non-disabled) repositories were found in the organization to read.")
    if missing_field_repos and not disabled_repos:
        api_errors.append(
            f"{len(missing_field_repos)} of {total_active} active repositories did not return the "
            "security_and_analysis.secret_scanning_push_protection field; the token may lack admin or security-manager visibility into this setting."
        )

    if disabled_repos:
        is_enabled = False
    elif api_errors or missing_field_repos:
        is_enabled = None
    else:
        is_enabled = True

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if is_enabled is None:
        fail_reasons.append("Push protection could not be read for every active repository: " + " ".join(api_errors))
        recommendations.append(
            "Use a token whose owner is an organization owner or security manager, with access to all repositories, "
            "and have an owner approve it if the organization requires approval for fine-grained tokens."
        )
    elif is_enabled:
        sample = ", ".join(enabled_repos[:5])
        pass_reasons.append(
            f"All {evaluated_count} active repositories report security_and_analysis.secret_scanning_push_protection.status='enabled' (e.g. {sample})."
        )
    else:
        sample_disabled = ", ".join(disabled_repos[:5])
        fail_reasons.append(
            f"{len(disabled_repos)} of {total_active} active repositories have secret_scanning_push_protection disabled or not enabled (e.g. {sample_disabled})."
        )
        if missing_field_repos:
            fail_reasons.append(
                f"{len(missing_field_repos)} active repositories did not return the security_and_analysis field at all."
            )
        recommendations.append(
            "Enable secret scanning push protection enterprise-wide via organization security settings, or enforce it via a repository security configuration applied to all repositories."
        )

    result = {
        "isSecretScanningPushProtectionEnabled": is_enabled,
        "totalActiveRepositories": total_active,
        "enabledRepositoryCount": len(enabled_repos),
        "disabledRepositoryCount": len(disabled_repos),
        "missingFieldRepositoryCount": len(missing_field_repos),
    }

    input_summary = {
        "totalActiveRepositories": total_active,
        "evaluatedRepositories": evaluated_count,
        "enabledRepositoryCount": len(enabled_repos),
        "disabledRepositoryCount": len(disabled_repos),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors if is_enabled is None else None,
        metadata={
            "transformationId": "isSecretScanningPushProtectionEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
