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

    if total_active == 0:
        is_enabled = False
        pass_reasons = []
        fail_reasons = ["No active (non-archived, non-disabled) repositories were found in the organization to evaluate."]
        recommendations = ["Verify the organization has repositories and that the token has access to security_and_analysis data."]
    elif evaluated_count == 0:
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_active} active repositories returned a security_and_analysis.secret_scanning_push_protection field; the token may lack admin visibility into this setting."
        ]
        recommendations = ["Use a token with organization admin or security-manager permissions so security_and_analysis fields are populated."]
    elif len(disabled_repos) == 0 and evaluated_count == total_active:
        is_enabled = True
        sample = ", ".join(enabled_repos[:5])
        pass_reasons = [
            f"All {evaluated_count} active repositories report security_and_analysis.secret_scanning_push_protection.status='enabled' (e.g. {sample})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enabled = False
        sample_disabled = ", ".join(disabled_repos[:5])
        fail_reasons = [
            f"{len(disabled_repos)} of {total_active} active repositories have secret_scanning_push_protection disabled or not enabled (e.g. {sample_disabled})."
        ]
        if missing_field_repos:
            fail_reasons.append(
                f"{len(missing_field_repos)} active repositories did not return the security_and_analysis field at all."
            )
        pass_reasons = []
        recommendations = [
            "Enable secret scanning push protection enterprise-wide via organization security settings, or enforce it via a repository security configuration applied to all repositories."
        ]

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
        metadata={
            "transformationId": "isSecretScanningPushProtectionEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
