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

    org = data if isinstance(data, dict) else {}

    login = org.get("login") or "unknown organization"
    ghas_flag = org.get("advanced_security_enabled_for_new_repositories")

    transformation_errors = []
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if ghas_flag is None:
        is_enabled = False
        fail_reasons.append(
            f"Organization '{login}' response did not include "
            "advanced_security_enabled_for_new_repositories; GitHub only returns this "
            "field when GHAS org-level settings are exposed, treating as not confirmed enabled."
        )
        recommendations.append(
            "Verify the token has admin:org scope and that the organization is on a plan "
            "supporting GitHub Advanced Security, then re-check "
            "advanced_security_enabled_for_new_repositories on GET /orgs/{org}."
        )
    else:
        is_enabled = bool(ghas_flag)
        if is_enabled:
            pass_reasons.append(
                f"Organization '{login}' has advanced_security_enabled_for_new_repositories=true, "
                "meaning GitHub Advanced Security (code scanning, CodeQL, expanded secret scanning) "
                "is enabled by default for newly created repositories."
            )
        else:
            fail_reasons.append(
                f"Organization '{login}' has advanced_security_enabled_for_new_repositories=false, "
                "meaning GitHub Advanced Security is NOT enabled by default for new repositories."
            )
            recommendations.append(
                "Enable 'Advanced Security' as an organization-wide default for new repositories "
                "under Settings > Code security and analysis."
            )

    input_summary = {
        "login": login,
        "advanced_security_enabled_for_new_repositories": ghas_flag,
    }

    result = {
        "isAdvancedSecurityEnabled": is_enabled,
        "advancedSecurityEnabledForNewRepositories": ghas_flag,
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
        transformation_errors=transformation_errors,
    )
