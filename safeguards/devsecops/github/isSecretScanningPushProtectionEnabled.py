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
        org = {}
    elif isinstance(data, dict):
        org = data
    else:
        org = {}

    login = org.get("login") or "unknown-org"
    push_protection_field = org.get("secret_scanning_push_protection_enabled_for_new_repositories")
    secret_scanning_field = org.get("secret_scanning_enabled_for_new_repositories")
    advanced_security_field = org.get("advanced_security_enabled_for_new_repositories")

    field_present = "secret_scanning_push_protection_enabled_for_new_repositories" in org

    is_enabled = bool(push_protection_field) if field_present else False

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if field_present and is_enabled:
        pass_reasons.append(
            f"Organization '{login}' reports secret_scanning_push_protection_enabled_for_new_repositories=true, "
            f"meaning push protection is enforced by default for new repositories org-wide "
            f"(secret_scanning_enabled_for_new_repositories={secret_scanning_field}, "
            f"advanced_security_enabled_for_new_repositories={advanced_security_field})."
        )
    elif field_present and not is_enabled:
        fail_reasons.append(
            f"Organization '{login}' reports secret_scanning_push_protection_enabled_for_new_repositories=false, "
            f"meaning push protection is not enforced by default for new repositories."
        )
        recommendations.append(
            "Enable 'Secret scanning push protection' as an org-wide default under "
            "Organization Settings -> Code security and analysis, so new repositories inherit push protection enforcement."
        )
    else:
        fail_reasons.append(
            f"Organization '{login}' response did not include the "
            f"secret_scanning_push_protection_enabled_for_new_repositories field; cannot confirm enforcement."
        )
        recommendations.append(
            "Verify the GitHub App/token has 'admin:org' scope and re-check the GET /orgs/{org} response "
            "for the secret_scanning_push_protection_enabled_for_new_repositories field."
        )

    result = {
        "isSecretScanningPushProtectionEnabled": is_enabled,
        "secretScanningEnabledForNewRepositories": bool(secret_scanning_field) if secret_scanning_field is not None else None,
        "advancedSecurityEnabledForNewRepositories": bool(advanced_security_field) if advanced_security_field is not None else None,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "orgLogin": login,
            "pushProtectionFieldPresent": field_present,
            "pushProtectionValue": push_protection_field,
        },
        metadata={
            "transformationId": "isSecretScanningPushProtectionEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
