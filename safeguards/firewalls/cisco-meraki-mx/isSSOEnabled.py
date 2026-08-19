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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    enabled_raw = data.get("enabled")
    sso_enabled = bool(enabled_raw) if enabled_raw is not None else False

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enabled_raw is None:
        fail_reasons.append(
            "Response from getOrganizationSaml did not include an 'enabled' field; "
            "unable to confirm SAML SSO configuration."
        )
        recommendations.append(
            "Verify the organization SAML settings endpoint is reachable and returns "
            "the 'enabled' field for this organization."
        )
    elif sso_enabled:
        pass_reasons.append(
            "Organization SAML SSO settings report enabled=true, confirming SAML "
            "single sign-on is configured for Dashboard administrator authentication."
        )
    else:
        fail_reasons.append(
            "Organization SAML SSO settings report enabled=false; SAML SSO is not "
            "configured for Dashboard administrator authentication."
        )
        recommendations.append(
            "Configure and enable SAML SSO under Organization > Settings > SAML SSO "
            "so administrators authenticate via the corporate identity provider."
        )

    result = {
        "isSSOEnabled": sso_enabled,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"enabled": enabled_raw},
        metadata={
            "transformationId": "isSSOEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
        api_errors=[],
        transformation_errors=[],
    )
