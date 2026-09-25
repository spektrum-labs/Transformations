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
        assignments = data
    elif isinstance(data, dict):
        assignments = data.get("inboundSsoAssignments") or []
    else:
        assignments = []

    total_assignments = len(assignments)
    enabled_assignments = []
    off_assignments = []
    for a in assignments:
        mode = a.get("ssoMode") if isinstance(a, dict) else None
        if mode and mode != "SSO_OFF":
            enabled_assignments.append(a)
        else:
            off_assignments.append(a)

    is_sso_enabled = len(enabled_assignments) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_sso_enabled:
        sample_names = [a.get("name", "unknown") for a in enabled_assignments[:3]]
        sample_modes = [a.get("ssoMode", "unknown") for a in enabled_assignments[:3]]
        pass_reasons.append(
            f"{len(enabled_assignments)} of {total_assignments} inboundSsoAssignments have ssoMode "
            f"other than SSO_OFF (examples: {list(zip(sample_names, sample_modes))})."
        )
    else:
        if total_assignments > 0:
            fail_reasons.append(
                f"All {total_assignments} inboundSsoAssignments report ssoMode='SSO_OFF'; no org unit or "
                f"group has SAML/OIDC SSO enabled."
            )
            recommendations.append(
                "Configure and assign an inbound SAML SSO profile to at least one organizational unit or "
                "group via Cloud Identity inboundSsoAssignments, then set ssoMode to a non-SSO_OFF value."
            )
        else:
            fail_reasons.append(
                "No inboundSsoAssignments were returned for this customer; SSO does not appear to be "
                "configured for any org unit or group."
            )
            recommendations.append(
                "Set up an inbound SAML SSO profile and assign it to organizational units or groups."
            )

    result = {
        "isSSOEnabled": is_sso_enabled,
        "totalSsoAssignments": total_assignments,
        "enabledSsoAssignments": len(enabled_assignments),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalSsoAssignments": total_assignments,
            "enabledSsoAssignments": len(enabled_assignments),
        },
        metadata={
            "transformationId": "isSSOEnabled",
            "vendor": "Google Gmail Workspace",
            "category": "emailsecurity",
        },
    )
