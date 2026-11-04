
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

    if isinstance(data, dict):
        policies = data.get("value") or data.get("data") or []
    elif isinstance(data, list):
        policies = data
    else:
        policies = []

    if not isinstance(policies, list):
        policies = []

    total_enabled = 0
    matched_policy_names = []
    trusted_only_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        state = p.get("state")
        if state != "enabled":
            continue
        total_enabled = total_enabled + 1

        grant = p.get("grantControls") or {}
        built_in = grant.get("builtInControls") or []
        auth_strength = grant.get("authenticationStrength")
        requires_mfa = ("mfa" in built_in) or bool(auth_strength)
        if not requires_mfa:
            continue

        conditions = p.get("conditions") or {}
        locations = conditions.get("locations") or {}
        include_locations = locations.get("includeLocations") or []
        exclude_locations = locations.get("excludeLocations") or []

        name = p.get("displayName") or p.get("id") or "unknown-policy"

        applies_remote = False
        if not locations:
            applies_remote = True
        else:
            if "All" in include_locations and "AllTrusted" not in exclude_locations:
                applies_remote = True
            elif "AllTrusted" in include_locations:
                applies_remote = False
                trusted_only_names.append(name)
            else:
                applies_remote = False

        if applies_remote:
            matched_policy_names.append(name)

    is_required = len(matched_policy_names) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_required:
        pass_reasons.append(
            f"{len(matched_policy_names)} enabled Conditional Access polic(y/ies) require MFA "
            f"(grantControls.builtInControls contains 'mfa' or authenticationStrength set) "
            f"without a trusted-network-only location restriction, covering remote access: "
            f"{', '.join(matched_policy_names[:5])}"
        )
    else:
        fail_reasons.append(
            f"Out of {total_enabled} enabled Conditional Access policies, none require MFA "
            f"for access that is not restricted to a trusted network location. "
            f"Policies scoped to AllTrusted locations only: {', '.join(trusted_only_names[:5]) if trusted_only_names else 'none found'}."
        )
        recommendations.append(
            "Create or modify a Conditional Access policy targeting all users/apps with "
            "grantControls.builtInControls=['mfa'] and no restrictive includeLocations=['AllTrusted'] "
            "condition, so MFA is enforced for access from outside the trusted network (remote access)."
        )

    result = {
        "isMFARequiredForRemoteAccess": is_required,
        "totalEnabledPolicies": total_enabled,
        "matchingPolicyCount": len(matched_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEnabledPolicies": total_enabled,
            "matchingPolicyCount": len(matched_policy_names),
        },
        metadata={
            "transformationId": "isMFARequiredForRemoteAccess",
            "vendor": "Microsoft Entra ID",
            "category": "iam",
        },
    )
