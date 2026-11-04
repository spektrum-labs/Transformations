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
        policies = data
    elif isinstance(data, dict):
        policies = data.get("value") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    transformation_errors = []

    def users_include_all(conditions):
        users = (conditions or {}).get("users") or {}
        include = users.get("includeUsers") or []
        if isinstance(include, list) and "All" in include:
            return True
        return False

    def users_exclude_broad(conditions):
        # An exclusion of "All" would negate tenant-wide MFA coverage.
        users = (conditions or {}).get("users") or {}
        exclude = users.get("excludeUsers") or []
        if isinstance(exclude, list) and "All" in exclude:
            return True
        return False

    enforcing_policies = []
    mfa_referencing_policies = []
    total_enabled = 0

    for p in policies:
        if not isinstance(p, dict):
            continue
        state = p.get("state")
        if state == "enabled":
            total_enabled = total_enabled + 1
        grant = p.get("grantControls") or {}
        if not isinstance(grant, dict):
            grant = {}
        built_in = grant.get("builtInControls") or []
        if not isinstance(built_in, list):
            built_in = []
        has_mfa_control = ("mfa" in built_in) or (grant.get("authenticationStrength") is not None)
        conditions = p.get("conditions") or {}
        if not isinstance(conditions, dict):
            conditions = {}

        name = p.get("displayName") or p.get("id") or "unnamed policy"

        if has_mfa_control and state == "enabled":
            mfa_referencing_policies.append(name)
            if users_include_all(conditions) and not users_exclude_broad(conditions):
                enforcing_policies.append(name)

    is_enforced = len(enforcing_policies) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        joined = ", ".join(enforcing_policies)
        pass_reasons.append(
            "Found %d enabled Conditional Access polic%s requiring grantControls.builtInControls=['mfa'] or an authenticationStrength, targeting conditions.users.includeUsers=['All'] without excluding all users: %s."
            % (len(enforcing_policies), "ies" if len(enforcing_policies) != 1 else "y", joined)
        )
    else:
        joined = ", ".join(mfa_referencing_policies) if mfa_referencing_policies else "none"
        fail_reasons.append(
            "No enabled Conditional Access policy requires MFA (builtInControls contains 'mfa' or authenticationStrength is set) while targeting conditions.users.includeUsers=['All']. %d enabled polic%s reference an MFA control but do not target all users: %s. Out of %d total policies, %d are enabled."
            % (len(mfa_referencing_policies), "ies" if len(mfa_referencing_policies) != 1 else "y", joined, len(policies), total_enabled)
        )
        recommendations.append(
            "Create or modify a Conditional Access policy with state=enabled, conditions.users.includeUsers=['All'] (and no 'All' in excludeUsers), and grantControls.builtInControls=['mfa'] (or an authenticationStrength requirement) to enforce MFA for all users tenant-wide."
        )

    input_summary = {
        "totalPolicies": len(policies),
        "totalEnabledPolicies": total_enabled,
        "mfaReferencingEnabledPolicies": len(mfa_referencing_policies),
        "mfaEnforcingAllUsersPolicies": len(enforcing_policies),
    }

    result = {
        "isMFAEnforcedForUsers": is_enforced,
        "totalPolicies": len(policies),
        "mfaEnforcingPolicyCount": len(enforcing_policies),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isMFAEnforcedForUsers",
            "vendor": "Microsoft Entra ID",
            "category": "iam",
        },
    )
