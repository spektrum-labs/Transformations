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


UNRESTRICTED_POLICY_ID = "microsoft-user-default-legacy"


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        record = data[0] if data else {}
    else:
        record = data

    if not isinstance(record, dict):
        record = {}

    default_perms = record.get("defaultUserRolePermissions") or {}
    if not isinstance(default_perms, dict):
        default_perms = {}

    policies = default_perms.get("permissionGrantPoliciesAssigned")
    if not isinstance(policies, list):
        policies = []

    transformation_errors = []
    if "defaultUserRolePermissions" not in record:
        transformation_errors.append(
            "defaultUserRolePermissions field missing from authorizationPolicy response"
        )

    is_restricted = (len(policies) == 0) or (UNRESTRICTED_POLICY_ID not in policies)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if len(policies) == 0:
        pass_reasons.append(
            "defaultUserRolePermissions.permissionGrantPoliciesAssigned is empty, "
            "meaning users cannot consent to app permission requests at all "
            "(most restrictive configuration)."
        )
    elif UNRESTRICTED_POLICY_ID in policies:
        fail_reasons.append(
            f"permissionGrantPoliciesAssigned contains '{UNRESTRICTED_POLICY_ID}', "
            f"which allows users to consent to any app (unrestricted), full list: {policies}."
        )
        recommendations.append(
            "Remove the 'microsoft-user-default-legacy' permission grant policy and "
            "assign a restricted policy such as 'microsoft-user-default-low-risk', or "
            "clear the list entirely to disable user consent."
        )
    else:
        pass_reasons.append(
            f"permissionGrantPoliciesAssigned is restricted to specific policies: {policies}, "
            f"which does not include the unrestricted '{UNRESTRICTED_POLICY_ID}' policy."
        )

    result = {
        "isAppConsentRestricted": is_restricted,
        "permissionGrantPoliciesAssigned": policies,
    }

    input_summary = {
        "policyCount": len(policies),
        "permissionGrantPoliciesAssigned": policies,
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
            "transformationId": "isAppConsentRestricted",
            "vendor": "Microsoft Defender for Cloud",
            "category": "cloudsecurity",
        },
    )
