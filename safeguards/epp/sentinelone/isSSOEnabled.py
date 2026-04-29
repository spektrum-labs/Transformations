"""
Transformation: isSSOEnabled
Vendor: SentinelOne | Category: epp
Checks if SSO is enabled for SentinelOne console access by inspecting user records
for source='sso' or source='scim'. A tenant is considered SSO-enabled when at least
one active user authenticates via SSO or is SCIM-provisioned.
No direct SSO configuration endpoint exists in the SentinelOne v2.1 API; the 'source'
field on user records is the only machine-readable SSO signal available.
"""
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

    users = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or len(users)

    sso_count = 0
    scim_count = 0
    mfa_count = 0

    for user in users:
        source = (user.get("source") or "").lower()
        if source == "sso":
            sso_count = sso_count + 1
        elif source == "scim":
            scim_count = scim_count + 1
        if user.get("primaryTwoFaMethod"):
            mfa_count = mfa_count + 1

    total_inspected = len(users)
    is_sso_enabled = (sso_count + scim_count) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if is_sso_enabled:
        if sso_count > 0:
            pass_reasons.append(
                f"{sso_count} of {total_inspected} inspected users (tenant total: {total_items}) "
                f"have source='sso', confirming SSO is actively used for console access."
            )
        if scim_count > 0:
            pass_reasons.append(
                f"{scim_count} user(s) have source='scim', indicating SCIM-provisioned SSO accounts."
            )
        if mfa_count > 0:
            additional_findings.append(
                f"{mfa_count} user(s) also have a primaryTwoFaMethod set (e.g., 'application'), "
                f"indicating MFA is in use alongside SSO."
            )
    else:
        fail_reasons.append(
            f"None of the {total_inspected} inspected users (tenant total: {total_items}) "
            f"have source='sso' or source='scim'. All users appear to use local authentication."
        )
        recommendations.append(
            "Configure SSO integration in the SentinelOne console under Settings > SSO to enforce "
            "federated identity and MFA for all administrative console access."
        )
        if mfa_count > 0:
            additional_findings.append(
                f"{mfa_count} local user(s) have a primaryTwoFaMethod configured (e.g., 'application'), "
                f"but tenant-level SSO/federated authentication is not detected."
            )

    return create_response(
        result={
            "isSSOEnabled": is_sso_enabled,
            "totalUsersInspected": total_inspected,
            "totalUsersInTenant": total_items,
            "ssoUserCount": sso_count,
            "scimUserCount": scim_count,
            "mfaEnabledUserCount": mfa_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalUsersInspected": total_inspected,
            "totalUsersInTenant": total_items,
            "ssoUserCount": sso_count,
            "scimUserCount": scim_count,
        },
        additional_findings=additional_findings,
        metadata={
            "transformationId": "isSSOEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
