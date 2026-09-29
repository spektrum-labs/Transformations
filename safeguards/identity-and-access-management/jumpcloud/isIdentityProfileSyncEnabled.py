"""Transformation: isIdentityProfileSyncEnabled - JumpCloud listIdentityProviders"""
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        providers = data
        total_count = len(data)
    elif isinstance(data, dict):
        providers = data.get("identityProviders")
        if providers is None:
            providers = data.get("results") or data.get("data") or []
        total_count = data.get("totalCount")
        if total_count is None:
            total_count = len(providers) if isinstance(providers, list) else 0
    else:
        providers = []
        total_count = 0

    if not isinstance(providers, list):
        providers = []

    enabled_providers = []
    for p in providers:
        if not isinstance(p, dict):
            continue
        is_disabled = p.get("disabled") is True
        if not is_disabled:
            enabled_providers.append(p)

    provider_count = len(providers)
    enabled_count = len(enabled_providers)
    sync_enabled = enabled_count > 0

    provider_names = [p.get("name") or p.get("id") or "unknown" for p in enabled_providers][:10]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if sync_enabled:
        pass_reasons.append(
            f"{enabled_count} of {provider_count} configured identity provider(s) are active "
            f"(not disabled): {', '.join(str(n) for n in provider_names)}. This evidences "
            f"identity profile/attribute synchronization is active between JumpCloud and the "
            f"external directory."
        )
    else:
        fail_reasons.append(
            f"listIdentityProviders returned totalCount={total_count} with {provider_count} "
            f"identity provider record(s) and {enabled_count} enabled/active among them. No "
            f"external identity provider integration is configured, so identity profile sync "
            f"cannot be considered enabled."
        )
        recommendations.append(
            "Configure an external Identity Provider (e.g. Azure AD, Okta, Google Workspace) "
            "under JumpCloud's Identity Providers / routing policies to enable identity "
            "profile synchronization."
        )

    result = {
        "isIdentityProfileSyncEnabled": sync_enabled,
        "totalIdentityProviders": provider_count,
        "activeIdentityProviders": enabled_count,
    }

    input_summary = {
        "totalCount": total_count,
        "providerCount": provider_count,
        "enabledProviderCount": enabled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isIdentityProfileSyncEnabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
