"""
Transformation: isSSOEnabled
Vendor: SentinelOne
Category: epp
Method: getSSOSettings (chained after checkLicenseStatus to derive accountId)

Reads /web/api/v2.1/settings/sso?accountIds={accountId} and confirms SSO is
enabled at the SentinelOne account level. SSO config is account-scoped: every
site under the same account inherits the same setting.

A pass requires BOTH:
  - data.enabled is True
  - An IdP is fully configured (idpEntityId + idpSsoUrl populated)

Just toggling enabled=True without configuring an IdP does not mean SSO works —
end users would still be unable to authenticate.
"""
import json
from datetime import datetime, timezone


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
        "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
    if not isinstance(data, dict):
        data = {}

    # Read either raw API field names (after Token-Service strips down to data.data)
    # or the engine-mapped names (in case the merged chain payload retains them).
    sso_enabled = data.get("ssoEnabled")
    if sso_enabled is None:
        sso_enabled = data.get("enabled", False)
    sso_enabled = bool(sso_enabled)

    idp_entity_id = data.get("idpEntityId") or ""
    idp_sso_url = data.get("idpSsoUrl") or ""
    idp_cert_name = data.get("idpCertName") or ""

    sso_domains = data.get("ssoDomains")
    if not isinstance(sso_domains, list):
        sso_domains = data.get("domains") or []
    if not isinstance(sso_domains, list):
        sso_domains = []

    has_idp = bool(idp_entity_id) and bool(idp_sso_url)
    is_enabled = sso_enabled and has_idp

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        domains_str = ", ".join(sso_domains) if sso_domains else "none configured"
        pass_reasons.append(
            f"SSO is enabled at the SentinelOne account level. "
            f"IdP entityId='{idp_entity_id}', ssoUrl='{idp_sso_url}'. "
            f"Authorized domains: {domains_str}."
        )
    else:
        if not sso_enabled:
            fail_reasons.append(
                "SSO is disabled at the SentinelOne account level (data.enabled is False). "
                "Note: SSO is configured per-account, so all sites under this account inherit the same setting."
            )
            recommendations.append(
                "Configure SSO in the SentinelOne management console under Settings > SSO. "
                "All sites under this account will inherit the configuration."
            )
        elif not has_idp:
            fail_reasons.append(
                f"SSO is flagged enabled but no IdP is configured "
                f"(idpEntityId='{idp_entity_id}', idpSsoUrl='{idp_sso_url}'). "
                f"Users cannot authenticate via SSO without a complete IdP configuration."
            )
            recommendations.append(
                "Complete the SSO IdP setup (SAML metadata, entityId, sign-in URL, certificate) "
                "in the SentinelOne management console under Settings > SSO."
            )

    return create_response(
        result={
            "isSSOEnabled": is_enabled,
            "ssoEnabled": sso_enabled,
            "idpEntityId": idp_entity_id,
            "idpSsoUrl": idp_sso_url,
            "idpCertName": idp_cert_name,
            "ssoDomains": sso_domains,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "isSSOEnabled": is_enabled,
            "ssoEnabled": sso_enabled,
            "idpConfigured": has_idp,
            "ssoDomains": sso_domains,
        },
        metadata={
            "transformationId": "isSSOEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
