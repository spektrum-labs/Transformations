
"""
Transformation: isAdminMFAPhishingResistant
Checks whether phish-resistant MFA factor types (FIDO2/WebAuthn, FIDO U2F hardware)
are ACTIVE at the Okta org level — a necessary gate condition for admins to use
phish-resistant MFA.
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


# Factor types and provider combinations considered phish-resistant
PHISH_RESISTANT_TYPES = ["webauthn"]
PHISH_RESISTANT_COMBOS = [("token:hardware", "FIDO")]


def transform(input):
    data, validation = extract_input(input)

    # Handle plain list (raw API returns array), dict wrapper, or empty input
    if isinstance(data, list):
        factors = data
    elif isinstance(data, dict):
        factors = data.get("apiResponse") or data.get("factors") or []
    else:
        factors = []

    if not isinstance(factors, list):
        factors = []

    total_factors = len(factors)
    active_phish_resistant = []
    all_active_labels = []
    transformation_errors = []

    for factor in factors:
        if not isinstance(factor, dict):
            continue
        factor_type = factor.get("factorType") or ""
        provider = factor.get("provider") or ""
        status = factor.get("status") or ""
        label = f"{factor_type}/{provider}"

        if status == "ACTIVE":
            all_active_labels.append(label)

        is_pr = False
        if factor_type in PHISH_RESISTANT_TYPES and status == "ACTIVE":
            is_pr = True
        for pr_type, pr_provider in PHISH_RESISTANT_COMBOS:
            if factor_type == pr_type and provider == pr_provider and status == "ACTIVE":
                is_pr = True

        if is_pr:
            active_phish_resistant.append(label)

    has_phish_resistant = len(active_phish_resistant) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if total_factors == 0:
        transformation_errors.append(
            "No factor entries returned by listOrgFactors — cannot determine phish-resistant MFA status."
        )

    if has_phish_resistant:
        active_list = ", ".join(active_phish_resistant)
        pass_reasons.append(
            f"The following phish-resistant factor type(s) are ACTIVE at the org level: "
            f"{active_list}. FIDO2/WebAuthn or hardware FIDO keys are available for admin enrollment, "
            f"satisfying the phish-resistant MFA gate condition."
        )
    else:
        active_str = ", ".join(all_active_labels) if all_active_labels else "none"
        fail_reasons.append(
            f"No phish-resistant factor types (webauthn/FIDO2 or token:hardware/FIDO) are ACTIVE "
            f"at the org level. Inspected {total_factors} org factor(s); currently active types: "
            f"{active_str}. Admins cannot enroll phish-resistant MFA when no qualifying factor is enabled."
        )
        recommendations.append(
            "Enable FIDO2 WebAuthn (passkeys) in Security > Multifactor > Factor Types, "
            "set its status to ACTIVE, and enforce it on admin sign-on policy rules via "
            "an authenticator constraint targeting privileged groups."
        )
        if all_active_labels:
            active_str2 = ", ".join(all_active_labels)
            additional_findings.append(
                f"Active factor types detected: {active_str2}. These are phishable (SMS OTP, "
                f"TOTP, email OTP, and standard push notifications are susceptible to real-time "
                f"phishing proxies). Only FIDO2/WebAuthn and hardware FIDO U2F keys qualify as "
                f"phish-resistant under NIST SP 800-63B AAL3 and CISA phishing-resistant MFA guidance."
            )

    return create_response(
        result={
            "isAdminMFAPhishingResistant": has_phish_resistant,
            "activePhishResistantFactors": active_phish_resistant,
            "totalOrgFactors": total_factors,
            "activeFactorTypes": all_active_labels,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        transformation_errors=transformation_errors if transformation_errors else None,
        input_summary={
            "totalFactors": total_factors,
            "activePhishResistantCount": len(active_phish_resistant),
            "activeFactorCount": len(all_active_labels),
        },
        metadata={
            "transformationId": "isAdminMFAPhishingResistant",
            "vendor": "Okta",
            "category": "iam",
        },
    )
