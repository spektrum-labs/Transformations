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


def is_webauthn_enrolled(user):
    """Check JumpCloud's documented mfaEnrollment.webAuthnStatus field for enrollment.
    Observed values: 'ENROLLED', 'NOT_ENROLLED'. Any other status string is treated
    as not enrolled unless it explicitly equals 'ENROLLED'.
    """
    mfa_enrollment = user.get("mfaEnrollment")
    if isinstance(mfa_enrollment, dict):
        status = mfa_enrollment.get("webAuthnStatus")
        if isinstance(status, str):
            status_upper = status.strip().upper()
            if status_upper == "ENROLLED":
                return True
            if status_upper in ("NOT_ENROLLED", "DISABLED", "NONE", ""):
                return False
    # Fallback: some tenants may expose a boolean flag under mfa.webAuthn (or similarly named key).
    mfa_obj = user.get("mfa")
    if isinstance(mfa_obj, dict):
        for k, v in mfa_obj.items():
            key_lower = str(k).lower()
            if "webauthn" in key_lower or "fido" in key_lower or "securitykey" in key_lower:
                if isinstance(v, bool):
                    return v
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
        total_count = len(items)
    else:
        items = data.get("results") or data.get("data") or []
        if not isinstance(items, list):
            items = []
        total_count = data.get("totalCount")
        if not isinstance(total_count, int) or total_count <= 0:
            total_count = len(items)

    webauthn_users = []
    for user in items:
        if not isinstance(user, dict):
            continue
        if is_webauthn_enrolled(user):
            webauthn_users.append(user.get("username") or user.get("email") or user.get("_id") or "unknown")

    webauthn_count = len(webauthn_users)

    # denominator scope: totalCount reflects the fleet-wide user count from the same
    # envelope; pagination.follow=true means items should ultimately cover the full
    # fleet, keeping numerator and denominator in the same scope.
    denominator = total_count if total_count and total_count > 0 else len(items)

    if denominator > 0:
        percentage = round((webauthn_count / denominator) * 100.0, 2)
    else:
        percentage = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if denominator == 0:
        fail_reasons.append("No system users were returned by listSystemUsers; WebAuthn adoption cannot be evaluated.")
        recommendations.append("Verify the JumpCloud API key has access to systemusers and that the org has users provisioned.")
    elif webauthn_count == 0:
        fail_reasons.append(
            f"None of the {denominator} system users examined have mfaEnrollment.webAuthnStatus='ENROLLED'."
        )
        recommendations.append(
            "Encourage or enforce WebAuthn (security key / platform authenticator) enrollment for JumpCloud user portal accounts to improve phishing-resistant MFA adoption."
        )
    else:
        pass_reasons.append(
            f"{webauthn_count} of {denominator} system users ({percentage}%) have mfaEnrollment.webAuthnStatus='ENROLLED'."
        )
        if percentage < 100.0:
            recommendations.append(
                f"Only {percentage}% of users have WebAuthn configured; consider expanding enforcement to the remaining {denominator - webauthn_count} users."
            )

    result = {
        "webAuthnCredentialAdoptionPercentage": percentage,
        "webAuthnEnrolledUsers": webauthn_count,
        "totalUsers": denominator,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalUsers": denominator, "webAuthnEnrolledUsers": webauthn_count, "usersExamined": len(items)},
        metadata={
            "transformationId": "webAuthnCredentialAdoptionPercentage",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
