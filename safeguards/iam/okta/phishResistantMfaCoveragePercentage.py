"""
Transformation: phishResistantMfaCoveragePercentage
Vendor: Okta
Category: iam
Method: listUsers

Computes the percentage of active users with detectable phish-resistant MFA
(FIDO2/WebAuthn, Okta FastPass/signed_nonce, hardware tokens) from the listUsers
response. Note: Okta's /api/v1/users endpoint returns minimal credentials data;
full per-user factor enrollment requires listUserFactors. This transform inspects
credentials.authenticators where available and reports coverage with appropriate
data-limitation notes.
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


# Okta factor/authenticator types that qualify as phish-resistant:
# - webauthn: FIDO2 hardware security keys and passkeys
# - signed_nonce: Okta FastPass (device-bound, phish-resistant)
# - token:hardware: FIDO U2F / hardware OTP tokens (phish-resistant variants)
# - u2f: legacy FIDO U2F
PHISH_RESISTANT_TYPES = {"webauthn", "signed_nonce", "token:hardware", "u2f"}

# Active-equivalent statuses in Okta (users who can log in and need MFA)
ACTIVE_STATUSES = {"ACTIVE", "PASSWORD_EXPIRED", "RECOVERY", "LOCKED_OUT"}


def check_phish_resistant_creds(user):
    """
    Inspect a user's credentials object for phish-resistant factor indicators.
    Returns True if a phish-resistant authenticator type is detected.
    """
    creds = user.get("credentials")
    if not isinstance(creds, dict):
        return False

    # Check credentials.authenticators (present in some Okta API versions)
    authenticators = creds.get("authenticators")
    if isinstance(authenticators, list):
        for auth in authenticators:
            if isinstance(auth, dict):
                atype = (auth.get("type") or "").lower()
                if atype in PHISH_RESISTANT_TYPES:
                    return True

    # Check credentials.factors (alternate shape in some tenants)
    factors = creds.get("factors")
    if isinstance(factors, list):
        for factor in factors:
            if isinstance(factor, dict):
                ftype = (factor.get("factorType") or "").lower()
                fstatus = (factor.get("status") or "").upper()
                if ftype in PHISH_RESISTANT_TYPES and fstatus == "ACTIVE":
                    return True
                if ftype == "webauthn" and fstatus == "ACTIVE":
                    return True
                if ftype == "signed_nonce" and fstatus == "ACTIVE":
                    return True

    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    # listUsers returns apiResponse as a top-level list; extract_input does not unwrap lists
    users = data.get("apiResponse")
    if not isinstance(users, list):
        users = data.get("data")
        if not isinstance(users, list):
            users = []

    total_in_response = len(users)

    # Separate active from non-active users
    active_users = [
        u for u in users
        if isinstance(u, dict) and u.get("status") in ACTIVE_STATUSES
    ]
    non_active_users = [
        u for u in users
        if isinstance(u, dict) and u.get("status") not in ACTIVE_STATUSES
    ]
    total_active = len(active_users)
    total_non_active = len(non_active_users)

    # Count users with detectable phish-resistant MFA
    phish_resistant_count = 0
    no_creds_count = 0
    for user in active_users:
        if check_phish_resistant_creds(user):
            phish_resistant_count = phish_resistant_count + 1
        creds = user.get("credentials")
        if not isinstance(creds, dict):
            no_creds_count = no_creds_count + 1

    # Compute coverage percentage
    if total_active == 0:
        coverage_pct = 0.0
    else:
        coverage_pct = round((phish_resistant_count / total_active) * 100, 2)

    # Build human-readable evaluation reasons
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    # Data limitation note — listUsers doesn't expose full factor enrollment
    additional_findings.append(
        "Data limitation: Okta's /api/v1/users endpoint returns minimal credentials "
        "data and does not expose per-user MFA factor enrollment. Phish-resistant "
        "coverage is computed from credentials.authenticators / credentials.factors "
        "fields where present. For authoritative coverage, per-user factor enumeration "
        "via /api/v1/users/{userId}/factors is required. Coverage may be underreported "
        "if credentials fields are absent or redacted."
    )

    if no_creds_count > 0:
        additional_findings.append(
            f"{no_creds_count} of {total_active} active users had no 'credentials' object "
            "in the response (likely redacted or unpopulated). Those users are counted "
            "as not having phish-resistant MFA."
        )

    if total_non_active > 0:
        additional_findings.append(
            f"{total_non_active} non-active user(s) (SUSPENDED / DEPROVISIONED / STAGED) "
            "were excluded from coverage calculation."
        )

    if total_active == 0:
        fail_reasons.append(
            "No active users found in the listUsers response. Cannot compute "
            "phish-resistant MFA coverage."
        )
    elif coverage_pct >= 95.0:
        pass_reasons.append(
            f"{phish_resistant_count} of {total_active} active users ({coverage_pct}%) "
            "have phish-resistant MFA credentials detected in their user object "
            "(webauthn/FIDO2, signed_nonce/Okta FastPass, or hardware token types). "
            "Coverage meets the >=95% threshold."
        )
    else:
        missing = total_active - phish_resistant_count
        fail_reasons.append(
            f"Only {phish_resistant_count} of {total_active} active users ({coverage_pct}%) "
            "have detectable phish-resistant MFA credentials. "
            f"{missing} active user(s) are missing phish-resistant MFA enrollment, "
            "falling below the required 95% threshold."
        )
        recommendations.append(
            "Enroll all active users in a phish-resistant authenticator: FIDO2 hardware "
            "security keys, passkeys (WebAuthn), or Okta FastPass (device-bound). "
            "Update Okta authenticator enrollment policies to mandate phish-resistant "
            "authenticators and block SMS, voice, and email-only MFA. Review users "
            "flagged as missing phish-resistant MFA via /api/v1/users/{userId}/factors."
        )

    return create_response(
        result={
            "phishResistantMfaCoveragePercentage": coverage_pct,
            "totalActiveUsers": total_active,
            "phishResistantMfaUsers": phish_resistant_count,
            "usersLackingPhishResistantMfa": total_active - phish_resistant_count,
            "totalUsersInResponse": total_in_response,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalUsersInResponse": total_in_response,
            "totalActiveUsers": total_active,
            "totalNonActiveUsers": total_non_active,
            "phishResistantMfaDetected": phish_resistant_count,
            "usersWithoutCredentialsData": no_creds_count,
        },
        additional_findings=additional_findings,
        metadata={
            "transformationId": "phishResistantMfaCoveragePercentage",
            "vendor": "Okta",
            "category": "iam",
        },
    )
