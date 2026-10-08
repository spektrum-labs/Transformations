"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft
Category: Identity / Secure Score

Evaluates if MFA is enforced for users based on:
- Microsoft Secure Score controlScores (MFARegistrationV2)
- Authentication method configurations

Authentication method configurations (GET /v1.0/policies/authenticationMethodsPolicy):
- Only a strong method counts (STRONG_METHOD_IDS, the same list as mfa/azure/ismfaenforcedforusers.py plus
  hardware OATH tokens). Email one-time passcodes (including the guest-only Email OTP setting), SMS and voice
  are weak factors and never make the key True (J.J., 3 Oct 2026: "no weak factors"). Before 5 Oct 2026 any
  enabled method passed, so a tenant whose only enabled method was Email OTP read True.
- An external authentication method (for example Cisco Duo) with no strong Microsoft method reads not
  evaluated (value None, dataCollection.status "error"): that provider enforces the factor and Entra cannot
  grade it. Same rule as mfa/azure/ismfaenforcedforusers.py.
- No method that targets members (nothing enabled, or only Email OTP with an empty includeTargets list, which
  reaches B2B guests only) reads not evaluated: the methods policy does not govern member sign-in then
  (J.J. 5 Oct, from the 3 Oct rule in mfa/azure/ismfaenforcedforusers.py). Guest Email OTP still fails
  authTypesAllowed.
- Neither Secure Score data nor an authenticationMethodConfigurations list reads not evaluated: a read that
  returned nothing is not evidence either way.
"""

import json
from datetime import datetime

STRONG_METHOD_IDS = ("microsoftauthenticator", "fido2", "softwareoath", "hardwareoath", "temporaryaccesspass")
WEAK_METHOD_IDS = ("email", "sms", "voice")


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    # Check if new enriched format
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    # Legacy format - unwrap common response wrappers
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):  # Max 3 levels of unwrapping
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
        "warnings": ["Legacy input format - no schema validation performed"]
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None, transformation_errors=None, api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "1.0",
        "transformationId": "isMFAEnforcedForUsers",
        "vendor": "Microsoft",
        "category": "Identity"
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": response_metadata
        }
    }


# ============================================================================
# Transformation Logic
# ============================================================================


def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    """
    Evaluates if MFA is enforced for users based on Microsoft Secure Score
    or authentication method configurations.

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    criteriaKey = "isMFAEnforcedForUsers"
    controlName = "MFARegistrationV2"

    try:
        # Parse input if string/bytes
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        # Extract data and validation (handles both new and legacy formats)
        data, validation = extract_input(input)


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        # Early return if schema validation failed
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"]
            )

        # Initialize tracking
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        mfa_info = None
        score_in_percentage = 0.0
        count = 0
        total = 0
        is_enabled = False

        # ----------------------------------------------------------------
        # Process Secure Score data
        # ----------------------------------------------------------------
        value = data.get("value", [])
        if len(value) > 0:
            control_scores = value[0].get("controlScores", [])
            matched_object_list = [i for i in control_scores if i.get('controlName') == controlName]

            if len(matched_object_list) > 1:
                fail_reasons.append(f"Ambiguous data: {len(matched_object_list)} objects match controlName '{controlName}'")
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=fail_reasons,
                    recommendations=["Check Microsoft Secure Score data for duplicate control entries"]
                )
            elif len(matched_object_list) == 1:
                matched_object = matched_object_list[0]

                # scoreInPercentage must be 100.00 to be considered enforced
                score_in_percentage = matched_object.get("scoreInPercentage", 0.0)
                is_enabled = score_in_percentage == 100.00

                # count = users with MFA configured
                count = matched_object.get("count", 0)
                # total = total users in scope
                total = matched_object.get("total", 0)

                if is_enabled:
                    pass_reasons.append(f"MFA registration score is 100% ({count}/{total} users)")
                else:
                    fail_reasons.append(f"MFA registration score is {score_in_percentage}% ({count}/{total} users)")
                    if total > 0 and count < total:
                        recommendations.append(f"Enable MFA for remaining {total - count} users")
                    else:
                        recommendations.append("Enable MFA registration for all users")
            else:
                fail_reasons.append(f"No control found matching '{controlName}' in Secure Score data")
                recommendations.append("Verify Microsoft Secure Score is collecting MFA data")

        # ----------------------------------------------------------------
        # Fallback: Process authentication method configurations
        # ----------------------------------------------------------------
        elif isinstance(data.get('authenticationMethodConfigurations'), list):
            mfa_info = {"mfaTypes": []}
            strong_methods = []
            weak_names = []
            external_names = []
            guest_only_email = False
            other_enabled = []
            for obj in data['authenticationMethodConfigurations']:
                if not isinstance(obj, dict) or str(obj.get('state') or '').lower() != "enabled":
                    continue
                method_id = str(obj.get('id') or '')
                if "externalauthenticationmethodconfiguration" in str(obj.get('@odata.type') or '').lower():
                    external_names.append(str(obj.get('displayName') or method_id or 'external method')[:60])
                elif method_id.lower() in STRONG_METHOD_IDS:
                    strong_methods.append(obj)
                elif method_id.lower() == "email" and isinstance(obj.get('includeTargets'), list) \
                        and len(obj.get('includeTargets')) == 0:
                    # Email OTP with no include targets reaches B2B guests only, not members. It still
                    # fails authTypesAllowed ("no weak factors"), but it says nothing about member MFA.
                    guest_only_email = True
                elif method_id.lower() in WEAK_METHOD_IDS:
                    weak_names.append(method_id)
                else:
                    other_enabled.append(method_id)
            mfa_info['mfaTypes'] = strong_methods
            if guest_only_email:
                mfa_info['guestOnlyEmail'] = True

            is_enabled = len(strong_methods) > 0

            if is_enabled:
                method_names = [m.get('id', 'unknown') for m in strong_methods[:5]]
                pass_reasons.append(f"{len(strong_methods)} strong MFA methods enabled: {', '.join(method_names)}")
            elif external_names:
                return create_response(
                    result={criteriaKey: None, "externalMethodsEnabled": external_names},
                    validation=validation,
                    api_errors=["No Microsoft MFA method is enabled; MFA is provided by an external authentication "
                                "method (" + ", ".join(external_names[:3]) + "), which Microsoft Entra cannot grade"],
                    recommendations=["Answer this check from the external MFA provider's own integration"]
                )
            elif not weak_names and not other_enabled:
                # No method that targets members is enabled (nothing at all, or only guest-only Email OTP).
                # The methods policy is then not what governs member sign-in (per-user MFA, security
                # defaults or Conditional Access may), so this read is not evidence either way.
                return create_response(
                    result={criteriaKey: None, "guestOnlyEmail": guest_only_email},
                    validation=validation,
                    api_errors=["No authentication method that targets members is enabled"
                                + (" (Email one-time passcode is enabled for B2B guests only)" if guest_only_email else "")
                                + ", so the authentication methods policy does not show whether MFA is enforced for users"],
                    recommendations=["Answer this check from Conditional Access or the Microsoft Entra ID integration"]
                )
            else:
                if weak_names:
                    fail_reasons.append("Only weak methods are enabled (" + ", ".join(weak_names) + "): email one-time "
                                        "passcodes, SMS and voice do not count as MFA enforcement")
                else:
                    fail_reasons.append("No strong MFA method is enabled (enabled: " + ", ".join(other_enabled[:5]) + ")")
                recommendations.append("Enable a strong MFA method (Microsoft Authenticator, FIDO2 security keys or "
                                       "OATH tokens) and require it for all users")
            if weak_names:
                mfa_info['weakMethodsEnabled'] = weak_names

        else:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=["MFA configuration data not available: no Secure Score data and no authentication "
                            "methods policy was read"],
                recommendations=["Verify the Microsoft Graph integration has Policy.Read.All and is returning data"]
            )

        # ----------------------------------------------------------------
        # Build result
        # ----------------------------------------------------------------
        result = {
            criteriaKey: is_enabled,
            "scoreInPercentage": score_in_percentage,
            "count": count,
            "total": total
        }
        if mfa_info is not None and 'mfaTypes' in mfa_info:
            result['mfaTypes'] = mfa_info['mfaTypes']
        if mfa_info is not None and 'weakMethodsEnabled' in mfa_info:
            result['weakMethodsEnabled'] = mfa_info['weakMethodsEnabled']

        input_summary = {
            "hasSecureScoreData": len(value) > 0,
            "hasAuthMethodData": 'authenticationMethodConfigurations' in data,
            "scoreInPercentage": score_in_percentage,
            "usersWithMFA": count,
            "totalUsers": total
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except json.JSONDecodeError as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
