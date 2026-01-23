"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft
Category: Identity / Secure Score

Evaluates if MFA is enforced for users based on:
- Microsoft Secure Score controlScores (MFARegistrationV2)
- Authentication method configurations
"""

import json
from datetime import datetime


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
                    recommendations=None, input_summary=None, metadata=None, transformation_errors=None):
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
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": response_metadata
        }
    }


# ============================================================================
# Transformation Logic
# ============================================================================

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
        elif 'authenticationMethodConfigurations' in data:
            mfa_info = {"mfaTypes": []}
            enabled_methods = [
                obj for obj in data['authenticationMethodConfigurations']
                if 'state' in obj and str(obj['state']).lower() == "enabled"
            ]
            mfa_info['mfaTypes'] = enabled_methods

            is_enabled = len(enabled_methods) > 0

            if is_enabled:
                method_names = [m.get('id', 'unknown') for m in enabled_methods[:5]]
                pass_reasons.append(f"{len(enabled_methods)} MFA method(s) enabled: {', '.join(method_names)}")
            else:
                fail_reasons.append("No MFA authentication methods are enabled")
                recommendations.append("Enable at least one MFA authentication method (e.g., Microsoft Authenticator)")

        else:
            fail_reasons.append("No Secure Score or authentication method data found")
            recommendations.append("Verify the Microsoft Graph API integration is returning data")

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
