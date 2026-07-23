"""
Transformation: isAdminMFAPhishingResistant
Vendor: Microsoft
Category: Identity / Secure Score

Evaluates admin MFA protection using the AdminMFAV2 Microsoft Secure Score control.
"""

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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
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
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isAdminMFAPhishingResistant",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def parse_api_error(raw_error, source=None):
    raw_error = raw_error or ""
    raw_lower = raw_error.lower()
    src = source or "external service"

    if "401" in raw_error:
        return (
            f"Could not connect to {src}: Authentication failed (HTTP 401)",
            f"Verify {src} credentials and permissions are valid",
        )
    elif "403" in raw_error:
        return (
            f"Could not connect to {src}: Access denied (HTTP 403)",
            f"Verify the integration has required {src} permissions",
        )
    elif "404" in raw_error:
        return (
            f"Could not connect to {src}: Resource not found (HTTP 404)",
            f"Verify the {src} resource and configuration exist",
        )
    elif "429" in raw_error:
        return (
            f"Could not connect to {src}: Rate limited (HTTP 429)",
            "Retry the request after waiting",
        )
    elif "500" in raw_error or "502" in raw_error or "503" in raw_error:
        return (
            f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
            f"{src} may be temporarily unavailable, retry later",
        )
    elif "timeout" in raw_lower:
        return (
            f"Could not connect to {src}: Request timed out",
            "Check network connectivity and retry",
        )
    elif "connection" in raw_lower:
        return (
            f"Could not connect to {src}: Connection failed",
            "Check network connectivity and firewall settings",
        )
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (
            f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration",
        )


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_number(value, default=0):
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            number = float(value)
            return int(number) if number.is_integer() else number
        except ValueError:
            return default
    return default


def transform(input):
    criteriaKey = "isAdminMFAPhishingResistant"
    controlName = "AdminMFAV2"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return create_response(
                result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
                validation=validation,
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if "PSError" in data:
            api_error, recommendation = parse_api_error(data.get("PSError", ""), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        score_in_percentage = 0.0
        count = 0
        total = 0
        is_resistant = False

        # AdminMFAV2 verifies admin MFA registration, not strict phishing-resistance; a stricter
        # check would need the authenticationMethodsPolicy feed.
        values = _as_list(data.get("value") or [])
        if len(values) > 0:
            secure_score = values[0] if isinstance(values[0], dict) else {}
            control_scores = _as_list(secure_score.get("controlScores") or [])
            matched = [
                entry for entry in control_scores
                if isinstance(entry, dict) and entry.get("controlName") == controlName
            ]

            if len(matched) > 1:
                fail_reasons.append(
                    f"Ambiguous data: {len(matched)} objects match controlName '{controlName}'"
                )
                return create_response(
                    result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
                    validation=validation,
                    fail_reasons=fail_reasons,
                    recommendations=["Check Microsoft Secure Score data for duplicate control entries"]
                )
            elif len(matched) == 1:
                matched_obj = matched[0]
                score_in_percentage = _as_number(matched_obj.get("scoreInPercentage"), 0.0)
                is_resistant = score_in_percentage == 100.00

                count = _as_number(matched_obj.get("count"), 0)
                total = _as_number(matched_obj.get("total"), 0)

                if is_resistant:
                    pass_reasons.append(f"Admin MFA control '{controlName}' is fully satisfied (score: 100%)")
                else:
                    fail_reasons.append(f"Admin MFA control '{controlName}' score is {score_in_percentage}%")
                    recommendations.append("Require MFA for all administrative role members")
            else:
                fail_reasons.append(f"Control '{controlName}' not found in Secure Score data")
                recommendations.append("Verify Microsoft Secure Score is collecting admin MFA data")
        else:
            fail_reasons.append("Microsoft Secure Score data not available - verify API permissions")
            recommendations.append("Verify the Microsoft Graph API integration is returning Secure Score data")

        return create_response(
            result={
                criteriaKey: is_resistant,
                "scoreInPercentage": score_in_percentage,
                "count": count,
                "total": total,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "hasSecureScoreData": len(values) > 0,
                "scoreInPercentage": score_in_percentage,
                "protectedCount": count,
                "totalCount": total,
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "scoreInPercentage": 0.0, "count": 0, "total": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
