"""
Transformation: isSafeAttachmentsEnabled
Vendor: Microsoft
Category: Email Security / Secure Score

Evaluates if Safe Attachments is enabled based on Microsoft Secure Score.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSafeAttachmentsEnabled", "vendor": "Microsoft", "category": "Email Security"}
        }
    }


def parse_api_error(raw_error, source=None):
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
        clean = (raw_error[0:80] + "...") if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

def transform(input):
    """
    Evaluates if Safe Attachments is enabled based on Microsoft Secure Score.

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    criteriaKey = "isSafeAttachmentsEnabled"
    controlName = "mdo_safeattachmentpolicy"
    enablementControlName = "mdo_safeattachments"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

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


        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        score_in_percentage = 0.0
        count = 0
        total = 0
        is_enabled = False
        enablement_score = 0.0
        enablement_count = 0
        enablement_total = 0

        # Process Secure Score data
        values = data.get("value", [])
        if len(values) > 0:
            control_scores = values[0].get("controlScores", [])

            # Look up the enablement control (mdo_safeattachments)
            enablement_list = [i for i in control_scores if i.get('controlName') == enablementControlName]
            if len(enablement_list) == 1:
                enablement_obj = enablement_list[0]
                enablement_score = enablement_obj.get("scoreInPercentage", 0.0)
                raw_en_count = enablement_obj.get("count", 0)
                raw_en_total = enablement_obj.get("total", 0)
                enablement_count = int(raw_en_count) if isinstance(raw_en_count, str) else raw_en_count
                enablement_total = int(raw_en_total) if isinstance(raw_en_total, str) else raw_en_total

                if enablement_score == 100.00:
                    additional_findings.append(f"Safe Attachments is enabled for all users ({enablement_count}/{enablement_total})")
                else:
                    additional_findings.append(f"Safe Attachments enablement is at {enablement_score}% ({enablement_count}/{enablement_total} users)")

            # Look up the policy control (mdo_safeattachmentpolicy)
            matched_object_list = [i for i in control_scores if i.get('controlName') == controlName]

            if len(matched_object_list) > 1:
                fail_reasons.append(f"Ambiguous data: {len(matched_object_list)} objects match controlName '{controlName}'")
                return create_response(
                    result={criteriaKey: enablement_score == 100.00},
                    validation=validation,
                    fail_reasons=fail_reasons,
                    recommendations=["Check Microsoft Secure Score data for duplicate control entries"],
                    additional_findings=additional_findings
                )
            elif len(matched_object_list) == 1:
                matched_object = matched_object_list[0]

                score_in_percentage = matched_object.get("scoreInPercentage", 0.0)

                raw_count = matched_object.get("count", 0)
                raw_total = matched_object.get("total", 0)
                count = int(raw_count) if isinstance(raw_count, str) else raw_count
                total = int(raw_total) if isinstance(raw_total, str) else raw_total

                if score_in_percentage == 100.00:
                    additional_findings.append(f"Safe Attachments policy is fully configured (score: 100%)")
                else:
                    additional_findings.append(f"Safe Attachments policy score is {score_in_percentage}% ({count}/{total} users securely configured)")
                    recommendations.append("Configure Safe Attachments policy to use Block mode in Microsoft Defender for Office 365")
            else:
                fail_reasons.append(f"No control found matching '{controlName}' in Secure Score data")
                recommendations.append("Verify Microsoft Secure Score is collecting Safe Attachments data")
        else:
            fail_reasons.append("Microsoft Secure Score data not available - verify API permissions")
            recommendations.append("Verify the Microsoft Graph API integration is returning Secure Score data")

        # Pass if either enablement or policy score is 100%
        is_enabled = enablement_score == 100.00 or score_in_percentage == 100.00

        if is_enabled:
            pass_reasons.append("Safe Attachments is enabled (enablement score: " + str(enablement_score) + "%, policy score: " + str(score_in_percentage) + "%)")
        else:
            fail_reasons.append("Safe Attachments is not fully enabled (enablement score: " + str(enablement_score) + "%, policy score: " + str(score_in_percentage) + "%)")

        result = {
            criteriaKey: is_enabled,
            "scoreInPercentage": score_in_percentage,
            "count": count,
            "total": total,
            "enablementScoreInPercentage": enablement_score,
            "enablementCount": enablement_count,
            "enablementTotal": enablement_total
        }

        input_summary = {
            "hasSecureScoreData": len(values) > 0,
            "policyScoreInPercentage": score_in_percentage,
            "policyProtectedCount": count,
            "policyTotalCount": total,
            "enablementScoreInPercentage": enablement_score,
            "enablementProtectedCount": enablement_count,
            "enablementTotalCount": enablement_total
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
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
