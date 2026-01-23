"""
Transformation: isSafeLinksProtectionEnabled
Vendor: Microsoft
Category: Email Security / Secure Score

Evaluates if Safe Links protection is enabled based on Microsoft Secure Score.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
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
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isSafeLinksProtectionEnabled",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isSafeLinksProtectionEnabled"
    controlName = "mdo_safelinksforemail"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Check for API error response
        if 'error' in data:
            error_info = data.get('error', {})
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": [error_info.get('message', 'API error')], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        score_in_percentage = 0.0
        is_enabled = False

        values = data.get("value", [])
        if len(values) > 0:
            control_scores = values[0].get("controlScores", [])
            matched = [i for i in control_scores if i.get('controlName') == controlName]

            if len(matched) == 1:
                score_in_percentage = matched[0].get("scoreInPercentage", 0.0)
                is_enabled = score_in_percentage == 100.00

                if is_enabled:
                    pass_reasons.append("Safe Links protection is fully enabled (score: 100%)")
                else:
                    fail_reasons.append(f"Safe Links protection score is {score_in_percentage}%")
                    recommendations.append("Enable Safe Links for all users in Microsoft Defender")
            else:
                fail_reasons.append(f"Control '{controlName}' not found in Secure Score")
        else:
            fail_reasons.append("No Secure Score data found")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"hasSecureScoreData": len(values) > 0, "scoreInPercentage": score_in_percentage}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
