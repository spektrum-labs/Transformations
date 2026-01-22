"""
Transformation: areAccessReviewsConfigured
Vendor: Microsoft
Category: Identity Governance

Evaluates if access reviews are configured in Azure AD.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "areAccessReviewsConfigured",
                "vendor": "Microsoft",
                "category": "Identity Governance"
            }
        }
    }


def transform(input):
    criteriaKey = "areAccessReviewsConfigured"

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
            inner_error = error_info.get('innerError', {})
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": [error_info.get('message', 'API error')], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get('code'), "innerErrorCode": inner_error.get('code') if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        reviews = data.get('value', [])
        if not isinstance(reviews, list):
            reviews = [reviews] if reviews else []

        is_configured = len(reviews) > 0

        if is_configured:
            pass_reasons.append(f"Access reviews configured: {len(reviews)} review definition(s) found")
        else:
            fail_reasons.append("No access reviews configured")
            recommendations.append("Configure access reviews in Azure AD Identity Governance")

        return create_response(
            result={criteriaKey: is_configured, "reviewCount": len(reviews)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"reviewCount": len(reviews)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
