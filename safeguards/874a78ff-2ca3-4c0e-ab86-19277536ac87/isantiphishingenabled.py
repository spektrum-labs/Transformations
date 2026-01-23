"""
Transformation: isAntiPhishingEnabled
Vendor: Microsoft
Category: Email Security

Evaluates if anti-phishing policies are enabled in Microsoft 365.
"""

import json
from datetime import datetime


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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
        "transformationId": "isAntiPhishingEnabled",
        "vendor": "Microsoft",
        "category": "Email Security"
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
    Evaluates if anti-phishing policies are enabled in Microsoft 365.

    Parameters:
        input: Either enriched format {"data": {...}, "validation": {...}}
               or legacy format (raw API response)

    Returns:
        dict: Standardized response with transformedResponse and additionalInfo
    """
    criteriaKey = "isAntiPhishingEnabled"

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
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Get policies from data
        policies = data.get('policies', [])
        if isinstance(policies, dict):
            policies = [policies]

        # Find enabled or default policies
        try:
            enabled_policies = [
                policy for policy in policies
                if str(policy.get("Enabled", "false")).lower() == "true" or
                   str(policy.get("IsDefault", "false")).lower() == "true"
            ]
        except Exception:
            enabled_policies = []

        is_enabled = len(enabled_policies) > 0

        if is_enabled:
            policy_names = [p.get("Name", p.get("Identity", "unnamed")) for p in enabled_policies[:5]]
            pass_reasons.append(f"{len(enabled_policies)} anti-phishing policy/policies enabled: {', '.join(policy_names)}")
        else:
            fail_reasons.append("No anti-phishing policies are enabled")
            recommendations.append("Enable anti-phishing policies in Microsoft Defender for Office 365")

        result = {
            criteriaKey: is_enabled,
            "policyDetails": enabled_policies
        }

        input_summary = {
            "totalPolicies": len(policies),
            "enabledPolicies": len(enabled_policies),
            "hasPolicyData": len(policies) > 0
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
