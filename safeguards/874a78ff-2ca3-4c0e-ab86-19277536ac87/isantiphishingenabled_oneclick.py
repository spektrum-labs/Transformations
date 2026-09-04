"""
Transformation: isAntiPhishingEnabled (Microsoft One-Click)
Vendor: Microsoft
Category: Email Security

Evaluates whether anti-phishing policies are enabled and reports the optional
Exchange-access prerequisite precisely for the Microsoft One-Click flow.
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from enriched and legacy input shapes."""
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
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "transformationId": "isAntiPhishingEnabled",
        "vendor": "Microsoft",
        "category": "Email Security",
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or [],
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
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


def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse a raw API error into the existing generic error contract."""
    raw_lower = raw_error.lower() if raw_error else ""
    src = source or "external service"

    if "401" in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    if "403" in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    if "404" in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    if "429" in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    if "500" in raw_error or "502" in raw_error or "503" in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    if "timeout" in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    if "connection" in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")

    clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
    return (f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration")


def is_exchange_access_required_error(raw_error):
    """Identify the EXO app-only role failure returned before Exchange completion."""
    raw_lower = str(raw_error or "").lower()
    return (
        "failed to connect to exchange online" in raw_lower
        and "exo app-only authentication" in raw_lower
    )


def transform(input):
    """Evaluate whether anti-phishing policies are enabled in Microsoft 365."""
    criteria_key = "isAntiPhishingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if isinstance(data, dict) and "PSError" in data:
            raw_error = data.get("PSError", "")
            api_error, recommendation = parse_api_error(raw_error, source="Microsoft 365")
            fail_reason = "Could not retrieve data from Microsoft 365"

            if is_exchange_access_required_error(raw_error):
                fail_reason = "Exchange access is required for this check."
                recommendation = (
                    "Complete Exchange access in Microsoft One-Click, "
                    "then re-evaluate this check."
                )

            return create_response(
                result={criteria_key: False},
                validation={"status": "unknown", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=[fail_reason],
                recommendations=[recommendation],
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"],
            )

        policies = data.get("policies", [])
        if isinstance(policies, dict):
            policies = [policies]

        try:
            enabled_policies = [
                policy for policy in policies
                if str(policy.get("Enabled", "false")).lower() == "true"
                or str(policy.get("IsDefault", "false")).lower() == "true"
            ]
        except Exception:
            enabled_policies = []

        is_enabled = len(enabled_policies) > 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if is_enabled:
            policy_names = [
                policy.get("Name", policy.get("Identity", "unnamed"))
                for policy in enabled_policies[:5]
            ]
            pass_reasons.append(
                f"{len(enabled_policies)} anti-phishing policy/policies enabled: "
                f"{', '.join(policy_names)}"
            )
        else:
            fail_reasons.append("No anti-phishing policies are enabled")
            recommendations.append("Enable anti-phishing policies in Microsoft Defender for Office 365")

        return create_response(
            result={criteria_key: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalPolicies": len(policies),
                "enabledPolicies": len(enabled_policies),
                "hasPolicyData": len(policies) > 0,
            },
        )

    except json.JSONDecodeError as error:
        return create_response(
            result={criteria_key: False},
            validation={"status": "unknown", "errors": [f"Invalid JSON: {str(error)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"],
        )
    except Exception as error:
        return create_response(
            result={criteria_key: False},
            validation={"status": "unknown", "errors": [], "warnings": []},
            transformation_errors=[str(error)],
            fail_reasons=[f"Transformation error: {str(error)}"],
        )
