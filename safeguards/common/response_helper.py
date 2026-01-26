"""
Response helper for standardized transformation outputs.

This module provides utilities for creating consistent transformation responses
with rich context including validation status, pass/fail reasons, and recommendations.

Works within RestrictedPython sandbox (only uses allowed stdlib imports).
"""

from datetime import datetime


def extract_input(input_data):
    """
    Extract data and validation from input, handling both new and legacy formats.

    New format (enriched):
        {
            "data": { ... actual API response ... },
            "validation": { "status": "passed", "errors": [], "warnings": [] }
        }

    Legacy format (raw):
        { ... actual API response ... }
        or wrapped in response/result/apiResponse

    Args:
        input_data: Raw input passed to transform function

    Returns:
        tuple: (data: dict, validation: dict)

    Example:
        def transform(input):
            data, validation = extract_input(input)
            if validation["status"] == "failed":
                return create_response(
                    result={"criteriaKey": False},
                    validation=validation,
                    fail_reasons=validation["errors"]
                )
            # Continue with business logic using data...
    """
    # Check if new enriched format
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    # Legacy format - unwrap common response wrappers
    data = input_data
    if isinstance(data, dict):
        # Handle nested wrappers (e.g., api_response.result)
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

    # Return with unknown validation status
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }

    return data, validation


def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """
    Parse a raw API error message and return a clean, factual error and recommendation.

    Args:
        raw_error: Raw error string from API (e.g., PSError)
        source: Name of the external system (e.g., "Microsoft 365", "AWS", "Okta")

    Returns:
        tuple: (clean_error: str, recommendation: str)

    Example:
        raw = "OAuth token request failed: Response status code does not indicate success: 401 (Unauthorized)."
        error, rec = parse_api_error(raw, source="Microsoft 365")
        # error = "Could not connect to Microsoft 365: Authentication failed (HTTP 401)"
        # rec = "Verify Microsoft 365 credentials and permissions are valid"
    """
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (
            f"Could not connect to {src}: Authentication failed (HTTP 401)",
            f"Verify {src} credentials and permissions are valid"
        )
    elif '403' in raw_error:
        return (
            f"Could not connect to {src}: Access denied (HTTP 403)",
            f"Verify the integration has required {src} permissions"
        )
    elif '404' in raw_error:
        return (
            f"Could not connect to {src}: Resource not found (HTTP 404)",
            f"Verify the {src} resource and configuration exist"
        )
    elif '429' in raw_error:
        return (
            f"Could not connect to {src}: Rate limited (HTTP 429)",
            "Retry the request after waiting"
        )
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (
            f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
            f"{src} may be temporarily unavailable, retry later"
        )
    elif 'timeout' in raw_lower:
        return (
            f"Could not connect to {src}: Request timed out",
            "Check network connectivity and retry"
        )
    elif 'connection' in raw_lower:
        return (
            f"Could not connect to {src}: Connection failed",
            "Check network connectivity and firewall settings"
        )
    elif 'certificate' in raw_lower or 'ssl' in raw_lower:
        return (
            f"Could not connect to {src}: SSL/Certificate error",
            "Verify SSL certificates are valid and trusted"
        )
    else:
        # Truncate long errors
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (
            f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration"
        )


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """
    Create a standardized transformation response with nested pipeline stages.

    All transformations should return this structure for consistency.
    The response is organized by pipeline stages: dataCollection → validation → transformation → evaluation

    Args:
        result: dict - The transformed response (e.g., {"isBackupEnabled": True})
        validation: dict - Validation result from schema validation
            {
                "status": "passed" | "failed" | "skipped" | "unknown",
                "errors": ["error messages"],
                "warnings": ["warning messages"]
            }
        pass_reasons: list[str] - Human-readable reasons why the primary criteria passed
        fail_reasons: list[str] - Human-readable reasons why the primary criteria failed
        recommendations: list[str] - Actionable recommendations for improvement
        input_summary: dict - Summary of what was found in the input data
        metadata: dict - Additional metadata to include
        transformation_errors: list[str] - Runtime errors during transformation
        api_errors: list[str] - API-level errors (OAuth, connectivity, etc.)
        additional_findings: list[dict] - Additional insights about related metrics
            Each finding should have:
            {
                "metric": "metricName",
                "status": "pass" | "fail",
                "reason": "Human-readable explanation",
                "recommendation": "Optional action item" (for fail status)
            }

    Returns:
        dict: Standardized response structure organized by pipeline stages

    Example:
        return create_response(
            result={"isBackupEnabled": True, "backupCount": 5},
            validation=validation,
            pass_reasons=["5 automated backups configured"],
            recommendations=["Consider enabling cross-region replication"],
            input_summary={"automatedBackups": 5, "manualSnapshots": 2},
            additional_findings=[
                {"metric": "isBackupEncrypted", "status": "pass", "reason": "All backups encrypted"},
                {"metric": "isBackupTested", "status": "fail", "reason": "No restore tests found",
                 "recommendation": "Schedule regular restore tests"}
            ]
        )
    """
    # Default validation if not provided
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    # Determine stage statuses
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []

    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"

    # Build metadata
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0"
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": data_collection_status,
                "errors": api_err_list
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
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
