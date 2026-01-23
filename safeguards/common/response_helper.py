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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None, transformation_errors=None):
    """
    Create a standardized transformation response.

    All transformations should return this structure for consistency.

    Args:
        result: dict - The transformed response (e.g., {"isBackupEnabled": True})
        validation: dict - Validation result from schema validation
            {
                "status": "passed" | "failed" | "skipped" | "unknown",
                "errors": ["error messages"],
                "warnings": ["warning messages"]
            }
        pass_reasons: list[str] - Human-readable reasons why criteria passed
        fail_reasons: list[str] - Human-readable reasons why criteria failed
        recommendations: list[str] - Actionable recommendations for improvement
        input_summary: dict - Summary of what was found in the input data
        metadata: dict - Additional metadata to include

    Returns:
        dict: Standardized response structure

    Example:
        return create_response(
            result={"isBackupEnabled": True, "backupCount": 5},
            validation=validation,
            pass_reasons=["5 automated backups configured", "Retention >= 7 days"],
            recommendations=["Consider enabling cross-region replication"],
            input_summary={"automatedBackups": 5, "manualSnapshots": 2}
        )
    """
    # Default validation if not provided
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    # Build metadata
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "1.0"
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
