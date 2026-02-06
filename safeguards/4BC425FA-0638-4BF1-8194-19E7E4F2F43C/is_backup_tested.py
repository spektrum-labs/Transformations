"""
Transformation: isBackupTested
Vendor: AWS
Category: Backups / Compliance

Checks whether any backups have been tested via restore operations.
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
    """
    Create standardized transformation response.

    Args:
        result: The transformed result dict (e.g., {criteriaKey: True/False})
        validation: Schema validation result from extract_input (status, errors, warnings)
        pass_reasons: List of reasons why the criteria passed
        fail_reasons: List of reasons why the criteria failed
        recommendations: List of actionable recommendations
        input_summary: Summary of input data processed
        transformation_errors: List of transformation execution errors (separate from validation)
    """
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
                "transformationId": "isBackupTested",
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


def transform(input):
    criteriaKey = "isBackupTested"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Navigate to resource members in CloudTrail events
        # Use `or {}` to handle both missing keys AND null values from API
        api_response = data.get("apiResponse", data) if isinstance(data, dict) else {}
        lookup_response = api_response.get("LookupEventsResponse") or {}
        lookup_result = lookup_response.get("LookupEventsResult") or {}
        events = lookup_result.get("Events") or {}
        member = events.get("member") or {}
        resources = member.get("Resources") or {}
        resource_members = resources.get("member") or []

        if isinstance(resource_members, dict):
            resource_members = [resource_members]

        # Check if any event is a DBInstance restore operation
        is_backup_tested = False
        restore_events = []
        for resource_member in resource_members:
            resource_type = resource_member.get("ResourceType", "")
            if "dbinstance" in resource_type.lower():
                is_backup_tested = True
                restore_events.append(resource_type)

        if is_backup_tested:
            pass_reasons.append(f"Backup restore test detected ({len(restore_events)} DB restore events found)")
        else:
            fail_reasons.append("No backup restore tests found in audit logs")
            recommendations.append("Perform periodic backup restore tests to verify backup integrity")

        return create_response(
            result={criteriaKey: is_backup_tested},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "restoreEventsFound": len(restore_events),
                "hasCloudTrailData": bool(lookup_response)
            }
        )

    except Exception as e:
        # Separate transformation errors from validation errors
        # - validationErrors: Schema validation issues (from Pydantic)
        # - transformationErrors: Runtime execution errors in transformation logic
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
