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

        # Navigate to event list. AWS CloudTrail returns events wrapped in
        # {Events: {member: [...]}}, where `member` may be a list (multiple
        # events) or a single dict (one event). Either shape is valid.
        api_response = data.get("apiResponse", data) if isinstance(data, dict) else {}
        lookup_response = api_response.get("LookupEventsResponse") or {}
        lookup_result = lookup_response.get("LookupEventsResult") or {}
        events_container = lookup_result.get("Events") or {}
        event_members = events_container.get("member") if isinstance(events_container, dict) else events_container
        if event_members is None:
            event_members = []
        if isinstance(event_members, dict):
            event_members = [event_members]
        if not isinstance(event_members, list):
            event_members = []

        # For each event, check if any of its Resources is a DBInstance.
        # Track successful vs errored events separately so the result output
        # can surface the breakdown to reviewers, even though both count
        # toward isBackupTested=true (see boolean comment below).
        successful_restores = []
        failed_restores = []
        for event in event_members:
            if not isinstance(event, dict):
                continue
            # Resources is either a dict-with-member (Query API XML→JSON shape)
            # or a direct list (modern JSON API shape). Handle both.
            resources = event.get("Resources")
            if isinstance(resources, dict):
                resource_members = resources.get("member") or []
            elif isinstance(resources, list):
                resource_members = resources
            else:
                resource_members = []
            if isinstance(resource_members, dict):
                resource_members = [resource_members]
            if not isinstance(resource_members, list):
                resource_members = []

            has_db_instance = False
            for resource_member in resource_members:
                if not isinstance(resource_member, dict):
                    continue
                resource_type = resource_member.get("ResourceType") or ""
                if isinstance(resource_type, str) and "dbinstance" in resource_type.lower():
                    has_db_instance = True
                    break

            if not has_db_instance:
                continue

            # Inspect CloudTrailEvent JSON for an errorCode so we can label
            # the event as successful or errored in the output.
            cloudtrail_raw = event.get("CloudTrailEvent") or ""
            had_error = False
            if isinstance(cloudtrail_raw, str) and cloudtrail_raw:
                try:
                    cte = json.loads(cloudtrail_raw)
                    had_error = bool(cte.get("errorCode"))
                except Exception:
                    had_error = False

            event_name = event.get("EventName") or "unknown"
            event_time = event.get("EventTime") or "unknown"
            user = event.get("Username") or "unknown"
            entry = {"eventName": event_name, "eventTime": event_time, "user": user}
            if had_error:
                failed_restores.append(entry)
            else:
                successful_restores.append(entry)

        # Boolean: any DBInstance restore event (successful or errored) counts
        # as evidence of backup-test activity. The output still surfaces the
        # success/failure breakdown so reviewers can interpret it.
        total_restore_events = len(successful_restores) + len(failed_restores)
        is_backup_tested = total_restore_events > 0

        if is_backup_tested:
            most_recent = successful_restores[0] if successful_restores else failed_restores[0]
            pass_reasons.append(
                f"Found {total_restore_events} DB restore event(s) in CloudTrail "
                f"({len(successful_restores)} successful, {len(failed_restores)} errored). "
                f"Most recent: {most_recent['eventName']} at {most_recent['eventTime']} by {most_recent['user']}."
            )
        else:
            fail_reasons.append("No backup restore events (DBInstance restores) found in CloudTrail logs.")
            recommendations.append(
                "Perform a periodic backup restore test (e.g. RestoreDBInstanceFromDBSnapshot) to verify backup integrity."
            )

        return create_response(
            result={criteriaKey: is_backup_tested},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "successfulRestores": len(successful_restores),
                "failedRestores": len(failed_restores),
                "totalEventsInspected": len(event_members),
                "hasCloudTrailData": bool(lookup_response),
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
