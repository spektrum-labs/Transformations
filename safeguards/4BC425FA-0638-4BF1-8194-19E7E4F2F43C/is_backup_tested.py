"""
Transformation: isBackupTested
Vendor: AWS
Category: Backups / Compliance

Checks whether any backups have been tested via restore operations.

Rule (fail closed, the same rule recoverytestcompleted.py applies to the same body): true when at
least one RestoreDBInstanceFromDBSnapshot event against a DB instance completed WITHOUT an errorCode
in its CloudTrailEvent. AWS records failed API calls as events too, so an errored restore is evidence
that someone tried, not that the backup restores. CloudTrail LookupEvents holds 90 days, which bounds
the window. A vendor error or unreadable body is reported as not measured, never as a finding.
"""

import json
from datetime import datetime

#: The criterion this file answers; a None value is reported as not measured.
CRITERIA_KEY = "isBackupTested"


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
    # Not measured is read off the criterion's value, so every path that leaves it None -- the
    # except branch included -- reaches Token-Service as not evaluated rather than as a gap.
    measured = result.get(CRITERIA_KEY) is not None
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if measured else "error",
                "errors": [] if measured else (api_errors or fail_reasons or transformation_errors
                                               or ["The response could not answer this check, so it was not evaluated."])
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


def vendor_error(data):
    """The vendor's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if not isinstance(data, dict):
        return None
    for key in ["error", "errors", "Error", "ErrorResponse", "__type", "errorType", "errorCode"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                inner = value.get("Error") if isinstance(value.get("Error"), dict) else value
                return str(inner.get("Message") or inner.get("message") or inner.get("Code") or value)
            return "%s: %s" % (value, data.get("Message") or data.get("message") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def transform(input):
    criteriaKey = CRITERIA_KEY

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Navigate to event list. AWS CloudTrail returns events wrapped in
        # {Events: {member: [...]}}, where `member` may be a list (multiple
        # events) or a single dict (one event). Either shape is valid.
        api_response = data.get("apiResponse", data) if isinstance(data, dict) else data
        error = vendor_error(api_response)
        lookup_response = api_response.get("LookupEventsResponse") if isinstance(api_response, dict) else None
        if error is None and not isinstance(lookup_response, dict):
            error = "Response has no LookupEventsResponse; CloudTrail restore events were not read"
        if error is not None:
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error]
            )
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
        # Track successful vs errored events separately; only a successful
        # restore counts toward isBackupTested=true (see boolean comment below).
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

        # Boolean: only a DBInstance restore that completed without an errorCode
        # shows the backup restores. An errored restore is an attempt, and is
        # still surfaced in the breakdown so reviewers can see it.
        total_restore_events = len(successful_restores) + len(failed_restores)
        is_backup_tested = len(successful_restores) > 0

        if is_backup_tested:
            most_recent = successful_restores[0]
            pass_reasons.append(
                f"Found {len(successful_restores)} successful DB restore event(s) in CloudTrail "
                f"({len(failed_restores)} errored). "
                f"Most recent: {most_recent['eventName']} at {most_recent['eventTime']} by {most_recent['user']}."
            )
        elif failed_restores:
            fail_reasons.append(
                f"All {len(failed_restores)} DB restore event(s) in CloudTrail carry an errorCode; no restore completed."
            )
            recommendations.append(
                "Investigate the failed restores and complete a successful restore test from a backup snapshot."
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
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
