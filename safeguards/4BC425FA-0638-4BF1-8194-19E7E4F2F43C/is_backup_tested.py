"""
Transformation: isBackupTested
Vendor: AWS
Category: Backups / Compliance

Checks whether any backups have been tested via restore operations.

Only a restore that succeeded counts as a test. A CloudTrail event whose CloudTrailEvent carries an
errorCode is a restore that failed and proves nothing about the backup, so it is not counted. An event
whose outcome cannot be read is not counted either. No readable CloudTrail answer is Not evaluated
(None plus a dataCollection error), never a fail.
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


def not_evaluated(validation, reason, input_summary=None, recommendations=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={"isBackupTested": None},
        validation=validation,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=[reason]
    )


def restore_outcome(event):
    """Outcome of one CloudTrail event (successful, errored or unknown), read from its CloudTrailEvent JSON.

    CloudTrail adds errorCode (and errorMessage) only to a call that failed, so a readable event without
    either is a successful call. A missing or unreadable CloudTrailEvent says nothing, so it is unknown."""
    raw = event.get("CloudTrailEvent")
    detail = None
    if isinstance(raw, str) and raw.strip():
        try:
            detail = json.loads(raw)
        except Exception:
            detail = None
    elif isinstance(raw, dict):
        detail = raw
    if not isinstance(detail, dict):
        return "unknown"
    if detail.get("errorCode") or detail.get("errorMessage"):
        return "errored"
    return "successful"


def transform(input):
    criteriaKey = "isBackupTested"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, "Could not read CloudTrail: input validation failed")

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Navigate to event list. AWS CloudTrail returns events wrapped in
        # {Events: {member: [...]}}, where `member` may be a list (multiple
        # events) or a single dict (one event). Either shape is valid.
        api_response = data.get("apiResponse", data) if isinstance(data, dict) else {}
        lookup_response = api_response.get("LookupEventsResponse") if isinstance(api_response, dict) else None
        if not isinstance(lookup_response, dict) or "LookupEventsResult" not in lookup_response:
            # An empty body, an error envelope or an outage carries no CloudTrail answer. Only a lookup
            # that came back (even with no events) is evidence about restores.
            return not_evaluated(
                validation,
                "CloudTrail returned no LookupEvents answer (empty body, error body or outage), so restore tests could not be read",
                input_summary={"hasCloudTrailData": False},
                recommendations=["Re-evaluate this check once the CloudTrail lookup succeeds"])
        lookup_result = lookup_response.get("LookupEventsResult") or {}
        if not isinstance(lookup_result, dict):
            lookup_result = {}
        events_container = lookup_result.get("Events") or {}
        event_members = events_container.get("member") if isinstance(events_container, dict) else events_container
        if event_members is None:
            event_members = []
        if isinstance(event_members, dict):
            event_members = [event_members]
        if not isinstance(event_members, list):
            event_members = []

        # For each event, check if any of its Resources is a DBInstance, then read whether the call
        # succeeded. Only a successful restore counts as a backup test.
        successful_restores = []
        failed_restores = []
        unread_restores = []
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

            event_name = event.get("EventName") or "unknown"
            event_time = event.get("EventTime") or "unknown"
            user = event.get("Username") or "unknown"
            entry = {"eventName": event_name, "eventTime": event_time, "user": user}
            outcome = restore_outcome(event)
            if outcome == "errored":
                failed_restores.append(entry)
            elif outcome == "successful":
                successful_restores.append(entry)
            else:
                unread_restores.append(entry)

        next_token = lookup_result.get("NextToken")
        more_pages = isinstance(next_token, str) and next_token.strip() != ""

        summary = {
            "successfulRestores": len(successful_restores),
            "failedRestores": len(failed_restores),
            "unreadRestores": len(unread_restores),
            "totalEventsInspected": len(event_members),
            "hasCloudTrailData": True,
        }

        # A restore that errored is not a test, so only successful restore events make this True.
        if successful_restores:
            most_recent = successful_restores[0]
            pass_reasons.append(
                f"Found {len(successful_restores)} successful DB restore event(s) in CloudTrail "
                f"({len(failed_restores)} errored restore(s) not counted). "
                f"Most recent: {most_recent['eventName']} at {most_recent['eventTime']} by {most_recent['user']}."
            )
            return create_response(
                result={criteriaKey: True},
                validation=validation,
                pass_reasons=pass_reasons,
                input_summary=summary
            )

        if unread_restores:
            return not_evaluated(
                validation,
                f"{len(unread_restores)} DB restore event(s) have no readable outcome, so it is unknown whether any restore succeeded",
                input_summary=summary,
                recommendations=["Re-evaluate this check once the CloudTrail event details can be read"])

        if more_pages:
            return not_evaluated(
                validation,
                "CloudTrail has more events than were read (NextToken present) and none read was a successful restore",
                input_summary=summary,
                recommendations=["Re-evaluate this check once the full CloudTrail lookup is read"])

        if failed_restores:
            fail_reasons.append(
                f"Found {len(failed_restores)} DB restore event(s) in CloudTrail but every one errored; "
                "a failed restore does not test a backup."
            )
        else:
            fail_reasons.append("No backup restore events (DBInstance restores) found in CloudTrail logs.")
        recommendations.append(
            "Perform a periodic backup restore test (e.g. RestoreDBInstanceFromDBSnapshot) to verify backup integrity."
        )
        return create_response(
            result={criteriaKey: False},
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary
        )

    except Exception as e:
        # An error is Not evaluated, never a fail: None plus a dataCollection error.
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=[f"Transformation error: {str(e)}"]
        )
