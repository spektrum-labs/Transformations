"""
Transformation: isBackupTested
Vendor: Rubrik  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether recent backup jobs have executed successfully in Rubrik CDM.
Checks GET /api/v1/event/latest (event_type=Backup) for events with a successful completion
status, confirming that backups have been run and tested.
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "vendor": "Rubrik",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def evaluate(data):
    try:
        events = data.get("data", [])
        if not isinstance(events, list):
            events = []

        total_events = len(events)
        successful_count = 0
        failed_count = 0
        running_count = 0
        successful_objects = []
        failed_objects = []

        success_statuses = ["Success", "Succeeded", "Succeeded with warnings", "SucceededWithWarnings"]

        for event in events:
            latest = event.get("latestEvent", event)
            status = latest.get("eventStatus", latest.get("status", ""))
            obj_name = latest.get("objectName", latest.get("objectId", "unknown"))

            if status in success_statuses:
                successful_count = successful_count + 1
                successful_objects.append(obj_name)
            elif status in ["Failure", "Failed"]:
                failed_count = failed_count + 1
                failed_objects.append(obj_name)
            elif status in ["Running", "Queued"]:
                running_count = running_count + 1

        is_tested = successful_count > 0

        return {
            "isBackupTested": is_tested,
            "totalBackupEvents": total_events,
            "successfulBackups": successful_count,
            "failedBackups": failed_count,
            "runningBackups": running_count,
            "successfulObjects": successful_objects,
            "failedObjects": failed_objects
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        total_events = eval_result.get("totalBackupEvents", 0)
        successful_count = eval_result.get("successfulBackups", 0)
        failed_count = eval_result.get("failedBackups", 0)
        running_count = eval_result.get("runningBackups", 0)
        successful_objects = eval_result.get("successfulObjects", [])
        failed_objects = eval_result.get("failedObjects", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                str(successful_count) + " of " + str(total_events) +
                " recent backup job event(s) completed successfully, confirming backups have been tested."
            )
            if successful_objects:
                trimmed = successful_objects[:5]
                additional_findings.append(
                    "Sample successfully backed-up objects: " + ", ".join(trimmed)
                )
        else:
            if total_events == 0:
                fail_reasons.append(
                    "No backup job events were returned by GET /api/v1/event/latest. "
                    "No backup activity could be confirmed."
                )
            else:
                fail_reasons.append(
                    str(total_events) + " backup event(s) found but none have a successful completion status. "
                    "Backups may not be running or may be consistently failing."
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Ensure Rubrik SLA Domain policies are assigned to workloads and that backup jobs "
                "are completing successfully. Review the Rubrik event log for failure details."
            )

        if failed_count > 0:
            additional_findings.append(
                str(failed_count) + " failed backup job(s) detected for: " + ", ".join(failed_objects[:5])
            )
        if running_count > 0:
            additional_findings.append(str(running_count) + " backup job(s) currently running or queued.")

        return create_response(
            result={
                criteriaKey: result_value,
                "totalBackupEvents": total_events,
                "successfulBackups": successful_count,
                "failedBackups": failed_count,
                "runningBackups": running_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalBackupEvents": total_events,
                "successfulBackups": successful_count,
                "failedBackups": failed_count,
                "isBackupTested": result_value
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
