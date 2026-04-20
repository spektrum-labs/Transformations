"""
Transformation: isBackupTested
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether backup restore tests (Live Mount or recovery validation events) have been performed recently in Rubrik.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def is_recovery_event(event):
    if not isinstance(event, dict):
        return False
    event_type = str(event.get("eventType", event.get("type", event.get("objectType", "")))).upper()
    event_series = str(event.get("eventSeries", event.get("series", ""))).upper()
    event_status = str(event.get("status", event.get("eventStatus", ""))).upper()

    is_recovery = (
        "RECOVERY" in event_type or
        "RESTORE" in event_type or
        "LIVEMOUNT" in event_type or
        "LIVE_MOUNT" in event_type or
        "RECOVERY" in event_series or
        "RESTORE" in event_series
    )
    is_successful = event_status in ["SUCCESS", "SUCCEEDED", "COMPLETED", "PASSED", ""]
    return is_recovery and is_successful


def evaluate(data):
    try:
        if isinstance(data, dict) and "backupTested" in data:
            tested = bool(data["backupTested"])
            last_test = str(data.get("lastTestDate", data.get("lastTestedAt", "Unknown")))
            return {"isBackupTested": tested, "lastTestDate": last_test, "successfulTestCount": int(data.get("testCount", 0))}

        if isinstance(data, dict) and "isBackupTested" in data:
            tested = bool(data["isBackupTested"])
            last_test = str(data.get("lastTestDate", "Unknown"))
            return {"isBackupTested": tested, "lastTestDate": last_test, "successfulTestCount": 0}

        event_list = []
        if isinstance(data, list):
            event_list = data
        elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
            event_list = data["data"]

        if len(event_list) > 0:
            recovery_events = [e for e in event_list if is_recovery_event(e)]
            recovery_count = len(recovery_events)
            last_test_date = "Unknown"
            if recovery_count > 0:
                last_event = recovery_events[0]
                last_test_date = str(last_event.get("time", last_event.get("startTime", last_event.get("date", "Unknown"))))
            return {
                "isBackupTested": recovery_count > 0,
                "successfulTestCount": recovery_count,
                "lastTestDate": last_test_date,
                "totalEventsChecked": len(event_list)
            }

        if isinstance(data, dict):
            test_count = data.get("successfulRecoveryCount", data.get("recoveryCount", data.get("testCount", None)))
            if test_count is not None:
                count_val = int(test_count)
                last_test = str(data.get("lastRecoveryDate", data.get("lastTestDate", "Unknown")))
                return {"isBackupTested": count_val > 0, "successfulTestCount": count_val, "lastTestDate": last_test}

        return {"isBackupTested": False, "error": "Could not determine backup test status from response", "successfulTestCount": 0}
    except Exception as e:
        return {"isBackupTested": False, "error": str(e), "successfulTestCount": 0}


def transform(input):
    criteriaKey = "isBackupTested"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Rubrik backup restore tests have been performed")
            additional_findings.append("Successful recovery tests: " + str(extra_fields.get("successfulTestCount", 0)))
            additional_findings.append("Last test date: " + str(extra_fields.get("lastTestDate", "Unknown")))
        else:
            fail_reasons.append("No Rubrik backup restore or recovery test events found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Schedule regular backup recovery tests (Live Mount or restore validation) in Rubrik to confirm data recoverability")
            recommendations.append("Aim for at least quarterly recovery tests to meet compliance standards")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"successfulTestCount": extra_fields.get("successfulTestCount", 0), "lastTestDate": extra_fields.get("lastTestDate", "Unknown")}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
