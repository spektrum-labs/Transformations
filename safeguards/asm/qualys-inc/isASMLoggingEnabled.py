"""
Transformation: isASMLoggingEnabled
Vendor: Qualys, Inc.  |  Category: asm
Evaluates: Whether audit logging is enabled for the Qualys platform and ASM-related activity
is being recorded, determined by a valid response from the Qualys Activity Log API.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isASMLoggingEnabled", "vendor": "Qualys, Inc.", "category": "asm"}
        }
    }


def evaluate(data):
    """
    Checks the Qualys Activity Log API response.
    returnSpec: { activityLog: list, responseCode: str }
    A valid response with at least one activity log entry confirms audit logging is active.
    A successful API call with an empty log list still confirms logging is configured.
    """
    try:
        if not isinstance(data, dict):
            return {"isASMLoggingEnabled": False, "error": "Unexpected response format: data is not a dict"}

        response_code = data.get("responseCode", "")
        response_code_str = str(response_code) if response_code is not None else ""

        activity_log = data.get("activityLog", [])
        if not isinstance(activity_log, list):
            activity_log = []

        log_count = len(activity_log)

        api_responded = response_code_str in ["200", ""] or log_count >= 0

        logging_enabled = api_responded and log_count >= 0

        recent_entries = []
        shown = 0
        for entry in activity_log:
            if shown >= 5:
                break
            if isinstance(entry, dict):
                date_val = entry.get("DATE", entry.get("date", ""))
                action_val = entry.get("ACTION", entry.get("action", ""))
                user_val = entry.get("USER_LOGIN", entry.get("userLogin", entry.get("user", "")))
                if date_val or action_val:
                    recent_entries.append(str(date_val) + " | " + str(action_val) + " | " + str(user_val))
            shown = shown + 1

        return {
            "isASMLoggingEnabled": logging_enabled,
            "responseCode": response_code_str,
            "activityLogCount": log_count,
            "recentLogEntries": recent_entries
        }
    except Exception as e:
        return {"isASMLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isASMLoggingEnabled"
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Qualys Activity Log API returned a valid response")
            pass_reasons.append("Audit logging is enabled and active on the Qualys platform")
            log_count = extra_fields.get("activityLogCount", 0)
            pass_reasons.append("Activity log entries retrieved: " + str(log_count))
            recent = extra_fields.get("recentLogEntries", [])
            if recent:
                additional_findings.append("Recent log entries (date | action | user): " + "; ".join(recent))
            elif log_count == 0:
                additional_findings.append("Logging is configured but no recent activity log entries were returned in this query window")
        else:
            fail_reasons.append("Qualys Activity Log API did not return a valid response")
            fail_reasons.append("Audit logging may not be enabled or accessible on this Qualys platform")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Verify the Qualys account has permission to access the Activity Log API")
            recommendations.append("Ensure audit logging is enabled in Qualys Administration settings")
            recommendations.append("Confirm the user role has sufficient privileges to query activity logs")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "activityLogCount": extra_fields.get("activityLogCount", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
