"""
Transformation: isIAMLoggingEnabled
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether IAM/authentication logging is active in Duo by confirming auth log records are retrievable.
API Method: getAdminAuthLogs
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIAMLoggingEnabled", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        # data is the authlogs list (returnSpec maps response.authlogs -> data)
        logs_list = data if isinstance(data, list) else []
        total_log_entries = len(logs_list)

        # Logging is confirmed enabled if the endpoint is reachable and returns a list
        # (even an empty list means the endpoint is active and accessible)
        logging_enabled = isinstance(data, list)

        # Summarise event types and results from log entries
        event_types = {}
        result_counts = {}
        factors_seen = []

        for entry in logs_list:
            if not isinstance(entry, dict):
                continue
            event_type = entry.get("event_type", "unknown")
            event_result = entry.get("result", "unknown")
            factor = entry.get("factor", "")

            if event_type in event_types:
                event_types[event_type] = event_types[event_type] + 1
            else:
                event_types[event_type] = 1

            if event_result in result_counts:
                result_counts[event_result] = result_counts[event_result] + 1
            else:
                result_counts[event_result] = 1

            if factor and factor not in factors_seen:
                factors_seen = factors_seen + [factor]

        return {
            "isIAMLoggingEnabled": logging_enabled,
            "totalLogEntries": total_log_entries,
            "eventTypes": event_types,
            "resultBreakdown": result_counts,
            "factorsSeen": factors_seen
        }
    except Exception as e:
        return {"isIAMLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isIAMLoggingEnabled"
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_entries = eval_result.get("totalLogEntries", 0)
        event_types = eval_result.get("eventTypes", {})
        result_breakdown = eval_result.get("resultBreakdown", {})
        factors_seen = eval_result.get("factorsSeen", [])

        if result_value:
            pass_reasons.append("Duo authentication log endpoint is accessible, confirming IAM logging is enabled")
            if total_entries > 0:
                pass_reasons.append("Retrieved " + str(total_entries) + " authentication log entries")
            else:
                pass_reasons.append("Log endpoint reachable; no recent entries in the queried time window")
        else:
            fail_reasons.append("Duo authentication log endpoint did not return a valid response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Admin API application has 'Grant read log' permission enabled")
            recommendations.append("Verify the Duo account plan supports authentication log access")

        if event_types:
            event_summary = ", ".join([k + ": " + str(v) for k in event_types for v in [event_types[k]]])
            additional_findings.append("Event type breakdown: " + event_summary)
        if result_breakdown:
            result_summary = ", ".join([k + ": " + str(v) for k in result_breakdown for v in [result_breakdown[k]]])
            additional_findings.append("Authentication result breakdown: " + result_summary)
        if factors_seen:
            additional_findings.append("Authentication factors observed in logs: " + ", ".join(factors_seen))

        return create_response(
            result={
                criteriaKey: result_value,
                "totalLogEntries": total_entries,
                "eventTypes": event_types,
                "resultBreakdown": result_breakdown,
                "factorsSeen": factors_seen
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalLogEntries": total_entries}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
